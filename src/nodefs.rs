//! Le disque d'un node, lu chez son kubelet par le proxy de l'apiserver.
//!
//! Ni l'objet `Node` ni metrics-server ne disent combien de disque un node consomme : le `Node`
//! porte une *capacité* (`ephemeral-storage`), metrics-server ne rend que CPU et mémoire. Le seul
//! endroit où le chiffre existe est le kubelet lui-même :
//!
//! ```text
//! GET /api/v1/nodes/{node}/proxy/stats/summary
//! ```
//!
//! C'est le même chemin que `kubectl get --raw`, et il demande `nodes/proxy` en RBAC. Un refus est
//! rendu comme un refus — la vue dit qu'elle n'a pas lu, jamais qu'il n'y a rien à lire.
//!
//! # Les trois filesystems, et pourquoi ils ne se confondent pas
//!
//! * **nodefs** — la racine du kubelet : logs des containers, `emptyDir`, couche inscriptible des
//!   pods. C'est celui qui remplit et qui déclenche `DiskPressure`.
//! * **imagefs** — là où le runtime range les images. Souvent le même filesystem que nodefs, pas
//!   toujours ; son seuil d'éviction par défaut n'est pas le même.
//! * **containerfs** — ajouté par les runtimes récents pour séparer les couches inscriptibles des
//!   images. Absent partout ailleurs, et absent veut dire absent, pas vide.
//!
//! # Les seuils sont ceux du kubelet, et ils sont *par défaut*
//!
//! `nodefs.available<10%`, `imagefs.available<15%`, `inodesFree<5%` sont les seuils d'éviction
//! durs qu'un kubelet applique quand personne ne les a changés. Un cluster qui les a reconfigurés
//! évincera ailleurs : le constat nomme donc le seuil qu'il applique, pour qu'on sache à quoi on
//! est comparé.

use std::time::Duration;

use http::Request;
use kube::Client;
use serde_json::Value;

use crate::events::{format_memory_bytes, LineColor};
use crate::lang::{fill, Strings};
use crate::storage::{Hint, HintLevel};

/// Au-delà, on n'attend plus : un kubelet qui ne répond pas est un fait à afficher, et le panneau
/// d'un node ne peut pas rester en attente parce qu'une machine est partie.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Sous ce disponible, le kubelet évince par défaut sur nodefs.
const NODEFS_EVICTION_PCT: i64 = 10;
/// Le même seuil pour imagefs.
const IMAGEFS_EVICTION_PCT: i64 = 15;
/// Et pour les inodes des deux.
const INODES_EVICTION_PCT: i64 = 5;
/// La marge au-dessus du seuil : pas encore une éviction, déjà une tendance.
const WARN_MARGIN_PCT: i64 = 10;

/// Combien de pods gros consommateurs sont nommés. Au-delà la liste cesse de désigner un coupable.
const TOP_PODS: usize = 5;

/// Un filesystem tel que le kubelet le rend : des octets, et des inodes.
///
/// Chaque champ est `Option` parce que le kubelet en omet selon le runtime et la version, et qu'un
/// zéro se lirait comme « rien d'utilisé » là où la vérité est « non mesuré ».
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Fs {
    pub capacity: Option<i64>,
    pub used: Option<i64>,
    pub available: Option<i64>,
    pub inodes: Option<i64>,
    pub inodes_used: Option<i64>,
    pub inodes_free: Option<i64>,
}

impl Fs {
    fn parse(v: &Value) -> Option<Fs> {
        let obj = v.as_object()?;
        let num = |k: &str| obj.get(k).and_then(|v| v.as_i64());
        let fs = Fs {
            capacity: num("capacityBytes"),
            used: num("usedBytes"),
            available: num("availableBytes"),
            inodes: num("inodes"),
            inodes_used: num("inodesUsed"),
            inodes_free: num("inodesFree"),
        };
        // Un objet présent mais vide de tout chiffre n'est pas un filesystem : le rendre ferait une
        // ligne « ? / ? » qui n'apprend rien.
        let empty = fs.capacity.is_none() && fs.used.is_none() && fs.available.is_none();
        (!empty).then_some(fs)
    }

    /// Le taux d'occupation en octets. `None` quand la capacité manque : il n'y a alors rien à
    /// quoi rapporter l'usage.
    pub fn used_pct(&self) -> Option<i64> {
        let (used, capacity) = (self.used?, self.capacity?);
        (capacity > 0).then(|| used.saturating_mul(100) / capacity)
    }

    /// Le disponible en pourcentage — la grandeur sur laquelle le kubelet évince, et donc celle
    /// qu'il faut comparer à son seuil plutôt que `100 - used`, que l'espace réservé fausse.
    pub fn available_pct(&self) -> Option<i64> {
        let (available, capacity) = (self.available?, self.capacity?);
        (capacity > 0).then(|| available.saturating_mul(100) / capacity)
    }

    /// Les inodes libres en pourcentage.
    pub fn inodes_free_pct(&self) -> Option<i64> {
        let (free, total) = (self.inodes_free?, self.inodes?);
        (total > 0).then(|| free.saturating_mul(100) / total)
    }

    /// Le ton d'une ligne de filesystem : le seuil d'éviction du kubelet, puis la marge au-dessus.
    pub fn tone(&self, eviction_pct: i64) -> LineColor {
        match self.available_pct() {
            Some(pct) if pct < eviction_pct => LineColor::Err,
            Some(pct) if pct < eviction_pct + WARN_MARGIN_PCT => LineColor::Warn,
            Some(_) => LineColor::Ok,
            None => LineColor::Dim,
        }
    }

    /// Le texte d'une ligne : ce qui est utilisé sur ce qu'il y a, et ce qui reste.
    pub fn text(&self, st: &'static Strings) -> String {
        let bytes = |v: Option<i64>| v.map(format_memory_bytes).unwrap_or_else(|| "?".to_string());
        let pct = |v: Option<i64>| v.map(|p| format!("{p}%")).unwrap_or_else(|| "?".to_string());
        fill(
            st.nfs_line,
            &[
                ("used", &bytes(self.used)),
                ("capacity", &bytes(self.capacity)),
                ("used_pct", &pct(self.used_pct())),
                ("available", &bytes(self.available)),
                ("available_pct", &pct(self.available_pct())),
            ],
        )
    }

    /// Le texte de la ligne inodes, ou `None` quand le kubelet ne les compte pas.
    pub fn inodes_text(&self, st: &'static Strings) -> Option<String> {
        let total = self.inodes?;
        Some(fill(
            st.nfs_inodes,
            &[
                ("used", &self.inodes_used.unwrap_or(0).to_string()),
                ("total", &total.to_string()),
                ("free_pct", &self.inodes_free_pct().map(|p| format!("{p}%")).unwrap_or_else(|| "?".to_string())),
            ],
        ))
    }
}

/// Ce qu'un pod écrit sur le disque de son node.
///
/// `ephemeral` couvre la couche inscriptible, les logs et les `emptyDir` ; `volumes` est la somme
/// des volumes montés que le kubelet mesure, PVC compris. Les deux se recoupent en partie selon le
/// type de volume, donc ils restent séparés plutôt qu'additionnés.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PodDisk {
    pub namespace: String,
    pub pod: String,
    pub ephemeral: Option<i64>,
    pub volumes: Option<i64>,
}

impl PodDisk {
    /// Ce sur quoi la liste est triée : ce que ce pod pèse sur le disque du node.
    pub fn weight(&self) -> i64 {
        self.ephemeral.unwrap_or(0).max(self.volumes.unwrap_or(0))
    }
}

/// Les filesystems d'un node, et les pods qui y écrivent le plus.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct NodeFilesystems {
    pub node: String,
    pub nodefs: Option<Fs>,
    pub imagefs: Option<Fs>,
    pub containerfs: Option<Fs>,
    /// Les plus gros consommateurs, du plus lourd au plus léger, tronqués à [`TOP_PODS`].
    pub pods: Vec<PodDisk>,
}

impl NodeFilesystems {
    /// Les constats. Un filesystem sous le seuil d'éviction du kubelet est un `Danger` : ce node
    /// évince déjà, ou s'apprête à le faire, et le pod qui partira n'est pas celui qui remplit.
    pub fn hints(&self, st: &'static Strings) -> Vec<Hint> {
        let mut out = Vec::new();
        // Sur la plupart des nodes, imagefs et containerfs *sont* nodefs : le kubelet rend alors
        // trois fois les mêmes capacité, disponible et inodes, et trois constats identiques
        // diraient trois fois la même chose du même disque. Les filesystems qui rendent les mêmes
        // chiffres sont donc constatés ensemble, sous le seuil le plus tôt franchi des leurs.
        for group in self.groups() {
            let fs = group.fs;
            let labels = group.labels.join("/");
            let eviction = group.eviction_pct;
            if let Some(pct) = fs.available_pct() {
                if pct < eviction {
                    out.push(Hint {
                        level: HintLevel::Danger,
                        text: fill(
                            st.nfs_below_eviction,
                            &[("fs", &labels), ("pct", &pct.to_string()), ("threshold", &eviction.to_string())],
                        ),
                    });
                } else if pct < eviction + WARN_MARGIN_PCT {
                    out.push(Hint {
                        level: HintLevel::Warn,
                        text: fill(
                            st.nfs_near_eviction,
                            &[("fs", &labels), ("pct", &pct.to_string()), ("threshold", &eviction.to_string())],
                        ),
                    });
                }
            }
            if let Some(pct) = fs.inodes_free_pct() {
                if pct < INODES_EVICTION_PCT {
                    out.push(Hint {
                        level: HintLevel::Danger,
                        text: fill(
                            st.nfs_inodes_below_eviction,
                            &[("fs", &labels), ("pct", &pct.to_string()), ("threshold", &INODES_EVICTION_PCT.to_string())],
                        ),
                    });
                } else if pct < INODES_EVICTION_PCT + WARN_MARGIN_PCT {
                    out.push(Hint {
                        level: HintLevel::Warn,
                        text: fill(
                            st.nfs_inodes_near_eviction,
                            &[("fs", &labels), ("pct", &pct.to_string()), ("threshold", &INODES_EVICTION_PCT.to_string())],
                        ),
                    });
                }
            }
        }
        out
    }

    /// Les filesystems regroupés par chiffres identiques.
    ///
    /// Deux filesystems qui rendent la même capacité, le même disponible et les mêmes inodes sont
    /// le même disque vu deux fois — c'est le cas courant, où le runtime partage la racine du
    /// kubelet. Le seuil retenu pour le groupe est le plus élevé de ses membres : c'est celui qui
    /// se franchit en premier, donc le premier qui fera évincer.
    fn groups(&self) -> Vec<FsGroup<'_>> {
        let mut out: Vec<FsGroup<'_>> = Vec::new();
        for (label, fs, eviction) in [
            ("nodefs", self.nodefs.as_ref(), NODEFS_EVICTION_PCT),
            ("imagefs", self.imagefs.as_ref(), IMAGEFS_EVICTION_PCT),
            ("containerfs", self.containerfs.as_ref(), NODEFS_EVICTION_PCT),
        ] {
            let Some(fs) = fs else { continue };
            match out.iter_mut().find(|g| same_device(g.fs, fs)) {
                Some(group) => {
                    group.labels.push(label);
                    group.eviction_pct = group.eviction_pct.max(eviction);
                }
                None => out.push(FsGroup { fs, labels: vec![label], eviction_pct: eviction }),
            }
        }
        out
    }

    /// Vrai quand ce filesystem rend les mêmes capacité, disponible et inodes que `nodefs` — ce
    /// qui se dit tel quel dans la vue, sans conclure que c'est le même point de montage.
    pub fn shares_nodefs(&self, fs: &Fs) -> bool {
        self.nodefs.as_ref().map(|root| same_device(root, fs)).unwrap_or(false)
    }

    /// Le taux d'occupation à mettre dans une cellule : celui de nodefs, qui est le filesystem dont
    /// le remplissage évince.
    pub fn headline_pct(&self) -> Option<i64> {
        self.nodefs.as_ref().and_then(|fs| fs.used_pct())
    }
}

/// Lit le résumé du kubelet d'un node et en garde ce qui concerne le disque.
///
/// L'erreur rendue est celle du proxy, chaîne des causes comprise : « refusé », « kubelet
/// injoignable » et « node parti » ne se traitent pas pareil, et les trois arrivent ici.
pub async fn fetch(client: &Client, node: &str) -> Result<NodeFilesystems, String> {
    let path = format!("/api/v1/nodes/{node}/proxy/stats/summary");
    let req = Request::get(&path).body(Vec::new()).map_err(|e| e.to_string())?;
    let body = match tokio::time::timeout(TIMEOUT, client.request_text(req)).await {
        Ok(Ok(text)) => text,
        Ok(Err(e)) => return Err(error_chain(&e)),
        Err(_) => {
            return Err(fill(
                crate::lang::active().nfs_timeout,
                &[("n", &TIMEOUT.as_secs().to_string())],
            ))
        }
    };
    let value: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    Ok(parse(node, &value))
}

/// Le tri du résumé, séparé de la lecture pour être testable sur une charge utile figée.
pub fn parse(node: &str, value: &Value) -> NodeFilesystems {
    let node_stats = value.get("node");
    let nodefs = node_stats.and_then(|n| n.get("fs")).and_then(Fs::parse);
    let runtime = node_stats.and_then(|n| n.get("runtime"));
    let imagefs = runtime.and_then(|r| r.get("imageFs")).and_then(Fs::parse);
    let containerfs = runtime.and_then(|r| r.get("containerFs")).and_then(Fs::parse);

    let mut pods: Vec<PodDisk> = value
        .get("pods")
        .and_then(|p| p.as_array())
        .map(|list| {
            list.iter()
                .map(|p| {
                    let reference = p.get("podRef");
                    let ephemeral = p
                        .get("ephemeral-storage")
                        .and_then(|e| e.get("usedBytes"))
                        .and_then(|v| v.as_i64());
                    // La somme des volumes que le kubelet mesure : un `emptyDir` qui gonfle et un
                    // PVC presque plein se voient tous les deux ici.
                    let volumes = p.get("volume").and_then(|v| v.as_array()).map(|vols| {
                        vols.iter()
                            .filter_map(|v| v.get("usedBytes").and_then(|u| u.as_i64()))
                            .sum::<i64>()
                    });
                    PodDisk {
                        namespace: str_at(reference, "namespace"),
                        pod: str_at(reference, "name"),
                        ephemeral,
                        volumes,
                    }
                })
                .filter(|p| p.weight() > 0)
                .collect()
        })
        .unwrap_or_default();
    pods.sort_by(|a, b| {
        b.weight()
            .cmp(&a.weight())
            .then(a.namespace.cmp(&b.namespace))
            .then(a.pod.cmp(&b.pod))
    });
    pods.truncate(TOP_PODS);

    NodeFilesystems { node: node.to_string(), nodefs, imagefs, containerfs, pods }
}

/// Des filesystems qui rendent les mêmes chiffres, constatés ensemble.
struct FsGroup<'a> {
    fs: &'a Fs,
    labels: Vec<&'static str>,
    eviction_pct: i64,
}

/// Mêmes capacité, même disponible, mêmes inodes : le kubelet décrit le même disque deux fois.
/// C'est une comparaison de chiffres, pas une lecture du point de montage — le résumé du kubelet
/// ne le donne pas.
fn same_device(a: &Fs, b: &Fs) -> bool {
    a.capacity == b.capacity && a.available == b.available && a.inodes == b.inodes
}

/// Un filesystem prêt à être rendu : ses chiffres, son ton, son seuil, et ce qu'il porte.
///
/// C'est la forme que kdt-web reçoit : le ton et le seuil descendent d'ici pour que le navigateur
/// peigne le même verdict que le TUI plutôt que de rejuger des octets.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FsBlock {
    pub label: &'static str,
    /// Le seuil d'éviction par défaut du kubelet appliqué à ce filesystem.
    pub eviction_pct: i64,
    pub note: String,
    pub tone: LineColor,
    pub inodes_tone: LineColor,
    pub used_text: String,
    pub capacity_text: String,
    pub available_text: String,
    pub used_pct: Option<i64>,
    pub available_pct: Option<i64>,
    pub inodes: Option<i64>,
    pub inodes_used: Option<i64>,
    pub inodes_free_pct: Option<i64>,
}

/// Les filesystems lus, dans l'ordre où ils se lisent : la racine du kubelet d'abord, parce que
/// c'est celle qui évince.
pub fn blocks(fs: &NodeFilesystems, st: &'static Strings) -> Vec<FsBlock> {
    let mut out = Vec::new();
    let bytes = |v: Option<i64>| v.map(format_memory_bytes).unwrap_or_else(|| "?".to_string());
    for (label, one, eviction, note) in [
        (
            "nodefs",
            fs.nodefs.as_ref(),
            NODEFS_EVICTION_PCT,
            fill(st.nfs_note_nodefs, &[("threshold", &NODEFS_EVICTION_PCT.to_string())]),
        ),
        (
            "imagefs",
            fs.imagefs.as_ref(),
            IMAGEFS_EVICTION_PCT,
            fill(st.nfs_note_imagefs, &[("threshold", &IMAGEFS_EVICTION_PCT.to_string())]),
        ),
        ("containerfs", fs.containerfs.as_ref(), NODEFS_EVICTION_PCT, String::new()),
    ] {
        let Some(one) = one else { continue };
        // Un filesystem qui rend les chiffres de nodefs est le même disque vu deux fois : répéter
        // son seuil d'éviction ferait croire à un second espace à surveiller.
        let note = if label != "nodefs" && fs.shares_nodefs(one) {
            st.nfs_same_device.to_string()
        } else {
            note
        };
        out.push(FsBlock {
            label,
            eviction_pct: eviction,
            note,
            tone: one.tone(eviction),
            inodes_tone: match one.inodes_free_pct() {
                Some(pct) if pct < INODES_EVICTION_PCT => LineColor::Err,
                Some(pct) if pct < INODES_EVICTION_PCT + WARN_MARGIN_PCT => LineColor::Warn,
                _ => LineColor::Dim,
            },
            used_text: bytes(one.used),
            capacity_text: bytes(one.capacity),
            available_text: bytes(one.available),
            used_pct: one.used_pct(),
            available_pct: one.available_pct(),
            inodes: one.inodes,
            inodes_used: one.inodes_used,
            inodes_free_pct: one.inodes_free_pct(),
        });
    }
    out
}

/// Le disque d'un node en une ligne : de quoi tenir dans un cumul ou dans un prompt.
///
/// La même ligne sert au bloc de cumuls du TUI, à l'export texte et au prompt de l'IA : ce que le
/// kubelet a dit ne se raconte pas de trois façons.
pub fn summary_text(
    fs: Option<&NodeFilesystems>,
    error: Option<&str>,
    st: &'static Strings,
) -> String {
    let Some(fs) = fs else {
        return fill(st.nfs_unread, &[("e", error.unwrap_or("?"))]);
    };
    let bytes = |v: Option<i64>| v.map(format_memory_bytes).unwrap_or_else(|| "?".to_string());
    let pct = |v: Option<i64>| v.map(|p| format!("{p}%")).unwrap_or_else(|| "?".to_string());
    let mut parts = Vec::new();
    for (label, one) in [
        ("nodefs", fs.nodefs.as_ref()),
        ("imagefs", fs.imagefs.as_ref()),
        ("containerfs", fs.containerfs.as_ref()),
    ] {
        let Some(one) = one else { continue };
        let mut part = format!(
            "{label} {}/{} {}",
            bytes(one.used),
            bytes(one.capacity),
            pct(one.used_pct()),
        );
        if let Some(free) = one.inodes_free_pct() {
            part.push_str(&format!(" (inodes {free}%)"));
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return st.nfs_nodefs_absent.to_string();
    }
    parts.join("   ")
}

/// Le ton de cette ligne : le pire des filesystems lus, chacun face à son propre seuil.
pub fn summary_tone(fs: Option<&NodeFilesystems>) -> LineColor {
    let Some(fs) = fs else { return LineColor::Info };
    let worst = |a: LineColor, b: LineColor| {
        let rank = |c: LineColor| match c {
            LineColor::Err => 3,
            LineColor::Warn => 2,
            LineColor::Ok => 1,
            _ => 0,
        };
        if rank(a) >= rank(b) { a } else { b }
    };
    let mut tone = LineColor::Dim;
    if let Some(one) = &fs.nodefs {
        tone = worst(tone, one.tone(NODEFS_EVICTION_PCT));
    }
    if let Some(one) = &fs.imagefs {
        tone = worst(tone, one.tone(IMAGEFS_EVICTION_PCT));
    }
    if let Some(one) = &fs.containerfs {
        tone = worst(tone, one.tone(NODEFS_EVICTION_PCT));
    }
    tone
}

/// Le bloc du panneau de détail d'un node : les filesystems, leurs inodes, puis qui écrit.
pub fn lines(fs: &NodeFilesystems, st: &'static Strings) -> Vec<(LineColor, String)> {
    let mut out: Vec<(LineColor, String)> = Vec::new();
    out.push((LineColor::Plain, String::new()));
    out.push((LineColor::Info, st.nfs_header.to_string()));

    match &fs.nodefs {
        Some(nodefs) => out.extend(fs_block(
            "nodefs",
            nodefs,
            NODEFS_EVICTION_PCT,
            &fill(st.nfs_note_nodefs, &[("threshold", &NODEFS_EVICTION_PCT.to_string())]),
            st,
        )),
        None => out.push((LineColor::Info, format!("  {}", st.nfs_nodefs_absent))),
    }
    if let Some(imagefs) = &fs.imagefs {
        let note = if fs.shares_nodefs(imagefs) {
            st.nfs_same_device.to_string()
        } else {
            fill(st.nfs_note_imagefs, &[("threshold", &IMAGEFS_EVICTION_PCT.to_string())])
        };
        out.extend(fs_block("imagefs", imagefs, IMAGEFS_EVICTION_PCT, &note, st));
    }
    if let Some(containerfs) = &fs.containerfs {
        let note = if fs.shares_nodefs(containerfs) { st.nfs_same_device } else { "" };
        out.extend(fs_block("containerfs", containerfs, NODEFS_EVICTION_PCT, note, st));
    }

    for hint in fs.hints(st) {
        let tone = match hint.level {
            HintLevel::Danger => LineColor::Err,
            HintLevel::Warn => LineColor::Warn,
            HintLevel::Info => LineColor::Info,
        };
        out.push((tone, format!("  ▲ {}", hint.text)));
    }

    if !fs.pods.is_empty() {
        out.push((LineColor::Info, format!("  {}", st.nfs_top_pods)));
        for p in &fs.pods {
            let bytes = |v: Option<i64>| v.map(format_memory_bytes).unwrap_or_else(|| "—".to_string());
            out.push((
                LineColor::Dim,
                format!(
                    "    {}/{}  ephemeral={}  volumes={}",
                    p.namespace,
                    p.pod,
                    bytes(p.ephemeral),
                    bytes(p.volumes),
                ),
            ));
        }
    }
    out
}

/// Le bloc, ou la raison pour laquelle il n'y en a pas. Un refus RBAC sur `nodes/proxy` est la
/// cause la plus fréquente, et l'écrire évite de chercher un disque qui va bien.
pub fn lines_or_reason(
    result: &Result<NodeFilesystems, String>,
    st: &'static Strings,
) -> Vec<(LineColor, String)> {
    match result {
        Ok(fs) => lines(fs, st),
        Err(e) => vec![
            (LineColor::Plain, String::new()),
            (LineColor::Info, st.nfs_header.to_string()),
            (LineColor::Info, format!("  {}", fill(st.nfs_unread, &[("e", e)]))),
        ],
    }
}

/// Les deux ou trois lignes d'un filesystem : les octets, les inodes quand ils sont comptés, et ce
/// que ce filesystem porte.
fn fs_block(
    label: &str,
    fs: &Fs,
    eviction: i64,
    note: &str,
    st: &'static Strings,
) -> Vec<(LineColor, String)> {
    let mut out = vec![(fs.tone(eviction), format!("  {:<12} {}", label, fs.text(st)))];
    if let Some(text) = fs.inodes_text(st) {
        let tone = match fs.inodes_free_pct() {
            Some(pct) if pct < INODES_EVICTION_PCT => LineColor::Err,
            Some(pct) if pct < INODES_EVICTION_PCT + WARN_MARGIN_PCT => LineColor::Warn,
            _ => LineColor::Dim,
        };
        out.push((tone, format!("  {:<12} {}", "", text)));
    }
    if !note.is_empty() {
        out.push((LineColor::Dim, format!("  {:<12} {}", "", note)));
    }
    out
}

fn str_at(v: Option<&Value>, key: &str) -> String {
    v.and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        let text = s.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        src = s.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn summary() -> Value {
        json!({
            "node": {
                "nodeName": "n1",
                "fs": {
                    "capacityBytes": 100_000_000_000_i64,
                    "usedBytes": 95_000_000_000_i64,
                    "availableBytes": 5_000_000_000_i64,
                    "inodes": 1_000_000,
                    "inodesUsed": 400_000,
                    "inodesFree": 600_000,
                },
                "runtime": {
                    "imageFs": {
                        "capacityBytes": 100_000_000_000_i64,
                        "usedBytes": 40_000_000_000_i64,
                        "availableBytes": 60_000_000_000_i64,
                    },
                },
            },
            "pods": [
                {
                    "podRef": { "name": "logger", "namespace": "apps" },
                    "ephemeral-storage": { "usedBytes": 8_000_000_000_i64 },
                    "volume": [{ "name": "cache", "usedBytes": 1_000_000_000_i64 }],
                },
                {
                    "podRef": { "name": "quiet", "namespace": "apps" },
                    "ephemeral-storage": { "usedBytes": 1_000_i64 },
                },
                {
                    "podRef": { "name": "unmeasured", "namespace": "apps" },
                },
            ],
        })
    }

    #[test]
    fn the_three_filesystems_are_kept_apart() {
        let fs = parse("n1", &summary());
        let nodefs = fs.nodefs.expect("nodefs");
        assert_eq!(nodefs.used_pct(), Some(95));
        assert_eq!(nodefs.available_pct(), Some(5));
        assert_eq!(nodefs.inodes_free_pct(), Some(60));
        assert_eq!(fs.imagefs.expect("imagefs").available_pct(), Some(60));
        // Absent veut dire absent : aucun runtime n'a rendu de containerfs ici.
        assert!(fs.containerfs.is_none());
    }

    #[test]
    fn a_filesystem_below_the_eviction_threshold_is_a_danger() {
        let fs = parse("n1", &summary());
        let hints = fs.hints(crate::lang::active());
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].level, HintLevel::Danger);
        assert!(hints[0].text.contains("nodefs"));
    }

    #[test]
    fn the_pods_are_ranked_and_the_unmeasured_ones_dropped() {
        let fs = parse("n1", &summary());
        assert_eq!(fs.pods.len(), 2);
        assert_eq!(fs.pods[0].pod, "logger");
        assert_eq!(fs.pods[0].ephemeral, Some(8_000_000_000));
        assert_eq!(fs.pods[0].volumes, Some(1_000_000_000));
        assert_eq!(fs.pods[1].pod, "quiet");
    }

    #[test]
    fn an_empty_filesystem_object_is_not_a_filesystem() {
        let fs = parse("n1", &json!({ "node": { "fs": { "time": "2026-01-01T00:00:00Z" } } }));
        assert!(fs.nodefs.is_none());
        // Ni chiffre ni faux zéro : le bloc dira que le kubelet n'a rien rendu.
        assert!(fs.headline_pct().is_none());
    }

    #[test]
    fn a_capacity_of_zero_yields_no_ratio() {
        let fs = Fs { capacity: Some(0), used: Some(10), ..Fs::default() };
        assert_eq!(fs.used_pct(), None);
        assert_eq!(fs.available_pct(), None);
        assert_eq!(fs.tone(NODEFS_EVICTION_PCT), LineColor::Dim);
    }

    #[test]
    fn filesystems_that_report_the_same_numbers_are_one_finding() {
        // Le cas courant : le runtime partage la racine du kubelet, et le résumé rend trois fois
        // les mêmes chiffres. Un seul constat, sous le seuil le plus tôt franchi des trois.
        let shared = json!({
            "capacityBytes": 100_000_000_000_i64,
            "usedBytes": 88_000_000_000_i64,
            "availableBytes": 12_000_000_000_i64,
            "inodes": 1_000_000,
            "inodesUsed": 100_000,
            "inodesFree": 900_000,
        });
        let fs = parse(
            "n1",
            &json!({
                "node": {
                    "fs": shared,
                    "runtime": { "imageFs": shared, "containerFs": shared },
                },
            }),
        );
        let hints = fs.hints(crate::lang::active());
        assert_eq!(hints.len(), 1);
        // 12 % libre : au-dessus du seuil de nodefs (10 %), sous celui d'imagefs (15 %).
        assert!(hints[0].text.contains("nodefs/imagefs/containerfs"), "{}", hints[0].text);
        assert!(hints[0].text.contains("15"), "{}", hints[0].text);
        assert_eq!(hints[0].level, HintLevel::Danger);

        // Et le bloc le dit plutôt que de répéter un second seuil à surveiller.
        let blocks = blocks(&fs, crate::lang::active());
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[1].note, crate::lang::active().nfs_same_device);
    }

    #[test]
    fn a_separate_image_filesystem_keeps_its_own_finding() {
        let fs = parse(
            "n1",
            &json!({
                "node": {
                    "fs": { "capacityBytes": 100_i64, "usedBytes": 95_i64, "availableBytes": 5_i64 },
                    "runtime": { "imageFs": { "capacityBytes": 200_i64, "usedBytes": 20_i64, "availableBytes": 180_i64 } },
                },
            }),
        );
        let hints = fs.hints(crate::lang::active());
        assert_eq!(hints.len(), 1);
        assert!(hints[0].text.starts_with("nodefs"), "{}", hints[0].text);
        assert!(!fs.shares_nodefs(fs.imagefs.as_ref().expect("imagefs")));
    }

    #[test]
    fn the_summary_line_says_what_was_not_read() {
        let text = summary_text(None, Some("nodes/proxy forbidden"), crate::lang::active());
        assert!(text.contains("nodes/proxy forbidden"));
        assert_eq!(summary_tone(None), LineColor::Info);
    }

    #[test]
    fn the_summary_line_names_each_filesystem_read() {
        let fs = parse("n1", &summary());
        let text = summary_text(Some(&fs), None, crate::lang::active());
        assert!(text.contains("nodefs"));
        assert!(text.contains("imagefs"));
        assert_eq!(summary_tone(Some(&fs)), LineColor::Err);
    }
}
