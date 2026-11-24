//! Le contexte `kdt-<contexte>` : le rebond d'une session, ouvert aux autres outils.
//!
//! Un cluster derrière un rebond n'est joignable que par le proxy SOCKS5 que kdt ouvre pour lui.
//! Le temps de la session, kdt déclare dans le kubeconfig un contexte qui passe par ce proxy :
//! `kubectl --context kdt-fpci get pods`, `helm`, `flux`… l'empruntent comme n'importe quel
//! contexte. Le cluster d'origine est recopié avec un `proxy-url` portant le jeton ; le user est
//! référencé, jamais recopié.
//!
//! # Ce qui appartient à kdt
//!
//! Chaque entrée écrite porte une extension `kdt` (pid et date de démarrage du processus). kdt ne
//! touche à rien d'autre : un nom déjà pris par une entrée sans cette marque est laissé tel quel et
//! le suivant est essayé (`kdt-fpci-2`…), comme pour une autre instance encore vivante. Une entrée
//! dont le processus a disparu (`kill -9`, coupure) est purgée par la prochaine écriture.
//!
//! # Le fichier
//!
//! Celui qui déclare le contexte d'origine — celui que `kubectl` lit pour lui. Il est verrouillé
//! comme le fait client-go (`<fichier>.lock`), et réécrit en place pour garder son mode et un
//! éventuel lien symbolique.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use serde_yaml::{Mapping, Value};

/// Le nom de l'extension qui marque une entrée écrite par kdt.
pub const MARK: &str = "kdt";
const PREFIX: &str = "kdt-";
const MAX_SUFFIX: u32 = 99;

/// Le processus propriétaire d'une entrée : le pid seul pourrait avoir été réattribué.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Owner {
    pid: u32,
    start: u64,
}

impl Owner {
    fn me() -> Owner {
        static ME: OnceLock<Owner> = OnceLock::new();
        *ME.get_or_init(|| {
            let pid = std::process::id();
            Owner { pid, start: start_time(pid).unwrap_or(0) }
        })
    }

    fn to_value(self) -> Value {
        let mut m = Mapping::new();
        m.insert("pid".into(), Value::Number(self.pid.into()));
        m.insert("start".into(), Value::Number(self.start.into()));
        Value::Mapping(m)
    }

    fn from_value(v: &Value) -> Option<Owner> {
        Some(Owner {
            pid: u32::try_from(v.get("pid")?.as_u64()?).ok()?,
            start: v.get("start")?.as_u64()?,
        })
    }
}

// Champ 22 de `/proc/<pid>/stat`, compté après la parenthèse fermante : le nom du programme peut
// contenir des espaces.
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

// Sans `/proc`, impossible de dire qu'un processus est mort : il est réputé vivant, et rien n'est
// repris.
fn alive(o: &Owner) -> bool {
    if !Path::new("/proc/self/stat").exists() {
        return true;
    }
    start_time(o.pid) == Some(o.start)
}

/// Un contexte `kdt-…` déclaré par cette session ; retiré du kubeconfig quand il est lâché.
#[derive(Debug)]
pub struct Alias {
    pub name: String,
    file: PathBuf,
}

impl Drop for Alias {
    fn drop(&mut self) {
        if let Err(e) = remove(&self.file, &self.name) {
            tracing::warn!("kubeconfig alias {} not removed from {}: {e:#}", self.name, self.file.display());
        }
        forget(&self.file, &self.name);
    }
}

/// Déclare `kdt-<context>` (ou le premier suffixe libre) dans le kubeconfig, à travers `proxy_url`.
pub fn create(context: &str, proxy_url: &str) -> Result<Alias> {
    let files = kubeconfig_files()?;
    let docs: Vec<(PathBuf, Value)> = files.iter().filter_map(|f| read(f).ok().map(|d| (f.clone(), d))).collect();
    let (file, _) = docs
        .iter()
        .find(|(_, d)| named(d, "contexts", context).is_some())
        .ok_or_else(|| anyhow!("context {context}: not found in the kubeconfig"))?;
    let cluster_name = docs
        .iter()
        .find_map(|(_, d)| named(d, "contexts", context)?.get("context")?.get("cluster")?.as_str().map(String::from))
        .ok_or_else(|| anyhow!("context {context}: no cluster"))?;
    let cluster = docs
        .iter()
        .find_map(|(_, d)| named(d, "clusters", &cluster_name)?.get("cluster").cloned())
        .ok_or_else(|| anyhow!("cluster {cluster_name}: not found in the kubeconfig"))?;
    let file = file.clone();
    let name = with_lock(&file, |doc| add(doc, context, &cluster, proxy_url, Owner::me(), alive))?;
    remember(&file, &name);
    install_panic_hook();
    Ok(Alias { name, file })
}

/// Si ce contexte a été écrit par kdt — un `kdt-…` d'une session, pas un contexte à proposer.
pub fn is_alias(c: &kube::config::NamedContext) -> bool {
    c.context
        .as_ref()
        .and_then(|c| c.extensions.as_ref())
        .is_some_and(|e| e.iter().any(|x| x.name == MARK))
}

fn remove(file: &Path, name: &str) -> Result<()> {
    with_lock(file, |doc| {
        drop_alias(doc, name, Owner::me());
        Ok(())
    })
}

// Les fichiers dans l'ordre de fusion de kubectl : `KUBECONFIG`, sinon `~/.kube/config`.
fn kubeconfig_files() -> Result<Vec<PathBuf>> {
    if let Some(v) = std::env::var_os("KUBECONFIG") {
        let paths: Vec<PathBuf> = std::env::split_paths(&v).filter(|p| !p.as_os_str().is_empty()).collect();
        if !paths.is_empty() {
            return Ok(paths);
        }
    }
    let home = std::env::home_dir().ok_or_else(|| anyhow!("no home directory"))?;
    Ok(vec![home.join(".kube").join("config")])
}

fn read(file: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(file).with_context(|| file.display().to_string())?;
    Ok(serde_yaml::from_str(&text).with_context(|| file.display().to_string())?)
}

// Le verrou de client-go : un `<fichier>.lock` créé en exclusif, retiré après l'écriture.
fn with_lock<T>(file: &Path, f: impl FnOnce(&mut Value) -> Result<T>) -> Result<T> {
    let mut lock_name = file.as_os_str().to_owned();
    lock_name.push(".lock");
    let lock = PathBuf::from(lock_name);
    let mut tries = 0;
    loop {
        match OpenOptions::new().write(true).create_new(true).open(&lock) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && tries < 20 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(anyhow!("{}: {e}", lock.display())),
        }
    }
    let result = (|| {
        let mut doc = read(file)?;
        let before = doc.clone();
        let out = f(&mut doc)?;
        if doc != before {
            let text = serde_yaml::to_string(&doc)?;
            let mut w = OpenOptions::new().write(true).truncate(true).open(file)?;
            w.write_all(text.as_bytes())?;
        }
        Ok(out)
    })();
    let _ = std::fs::remove_file(&lock);
    result
}

fn list<'a>(doc: &'a Value, key: &str) -> &'a [Value] {
    doc.get(key).and_then(Value::as_sequence).map(Vec::as_slice).unwrap_or(&[])
}

fn named<'a>(doc: &'a Value, key: &str, name: &str) -> Option<&'a Value> {
    list(doc, key).iter().find(|e| e.get("name").and_then(Value::as_str) == Some(name))
}

fn owner_of(entry: &Value, inner: &str) -> Option<Owner> {
    entry
        .get(inner)?
        .get("extensions")?
        .as_sequence()?
        .iter()
        .find(|x| x.get("name").and_then(Value::as_str) == Some(MARK))
        .and_then(|x| Owner::from_value(x.get("extension")?))
}

fn seq_mut<'a>(doc: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    if !doc.is_mapping() {
        *doc = Value::Mapping(Mapping::new());
    }
    let map = doc.as_mapping_mut().expect("mapping");
    let slot = map.entry(key.into()).or_insert(Value::Sequence(Vec::new()));
    if !slot.is_sequence() {
        *slot = Value::Sequence(Vec::new());
    }
    slot.as_sequence_mut().expect("sequence")
}

// Retire les entrées marquées kdt que `keep` refuse ; les autres ne sont jamais regardées.
fn retain_owned(doc: &mut Value, keep: impl Fn(&str, Owner) -> bool) {
    for (key, inner) in [("contexts", "context"), ("clusters", "cluster")] {
        seq_mut(doc, key).retain(|e| match (owner_of(e, inner), e.get("name").and_then(Value::as_str)) {
            (Some(o), Some(n)) => keep(n, o),
            _ => true,
        });
    }
}

fn add(
    doc: &mut Value,
    context: &str,
    cluster: &Value,
    proxy_url: &str,
    me: Owner,
    alive: impl Fn(&Owner) -> bool,
) -> Result<String> {
    retain_owned(doc, |_, o| o == me || alive(&o));
    let ctx = named(doc, "contexts", context)
        .and_then(|c| c.get("context"))
        .cloned()
        .ok_or_else(|| anyhow!("context {context}: not found"))?;
    let base = format!("{PREFIX}{context}");
    let taken = |n: &str| named(doc, "contexts", n).is_some() || named(doc, "clusters", n).is_some();
    let name = std::iter::once(base.clone())
        .chain((2..=MAX_SUFFIX).map(|i| format!("{base}-{i}")))
        .find(|n| !taken(n))
        .ok_or_else(|| anyhow!("{base}: no free name up to -{MAX_SUFFIX}"))?;

    let mark = || {
        let mut m = Mapping::new();
        m.insert("name".into(), MARK.into());
        m.insert("extension".into(), me.to_value());
        Value::Sequence(vec![Value::Mapping(m)])
    };

    let mut cl = cluster.as_mapping().cloned().unwrap_or_default();
    cl.insert("proxy-url".into(), proxy_url.into());
    cl.insert("extensions".into(), mark());
    let mut entry = Mapping::new();
    entry.insert("name".into(), name.clone().into());
    entry.insert("cluster".into(), Value::Mapping(cl));
    seq_mut(doc, "clusters").push(Value::Mapping(entry));

    let mut cx = Mapping::new();
    cx.insert("cluster".into(), name.clone().into());
    for key in ["user", "namespace"] {
        if let Some(v) = ctx.get(key) {
            cx.insert(key.into(), v.clone());
        }
    }
    cx.insert("extensions".into(), mark());
    let mut entry = Mapping::new();
    entry.insert("name".into(), name.clone().into());
    entry.insert("context".into(), Value::Mapping(cx));
    seq_mut(doc, "contexts").push(Value::Mapping(entry));
    Ok(name)
}

fn drop_alias(doc: &mut Value, name: &str, me: Owner) {
    retain_owned(doc, |n, o| !(n == name && o == me));
    // Un `kubectl config use-context kdt-…` laisserait sinon un contexte courant qui n'existe plus.
    if doc.get("current-context").and_then(Value::as_str) == Some(name) {
        if let Some(m) = doc.as_mapping_mut() {
            m.insert("current-context".into(), "".into());
        }
    }
}

// Ce que le crochet de panique retire : `panic = "abort"` ne déroule rien, aucun `Drop` ne passe.
fn registry() -> &'static Mutex<Vec<(PathBuf, String)>> {
    static LIVE: OnceLock<Mutex<Vec<(PathBuf, String)>>> = OnceLock::new();
    LIVE.get_or_init(|| Mutex::new(Vec::new()))
}

fn remember(file: &Path, name: &str) {
    if let Ok(mut v) = registry().lock() {
        v.push((file.to_path_buf(), name.to_string()));
    }
}

fn forget(file: &Path, name: &str) {
    if let Ok(mut v) = registry().lock() {
        v.retain(|(f, n)| !(f == file && n == name));
    }
}

/// Chaîne un crochet de panique qui retire les alias encore déclarés, avant celui déjà en place
/// (celui de ratatui, qui rend le terminal).
pub fn install_panic_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Ok(v) = registry().try_lock() {
                for (file, name) in v.iter() {
                    let _ = remove(file, name);
                }
            }
            previous(info);
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Owner = Owner { pid: 10, start: 100 };
    const OTHER: Owner = Owner { pid: 20, start: 200 };

    fn doc() -> Value {
        serde_yaml::from_str(
            r#"
apiVersion: v1
kind: Config
current-context: fpci
clusters:
- name: fpci
  cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: Q0E=
contexts:
- name: fpci
  context:
    cluster: fpci
    user: admin
    namespace: apps
users:
- name: admin
  user:
    token: secret
"#,
        )
        .unwrap()
    }

    fn cluster(d: &Value) -> Value {
        named(d, "clusters", "fpci").unwrap().get("cluster").unwrap().clone()
    }

    #[test]
    fn writes_cluster_copy_and_context_referencing_user() {
        let mut d = doc();
        let c = cluster(&d);
        let name = add(&mut d, "fpci", &c, "socks5://kdt:t@127.0.0.1:1", ME, |_| true).unwrap();
        assert_eq!(name, "kdt-fpci");
        let cl = named(&d, "clusters", "kdt-fpci").unwrap().get("cluster").unwrap();
        assert_eq!(cl.get("server").unwrap().as_str(), Some("https://127.0.0.1:6443"));
        assert_eq!(cl.get("proxy-url").unwrap().as_str(), Some("socks5://kdt:t@127.0.0.1:1"));
        assert_eq!(owner_of(named(&d, "clusters", "kdt-fpci").unwrap(), "cluster"), Some(ME));
        let cx = named(&d, "contexts", "kdt-fpci").unwrap().get("context").unwrap();
        assert_eq!(cx.get("cluster").unwrap().as_str(), Some("kdt-fpci"));
        assert_eq!(cx.get("user").unwrap().as_str(), Some("admin"));
        assert_eq!(cx.get("namespace").unwrap().as_str(), Some("apps"));
        assert_eq!(list(&d, "users").len(), 1);
        assert_eq!(d.get("current-context").unwrap().as_str(), Some("fpci"));
    }

    #[test]
    fn live_instance_gets_next_suffix() {
        let mut d = doc();
        let c = cluster(&d);
        add(&mut d, "fpci", &c, "u1", OTHER, |_| true).unwrap();
        let name = add(&mut d, "fpci", &c, "u2", ME, |_| true).unwrap();
        assert_eq!(name, "kdt-fpci-2");
    }

    #[test]
    fn dead_instance_is_purged_and_name_reclaimed() {
        let mut d = doc();
        let c = cluster(&d);
        add(&mut d, "fpci", &c, "u1", OTHER, |_| true).unwrap();
        let name = add(&mut d, "fpci", &c, "u2", ME, |o| *o != OTHER).unwrap();
        assert_eq!(name, "kdt-fpci");
        assert_eq!(list(&d, "contexts").len(), 2);
        assert_eq!(list(&d, "clusters").len(), 2);
    }

    #[test]
    fn unmarked_entry_is_never_overwritten() {
        let mut d = doc();
        let c = cluster(&d);
        let mut foreign = Mapping::new();
        foreign.insert("name".into(), "kdt-fpci".into());
        foreign.insert("context".into(), serde_yaml::from_str("{cluster: elsewhere, user: x}").unwrap());
        seq_mut(&mut d, "contexts").push(Value::Mapping(foreign));
        let name = add(&mut d, "fpci", &c, "u", ME, |_| false).unwrap();
        assert_eq!(name, "kdt-fpci-2");
        let kept = named(&d, "contexts", "kdt-fpci").unwrap().get("context").unwrap();
        assert_eq!(kept.get("cluster").unwrap().as_str(), Some("elsewhere"));
    }

    #[test]
    fn removal_touches_only_own_entries() {
        let mut d = doc();
        let c = cluster(&d);
        add(&mut d, "fpci", &c, "u1", OTHER, |_| true).unwrap();
        let mine = add(&mut d, "fpci", &c, "u2", ME, |_| true).unwrap();
        drop_alias(&mut d, &mine, ME);
        drop_alias(&mut d, "kdt-fpci", ME);
        assert!(named(&d, "contexts", "kdt-fpci").is_some());
        assert!(named(&d, "clusters", "kdt-fpci").is_some());
        assert!(named(&d, "contexts", &mine).is_none());
        assert!(named(&d, "clusters", &mine).is_none());
        assert!(named(&d, "contexts", "fpci").is_some());
    }

    #[test]
    fn current_context_on_removed_alias_is_cleared() {
        let mut d = doc();
        let c = cluster(&d);
        let name = add(&mut d, "fpci", &c, "u", ME, |_| true).unwrap();
        d.as_mapping_mut().unwrap().insert("current-context".into(), name.clone().into());
        drop_alias(&mut d, &name, ME);
        assert_eq!(d.get("current-context").unwrap().as_str(), Some(""));
    }

    #[test]
    fn own_start_time_is_read() {
        let me = Owner::me();
        assert!(alive(&me));
        assert!(!alive(&Owner { pid: me.pid, start: me.start + 1 }) || me.start == 0);
    }
}
