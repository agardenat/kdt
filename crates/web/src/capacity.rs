//! La vue capacité : non pas « voilà la consommation », mais « voilà ce qui va casser ».
//!
//! Trois questions, trois mondes, une seule lecture — les mêmes que `:capacity` dans le TUI :
//!
//! - **Nodes** — ce qui est réservé face à ce qui existe, et surtout : *si ce node tombe, ses pods
//!   ont-ils où atterrir ?* C'est la question à laquelle `kubectl top` ne répond pas, parce qu'elle
//!   demande les requests, la place restante, les taints et les sélecteurs en même temps.
//! - **Workloads** — ceux que le scheduler ne voit pas (sans requests), ceux qui réservent bien
//!   plus qu'ils n'utilisent, et ceux qui touchent leur propre limite.
//! - **Quotas** — le `ResourceQuota` qui refusera le prochain déploiement.
//!
//! # Rien n'est jugé ici
//!
//! La simulation de perte, les constats, les seuils de tension, les unités : tout vient de
//! `kdt::capacity`, qui est ce que le TUI affiche. Ce module joint la lecture à la portée demandée
//! et met en forme ; il ne décide d'aucun verdict, sinon les deux interfaces finiraient par peindre
//! deux couleurs du même node.
//!
//! # La portée ne s'applique pas aux nodes
//!
//! Un node n'a pas de namespace, et c'est précisément ce qui rend la question « si celui-ci tombe »
//! intéressante depuis n'importe quelle portée. Les workloads et les quotas, eux, sont filtrés —
//! comme le titre du TUI, qui compte ce que la portée contient et non ce que le cluster contient.
//!
//! # Lecture seule
//!
//! Cette vue constate. Agir sur ce qu'elle montre — cordonner un node, redimensionner un workload —
//! se fait depuis les vues qui possèdent ces objets, ou par les gestes génériques sur la ligne.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::capacity::{
    cpu_text, first_sentence, homeless_why, loss_short, loss_tone, loss_word, mem_text,
    node_record, pct, quota_record, tension, workload_record, Loss, NodeRoom, QuotaPressure,
    WorkloadSizing,
};
use kdt::lang::{fill, Strings};
use serde::Deserialize;
use tracing::warn;

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

#[derive(Deserialize)]
pub struct CapacityQuery {
    /// Un seul namespace, ou vide pour tout le cluster.
    #[serde(default)]
    ns: String,
    #[serde(default)]
    lang: String,
}

/// Les trois mondes de la capacité, dans la portée demandée.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CapacityQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let scope = query.ns.trim().to_string();

    let inventory = match kdt::capacity::capacity_inventory(&client, st).await {
        Ok(inv) => inv,
        // Les nodes et les pods sont la matière même de la vue : sans eux il n'y a rien à dire, et
        // une réponse vide se lirait comme un cluster désert plutôt que comme un refus.
        Err(e) => {
            warn!(erreur = %e, "lecture de la capacité refusée");
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    };

    let in_scope = |ns: &str| scope.is_empty() || scope == ns;
    let analysis = inventory.analysis;

    axum::Json(serde_json::json!({
        // Les nodes ignorent la portée : ils n'ont pas de namespace, et « si celui-ci tombe » se
        // pose depuis n'importe où.
        "nodes": analysis.nodes.iter().map(|n| node_json(n, st)).collect::<Vec<_>>(),
        "workloads": analysis
            .workloads
            .iter()
            .filter(|w| in_scope(&w.namespace))
            .map(workload_json)
            .collect::<Vec<_>>(),
        "quotas": analysis
            .quotas
            .iter()
            .filter(|q| in_scope(&q.namespace))
            .map(quota_json)
            .collect::<Vec<_>>(),
        // Les constats qui n'appartiennent à aucune ligne : ceux du cluster.
        "cluster_hints": analysis.cluster_hints,
        // Faux sans metrics-server. Toute la colonne « utilisé » est alors `null`, et la vue le dit
        // au lieu d'afficher des zéros qui se liraient comme un cluster au repos.
        "metrics_available": inventory.metrics_available,
        // Ce que la simulation de perte vaut, dit par kdt : un first-fit honnête, qui tient compte
        // des taints et des sélecteurs mais pas des affinités souples. La vue le dit plutôt que de
        // se faire passer pour le scheduler.
        "simulation_note": st.cap_simulation_note,
    }))
    .into_response()
}

/// Un node, ses deux ratios, et ce que sa perte coûterait.
fn node_json(n: &NodeRoom, st: &'static Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(n).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("uid".to_string(), n.uid().into());
        // Réservé : ce que le scheduler regarde. C'est ce ratio-là qui décide si un pod de plus
        // tient, quelle que soit la mesure.
        object.insert(
            "cpu_reserved".to_string(),
            ratio_json(n.req_cpu, n.alloc_cpu, cpu_text),
        );
        object.insert(
            "mem_reserved".to_string(),
            ratio_json(n.req_mem, n.alloc_mem, mem_text),
        );
        // Mesuré, quand metrics-server est là pour le mesurer. `null` sinon : un zéro se lirait
        // comme un node inactif.
        object.insert(
            "cpu_used".to_string(),
            n.use_cpu
                .map(|v| ratio_json(v, n.alloc_cpu, cpu_text))
                .unwrap_or(serde_json::Value::Null),
        );
        object.insert(
            "mem_used".to_string(),
            n.use_mem
                .map(|v| ratio_json(v, n.alloc_mem, mem_text))
                .unwrap_or(serde_json::Value::Null),
        );
        object.insert("cpu_limits_text".to_string(), cpu_text(n.lim_cpu).into());
        object.insert("mem_limits_text".to_string(), mem_text(n.lim_mem).into());
        // Les slots de pods sont un plafond dur du kubelet : un node peut avoir du CPU libre et
        // refuser un pod de plus. `0` veut dire que l'allocatable ne l'a pas dit.
        object.insert(
            "pods_pct".to_string(),
            match n.pod_capacity > 0 {
                true => pct(n.pods as i64, n.pod_capacity).into(),
                false => serde_json::Value::Null,
            },
        );
        object.insert("loss".to_string(), loss_json(&n.loss, st));
        object.insert("record".to_string(), record_json(node_record(n, st)));
    }
    value
}

/// Le verdict de perte, avec ce qu'il faut pour l'écrire : le mot court de la colonne, le ton, et —
/// quand des pods restent sur le carreau — pourquoi chacun n'a nulle part où aller.
///
/// La distinction compte : « pas de place » se règle en ajoutant de la capacité, un taint ou un
/// sélecteur se règle en changeant le pod, et aucun node neuf n'y changera quoi que ce soit.
fn loss_json(loss: &Loss, st: &'static Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(loss).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("short".to_string(), loss_short(loss, st).into());
        object.insert("word".to_string(), loss_word(loss, st).into());
        object.insert("tone".to_string(), tone_json(loss_tone(loss)));
        // La phrase du panneau, rédigée par kdt. Elle est indentée pour le terminal : ce sont les
        // seules espaces qu'on retire, le texte lui-même n'est pas reformulé.
        object.insert(
            "note".to_string(),
            match loss {
                Loss::Alone => st.cap_alone_note.trim().to_string(),
                Loss::Fits => st.cap_fits_note.trim().to_string(),
                Loss::Tight => st.cap_tight_note.trim().to_string(),
                Loss::Homeless(v) => fill(
                    st.plural(v.len(), st.cap_homeless_note_one, st.cap_homeless_note_many).trim(),
                    &[("n", &v.len().to_string())],
                ),
            }
            .into(),
        );
        if let Loss::Homeless(pods) = loss {
            if let Some(slots) = object.get_mut("pods").and_then(|p| p.as_array_mut()) {
                for (slot, p) in slots.iter_mut().zip(pods.iter()) {
                    let Some(entry) = slot.as_object_mut() else { continue };
                    entry.insert("cpu_text".to_string(), cpu_text(p.cpu).into());
                    entry.insert("mem_text".to_string(), mem_text(p.mem).into());
                    entry.insert("why_label".to_string(), homeless_why(p.why, st).into());
                }
            }
        }
    }
    value
}

/// Un workload et son dimensionnement : ce qu'il réserve, ce qu'il permet, ce qu'il consomme.
fn workload_json(w: &WorkloadSizing) -> serde_json::Value {
    let mut value = serde_json::to_value(w).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("uid".to_string(), w.uid().into());
        object.insert("qos_label".to_string(), w.qos.label().into());
        for (field, v) in [
            ("cpu_req_text", cpu_text(w.cpu_req)),
            ("cpu_lim_text", cpu_text(w.cpu_lim)),
            ("mem_req_text", mem_text(w.mem_req)),
            ("mem_lim_text", mem_text(w.mem_lim)),
        ] {
            object.insert(field.to_string(), v.into());
        }
        object.insert(
            "cpu_use_text".to_string(),
            w.cpu_use.map(cpu_text).map(Into::into).unwrap_or(serde_json::Value::Null),
        );
        object.insert(
            "mem_use_text".to_string(),
            w.mem_use.map(mem_text).map(Into::into).unwrap_or(serde_json::Value::Null),
        );
        // Le constat en tête, ramené à sa première phrase : la table en montre la tête, le panneau
        // la phrase entière. La coupe est celle de kdt, pas une troncature du navigateur.
        object.insert(
            "finding".to_string(),
            w.hints
                .first()
                .map(|h| first_sentence(&h.text))
                .unwrap_or_default()
                .into(),
        );
        object.insert("record".to_string(), record_json(workload_record(w)));
    }
    value
}

/// Un quota et ses compteurs. La ligne montre le plus tendu — celui qui refusera la prochaine
/// création — et le panneau les liste tous.
fn quota_json(q: &QuotaPressure) -> serde_json::Value {
    let mut value = serde_json::to_value(q).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("uid".to_string(), q.uid().into());
        object.insert("worst_pct".to_string(), q.worst_pct().into());
        object.insert("worst_tension".to_string(), tension_json(q.worst_pct()));
        if let Some(slots) = object.get_mut("items").and_then(|i| i.as_array_mut()) {
            for (slot, item) in slots.iter_mut().zip(q.items.iter()) {
                let Some(entry) = slot.as_object_mut() else { continue };
                entry.insert("pct".to_string(), item.pct().into());
                entry.insert("tension".to_string(), tension_json(item.pct()));
            }
        }
        object.insert("record".to_string(), record_json(quota_record(q)));
    }
    value
}

/// Une ressource rapportée à ce qui existe : les deux quantités écrites comme kdt les écrit, le
/// pourcentage, et à quel point c'est tendu.
fn ratio_json(part: i64, whole: i64, format: fn(i64) -> String) -> serde_json::Value {
    let p = pct(part, whole);
    serde_json::json!({
        "text": format(part),
        "total_text": format(whole),
        "pct": p,
        "tension": tension_json(p),
    })
}

fn tension_json(pct: i64) -> serde_json::Value {
    serde_json::to_value(tension(pct)).unwrap_or(serde_json::Value::Null)
}

fn tone_json(tone: kdt::events::LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

/// L'enregistrement que la ligne représente, ton compris : c'est lui qui donne à la vue `y`, `e`,
/// `h`, `Ctrl-D` et l'onglet Related, exactement comme dans le TUI.
fn record_json(record: kdt::events::EventRecord) -> serde_json::Value {
    let tone = record.tone();
    let mut value = serde_json::to_value(&record).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "tone".to_string(),
            serde_json::to_value(tone).unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt::capacity::{Homeless, HomelessPod, Qos, QuotaItem};
    use kdt::storage::{Hint, HintLevel};

    fn node() -> NodeRoom {
        // Les chiffres d'un node à quatre cœurs et 8 Gi, dont 3,6 sont réservés : le cas courant,
        // où rien n'est encore tendu.
        NodeRoom {
            name: "worker-1".into(),
            ready: true,
            schedulable: true,
            alloc_cpu: 4000,
            alloc_mem: 8_000_000_000,
            req_cpu: 1000,
            req_mem: 3_600_000_000,
            lim_cpu: 6000,
            lim_mem: 9_000_000_000,
            use_cpu: Some(400),
            use_mem: Some(2_000_000_000),
            pods: 24,
            pod_capacity: 110,
            loss: Loss::Fits,
            hints: Vec::new(),
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn une_ligne_de_node_porte_ce_que_le_navigateur_lit() {
        let v = node_json(&node(), lang_of("fr"));
        assert_eq!(v["uid"], "cap-node-worker-1");
        assert_eq!(v["cpu_reserved"]["text"], "1");
        assert_eq!(v["cpu_reserved"]["total_text"], "4");
        assert_eq!(v["cpu_reserved"]["pct"], 25);
        assert_eq!(v["cpu_reserved"]["tension"], "ok");
        assert_eq!(v["cpu_used"]["pct"], 10);
        assert_eq!(v["loss"]["kind"], "fits");
        assert_eq!(v["loss"]["tone"], "ok");
        assert_eq!(v["record"]["kind"], "Node");
        assert_eq!(v["record"]["name"], "worker-1");
        assert_eq!(v["record"]["tone"], "ok");
    }

    // Les seuils sont ceux des règles : à 92 % de réservé, un pod normal ne rentre plus, et la
    // cellule doit le dire avant que le constat ne l'écrive.
    #[test]
    fn la_tension_suit_les_seuils_des_regles() {
        let tendu = NodeRoom { req_cpu: 3680, ..node() };
        assert_eq!(node_json(&tendu, lang_of("fr"))["cpu_reserved"]["tension"], "high");
        let deborde = NodeRoom { req_cpu: 4400, ..node() };
        let v = node_json(&deborde, lang_of("fr"));
        assert_eq!(v["cpu_reserved"]["pct"], 110);
        assert_eq!(v["cpu_reserved"]["tension"], "over");
    }

    // Le cas qui motive tout le `Option` : sans metrics-server, l'usage n'est pas zéro, il est
    // inconnu — et un zéro se lirait comme un node au repos.
    #[test]
    fn sans_metrics_l_usage_est_nul_et_la_reservation_reste_vraie() {
        let v = node_json(&NodeRoom { use_cpu: None, use_mem: None, ..node() }, lang_of("fr"));
        assert!(v["cpu_used"].is_null());
        assert!(v["mem_used"].is_null());
        assert_eq!(v["cpu_reserved"]["text"], "1");
    }

    // La question que la vue existe pour poser. Chaque pod part avec sa raison : « pas de place »
    // se règle en ajoutant de la capacité, un sélecteur se règle en changeant le pod.
    #[test]
    fn un_node_dont_la_perte_laisse_des_pods_dehors_les_nomme_avec_leur_raison() {
        let loss = Loss::Homeless(vec![HomelessPod {
            namespace: "prod".into(),
            name: "api-7f".into(),
            why: Homeless::Selector,
            cpu: 500,
            mem: 1_000_000_000,
        }]);
        let v = node_json(&NodeRoom { loss, ..node() }, lang_of("fr"));
        assert_eq!(v["loss"]["kind"], "homeless");
        assert_eq!(v["loss"]["tone"], "err");
        assert_eq!(v["loss"]["pods"][0]["namespace"], "prod");
        assert_eq!(v["loss"]["pods"][0]["why"], "selector");
        assert_eq!(v["loss"]["pods"][0]["cpu_text"], "500m");
        // La raison est rédigée par kdt, pas déduite du code par le navigateur.
        assert!(!v["loss"]["pods"][0]["why_label"].as_str().unwrap().is_empty());
        // Et la phrase du panneau n'arrive pas indentée pour un terminal.
        let note = v["loss"]["note"].as_str().unwrap();
        assert_eq!(note, note.trim());
    }

    #[test]
    fn un_workload_sans_mesure_dit_sa_reservation_seule() {
        let w = WorkloadSizing {
            namespace: "prod".into(),
            kind: "Deployment".into(),
            name: "api".into(),
            pods: 3,
            cpu_req: 1500,
            mem_req: 2_000_000_000,
            cpu_lim: 3000,
            mem_lim: 4_000_000_000,
            cpu_use: None,
            mem_use: None,
            qos: Qos::Burstable,
            no_cpu_request: false,
            no_mem_request: false,
            no_mem_limit: false,
            hints: vec![Hint {
                level: HintLevel::Warn,
                text: "réserve 4× ce qu'il utilise : de la capacité qui dort".into(),
            }],
        };
        let v = workload_json(&w);
        assert_eq!(v["uid"], "cap-wl-Deployment-prod-api");
        assert_eq!(v["cpu_req_text"], "1.50");
        assert!(v["cpu_use_text"].is_null());
        assert_eq!(v["qos_label"], "Burstable");
        // La table montre la tête du constat, coupée par kdt ; le panneau garde la phrase entière.
        assert_eq!(v["finding"], "réserve 4× ce qu'il utilise");
        // `y` sur cette ligne doit atteindre le bon objet : un Deployment vit sous `apps/v1`.
        assert_eq!(v["record"]["api_version"], "apps/v1");
        assert_eq!(v["record"]["tone"], "warn");
    }

    // Un quota est un objet avec plusieurs compteurs : la ligne montre le plus tendu, le panneau
    // les liste tous, et chacun porte sa propre tension.
    #[test]
    fn un_quota_porte_la_tension_de_chaque_compteur() {
        let q = QuotaPressure {
            namespace: "prod".into(),
            name: "team".into(),
            items: vec![
                QuotaItem {
                    resource: "requests.cpu".into(),
                    used: 9500,
                    hard: 10000,
                    used_text: "9500m".into(),
                    hard_text: "10".into(),
                },
                QuotaItem {
                    resource: "pods".into(),
                    used: 4,
                    hard: 20,
                    used_text: "4".into(),
                    hard_text: "20".into(),
                },
            ],
            hints: Vec::new(),
        };
        let v = quota_json(&q);
        assert_eq!(v["worst_pct"], 95);
        assert_eq!(v["worst_tension"], "high");
        assert_eq!(v["items"][0]["pct"], 95);
        assert_eq!(v["items"][0]["tension"], "high");
        assert_eq!(v["items"][1]["tension"], "ok");
        assert_eq!(v["record"]["kind"], "ResourceQuota");
    }
}
