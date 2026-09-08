//! La vue stockage : PVC, PV et StorageClass — et surtout ce qui ne va pas avec eux.
//!
//! L'intérêt de cette vue n'est pas de lister des volumes, `kubectl get pvc` le fait déjà, mais de
//! dire ce qui coûte une après-midi : une claim qui ne se liera jamais et pourquoi, un PV qui tient
//! encore la donnée d'une claim disparue, un `reclaimPolicy: Delete` sur ce que personne ne veut
//! perdre, un cluster sans StorageClass par défaut — ou avec deux.
//!
//! # Rien n'est jugé ici
//!
//! Les constats, le ton d'une phase, les octets qui dorment en `Released` viennent de
//! `kdt::storage`, qui est ce que le TUI affiche. Ce module lit dans la portée demandée et rend ;
//! il ne rejuge rien.
//!
//! # Ce que la vue refuse de dire
//!
//! Lister les pods est un droit, et tout le monde ne l'a pas. Un refus rendrait « rien ne monte
//! cette claim » — inquiétant, et faux. `mounts_known` distingue les deux cas, et la règle
//! correspondante se tait plutôt que d'affirmer une absence qu'elle n'a pas constatée. Même
//! logique pour les PV et les classes : leur lecture dégrade le diagnostic au lieu de vider l'écran.
//!
//! # Lecture seule
//!
//! Cette vue inspecte, elle n'écrit pas. Supprimer passe par les garde-fous génériques de
//! `Ctrl-D`, qui traitent déjà PVC et PV comme de la donnée persistante.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::events::format_memory_bytes;
use kdt::storage::{
    phase_tone, pv_record, pvc_record, sc_record, PvResource, PvcResource, ScResource,
};
use kdt::lang::Strings;
use serde::Deserialize;
use tracing::warn;

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

#[derive(Deserialize)]
pub struct StorageQuery {
    /// Un seul namespace, ou vide pour tout le cluster.
    ///
    /// Elle ne porte que sur les claims : un PV et une StorageClass sont cluster-scoped, et les
    /// écarter couperait la vue de ce à quoi les claims se lient.
    #[serde(default)]
    ns: String,
    #[serde(default)]
    lang: String,
}

/// L'inventaire du stockage de la portée, diagnostiqué.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<StorageQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let namespace = Some(query.ns.trim().to_string()).filter(|s| !s.is_empty());

    let inventory = match kdt::storage::storage_inventory(&client, namespace, st).await {
        Ok(inv) => inv,
        // Les claims sont la seule dépendance dure : sans elles la vue n'a rien à dire, donc c'est
        // bien une erreur et non une liste vide qui ferait croire à un cluster sans stockage.
        Err(e) => {
            warn!(erreur = %e, "lecture du stockage refusée");
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    };

    let d = inventory.diagnosed;
    axum::Json(serde_json::json!({
        "pvcs": d.pvcs.iter().map(|c| pvc_json(c, st)).collect::<Vec<_>>(),
        "pvs": d.pvs.iter().map(pv_json).collect::<Vec<_>>(),
        "classes": d.classes.iter().map(sc_json).collect::<Vec<_>>(),
        // Les constats qui n'appartiennent à aucune ligne : pas de classe par défaut, deux
        // classes par défaut, du `Released` qui s'accumule.
        "cluster_hints": d.cluster_hints,
        // Les octets que plus personne ne peut atteindre et que quelqu'un paie quand même. C'est
        // le seul chiffre qui appartient au cluster et à aucun volume, et la raison d'ouvrir la vue.
        "released_bytes": d.released_bytes,
        "released_text": format_memory_bytes(d.released_bytes),
        "mounts_known": inventory.mounts_known,
    }))
    .into_response()
}

/// Une claim : ce qu'un workload a demandé, et s'il l'a obtenu.
fn pvc_json(c: &PvcResource, st: &'static Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(c).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "pvc".into());
        object.insert("phase_tone".to_string(), tone_json(phase_tone(&c.phase)));
        // Ce que la ligne affiche en taille : le volume donne parfois plus que ce qui a été
        // demandé, et c'est ce qu'on a réellement qui compte. La demande reste dans le panneau.
        object.insert(
            "size".to_string(),
            if c.capacity.is_empty() { c.requested.clone() } else { c.capacity.clone() }.into(),
        );
        // La chaîne vide n'est pas une absence : c'est ainsi que Kubernetes écrit « aucun
        // provisionnement dynamique ». Les deux cas expliquent très différemment une claim
        // Pending, et c'est kdt qui les nomme.
        object.insert(
            "class_label".to_string(),
            match c.storage_class.as_deref() {
                Some("") => st.sto_class_refused.to_string(),
                Some(name) => name.to_string(),
                None => st.sto_class_default.to_string(),
            }
            .into(),
        );
        object.insert(
            "mounted_label".to_string(),
            if c.mounted_by.is_empty() {
                st.sto_no_pod.to_string()
            } else {
                c.mounted_by.join(", ")
            }
            .into(),
        );
        object.insert("record".to_string(), record_json(pvc_record(c, st)));
    }
    value
}

/// Un volume : où vit la donnée, et ce qui lui arrivera quand la claim partira.
fn pv_json(v: &PvResource) -> serde_json::Value {
    let mut value = serde_json::to_value(v).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "pv".into());
        object.insert("phase_tone".to_string(), tone_json(phase_tone(&v.phase)));
        // `Delete` est la politique qui perd la donnée sur un `kubectl delete pvc` : c'est la seule
        // que la table signale, parce que c'est la seule qui surprenne.
        object.insert("reclaim_deletes".to_string(), (v.reclaim_policy == "Delete").into());
        object.insert("record".to_string(), record_json(pv_record(v)));
    }
    value
}

/// Une classe : qui provisionne, et quand la liaison se fait.
fn sc_json(c: &ScResource) -> serde_json::Value {
    let mut value = serde_json::to_value(c).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "sc".into());
        object.insert("record".to_string(), record_json(sc_record(c)));
    }
    value
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
    use kdt::storage::{Hint, HintLevel};

    fn claim() -> PvcResource {
        PvcResource {
            uid: "pvc|prod/data".into(),
            namespace: "prod".into(),
            name: "data".into(),
            phase: "Bound".into(),
            volume_name: Some("pvc-9f2c".into()),
            capacity: "20Gi".into(),
            requested: "10Gi".into(),
            access_modes: "RWO".into(),
            storage_class: Some("fast".into()),
            age: "31d".into(),
            mounted_by: vec!["api-0".into()],
            hints: Vec::new(),
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn une_ligne_de_claim_porte_ce_que_le_navigateur_lit() {
        let v = pvc_json(&claim(), lang_of("fr"));
        assert_eq!(v["row"], "pvc");
        assert_eq!(v["uid"], "pvc|prod/data");
        assert_eq!(v["phase_tone"], "ok");
        // Ce qu'on a réellement, pas ce qu'on a demandé : un volume donne parfois plus.
        assert_eq!(v["size"], "20Gi");
        assert_eq!(v["class_label"], "fast");
        assert_eq!(v["mounted_label"], "api-0");
        assert_eq!(v["record"]["kind"], "PersistentVolumeClaim");
        assert_eq!(v["record"]["tone"], "ok");
    }

    // Les deux façons de ne pas nommer de classe n'expliquent pas la même chose : le champ absent
    // veut dire « prends la classe par défaut », la chaîne vide veut dire « aucun provisionnement
    // dynamique ». Les confondre envoie chercher un provisionneur qui n'aurait jamais dû agir.
    #[test]
    fn labsence_de_classe_et_le_refus_de_classe_ne_se_confondent_pas() {
        let defaut = pvc_json(&PvcResource { storage_class: None, ..claim() }, lang_of("fr"));
        let refus =
            pvc_json(&PvcResource { storage_class: Some(String::new()), ..claim() }, lang_of("fr"));
        assert_ne!(defaut["class_label"], refus["class_label"]);
        assert!(refus["class_label"].as_str().unwrap().contains("\"\""));
    }

    // Une claim sans volume tombe sur ce qu'elle a demandé, et une claim que rien ne monte reçoit
    // la phrase de kdt plutôt qu'une chaîne vide qu'on lirait comme une donnée manquante.
    #[test]
    fn une_claim_en_attente_montre_sa_demande_et_dit_que_rien_ne_la_monte() {
        let pending = PvcResource {
            phase: "Pending".into(),
            volume_name: None,
            capacity: String::new(),
            mounted_by: Vec::new(),
            hints: vec![Hint { level: HintLevel::Warn, text: "aucune classe par défaut".into() }],
            ..claim()
        };
        let v = pvc_json(&pending, lang_of("fr"));
        assert_eq!(v["size"], "10Gi");
        assert_eq!(v["phase_tone"], "warn");
        assert!(!v["mounted_label"].as_str().unwrap().is_empty());
        // La sévérité vient du diagnostic, jamais de la phase : c'est la règle qui a tranché.
        assert_eq!(v["record"]["tone"], "warn");
    }

    // `Delete` est la seule politique qui perde la donnée sur un `kubectl delete pvc` : c'est la
    // seule que la table signale, et le drapeau vient d'ici plutôt que d'une comparaison de chaîne
    // refaite dans le navigateur.
    #[test]
    fn seul_reclaim_delete_se_signale() {
        let base = PvResource {
            uid: "pv|pvc-9f2c".into(),
            name: "pvc-9f2c".into(),
            capacity: "20Gi".into(),
            access_modes: "RWO".into(),
            reclaim_policy: "Delete".into(),
            phase: "Bound".into(),
            claim: Some("prod/data".into()),
            storage_class: "fast".into(),
            source: "csi:ebs.csi.aws.com".into(),
            node_affinity: String::new(),
            age: "31d".into(),
            hints: Vec::new(),
        };
        assert_eq!(pv_json(&base)["reclaim_deletes"], true);
        let retain = PvResource { reclaim_policy: "Retain".into(), ..base.clone() };
        assert_eq!(pv_json(&retain)["reclaim_deletes"], false);
        // Un volume libéré tient encore la donnée d'une claim disparue : la phase le dit.
        let released = PvResource { phase: "Released".into(), ..base };
        assert_eq!(pv_json(&released)["phase_tone"], "warn");
    }

    #[test]
    fn une_classe_porte_son_provisionneur_et_son_objet() {
        let sc = ScResource {
            uid: "sc|fast".into(),
            name: "fast".into(),
            provisioner: "ebs.csi.aws.com".into(),
            reclaim_policy: "Delete".into(),
            binding_mode: "WaitForFirstConsumer".into(),
            allow_expansion: true,
            is_default: true,
            age: "412d".into(),
            hints: Vec::new(),
        };
        let v = sc_json(&sc);
        assert_eq!(v["row"], "sc");
        assert_eq!(v["record"]["kind"], "StorageClass");
        assert_eq!(v["record"]["api_version"], "storage.k8s.io/v1");
        assert!(v["record"]["message"].as_str().unwrap().contains("(default)"));
    }
}
