//! La vue network policies : deux mondes de politiques dans une même liste.
//!
//! Le `NetworkPolicy` natif de Kubernetes, entièrement typé, avec un vrai verdict de posture
//! calculé depuis une sémantique spécifiée ; et les CRD propres au CNI — `CiliumNetworkPolicy`,
//! `CiliumClusterwideNetworkPolicy`, les `NetworkPolicy` et `GlobalNetworkPolicy` de Calico — qui
//! sont découvertes (donc un CNI absent ne rend simplement rien) et rendues **factuellement** :
//! leur sélecteur et leurs compteurs de règles, sans verdict ingress/egress.
//!
//! # Pourquoi les CRD n'ont pas de verdict
//!
//! Le défaut allow/deny de chaque moteur diffère de celui du natif, et l'affirmer serait deviner.
//! C'est la règle de `kdt::netpol`, et elle ne se rediscute pas côté navigateur : le front peint le
//! `DirEffect` qu'il reçoit, `unknown` compris, il ne le déduit pas d'un compte de règles.
//!
//! # Lecture seule
//!
//! Cette vue constate. Chaque ligne désigne son objet réel, donc les gestes génériques — `y`, `e`,
//! `h`, `Ctrl-D` — agissent dessus comme partout ailleurs.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use kdt::netpol::{dir_tone, netpol_record, NetPolEngine, NetPolResource};
use serde::Deserialize;

use crate::api::session_client;
use crate::AppState;

#[derive(Deserialize)]
pub struct NetpolQuery {
    /// Un seul namespace, ou vide pour tout le cluster.
    ///
    /// Les politiques cluster-scoped — `CiliumClusterwideNetworkPolicy`, `GlobalNetworkPolicy` —
    /// restent listées quelle que soit la portée : elles s'appliquent aux pods du namespace regardé,
    /// et les cacher donnerait à croire que rien ne les gouverne.
    #[serde(default)]
    ns: String,
}

/// Les politiques réseau de la portée, tous moteurs confondus.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NetpolQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let namespace = Some(query.ns.trim().to_string()).filter(|s| !s.is_empty());

    let (policies, native_error) = kdt::netpol::list_netpols(&client, &namespace).await;

    let count = |engine: NetPolEngine| policies.iter().filter(|p| p.engine == engine).count();
    axum::Json(serde_json::json!({
        "rows": policies.iter().map(row_json).collect::<Vec<_>>(),
        // Les compteurs par moteur : c'est ce que le titre du TUI annonce, et c'est ce qui dit
        // d'un coup d'œil si le CNI a ses propres politiques à côté des natives.
        "counts": {
            "k8s": count(NetPolEngine::K8s),
            "cilium": count(NetPolEngine::Cilium),
            "calico": count(NetPolEngine::Calico),
        },
        // Seule l'erreur sur les natives est remontée : un CNI absent n'est pas une panne, et un
        // message par CRD non installée transformerait chaque cluster en mur d'avertissements.
        // Les lignes déjà lues partent avec, plutôt qu'à leur place.
        "error": native_error,
    }))
    .into_response()
}

/// Une politique, son moteur, et le ton de chaque direction.
fn row_json(p: &NetPolResource) -> serde_json::Value {
    let mut value = serde_json::to_value(p).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("engine_label".to_string(), p.engine.label().into());
        // `Deny` est **vert** : une direction gouvernée sans rien d'autorisé est une posture
        // fermée, c'est-à-dire ce qu'on cherche. C'est le verdict de kdt, pas une couleur choisie ici.
        object.insert("ingress_tone".to_string(), tone_json(dir_tone(p.ingress_effect)));
        object.insert("egress_tone".to_string(), tone_json(dir_tone(p.egress_effect)));
        // Vide pour les politiques cluster-scoped : c'est au front de le dire, il n'y a pas de
        // namespace à inventer.
        object.insert("cluster_scoped".to_string(), p.namespace.is_empty().into());
        object.insert("record".to_string(), record_json(netpol_record(p)));
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
    use kdt::netpol::DirEffect;

    fn native(ingress: DirEffect, egress: DirEffect) -> NetPolResource {
        NetPolResource {
            engine: NetPolEngine::K8s,
            kind: "NetworkPolicy".into(),
            api_version: "networking.k8s.io/v1".into(),
            namespace: "prod".into(),
            name: "default-deny".into(),
            target: "all pods".into(),
            types: "Ingress,Egress".into(),
            ingress: "deny".into(),
            egress: "deny".into(),
            ingress_effect: ingress,
            egress_effect: egress,
            age: "90d".into(),
            uid: "netpol|prod/default-deny".into(),
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn une_ligne_native_porte_ce_que_le_navigateur_lit() {
        let v = row_json(&native(DirEffect::Deny, DirEffect::Deny));
        assert_eq!(v["engine"], "k8s");
        assert_eq!(v["engine_label"], "k8s");
        assert_eq!(v["cluster_scoped"], false);
        assert_eq!(v["ingress_effect"], "deny");
        assert_eq!(v["record"]["kind"], "NetworkPolicy");
        assert_eq!(v["record"]["api_version"], "networking.k8s.io/v1");
    }

    // Le sens des couleurs, qui n'est pas celui qu'on attend : une direction gouvernée sans rien
    // d'autorisé est une posture **fermée**, donc une bonne nouvelle. C'est `allow-all` qui mérite
    // un regard.
    #[test]
    fn deny_est_une_bonne_nouvelle_et_allow_all_une_question() {
        let v = row_json(&native(DirEffect::Deny, DirEffect::AllowAll));
        assert_eq!(v["ingress_tone"], "ok");
        assert_eq!(v["egress_tone"], "warn");
        // Une direction que la policy ne gouverne pas ne dit rien : elle est laissée aux autres.
        let muet = row_json(&native(DirEffect::Selective, DirEffect::Unaffected));
        assert_eq!(muet["ingress_tone"], "plain");
        assert_eq!(muet["egress_tone"], "dim");
    }

    // La règle qui décide de toute la vue : le défaut allow/deny de chaque CNI diffère de celui du
    // natif, donc aucun verdict n'est asserté — et surtout aucune couleur qui en tiendrait lieu.
    #[test]
    fn une_crd_de_cni_ne_recoit_aucun_verdict() {
        let cilium = NetPolResource {
            engine: NetPolEngine::Cilium,
            kind: "CiliumClusterwideNetworkPolicy".into(),
            api_version: "cilium.io/v2".into(),
            namespace: String::new(),
            name: "baseline".into(),
            types: String::new(),
            ingress: "2 rules".into(),
            egress: "1 rule".into(),
            ingress_effect: DirEffect::Unknown,
            egress_effect: DirEffect::Unknown,
            ..native(DirEffect::Unknown, DirEffect::Unknown)
        };
        let v = row_json(&cilium);
        assert_eq!(v["engine"], "cilium");
        assert_eq!(v["ingress_effect"], "unknown");
        assert_eq!(v["ingress_tone"], "dim");
        assert_eq!(v["egress_tone"], "dim");
        // Cluster-scoped : le namespace est vide, et c'est au front de le nommer.
        assert_eq!(v["cluster_scoped"], true);
        assert_eq!(v["namespace"], "");
        // Une policy n'est ni saine ni malade : elle décrit une posture.
        assert_eq!(v["record"]["tone"], "ok");
    }
}
