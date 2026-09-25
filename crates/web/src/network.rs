//! La vue réseau : Services et Ingress, les deux premiers mondes de la vue réseau de kdt (le
//! troisième, les policies, a sa route à lui dans [`crate::netpol`]).
//!
//! # Rien n'est jugé ici
//!
//! Le compte d'endpoints prêts, le ton d'un Secret TLS, la couverture des SAN : tout vient de
//! `kdt::svc`, qui est ce que le TUI affiche. Ce module lit dans la portée demandée et rend.
//!
//! # Les Secrets TLS se relisent à chaque requête
//!
//! Le TUI garde un cache de lectures de Secrets (60 s pour un certificat lu, 15 s pour un défaut).
//! Ici il n'y en a pas d'un compte à l'autre : un droit de lecture sur un Secret ne se prête pas, et
//! un cache partagé montrerait à l'un ce que seul l'autre avait le droit de lire. D'où un
//! rafraîchissement plus lent du monde Ingress côté navigateur.
//!
//! # Lecture seule
//!
//! Le seul geste propre à la vue dans le TUI est le port-forward, qui ouvre un port sur le poste
//! qui lance kdt : il n'a pas de sens depuis un navigateur. Le reste passe par les gestes
//! génériques, sur l'objet réel de chaque ligne.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::lang::Strings;
use kdt::svc::{
    endpoint_belongs_to, endpoint_record, format_ingress_tls, ingress_class_record, ingress_record,
    service_record, EndpointRow, IngressClassResource, IngressResource, IngressTls,
    ServiceResource, TlsCache,
};
use serde::Deserialize;
use tracing::warn;

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

#[derive(Deserialize)]
pub struct NetworkQuery {
    /// Un seul namespace, ou vide pour tout le cluster. Les IngressClass sont cluster-scoped et
    /// restent listées quelle que soit la portée : ce sont elles qui nomment le controller.
    #[serde(default)]
    ns: String,
    #[serde(default)]
    lang: String,
}

/// Les Services de la portée, chacun avec les endpoints de ses EndpointSlices.
pub async fn services(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NetworkQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let namespace = Some(query.ns.trim().to_string()).filter(|s| !s.is_empty());

    let inventory = match kdt::svc::services_inventory(&client, &namespace).await {
        Ok(inv) => inv,
        Err(e) => return refused("services", e),
    };
    let known = inventory.endpoints_error.is_none();
    axum::Json(serde_json::json!({
        "services": inventory
            .services
            .iter()
            .map(|s| service_json(s, &inventory.endpoints, known))
            .collect::<Vec<_>>(),
        "endpoints_total": inventory.endpoints.len(),
        // Un refus sur les EndpointSlices voyage avec les Services : la colonne ENDPOINTS dit
        // alors « ? » et non « 0/0 », qui se lirait comme un Service sans backend.
        "endpoints_error": inventory.endpoints_error,
    }))
    .into_response()
}

/// Les Ingress de la portée, l'état de chaque Secret TLS qu'ils nomment, et les IngressClass.
pub async fn ingress(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NetworkQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let namespace = Some(query.ns.trim().to_string()).filter(|s| !s.is_empty());

    let mut cache = TlsCache::new();
    let inventory = match kdt::svc::ingress_inventory(&client, &namespace, &mut cache).await {
        Ok(inv) => inv,
        Err(e) => return refused("ingress", e),
    };
    axum::Json(serde_json::json!({
        "ingresses": inventory.ingresses.iter().map(|i| ingress_json(i, st)).collect::<Vec<_>>(),
        "classes": inventory.classes.iter().map(class_json).collect::<Vec<_>>(),
        // Les classes sont cluster-scoped : un rôle de namespace ne les lit souvent pas, et les
        // Ingress s'affichent alors sans leur ligne de classe plutôt que pas du tout.
        "classes_error": inventory.classes_error,
    }))
    .into_response()
}

/// Sans la liste elle-même, la vue n'a rien à dire : c'est une erreur, pas une liste vide qui
/// ferait croire à un cluster sans Service.
fn refused(what: &str, e: String) -> Response {
    warn!(erreur = %e, "lecture des {what} refusée");
    (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({ "error": e }))).into_response()
}

/// Un Service, son verdict d'endpoints, et les endpoints qui le servent, rangés dessous.
fn service_json(s: &ServiceResource, endpoints: &[EndpointRow], known: bool) -> serde_json::Value {
    let mut value = serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("endpoints_label".to_string(), s.endpoints_label(known).into());
        object.insert("endpoints_tone".to_string(), tone_json(s.endpoints_tone(known)));
        object.insert(
            "endpoints".to_string(),
            endpoints
                .iter()
                .filter(|e| endpoint_belongs_to(e, s))
                .map(endpoint_json)
                .collect::<Vec<_>>()
                .into(),
        );
        object.insert("record".to_string(), record_json(service_record(s)));
    }
    value
}

/// Un endpoint : le pod qui sert, s'il est prêt, et sur quel nœud.
fn endpoint_json(e: &EndpointRow) -> serde_json::Value {
    let mut value = serde_json::to_value(e).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("ready_label".to_string(), e.ready_label().into());
        object.insert("ready_tone".to_string(), tone_json(e.ready_tone()));
        // Une adresse nue n'a pas d'objet derrière elle : ni case ni hamburger.
        object.insert("addressable".to_string(), e.addressable().into());
        object.insert("record".to_string(), record_json(endpoint_record(e)));
    }
    value
}

/// Un Ingress, chaque entrée TLS avec son libellé et son ton, et le détail que l'onglet Status
/// du TUI rédige.
fn ingress_json(i: &IngressResource, st: &'static Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(i).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "tls".to_string(),
            i.tls.iter().map(|t| tls_json(t, st)).collect::<Vec<_>>().into(),
        );
        object.insert(
            "tls_tone".to_string(),
            i.tls_tone().map(tone_json).unwrap_or(serde_json::Value::Null),
        );
        object.insert("first_tls_secret".to_string(), i.first_tls_secret().into());
        object.insert(
            "tls_lines".to_string(),
            format_ingress_tls(&i.tls, st)
                .into_iter()
                .map(|(tone, text)| serde_json::json!({ "tone": tone_json(tone), "text": text }))
                .collect::<Vec<_>>()
                .into(),
        );
        object.insert("record".to_string(), record_json(ingress_record(i, st)));
    }
    value
}

fn tls_json(t: &IngressTls, st: &'static Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(t).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("label".to_string(), t.label(st).into());
        object.insert("tone".to_string(), tone_json(t.tone()));
    }
    value
}

fn class_json(c: &IngressClassResource) -> serde_json::Value {
    let mut value = serde_json::to_value(c).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("record".to_string(), record_json(ingress_class_record(c)));
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
    use kdt::lang::FR;
    use kdt::svc::TlsSecretState;

    fn service(name: &str, ready: usize, total: usize) -> ServiceResource {
        ServiceResource {
            namespace: "prod".into(),
            name: name.into(),
            type_: "ClusterIP".into(),
            cluster_ip: "10.0.0.1".into(),
            external_ip: "<none>".into(),
            ports: "80/TCP".into(),
            age: "3d".into(),
            uid: format!("service|prod/{name}"),
            endpoints_ready: ready,
            endpoints_total: total,
            port_specs: Vec::new(),
            external_name: false,
        }
    }

    fn endpoint(svc: &str, pod: &str, ready: bool) -> EndpointRow {
        EndpointRow {
            service_namespace: "prod".into(),
            service_name: svc.into(),
            target_name: pod.into(),
            target_kind: "Pod".into(),
            address: "10.1.0.4".into(),
            node: "n1".into(),
            ready,
            uid: format!("endpoint|prod/{svc}|{pod}"),
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn un_service_porte_ses_endpoints_et_leur_verdict() {
        let eps = vec![endpoint("web", "web-1", true), endpoint("web", "web-2", false), endpoint("db", "db-0", true)];
        let v = service_json(&service("web", 1, 2), &eps, true);
        assert_eq!(v["endpoints_label"], "1/2");
        assert_eq!(v["endpoints_tone"], "warn");
        assert_eq!(v["endpoints"].as_array().map(Vec::len), Some(2));
        assert_eq!(v["endpoints"][1]["ready_tone"], "err");
        assert_eq!(v["endpoints"][0]["addressable"], true);
        assert_eq!(v["endpoints"][0]["record"]["kind"], "Pod");
        assert_eq!(v["record"]["kind"], "Service");
        assert_eq!(v["record"]["api_version"], "v1");
    }

    // Deux silences qui ne sont pas un zéro : un alias DNS n'a pas d'endpoints par construction,
    // et des EndpointSlices illisibles ne disent rien. Ni l'un ni l'autre ne se peint en rouge.
    #[test]
    fn ni_un_externalname_ni_un_refus_ne_se_lisent_comme_un_service_vide() {
        let vide = service_json(&service("web", 0, 0), &[], true);
        assert_eq!(vide["endpoints_tone"], "err");
        let refus = service_json(&service("web", 0, 0), &[], false);
        assert_eq!(refus["endpoints_label"], "?");
        assert_eq!(refus["endpoints_tone"], "dim");
        let alias = ServiceResource { external_name: true, ..service("ext", 0, 0) };
        let alias = service_json(&alias, &[], true);
        assert_eq!(alias["endpoints_label"], "—");
        assert_eq!(alias["endpoints_tone"], "dim");
    }

    #[test]
    fn une_adresse_nue_n_offre_aucun_geste() {
        let bare = EndpointRow { target_kind: "Address".into(), ..endpoint("web", "10.1.0.9", true) };
        assert_eq!(endpoint_json(&bare)["addressable"], false);
    }

    // Seul un Secret lu reçoit un verdict ; un Secret absent rend l'Ingress en avertissement.
    #[test]
    fn un_ingress_porte_le_ton_de_chaque_secret_et_le_detail_du_tui() {
        let ing = IngressResource {
            namespace: "prod".into(),
            name: "web".into(),
            class: Some("nginx".into()),
            hosts: "a.example.com".into(),
            rules: "a.example.com/ → web:80".into(),
            tls: vec![
                IngressTls { secret: Some("gone".into()), hosts: vec!["a.example.com".into()], state: TlsSecretState::Missing },
                IngressTls { secret: None, hosts: vec!["b.example.com".into()], state: TlsSecretState::Default },
            ],
            address: "1.2.3.4".into(),
            age: "1d".into(),
            uid: "ingress|prod/web".into(),
        };
        let v = ingress_json(&ing, &FR);
        assert_eq!(v["tls"][0]["label"], "gone");
        assert_eq!(v["tls"][0]["tone"], "err");
        assert_eq!(v["tls"][0]["state"]["kind"], "missing");
        assert_eq!(v["tls"][1]["label"], FR.ing_tls_default_short);
        assert_eq!(v["tls"][1]["tone"], "dim");
        assert_eq!(v["tls_tone"], "err");
        assert_eq!(v["first_tls_secret"], "gone");
        assert_eq!(v["record"]["severity"], "warning");
        assert!(v["tls_lines"].as_array().is_some_and(|l| l.iter().any(|x| x["text"] == "▸ Secret gone → a.example.com")));
    }

    #[test]
    fn un_ingress_sans_tls_n_a_pas_de_ton() {
        let ing = IngressResource {
            namespace: "prod".into(),
            name: "plain".into(),
            class: None,
            hosts: "*".into(),
            rules: String::new(),
            tls: Vec::new(),
            address: String::new(),
            age: "1d".into(),
            uid: "ingress|prod/plain".into(),
        };
        let v = ingress_json(&ing, &FR);
        assert!(v["tls_tone"].is_null());
        assert!(v["first_tls_secret"].is_null());
        assert_eq!(v["record"]["tone"], "ok");
    }
}
