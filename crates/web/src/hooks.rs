//! La vue hooks : les trois surfaces que l'apiserver appelle.
//!
//! Les webhooks d'admission (validating et mutating), les CRD qui confient leur conversion à un
//! webhook, et les APIService agrégées. Trois mondes, un seul mode de panne — un service backing
//! qui ne répond pas — et trois conséquences différentes : des écritures refusées, des **lectures**
//! cassées, une découverte incomplète pour tout le cluster.
//!
//! # Un seul appel pour les trois mondes
//!
//! `kdt::hooks::hooks_inventory` lit les quatre kinds d'une seule vague puis interroge chaque
//! Service **une fois**, parce qu'un même Service backe couramment plusieurs webhooks et une
//! conversion. Le front reçoit donc les trois listes ensemble et change de monde sans requête : le
//! `g` du TUI et l'onglet du navigateur coûtent la même chose, c'est-à-dire rien.
//!
//! # Ce que le serveur ne dit pas
//!
//! Un backend que kdt n'a pas pu interroger est `unchecked`, jamais en panne. Le front peint ce
//! qu'il reçoit ; il ne conclut pas d'un `reach` à une couleur d'alerte de son côté.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::hooks::{
    admission_record, apiservice_record, config_record, conversion_record, AdmissionConfig,
    AdmissionHook, ApiServiceHook, ConversionHook, HookWorld, HooksState, WebhookKind,
};
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

#[derive(Deserialize)]
pub struct HooksQuery {
    #[serde(default)]
    lang: String,
}

/// L'inventaire complet : les trois mondes, leurs compteurs et leurs erreurs.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HooksQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let inventory = kdt::hooks::hooks_inventory(&client, st).await;
    axum::Json(payload(&inventory)).into_response()
}

fn payload(state: &HooksState) -> serde_json::Value {
    serde_json::json!({
        "configs": state.configs.iter().map(config_row).collect::<Vec<_>>(),
        "admission": state.admission.iter().map(admission_row).collect::<Vec<_>>(),
        "conversion": state.conversion.iter().map(conversion_row).collect::<Vec<_>>(),
        "apiservices": state.apiservices.iter().map(apiservice_row).collect::<Vec<_>>(),
        "counts": {
            "admission": counts_json(state, HookWorld::Admission),
            "conversion": counts_json(state, HookWorld::Conversion),
            "apiservice": counts_json(state, HookWorld::ApiService),
        },
        // Une erreur par monde, exprès : un refus RBAC sur `apiextensions.k8s.io` ne doit pas
        // blanchir le monde admission, qui est celui qui compte le plus.
        "error": state.error,
        "conversion_error": state.conversion_error,
        "apiservice_error": state.apiservice_error,
        // Les APIService locales ne sont pas listées — l'apiserver s'y décrit lui-même, il n'y a ni
        // backend ni caBundle dont cette vue puisse parler — mais elles sont comptées, pour que le
        // titre dise « 3 agrégées sur 41 » plutôt que de taire les 38 autres.
        "local_apiservices": state.local_apiservices,
    })
}

fn counts_json(state: &HooksState, world: HookWorld) -> serde_json::Value {
    serde_json::to_value(state.counts(world)).unwrap_or_else(|_| serde_json::json!({}))
}

fn admission_row(h: &AdmissionHook) -> serde_json::Value {
    let mut value = serde_json::to_value(h).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("kind_label".to_string(), h.kind.label().into());
        object.insert("reach_label".to_string(), h.reach.label().into());
        object.insert("backend_label".to_string(), h.backend.short().into());
        object.insert("catch_all".to_string(), h.rules.iter().any(|r| r.is_catch_all()).into());
        object.insert("broken".to_string(), h.reach.is_broken().into());
        // La ligne montre un webhook nommé ; l'enregistrement désigne la **configuration**, seul
        // objet d'API sur lequel `y`, `e` et la suppression puissent agir.
        object.insert("record".to_string(), record_json(admission_record(h)));
    }
    value
}

fn config_row(c: &AdmissionConfig) -> serde_json::Value {
    let mut value = serde_json::to_value(c).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("kind_label".to_string(), c.kind.label().into());
        object.insert("api_kind".to_string(), c.kind.api_kind().into());
        object.insert("record".to_string(), record_json(config_record(c)));
    }
    value
}

fn conversion_row(c: &ConversionHook) -> serde_json::Value {
    let mut value = serde_json::to_value(c).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("reach_label".to_string(), c.reach.label().into());
        object.insert("backend_label".to_string(), c.backend.short().into());
        object.insert("served_label".to_string(), c.served_label().into());
        object.insert("broken".to_string(), c.reach.is_broken().into());
        object.insert("record".to_string(), record_json(conversion_record(c)));
    }
    value
}

fn apiservice_row(a: &ApiServiceHook) -> serde_json::Value {
    let mut value = serde_json::to_value(a).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("reach_label".to_string(), a.reach.label().into());
        object.insert("backend_label".to_string(), a.backend.short().into());
        object.insert("available_label".to_string(), a.available_label().into());
        object.insert("broken".to_string(), a.reach.is_broken().into());
        object.insert("record".to_string(), record_json(apiservice_record(a)));
    }
    value
}

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

// --- écriture -----------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct FailurePolicyBody {
    /// `validating` ou `mutating`, tel que la ligne le porte.
    kind: String,
    config: String,
    index: usize,
    /// Le nom du webhook visé. Le patch le teste avant d'écrire : entre la lecture et l'écriture un
    /// opérateur peut avoir réordonné `webhooks[]`, et un index nu basculerait le mauvais hook.
    name: String,
    /// `Fail` ou `Ignore`. Rien d'autre n'est accepté : l'apiserver ne connaît que ces deux-là.
    to: String,
    #[serde(default)]
    lang: String,
}

/// Bascule le `failurePolicy` d'un webhook. Portée cluster, sous l'identité de la personne connectée.
pub async fn failure_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<FailurePolicyBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let kind = match body.kind.as_str() {
        "validating" => WebhookKind::Validating,
        "mutating" => WebhookKind::Mutating,
        other => return refused(format!("kind inconnu: {}", other)),
    };
    if !matches!(body.to.as_str(), "Fail" | "Ignore") {
        return refused(format!("failurePolicy inconnue: {}", body.to));
    }
    info!(
        webhook = %format!("{}#{} ({})", body.config, body.index, body.name),
        to = %body.to,
        "bascule de failurePolicy demandée"
    );
    match kdt::hooks::set_failure_policy(
        &client,
        kind,
        &body.config,
        body.index,
        &body.name,
        &body.to,
    )
    .await
    {
        Ok(()) => {
            let st = lang_of(&body.lang);
            let message = kdt::lang::fill(
                st.msg_hk_policy_done,
                &[("name", &body.name), ("to", &body.to)],
            );
            axum::Json(serde_json::json!({ "message": message })).into_response()
        }
        Err(e) => refused(e),
    }
}

/// 409 et non 500 : la demande est arrivée, c'est l'objet ou son état qui la repousse.
fn refused(e: String) -> Response {
    warn!(erreur = %e, "action hooks refusée");
    (
        StatusCode::CONFLICT,
        axum::Json(serde_json::json!({ "error": e })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt::hooks::{Backend, CaBundle, Reach};

    fn hook(fail_closed: bool, reach: Reach) -> AdmissionHook {
        AdmissionHook {
            kind: WebhookKind::Validating,
            config: "kyverno-cfg".into(),
            index: 1,
            siblings: 2,
            name: "validate.kyverno.svc-fail".into(),
            backend: Backend::Service {
                namespace: "kyverno".into(),
                name: "kyverno-svc".into(),
                path: "/validate".into(),
                port: 443,
            },
            reach,
            fail_closed,
            failure_policy_defaulted: false,
            timeout_seconds: Some(10),
            side_effects: "None".into(),
            match_policy: "Equivalent".into(),
            reinvocation_policy: None,
            admission_review_versions: vec!["v1".into()],
            rules: Vec::new(),
            namespace_selector: Default::default(),
            object_selector: Default::default(),
            match_conditions: 0,
            ca: CaBundle::Absent { injector: None },
            hints: Vec::new(),
            age: "12d".into(),
            uid: "hooks|adm|val/kyverno-cfg#1".into(),
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn une_ligne_admission_porte_ce_que_le_navigateur_lit() {
        let v = admission_row(&hook(true, Reach::Ready));
        assert_eq!(v["kind"], "validating");
        assert_eq!(v["kind_label"], "val");
        assert_eq!(v["reach"], "ready");
        assert_eq!(v["reach_label"], "ready");
        assert_eq!(v["backend_label"], "kyverno/kyverno-svc");
        assert_eq!(v["fail_closed"], true);
        assert_eq!(v["broken"], false);
        assert_eq!(v["index"], 1);
        assert_eq!(v["ca"]["state"], "absent");
    }

    // La ligne montre le webhook, l'enregistrement désigne la configuration : c'est le seul objet
    // que `y`, `e` et la suppression puissent atteindre.
    #[test]
    fn le_record_d_une_ligne_admission_designe_la_configuration() {
        let v = admission_row(&hook(true, Reach::Ready));
        assert_eq!(v["name"], "validate.kyverno.svc-fail");
        assert_eq!(v["record"]["kind"], "ValidatingWebhookConfiguration");
        assert_eq!(v["record"]["name"], "kyverno-cfg");
        assert_eq!(v["record"]["namespace"], "");
    }

    // La règle anti-invention, telle que le navigateur la reçoit : un service qu'on n'a pas pu
    // interroger n'est pas peint en panne.
    #[test]
    fn un_service_non_interrogeable_n_est_pas_peint_en_panne() {
        let v = admission_row(&hook(true, Reach::Unchecked));
        assert_eq!(v["reach"], "unchecked");
        assert_eq!(v["broken"], false);
        assert_eq!(v["record"]["tone"], "ok");

        let mort = admission_row(&hook(true, Reach::NoEndpoints));
        assert_eq!(mort["reach"], "no-endpoints");
        assert_eq!(mort["broken"], true);
    }

    // Trois champs d'erreur, pas un : un refus RBAC sur les CRD ne doit pas donner à croire que le
    // monde admission est vide.
    #[test]
    fn les_trois_mondes_ont_chacun_leur_champ_d_erreur() {
        let state = HooksState {
            admission: vec![hook(true, Reach::Ready)],
            conversion_error: Some("forbidden".into()),
            local_apiservices: 38,
            installed: true,
            ..Default::default()
        };
        let v = payload(&state);
        assert_eq!(v["error"], serde_json::Value::Null);
        assert_eq!(v["conversion_error"], "forbidden");
        assert_eq!(v["apiservice_error"], serde_json::Value::Null);
        assert_eq!(v["admission"].as_array().unwrap().len(), 1);
        assert_eq!(v["counts"]["admission"]["rows"], 1);
        assert_eq!(v["counts"]["admission"]["fail_closed"], 1);
        // Comptées, pas listées.
        assert_eq!(v["local_apiservices"], 38);
        assert_eq!(v["apiservices"].as_array().unwrap().len(), 0);
    }
}
