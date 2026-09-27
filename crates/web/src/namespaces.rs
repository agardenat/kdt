//! La vue Namespaces : chaque namespace comme un objet de première classe — phase, âge,
//! provenance, labels et annotations — et non plus seulement un nom dans le sélecteur de portée.
//!
//! Sans portée, évidemment : un namespace est cluster-scoped, et c'est la liste elle-même qu'on
//! regarde. La phase et son ton, la provenance et l'enregistrement viennent de `kdt::namespaces`.
//!
//! Le manifeste ne voyage pas : le TUI le garde pour sa copie `c`, le web le lit par le geste
//! générique `y`, qui le relit au moment où on le demande.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::namespaces::NamespaceInfo;
use serde::Deserialize;
use tracing::warn;

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

#[derive(Deserialize)]
pub struct NsQuery {
    #[serde(default)]
    lang: String,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NsQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    match kdt::namespaces::namespaces_inventory(&client).await {
        Ok(items) => axum::Json(serde_json::json!({
            "namespaces": items.iter().map(|ns| row_json(ns, st)).collect::<Vec<_>>(),
        }))
        .into_response(),
        // Lister les namespaces est un droit cluster-scoped que beaucoup n'ont pas : le refus se
        // dit, il ne se rend pas comme un cluster sans namespace.
        Err(e) => {
            warn!(erreur = %e, "lecture des namespaces refusée");
            (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({ "error": e }))).into_response()
        }
    }
}

fn row_json(ns: &NamespaceInfo, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(ns).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("uid".to_string(), format!("namespace|{}", ns.name).into());
        object.insert("provenance_label".to_string(), ns.provenance.label().into());
        object.insert(
            "phase_tone".to_string(),
            serde_json::to_value(ns.phase_tone()).unwrap_or(serde_json::Value::Null),
        );
        let record = ns.record(st);
        let tone = record.tone();
        let mut record = serde_json::to_value(record).unwrap_or(serde_json::Value::Null);
        if let Some(r) = record.as_object_mut() {
            r.insert("tone".to_string(), serde_json::to_value(tone).unwrap_or(serde_json::Value::Null));
        }
        object.insert("record".to_string(), record);
    }
    value
}
