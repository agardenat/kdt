//! La vue Workloads : les workloads du namespace, leurs pods, et les containers de chaque pod.
//!
//! Comme ailleurs, rien n'est jugé ici. L'état d'un pod, le ton de sa ligne, l'étiquette `READY`
//! d'un workload — qui ne se compte pas pareil selon le kind — et le rattachement d'un pod à son
//! workload viennent tous de `kdt::pods`, qui est ce que le TUI affiche.
//!
//! # Le rattachement est calculé ici, le pliage non
//!
//! Chaque pod part avec le `group` de son workload — le résultat de `PodResource::belongs_to`,
//! qui remonte les `ownerReferences` en résolvant ReplicaSet → Deployment. Le navigateur ne
//! rejoue pas cette remontée : il assemble des lignes à partir d'un rattachement déjà décidé.
//! Ce qui lui reste est ce qui le regarde — quels pods sont dépliés, et si les workloads sont
//! affichés du tout.
//!
//! # Portée
//!
//! Contrairement à l'arbre Flux, cette vue **est** dans la portée de namespaces : elle liste des
//! objets indépendants, pas un graphe dont un filtre couperait les arêtes. C'est aussi ce que
//! fait le TUI, où `Mode::Pods` se réouvre quand la portée change.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::pods::{ContainerResource, OwnerRef, PodResource, WorkloadResource};
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::AppState;

#[derive(Deserialize)]
pub struct ScopeQuery {
    /// Un seul namespace, ou vide pour tout le cluster.
    ///
    /// Un seul et non une liste comme pour les évènements : la hiérarchie se lit workload par
    /// workload, et deux namespaces mélangés dans le même arbre n'auraient pas de racine commune.
    #[serde(default)]
    ns: String,
}

/// Les workloads et les pods de la portée demandée.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ScopeQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    let namespace = Some(query.ns.trim().to_string()).filter(|s| !s.is_empty());
    let inventory = match kdt::pods::workloads(client, namespace).await {
        Ok(inv) => inv,
        // Le refus porte sur la liste des pods elle-même : sans elle il n'y a pas de vue, donc
        // c'est bien une erreur et non une liste vide qui ferait croire à un namespace désert.
        Err(e) => {
            warn!(erreur = %e, "lecture des workloads refusée");
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    };

    let workloads: Vec<serde_json::Value> =
        inventory.workloads.iter().map(workload_json).collect();
    let pods: Vec<serde_json::Value> = inventory
        .pods
        .iter()
        .map(|p| pod_json(p, &inventory.workloads))
        .collect();

    axum::Json(serde_json::json!({
        "workloads": workloads,
        "pods": pods,
        // Un kind refusé par le RBAC voyage avec les lignes plutôt qu'à leur place : sans ça, la
        // vue dirait « aucun Job » là où la vérité est « pas le droit de regarder ».
        "missing_kinds": inventory.missing_kinds,
    }))
    .into_response()
}

fn workload_json(w: &WorkloadResource) -> serde_json::Value {
    let mut value = serde_json::to_value(w).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("ready_label".to_string(), w.ready_label().into());
        object.insert("status_label".to_string(), w.status_label().into());
        object.insert("status_tone".to_string(), tone_json(w.status_tone()));
        // Ce que cette ligne accepte comme action. `spec.replicas` est le seul témoin qu'un kind
        // se scale : un DaemonSet a un nombre désiré, mais c'est le scheduler qui le décide.
        object.insert("scalable".to_string(), w.is_scalable().into());
        object.insert("restartable".to_string(), w.is_restartable().into());
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::pods::synthetic_workload_record(w))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

/// Le pod, son verdict, et le workload auquel kdt le rattache.
fn pod_json(p: &PodResource, workloads: &[WorkloadResource]) -> serde_json::Value {
    let mut value = serde_json::to_value(p).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        usage_json(object, p.cpu_milli, p.mem_bytes, p.cpu_req, p.cpu_lim, p.mem_req, p.mem_lim);
        object.insert("status_tone".to_string(), tone_json(p.status_tone()));
        object.insert("row_tone".to_string(), tone_json(p.row_tone()));
        object.insert("restarts_tone".to_string(), tone_json(p.restarts_tone()));
        // Le rattachement, décidé par kdt en remontant les ownerReferences (ReplicaSet →
        // Deployment). `null` veut dire orphelin : un pod nu, ou celui d'un ReplicaSet sans
        // Deployment au-dessus.
        object.insert(
            "group".to_string(),
            match workloads.iter().find(|w| p.belongs_to(w)) {
                Some(w) => w.uid.clone().into(),
                None => serde_json::Value::Null,
            },
        );
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::pods::synthetic_pod_record(p))
                .unwrap_or(serde_json::Value::Null),
        );
        if let Some(containers) = object.get_mut("containers").and_then(|c| c.as_array_mut()) {
            for (slot, c) in containers.iter_mut().zip(p.containers.iter()) {
                enrich_container(slot, c);
            }
        }
    }
    value
}

/// Les quatre ratios de la ligne : la consommation rapportée à ce qui a été demandé, puis à ce qui
/// est permis. Calculés ici parce que la bande de pression est un verdict de `kdt` — dépasser une
/// limite n'est pas dépasser une requête — et non une division que le navigateur referait.
fn usage_json(
    object: &mut serde_json::Map<String, serde_json::Value>,
    cpu: Option<i64>,
    mem: Option<i64>,
    cpu_req: Option<i64>,
    cpu_lim: Option<i64>,
    mem_req: Option<i64>,
    mem_lim: Option<i64>,
) {
    for (field, usage, base) in [
        ("cpu_req_pct", cpu, cpu_req),
        ("cpu_lim_pct", cpu, cpu_lim),
        ("mem_req_pct", mem, mem_req),
        ("mem_lim_pct", mem, mem_lim),
    ] {
        object.insert(
            field.to_string(),
            match kdt::pods::usage_pct(usage, base) {
                Some((pct, pressure)) => serde_json::json!({
                    "pct": pct,
                    "pressure": pressure,
                }),
                // Pas de mesure, ou pas de base : la colonne n'a rien à dire, et un zéro se
                // lirait comme une consommation nulle.
                None => serde_json::Value::Null,
            },
        );
    }
}

fn enrich_container(slot: &mut serde_json::Value, c: &ContainerResource) {
    let Some(object) = slot.as_object_mut() else { return };
    usage_json(object, c.cpu_milli, c.mem_bytes, c.cpu_req, c.cpu_lim, c.mem_req, c.mem_lim);
    object.insert("tone".to_string(), tone_json(c.tone()));
    object.insert("restarts_tone".to_string(), tone_json(c.restarts_tone()));
    object.insert("display_name".to_string(), c.display_name().into());
    // Seul un container qui tourne peut recevoir un `exec`. Le dire à l'avance évite de proposer
    // une action sur un init `Completed`, qui a pourtant tout l'air d'une ligne saine.
    object.insert("running".to_string(), c.is_running().into());
    object.insert(
        "record".to_string(),
        serde_json::to_value(kdt::pods::synthetic_container_record(c))
            .unwrap_or(serde_json::Value::Null),
    );
}

fn tone_json(tone: kdt::events::LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

/// La cible d'une action, et ce qu'elle demande.
#[derive(Deserialize)]
pub struct ActionBody {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
    /// Le nombre de répliques visé. Requis par `scale` et par `recycle`, ignoré ailleurs.
    #[serde(default)]
    replicas: Option<i32>,
}

impl ActionBody {
    fn owner(&self) -> OwnerRef {
        OwnerRef {
            kind: self.kind.clone(),
            name: self.name.clone(),
            namespace: self.namespace.clone(),
            api_version: self.api_version.clone(),
        }
    }
}

/// Porte le nombre de répliques d'un workload à une valeur absolue.
pub async fn scale(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ActionBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let Some(replicas) = body.replicas.filter(|r| *r >= 0) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": "replicas manquant ou négatif" })),
        )
            .into_response();
    };

    info!(kind = %body.kind, objet = %format!("{}/{}", body.namespace, body.name), replicas, "scale demandé");
    outcome(kdt::pods::scale_once(&client, &body.owner(), replicas).await)
}

/// Redémarre progressivement, par l'annotation `restartedAt` du template.
pub async fn restart(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ActionBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    info!(kind = %body.kind, objet = %format!("{}/{}", body.namespace, body.name), "restart demandé");
    outcome(kdt::pods::restart_once(&client, &body.owner()).await)
}

/// Descend à zéro puis remonte : recrée tous les pods d'un coup, avec une coupure brève.
///
/// L'appel est **long** — deux secondes d'attente entre la descente et la remontée, côté `kdt` —
/// et la réponse n'arrive qu'une fois la remontée tentée. C'est voulu : une descente réussie
/// suivie d'une remontée en échec laisse le workload à zéro, et le navigateur doit l'apprendre de
/// la réponse plutôt que d'un rafraîchissement où il verrait `0/3` sans savoir pourquoi.
pub async fn recycle(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ActionBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let Some(replicas) = body.replicas.filter(|r| *r > 0) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": "replicas requis et strictement positif" })),
        )
            .into_response();
    };

    info!(kind = %body.kind, objet = %format!("{}/{}", body.namespace, body.name), replicas, "recycle demandé");
    outcome(kdt::pods::recycle_once(&client, &body.owner(), replicas).await)
}

/// La phrase que `kdt` rédige, rendue telle quelle — c'est elle qui dit ce qui s'est réellement
/// passé, y compris le cas où le workload est resté à zéro.
fn outcome(result: Result<String, String>) -> Response {
    match result {
        Ok(message) => axum::Json(serde_json::json!({ "message": message })).into_response(),
        // 409 : la demande est arrivée, c'est l'objet ou son kind qui la repousse.
        Err(e) => {
            warn!(erreur = %e, "action sur le workload refusée");
            (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    }
}
