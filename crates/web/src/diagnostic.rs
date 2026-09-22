//! Le diagnostic du cluster, `D` dans kdt : une séquence fixe d'étapes en lecture seule.
//!
//! Les vingt-cinq étapes sont celles de `kdt::diagnostic`, dans le même ordre, avec les mêmes
//! verdicts. Ce module ne juge rien : il lance la séquence sous le credential de la personne
//! connectée et pousse au navigateur ce que le panneau du TUI affiche pendant qu'elle tourne.
//!
//! # Pourquoi en flux
//!
//! Le diagnostic dure. Il interroge l'apiserver, les webhooks, chaque add-on installé, et lit des
//! logs de pods : une minute n'est pas rare sur un gros cluster. Une seule réponse à la fin
//! laisserait le navigateur devant un sablier sans savoir ce qui est déjà su — alors que le TUI,
//! lui, remplit sa liste étape par étape. Chaque étape part dès qu'elle est terminée.
//!
//! # Ce que la personne voit dépend de ses droits
//!
//! Une étape qui ne peut pas lire est une étape en erreur, pas une étape absente : le RBAC de la
//! personne connectée s'applique comme partout ailleurs, et un `Err` sur les webhooks dit « je n'ai
//! pas le droit de les lire », jamais « il n'y en a pas ».

use std::convert::Infallible;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use kdt::diagnostic::{
    format_diagnostic_for_ai, new_diagnostic_state, run_diagnostic, synthetic_diagnostic_record,
    DiagStatus, DiagnosticStep,
};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

/// Le pas de relecture de l'état partagé. Une étape courte dure quelques dizaines de
/// millisecondes, une étape qui lit des logs plusieurs secondes : relire deux fois par seconde
/// suffit à ne jamais laisser le navigateur en avance sur ce qui est su.
const POLL: std::time::Duration = std::time::Duration::from_millis(400);

#[derive(Deserialize)]
pub struct DiagnosticBody {
    #[serde(default)]
    lang: String,
}

/// Le diagnostic, étape par étape.
///
/// Les évènements : `step` à chaque fois qu'une étape apparaît ou change, puis `done` avec la
/// durée, les compteurs, et de quoi envoyer le tout à un modèle.
///
/// `POST` plutôt qu'un `EventSource` : la langue voyage dans le corps comme pour les autres
/// écritures, et le navigateur lit le flux à la main — c'est le même `postStream` que le drain.
pub async fn run(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<DiagnosticBody>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);
    let cluster = state.cluster_label.clone();

    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(64);
    tokio::spawn(async move {
        let shared = new_diagnostic_state();
        let worker = tokio::spawn({
            let client = client.clone();
            let shared = shared.clone();
            async move { run_diagnostic(client, shared, st).await }
        });

        // Ce qui a déjà été poussé, par index. Une étape est envoyée à sa naissance — le TUI
        // affiche « … » pendant qu'elle tourne, et le navigateur doit pouvoir en faire autant —
        // puis de nouveau quand son verdict tombe. Comparer le JSON évite de renvoyer vingt-cinq
        // étapes figées à chaque tour.
        let mut sent: Vec<String> = Vec::new();
        loop {
            let (steps, finished, elapsed) = {
                let s = shared.lock().expect("diagnostic poisoned");
                (s.steps.clone(), s.finished, s.elapsed_ms)
            };

            let mut gone = false;
            for (index, step) in steps.iter().enumerate() {
                let payload = step_json(index, step);
                let text = payload.to_string();
                match sent.get(index) {
                    Some(previous) if *previous == text => continue,
                    Some(_) => sent[index] = text,
                    None => sent.push(text),
                }
                if tx.send(Ok(sse("step", payload))).await.is_err() {
                    // Navigateur parti. Le diagnostic ne lit que le cluster : l'abandonner ici ne
                    // laisse rien à moitié fait.
                    gone = true;
                    break;
                }
            }
            if gone {
                break;
            }

            if finished {
                let snapshot = shared.lock().expect("diagnostic poisoned").clone();
                let record = synthetic_diagnostic_record(&cluster, st);
                let tone = record.tone();
                let mut record = serde_json::to_value(&record).unwrap_or_default();
                if let Some(object) = record.as_object_mut() {
                    object.insert(
                        "tone".to_string(),
                        serde_json::to_value(tone).unwrap_or(serde_json::Value::Null),
                    );
                }
                let _ = tx
                    .send(Ok(sse(
                        "done",
                        serde_json::json!({
                            "elapsed_ms": elapsed,
                            "counts": counts_json(&snapshot.steps),
                            "record": record,
                            // Le même bloc que `i` envoie au modèle depuis le TUI. Il part avec le
                            // `done` plutôt qu'au moment de l'analyse : le serveur ne garde aucun
                            // état entre deux requêtes, et refaire tourner vingt-cinq étapes pour
                            // remplir un prompt coûterait une seconde minute au cluster.
                            "ai_text": format_diagnostic_for_ai(&snapshot, st),
                        }),
                    )))
                    .await;
                break;
            }

            tokio::time::sleep(POLL).await;
        }
        let _ = worker.await;
    });

    Sse::new(ReceiverStream::new(rx))
        // Une étape qui lit les logs du Rancher agent ne dit rien pendant plusieurs secondes :
        // sans battement, un proxy intermédiaire refermerait la connexion au milieu de la liste.
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Une étape, telle que le navigateur la peint.
///
/// Le statut et le ton de chaque ligne sont ceux de `kdt::diagnostic` : le front les affiche, il ne
/// les redéduit pas du texte — sinon les deux interfaces finiraient par colorer différemment la
/// même constatation.
fn step_json(index: usize, step: &DiagnosticStep) -> serde_json::Value {
    serde_json::json!({
        "index": index,
        "title": step.title,
        "command": step.command,
        "status": step.status,
        // Le glyphe du TUI, rendu ici pour que la pastille dise la même chose dans les deux
        // interfaces sans que le navigateur tienne sa propre table.
        "label": step.status.label(),
        "lines": step
            .lines
            .iter()
            .map(|(tone, text)| serde_json::json!({ "tone": tone, "text": text }))
            .collect::<Vec<_>>(),
    })
}

/// Les quatre compteurs de l'en-tête du TUI. Une étape encore en cours n'en alimente aucun.
fn counts_json(steps: &[DiagnosticStep]) -> serde_json::Value {
    let count = |status: DiagStatus| steps.iter().filter(|s| s.status == status).count();
    serde_json::json!({
        "steps": steps.len(),
        "ok": count(DiagStatus::Ok),
        "info": count(DiagStatus::Info),
        "warn": count(DiagStatus::Warn),
        "err": count(DiagStatus::Err),
    })
}

fn sse(name: &str, payload: serde_json::Value) -> Event {
    Event::default().event(name).data(payload.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt::events::LineColor;

    fn step(status: DiagStatus) -> DiagnosticStep {
        DiagnosticStep {
            title: "kdt-identity".to_string(),
            command: "kubectl get kdtusers,kdtgroups".to_string(),
            status,
            lines: vec![(LineColor::Warn, "portail à un seul replica".to_string())],
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn une_etape_porte_ce_que_le_navigateur_lit() {
        let v = step_json(3, &step(DiagStatus::Warn));
        assert_eq!(v["index"], 3);
        assert_eq!(v["status"], "warn");
        assert_eq!(v["label"], "!");
        assert_eq!(v["lines"][0]["tone"], "warn");
        assert_eq!(v["lines"][0]["text"], "portail à un seul replica");
    }

    // Une étape encore en cours ne compte nulle part : l'en-tête annonce ce qui est su, pas ce qui
    // est en train de se lire.
    #[test]
    fn une_etape_en_cours_nalimente_aucun_compteur() {
        let steps = vec![
            step(DiagStatus::Ok),
            step(DiagStatus::Warn),
            step(DiagStatus::Running),
        ];
        let v = counts_json(&steps);
        assert_eq!(v["steps"], 3);
        assert_eq!(v["ok"], 1);
        assert_eq!(v["warn"], 1);
        assert_eq!(v["info"], 0);
        assert_eq!(v["err"], 0);
    }
}
