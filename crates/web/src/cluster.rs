//! Le bandeau : quel cluster on regarde, et dans quel état il est.
//!
//! C'est la première ligne du TUI, portée au web. Elle répond à la question qu'on se pose avant
//! toute autre — « suis-je sur le bon cluster ? » — et à celle qu'on se pose juste après : est-ce
//! qu'il va bien, et reste-t-il de la place.
//!
//! # Rien n'est jugé ici
//!
//! Les totaux, les pourcentages, les unités et le ton de chaque taux viennent de `kdt::events`,
//! qui est ce que le TUI affiche. Le navigateur reçoit des chaînes déjà formatées et un ton déjà
//! choisi : sans ça, deux interfaces finiraient par peindre deux couleurs du même cluster.
//!
//! # Ce que le bandeau refuse de dire
//!
//! Lire les nodes est un droit, et tout le monde ne l'a pas. Un refus rendrait `0/0 ready` — vert,
//! rassurant, et faux. `nodes_readable` distingue les deux cas, et ce qui n'a pas été lu est rendu
//! `null` plutôt que zéro : le front affiche alors un tiret, qui ne promet rien.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use kdt::events::{
    fetch_cluster_info, format_cpu_milli, format_memory_bytes, new_cluster_info_state, usage_pct,
    usage_tone, ClusterInfo, LineColor,
};

use crate::api::session_client;
use crate::AppState;

/// L'état du cluster, tel que la personne connectée peut le voir.
///
/// Les chiffres sont relus à chaque appel : ils bougent, et un bandeau qui ne bouge pas ne dirait
/// rien de plus qu'une capture d'écran. C'est le pendant du rafraîchissement de 20 s du TUI, sauf
/// que la cadence est ici décidée par l'onglet — qui sait, lui, s'il est encore visible.
pub async fn banner(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };

    let shared = new_cluster_info_state();
    fetch_cluster_info(client, shared.clone()).await;
    let info = shared.lock().expect("cluster info poisoned").clone();

    axum::Json(payload(
        &state.cluster_label,
        &state.kube.cluster_url.to_string(),
        &info,
    ))
    .into_response()
}

/// Le bandeau tel qu'il part sur le réseau.
///
/// Séparé de la route pour que les trois cas qui comptent — cluster lisible, metrics absent,
/// nodes refusés — se vérifient sans cluster.
fn payload(cluster: &str, apiserver: &str, info: &ClusterInfo) -> serde_json::Value {
    // Les nodes portent les totaux : sans eux, ni compte, ni allocation, ni taux. Un seul `null`
    // pour les trois, plutôt que des zéros qui se liraient comme des mesures.
    let nodes = info.nodes_readable.then(|| {
        serde_json::json!({
            "ready": info.nodes_ready,
            "total": info.node_count,
            "tone": tone_json(if info.nodes_ready == info.node_count {
                LineColor::Ok
            } else {
                LineColor::Warn
            }),
        })
    });

    let cpu = info.nodes_readable.then(|| {
        resource_json(
            info.metrics_available.then_some(info.cpu_use_milli),
            info.cpu_alloc_milli,
            format_cpu_milli,
        )
    });
    let mem = info.nodes_readable.then(|| {
        resource_json(
            info.metrics_available.then_some(info.mem_use_bytes),
            info.mem_alloc_bytes,
            format_memory_bytes,
        )
    });

    serde_json::json!({
        "cluster": cluster,
        // L'adresse de l'apiserver est ce qui rend un mauvais cluster évident, et c'est la seule
        // chose que le serveur sache avec certitude : le nom, lui, est un libellé qu'on lui a
        // donné. Elle voyage donc avec, et le front la met sous le nom.
        "apiserver": apiserver,
        // Absente quand l'apiserver n'a pas répondu à `/version` : ne rien afficher vaut mieux
        // qu'afficher la version d'avant.
        "server_version": info.server_version,
        "nodes": nodes,
        "cpu": cpu,
        "mem": mem,
        "metrics_available": info.metrics_available,
    })
}

/// Une ressource du bandeau : ce qui est alloué, ce qui est utilisé, et à quel point c'est tendu.
///
/// L'usage est `None` sans metrics-server — l'allocation, elle, se lit sur les nodes et reste
/// vraie. C'est le même partage que dans le TUI, qui affiche « CPU alloc » seul dans ce cas.
fn resource_json(
    used: Option<i64>,
    alloc: i64,
    format: fn(i64) -> String,
) -> serde_json::Value {
    let pct = used.and_then(|u| usage_pct(u, alloc));
    serde_json::json!({
        "used": used.map(format),
        "alloc": format(alloc),
        "pct": pct,
        "tone": pct.map(|p| tone_json(usage_tone(p))),
    })
}

fn tone_json(tone: LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hz() -> ClusterInfo {
        // Les chiffres de `hz`, relevés dans le bandeau du TUI : un node, 4 cœurs, 7,6 Gi.
        ClusterInfo {
            server_version: Some("v1.35.4+k3s1".to_string()),
            nodes_readable: true,
            node_count: 1,
            nodes_ready: 1,
            cpu_alloc_milli: 4000,
            cpu_use_milli: 395,
            mem_alloc_bytes: 8_160_437_000,
            mem_use_bytes: 5_690_650_000,
            metrics_available: true,
            loaded: true,
        }
    }

    #[test]
    fn le_bandeau_rend_les_memes_chiffres_que_le_tui() {
        let v = payload("hz", "https://127.0.0.1:6443/", &hz());
        assert_eq!(v["cluster"], "hz");
        assert_eq!(v["server_version"], "v1.35.4+k3s1");
        assert_eq!(v["nodes"]["ready"], 1);
        assert_eq!(v["nodes"]["total"], 1);
        assert_eq!(v["nodes"]["tone"], "ok");
        assert_eq!(v["cpu"]["used"], "395m");
        assert_eq!(v["cpu"]["alloc"], "4");
        assert_eq!(v["cpu"]["pct"], 9);
        assert_eq!(v["cpu"]["tone"], "ok");
        assert_eq!(v["mem"]["pct"], 69);
        assert_eq!(v["mem"]["tone"], "info");
    }

    #[test]
    fn un_node_absent_teinte_le_compte_sans_le_cacher() {
        let info = ClusterInfo { node_count: 3, nodes_ready: 2, ..hz() };
        let v = payload("hz", "https://127.0.0.1:6443/", &info);
        assert_eq!(v["nodes"]["ready"], 2);
        assert_eq!(v["nodes"]["tone"], "warn");
    }

    #[test]
    fn sans_metrics_l_allocation_reste_vraie_et_l_usage_est_nul() {
        let info = ClusterInfo { metrics_available: false, ..hz() };
        let v = payload("hz", "https://127.0.0.1:6443/", &info);
        assert_eq!(v["cpu"]["alloc"], "4");
        assert!(v["cpu"]["used"].is_null());
        assert!(v["cpu"]["pct"].is_null());
        assert!(v["cpu"]["tone"].is_null());
        assert_eq!(v["metrics_available"], false);
    }

    // Le cas qui motive tout `nodes_readable` : un refus RBAC ne doit pas se lire comme un
    // cluster sain à zéro node, ni comme un cluster sans la moindre ressource.
    #[test]
    fn des_nodes_refuses_ne_rendent_ni_compte_ni_allocation() {
        let info = ClusterInfo {
            nodes_readable: false,
            node_count: 0,
            nodes_ready: 0,
            cpu_alloc_milli: 0,
            mem_alloc_bytes: 0,
            metrics_available: false,
            ..hz()
        };
        let v = payload("hz", "https://127.0.0.1:6443/", &info);
        assert!(v["nodes"].is_null());
        assert!(v["cpu"].is_null());
        assert!(v["mem"].is_null());
        // Le nom du cluster, lui, ne dépend d'aucun droit : c'est ce qui reste à afficher.
        assert_eq!(v["cluster"], "hz");
    }

    // Un dépassement se dit : la jauge sature à 100 %, le pourcentage non.
    #[test]
    fn un_depassement_reste_un_depassement() {
        let info = ClusterInfo { cpu_use_milli: 4400, ..hz() };
        let v = payload("hz", "https://127.0.0.1:6443/", &info);
        assert_eq!(v["cpu"]["pct"], 110);
        assert_eq!(v["cpu"]["tone"], "err");
    }
}
