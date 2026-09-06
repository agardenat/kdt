//! La vue cert-manager : la chaîne d'émission, ses constats, et les deux leviers qui la relancent.
//!
//! Ce que cette vue apporte n'est pas la liste des Certificates — `kubectl get certificates` la
//! donne — mais la **chaîne** : Issuer → Certificate → CertificateRequest → Order → Challenge, puis
//! le Secret produit et ceux qui le servent. Elle est résolue par `kdt::certmanager`, comme dans le
//! TUI, et le navigateur n'en redessine aucune arête : il reçoit l'arbre déjà construit, en
//! parcours préfixe, chaque ligne portant sa profondeur.
//!
//! # Ce qui est calculé ici, et ce qui ne l'est pas
//!
//! Rien de ce qui juge le cluster. La lisibilité (`ready`), le libellé READY, le ton d'une échéance,
//! les constats de la chaîne (`chain_hints`) et le refus de réessayer sous quota ACME viennent tous
//! de `kdt`. Ce module joint deux lectures — les objets cert-manager et les Secrets de la portée —
//! et rend le résultat.
//!
//! # Pourquoi les Secrets sont relus ici
//!
//! Un Certificate `Ready` dont le Secret est absent est la seule panne que rien d'autre ne signale,
//! et un keystore demandé qui n'a jamais atterri ne se voit que dans les clés du Secret. Ces faits
//! sont ceux de la vue Secrets, jamais recalculés : `kdt::secrets` les fournit, et une lecture
//! refusée laisse les constats **muets** plutôt que d'affirmer une absence — un Secret illisible
//! n'est pas un Secret manquant.
//!
//! # Le coût, dit franchement
//!
//! Les constats sont calculés **pour chaque ligne**, et chacun remonte puis redescend la chaîne :
//! le coût croît plus vite que le nombre d'objets. C'est tenable sur les inventaires qu'on voit —
//! quelques dizaines d'objets, les Orders et Challenges étant ramassés par le garbage collector —
//! et c'est ce qui permet au panneau d'ouvrir n'importe quelle ligne sans une seconde requête. Un
//! inventaire qui se compterait en milliers demanderait de les calculer à la sélection.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::certmanager::{
    build_cert_tree, chain_hints, filter_chains, in_flight_request, is_rate_limited,
    owning_certificate, CertFilter, CmKind, CmResource, PasswordRef, SecretFacts,
};
use kdt::secrets::SecretInfo;
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::AppState;

#[derive(Deserialize)]
pub struct CertsQuery {
    /// La portée : un namespace, ou vide pour tout le cluster.
    #[serde(default)]
    ns: String,
    /// Le filtre de la vue. C'est une règle de kdt — elle garde les ancêtres de ce qu'elle retient —
    /// donc elle s'applique ici et non dans le navigateur, qui n'a pas les arêtes pour la refaire.
    #[serde(default)]
    filter: CertFilter,
    #[serde(default)]
    lang: String,
}

/// L'arbre cert-manager de la portée, ses constats et ses leviers.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CertsQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);
    let scope = query.ns.trim().to_string();

    let inventory = kdt::certmanager::certs_inventory(&client, st).await;

    // La portée ne s'applique qu'aux kinds namespacés : un ClusterIssuer n'a pas de namespace et
    // c'est précisément ce que pointe le Certificate de celui-ci — l'écarter couperait la chaîne
    // que la vue existe pour montrer.
    let scoped: Vec<CmResource> = if scope.is_empty() {
        inventory.resources.clone()
    } else {
        inventory
            .resources
            .iter()
            .filter(|r| r.namespace.is_empty() || r.namespace == scope)
            .cloned()
            .collect()
    };
    let resources = filter_chains(&scoped, query.filter);

    // Les Secrets de la même portée, pour la feuille de chaîne et pour les constats. Un refus n'est
    // pas une absence : les faits restent inconnus, et les règles s'abstiennent.
    let (secrets, secrets_error) = match kdt::secrets::secrets(
        client.clone(),
        Some(scope.clone()).filter(|s| !s.is_empty()),
    )
    .await
    {
        Ok(inv) => (inv.secrets, None),
        Err(e) => {
            warn!(erreur = %e, "Secrets illisibles : les constats de chaîne s'abstiendront");
            (Vec::new(), Some(e))
        }
    };
    let known: HashSet<(String, String)> = secrets
        .iter()
        .map(|s| (s.namespace.clone(), s.name.clone()))
        .collect();

    // Déplié, comme l'arbre Flux : le pliage est un état de la personne qui regarde, pas du cluster.
    let nodes = build_cert_tree(&resources, &HashSet::new());
    let mut rows: Vec<serde_json::Value> = Vec::new();
    for node in &nodes {
        let Some(r) = resources.get(node.idx) else { continue };
        let facts = secret_facts(&resources, node.idx, &secrets, &scope);
        rows.push(resource_json(
            r,
            node.idx,
            node.depth,
            node.has_children,
            &resources,
            facts.as_ref(),
            st,
        ));
        // Le Secret produit ferme la chaîne : c'est lui que l'Ingress sert réellement. Il n'est
        // affiché que s'il existe — une feuille pour un Secret qu'on n'a pas lu ne dirait rien.
        if r.kind == CmKind::Certificate {
            if let Some(sn) = &r.secret_name {
                if known.contains(&(r.namespace.clone(), sn.clone())) {
                    rows.push(secret_json(&r.namespace, sn, node.depth + 1, &secrets));
                }
            }
        }
    }

    let (total, ready, failed, in_flight, expiring) = kdt::certmanager::CertState {
        resources: resources.clone(),
        ..Default::default()
    }
    .counts();

    axum::Json(serde_json::json!({
        "rows": rows,
        "counts": {
            "total": total,
            "ready": ready,
            "failed": failed,
            "in_flight": in_flight,
            "expiring": expiring,
        },
        "installed": inventory.installed,
        // Absent sur un cluster qui n'émet que depuis une CA ou un selfSigned : ce n'est pas une
        // panne, et le dire évite de chercher des Orders qui n'existeront jamais.
        "acme_installed": inventory.acme_installed,
        "error": inventory.error,
        "secrets_error": secrets_error,
    }))
    .into_response()
}

/// Ce que la vue Secrets sait du Secret que cette chaîne produit.
///
/// La règle est celle du TUI, mot pour mot : une liste vide ou une portée qui ne couvre pas le
/// namespace du Certificate veut dire **inconnu**, jamais « absent ». Signaler un Secret manquant
/// sur la foi d'une liste qui n'a rien lu serait une fausse alerte.
fn secret_facts(
    resources: &[CmResource],
    idx: usize,
    secrets: &[SecretInfo],
    scope: &str,
) -> Option<SecretFacts> {
    let cert = owning_certificate(idx, resources)?;
    let sn = resources[cert].secret_name.as_ref()?;
    let ns = &resources[cert].namespace;
    if secrets.is_empty() || (!scope.is_empty() && scope != ns.as_str()) {
        return None;
    }

    // Le mot de passe d'un keystore vit dans un **autre** Secret du même namespace, résolu ici pour
    // que les règles restent pures. L'ordre suit `CmResource::keystores`, et un keystore dont le mot
    // de passe est littéral garde sa place pour que la correspondance ne se décale pas.
    let password_refs = resources[cert]
        .keystores
        .iter()
        .map(|ks| match &ks.password_ref {
            Some((name, key)) => {
                match secrets.iter().find(|x| &x.namespace == ns && &x.name == name) {
                    Some(sec) => PasswordRef {
                        secret_found: true,
                        key_found: sec.data_keys.iter().any(|k| k == key),
                    },
                    None => PasswordRef::default(),
                }
            }
            None => PasswordRef { secret_found: true, key_found: true },
        })
        .collect();

    Some(match secrets.iter().find(|x| &x.namespace == ns && &x.name == sn) {
        Some(found) => SecretFacts {
            found: true,
            days_remaining: found.tls.as_ref().map(|c| c.days_remaining),
            ingress_refs: found.ingress_refs.len(),
            data_keys: found.data_keys.clone(),
            password_refs,
        },
        None => SecretFacts { password_refs, ..SecretFacts::default() },
    })
}

/// Une ligne de l'arbre : la ressource, ce que kdt en peint, et ce qu'il en dit.
fn resource_json(
    r: &CmResource,
    idx: usize,
    depth: usize,
    has_children: bool,
    resources: &[CmResource],
    facts: Option<&SecretFacts>,
    st: &'static kdt::lang::Strings,
) -> serde_json::Value {
    let mut value = serde_json::to_value(r).unwrap_or_else(|_| serde_json::json!({}));
    let cert_idx = owning_certificate(idx, resources);
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "resource".into());
        object.insert("uid".to_string(), r.uid().into());
        // Le rang dans l'ordre de kdt — problèmes d'abord, puis l'échéance la plus proche. L'arbre
        // a son propre ordre, celui de la lignée ; la vue à plat se range sur celui-ci, et le tri
        // reste celui de kdt plutôt qu'un second tri écrit dans le navigateur.
        object.insert("rank".to_string(), idx.into());
        object.insert("kind_short".to_string(), r.kind.short().into());
        object.insert("depth".to_string(), depth.into());
        object.insert("has_children".to_string(), has_children.into());
        object.insert("ready_label".to_string(), r.ready.label().into());
        object.insert("ready_glyph".to_string(), r.ready.glyph().into());
        object.insert("ready_tone".to_string(), tone_json(r.ready.tone()));
        object.insert("target".to_string(), r.target().into());
        object.insert("keystore_formats".to_string(), r.keystore_formats().into());
        object.insert("expiry_tone".to_string(), expiry_tone(r.days_remaining));
        // Le Certificate qui commande cette ligne, quel que soit l'étage de la chaîne où l'on est :
        // c'est lui que `renew` vise, et c'est sa section « Secret produit » qu'on lit.
        object.insert(
            "cert_uid".to_string(),
            match cert_idx {
                Some(i) => resources[i].uid().into(),
                None => serde_json::Value::Null,
            },
        );
        // Les constats de la chaîne autour de cette ligne. C'est la différence entre cette vue et
        // `kubectl get challenges`, et c'est kdt qui les rédige — dans la langue demandée.
        object.insert(
            "hints".to_string(),
            serde_json::to_value(chain_hints(idx, resources, facts, st))
                .unwrap_or(serde_json::Value::Null),
        );
        if r.kind == CmKind::Certificate {
            object.insert("produced".to_string(), produced_json(r, facts));
            object.insert("actions".to_string(), actions_json(idx, resources));
        }
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::certmanager::synthetic_record(r))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

/// Le Secret que ce Certificate produit, et les keystores qu'il a demandés.
///
/// `known` à faux veut dire que les clés du Secret ne sont pas connues : chaque fichier de keystore
/// reste alors à `null` — ni présent, ni absent — plutôt que d'être affiché comme manquant.
fn produced_json(r: &CmResource, facts: Option<&SecretFacts>) -> serde_json::Value {
    let Some(sn) = &r.secret_name else { return serde_json::Value::Null };
    let keys: &[String] = facts.map(|f| f.data_keys.as_slice()).unwrap_or(&[]);
    let known = !keys.is_empty();
    let keystores: Vec<serde_json::Value> = r
        .keystores
        .iter()
        .enumerate()
        .map(|(n, ks)| {
            let file = |key: &'static str| {
                serde_json::json!({
                    "key": key,
                    "present": if known { serde_json::Value::Bool(keys.iter().any(|k| k == key)) } else { serde_json::Value::Null },
                })
            };
            serde_json::json!({
                "format": ks.format.as_str(),
                "alias": ks.alias,
                // Le truststore n'est écrit que si l'émetteur a rendu une CA : son absence n'est un
                // constat que lorsque le Secret porte un `ca.crt`, et c'est `chain_hints` qui le
                // tranche. Ici on ne fait que dire ce qui est là.
                "files": [file(ks.format.keystore_key()), file(ks.format.truststore_key())],
                "password_ref": match &ks.password_ref {
                    Some((name, key)) => serde_json::json!({
                        "name": name,
                        "key": key,
                        "secret_found": facts.and_then(|f| f.password_refs.get(n)).map(|p| p.secret_found),
                        "key_found": facts.and_then(|f| f.password_refs.get(n)).map(|p| p.key_found),
                    }),
                    None => serde_json::Value::Null,
                },
            })
        })
        .collect();

    serde_json::json!({
        "secret_name": sn,
        "namespace": r.namespace,
        "known": facts.is_some(),
        "found": facts.map(|f| f.found),
        "days_remaining": facts.and_then(|f| f.days_remaining),
        "ingress_refs": facts.map(|f| f.ingress_refs),
        "keystores": keystores,
        "renewal_time": r.renewal_time,
        "not_after": r.not_after,
    })
}

/// Les deux leviers, et ce sur quoi ils portent.
///
/// `acme_retry` ne nomme une cible que s'il y a une demande vivante à relancer, et jamais sous quota
/// ACME : réessayer là ne fait que brûler ce qui reste et repousser la sortie.
fn actions_json(cert_idx: usize, resources: &[CmResource]) -> serde_json::Value {
    let rate_limited = is_rate_limited(cert_idx, resources);
    let retry = in_flight_request(cert_idx, resources)
        .filter(|_| !rate_limited)
        .map(|i| {
            let r = &resources[i];
            serde_json::json!({
                "apiVersion": r.api_version,
                "namespace": r.namespace,
                "name": r.name,
            })
        });
    serde_json::json!({
        "renew": true,
        "acme_retry": retry,
        "rate_limited": rate_limited,
    })
}

/// La feuille TLS : le Secret que la chaîne produit, avec ce que la vue Secrets en sait.
fn secret_json(
    namespace: &str,
    name: &str,
    depth: usize,
    secrets: &[SecretInfo],
) -> serde_json::Value {
    let found = secrets.iter().find(|s| s.namespace == namespace && s.name == name);
    let days = found.and_then(|s| s.tls.as_ref().map(|c| c.days_remaining));
    serde_json::json!({
        "row": "secret",
        "uid": format!("cmsec|{}/{}", namespace, name),
        "namespace": namespace,
        "name": name,
        "depth": depth,
        "has_children": false,
        "days_remaining": days,
        "expiry_tone": expiry_tone(days),
        "ingress_refs": found.map(|s| s.ingress_refs.len()).unwrap_or(0),
        "record": serde_json::to_value(kdt::certmanager::secret_record(namespace, name))
            .unwrap_or(serde_json::Value::Null),
    })
}

/// La bande d'urgence d'une échéance, celle de la vue Secrets : une date se lit pareil partout.
fn expiry_tone(days: Option<i64>) -> serde_json::Value {
    match days {
        Some(d) => tone_json(kdt::secrets::Expiry::from_days(d).tone()),
        None => serde_json::Value::Null,
    }
}

fn tone_json(tone: kdt::events::LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

/// Le corps d'une demande de renouvellement ou de relance ACME.
#[derive(Deserialize)]
pub struct CertTarget {
    #[serde(rename = "apiVersion")]
    api_version: String,
    namespace: String,
    name: String,
    #[serde(default)]
    lang: String,
}

/// Force la ré-émission, comme `cmctl renew` : la condition `Issuing` passée à True.
pub async fn renew(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<CertTarget>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    info!(
        certificate = %format!("{}/{}", body.namespace, body.name),
        "renouvellement demandé"
    );
    match kdt::certmanager::renew_once(
        &client,
        &body.api_version,
        &body.namespace,
        &body.name,
        lang_of(&body.lang),
    )
    .await
    {
        Ok(message) => axum::Json(serde_json::json!({ "message": message })).into_response(),
        Err(e) => refused(e),
    }
}

/// Relance un cycle ACME bloqué en supprimant la CertificateRequest en cours.
///
/// La cible est celle que le serveur a nommée dans la charge utile de la liste : supprimer le
/// Challenge ne servirait à rien — son Order le recrée à l'identique — et c'est la demande qui
/// emporte l'Order et ses Challenges avec elle.
pub async fn acme_retry(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<CertTarget>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    info!(
        request = %format!("{}/{}", body.namespace, body.name),
        "relance ACME demandée"
    );
    match kdt::certmanager::retry_acme_once(
        &client,
        &body.api_version,
        &body.namespace,
        &body.name,
        lang_of(&body.lang),
    )
    .await
    {
        Ok(message) => axum::Json(serde_json::json!({ "message": message })).into_response(),
        Err(e) => refused(e),
    }
}

/// 409 et non 500 : la demande est arrivée, c'est l'objet ou son état qui la repousse.
fn refused(e: String) -> Response {
    warn!(erreur = %e, "action cert-manager refusée");
    (
        StatusCode::CONFLICT,
        axum::Json(serde_json::json!({ "error": e })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt::certmanager::{CmReady, KeystoreFormat, KeystoreSpec};

    fn res(kind: CmKind, ns: &str, name: &str) -> CmResource {
        CmResource {
            kind,
            api_version: "cert-manager.io/v1".into(),
            namespace: ns.into(),
            name: name.into(),
            ready: CmReady::Ready,
            message: String::new(),
            age: "3d".into(),
            age_secs: 0,
            owner: None,
            issuer_ref: None,
            secret_name: None,
            dns_names: vec![],
            not_after: None,
            days_remaining: None,
            renewal_time: None,
            issuer_type: None,
            challenge: None,
            keystores: vec![],
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`. En renommer une côté serveur
    // se verrait ici plutôt qu'à l'écran, sous la forme d'une colonne vide.
    #[test]
    fn une_ligne_porte_ce_que_le_navigateur_lit() {
        let mut issuer = res(CmKind::ClusterIssuer, "", "letsencrypt");
        issuer.issuer_type = Some("acme".into());
        let mut cert = res(CmKind::Certificate, "mon", "grafana-tls");
        cert.issuer_ref = Some(("ClusterIssuer".into(), "letsencrypt".into(), String::new()));
        cert.secret_name = Some("grafana-tls".into());
        cert.dns_names = vec!["grafana.example".into(), "g.example".into()];
        cert.days_remaining = Some(12);
        cert.keystores = vec![KeystoreSpec {
            format: KeystoreFormat::Jks,
            password_ref: Some(("ks-pw".into(), "password".into())),
            alias: None,
        }];
        let all = vec![issuer, cert];

        let facts = SecretFacts {
            found: true,
            days_remaining: Some(12),
            ingress_refs: 1,
            data_keys: vec!["tls.crt".into(), "keystore.jks".into()],
            password_refs: vec![PasswordRef { secret_found: true, key_found: false }],
        };
        let v = resource_json(&all[1], 1, 1, false, &all, Some(&facts), lang_of("fr"));

        assert_eq!(v["row"], "resource");
        assert_eq!(v["uid"], "Certificate|mon/grafana-tls");
        assert_eq!(v["rank"], 1);
        assert_eq!(v["depth"], 1);
        assert_eq!(v["has_children"], false);
        assert_eq!(v["kind"], "Certificate");
        assert_eq!(v["kind_short"], "Certificate");
        assert_eq!(v["ready"], "ready");
        assert_eq!(v["ready_label"], "Ready");
        assert_eq!(v["ready_tone"], "ok");
        // Deux DNS : le premier, puis le compte des autres — la forme de la colonne du TUI.
        assert_eq!(v["target"], "grafana.example +1");
        // Douze jours : la bande rouge de la vue Secrets, pas une couleur inventée ici.
        assert_eq!(v["expiry_tone"], "err");
        assert_eq!(v["keystore_formats"][0], "JKS");
        // Le Certificate qui commande la ligne, c'est lui-même ici.
        assert_eq!(v["cert_uid"], "Certificate|mon/grafana-tls");
        assert!(v["hints"].is_array());
        assert_eq!(v["record"]["kind"], "Certificate");
        assert_eq!(v["record"]["uid"], "cm|Certificate|mon/grafana-tls");

        let produced = &v["produced"];
        assert_eq!(produced["secret_name"], "grafana-tls");
        assert_eq!(produced["found"], true);
        assert_eq!(produced["ingress_refs"], 1);
        let files = &produced["keystores"][0]["files"];
        assert_eq!(files[0]["key"], "keystore.jks");
        assert_eq!(files[0]["present"], true);
        // Le truststore n'est pas dans les clés : absent, et dit comme tel puisqu'on les connaît.
        assert_eq!(files[1]["key"], "truststore.jks");
        assert_eq!(files[1]["present"], false);
        assert_eq!(produced["keystores"][0]["password_ref"]["key_found"], false);

        // Rien en vol : aucune cible de relance, et le levier de renouvellement reste offert.
        assert_eq!(v["actions"]["renew"], true);
        assert!(v["actions"]["acme_retry"].is_null());
        assert_eq!(v["actions"]["rate_limited"], false);
    }

    // Sans faits sur le Secret, un fichier de keystore n'est ni présent ni absent : il est inconnu.
    // Le dire manquant sur une lecture qui n'a pas eu lieu ferait ouvrir un incident pour rien.
    #[test]
    fn sans_faits_les_fichiers_de_keystore_restent_inconnus() {
        let mut cert = res(CmKind::Certificate, "mon", "grafana-tls");
        cert.secret_name = Some("grafana-tls".into());
        cert.keystores = vec![KeystoreSpec {
            format: KeystoreFormat::Pkcs12,
            password_ref: None,
            alias: Some("certificate".into()),
        }];
        let all = vec![cert];
        let v = resource_json(&all[0], 0, 0, false, &all, None, lang_of("fr"));
        let produced = &v["produced"];
        assert_eq!(produced["known"], false);
        assert!(produced["found"].is_null());
        assert!(produced["keystores"][0]["files"][0]["present"].is_null());
        assert!(produced["keystores"][0]["password_ref"].is_null());
    }

    // La feuille TLS n'est pas un objet cert-manager : elle porte son propre enregistrement, pour
    // que les gestes sur cette ligne visent le Secret et non le Certificate au-dessus.
    #[test]
    fn la_feuille_tls_adresse_le_secret() {
        let v = secret_json("mon", "grafana-tls", 2, &[]);
        assert_eq!(v["row"], "secret");
        assert_eq!(v["uid"], "cmsec|mon/grafana-tls");
        assert_eq!(v["depth"], 2);
        assert_eq!(v["record"]["kind"], "Secret");
        assert_eq!(v["record"]["api_version"], "v1");
        // Secret inconnu de la liste : aucune échéance, et surtout pas un zéro.
        assert!(v["days_remaining"].is_null());
        assert!(v["expiry_tone"].is_null());
    }
}
