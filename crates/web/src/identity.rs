//! La vue kdt-identity : les comptes locaux que ce cluster écrit, et ce qu'ils peuvent atteindre.
//!
//! Kubernetes n'a ni `User` ni `Group` : kdt-identity comble le trou avec deux CRD et un
//! controller. Cette vue est le côté exploitation — qui existe, qui est dans quoi, et qui peut
//! réellement se connecter.
//!
//! # Ce qui est calculé ici, et ce qui ne l'est pas
//!
//! Rien de ce qui juge le cluster. La phase (`Locked` compris, qui est le verdict propre à kdt et
//! que le controller n'écrit jamais), le ton de l'invitation, celui de la colonne des sessions, le
//! constat qu'un groupe ne donne aucun droit : tout vient de `kdt::identity`, comme dans le TUI. Ce
//! module joint la lecture et la rend.
//!
//! # Les deux silences qui ne sont pas des zéros
//!
//! Un Secret de sessions illisible n'est pas « personne n'est connecté », et un Secret de credential
//! illisible n'est pas « aucune invitation en cours ». Les deux erreurs de lecture voyagent
//! séparément — elles taisent une colonne chacune — et la vue les dit plutôt que d'afficher un
//! compte à zéro que personne ne saurait interpréter.
//!
//! # Le mode de délivrance appartient au déploiement
//!
//! `certificate` ou `oidc` est une valeur du chart, lue dans l'`env` du pod controller, et c'est
//! elle qui décide en combien de temps une révocation mord. Variable absente ⇒ on n'affirme rien :
//! l'amont défaute à `certificate`, mais l'absence décrit aussi un déploiement 0.1 qui ne révoque
//! rien du tout.
//!
//! # Le mode d'authentification est un second axe
//!
//! `authMode: local`, `ldap` ou `oidc` dit qui le portail **reconnaît**, là où `credentialMode` dit
//! ce qu'il **remet** : toutes les combinaisons sont valides. Dans les deux modes fédérés, les
//! comptes naissent d'une connexion réussie, portent le label `identity.kdt.sh/source` de leur
//! source et l'annotation qui épingle leur identité chez elle — un DN pour un annuaire, le sujet du
//! jeton pour un fournisseur —, et leur appartenance est réalignée à chaque relecture. Variable
//! absente ⇒ on n'affirme rien, comme pour la délivrance : c'est aussi ce à quoi ressemble un
//! déploiement antérieur à 1.2.
//!
//! Une différence de fond entre les deux sources voyage avec le reste : en `oidc`, la relecture
//! n'existe que si l'accès à l'API du fournisseur est déclaré. Sans elle rien n'est relu, aucun
//! compte n'est désactivé par le contrôleur, et `resync` **est nul** plutôt que court — le front
//! n'a donc pas à choisir un défaut, il lui suffit de dire ce qui lui arrive.
//!
//! # Les deux écritures qui ne passent pas par l'apiserver
//!
//! `invite` et `revoke` sont des commandes lancées **dans le pod controller** : elles ont besoin de
//! la configuration et du magasin de sessions de l'opérateur. Le pod est résolu ici, par les labels
//! du chart — jamais par un nom que le navigateur aurait fourni — et la sortie de la commande
//! devient la réponse **telle quelle** : kdt ne reformule pas « n sessions fermées ».

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::identity::{IdentGroup, IdentUser, IdentityWrite, WriteOutcome};
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::{auth, AppState};

#[derive(Deserialize)]
pub struct IdentityQuery {
    #[serde(default)]
    lang: String,
}

/// L'annuaire local : les comptes, les groupes, et ce que le déploiement dit de la délivrance.
///
/// Sans portée de namespace : les deux CRD sont *cluster-scoped*, et un compte n'appartient à aucun
/// namespace. La barre de portée se désactive donc sur cette vue, comme sur l'arbre Flux.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IdentityQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);

    let inv = kdt::identity::identity_inventory(&client, st).await;

    axum::Json(serde_json::json!({
        "installed": inv.installed,
        "error": inv.error,
        "creds_error": inv.creds_error,
        "sessions_error": inv.sessions_error,
        "controller": inv.controller,
        "delivery": delivery_json(&inv.delivery),
        "federation": federation_json(&inv.federation),
        // La colonne SOURCE ne se paie que là où une source extérieure est en jeu — soit le cluster
        // s'authentifie contre elle, soit un objet en porte encore le label.
        "shows_source": inv.shows_source(),
        "counts": {
            "users": inv.users.len(),
            "active": inv.active_users(),
            "pending": inv
                .users
                .iter()
                .filter(|u| u.phase == kdt::identity::Phase::Pending)
                .count(),
            // Pas le même nombre qu'`active` : un compte peut être en règle et connecté de nulle
            // part, ce qui est exactement ce qui rend une révocation inutile.
            "connected": inv.connected_users(),
            "groups": inv.groups.len(),
            "unbound": inv.unbound_groups(),
            "federated": inv.federated_users(),
        },
        // Ce que la table déclare et que le cluster n'a pas encore : jamais une faute, l'amont
        // crée chaque group à la première connexion d'un de ses members.
        "missing_mapped_groups": inv.missing_mapped_groups(),
        "users": inv.users.iter().map(|u| user_json(u, st)).collect::<Vec<_>>(),
        "groups": inv.groups.iter().map(|g| group_json(g, st)).collect::<Vec<_>>(),
        // La commande d'installation, pour un cluster qui n'a pas kdt-identity : c'est le geste
        // utile suivant, et le TUI l'offre au même endroit. L'adresse de l'apiserver est celle que
        // kdt-web vise ; le nom du cluster, que personne ici ne connaît, reste un exemple visible.
        "install_command": kdt::identity::install_command("", &state.kube.cluster_url.to_string()),
    }))
    .into_response()
}

/// Ce que le déploiement déclare de la délivrance, plus les deux questions qu'on lui pose.
///
/// `revocation_window` et `download_open` sont des règles de kdt, pas des champs : la première
/// choisit le TTL selon le mode, la seconde nomme le seul accès que ni `revoke` ni `spec.disabled`
/// n'atteignent. Les calculer ici évite que le navigateur les redevine.
fn delivery_json(d: &kdt::identity::Delivery) -> serde_json::Value {
    let mut value = serde_json::to_value(d).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("revocation_window".to_string(), d.revocation_window().into());
        object.insert("download_open".to_string(), d.download_open().into());
    }
    value
}

/// Ce que le déploiement déclare de la source d'identité, plus les trois questions qu'on lui pose.
///
/// Ce sont des règles de kdt, pas des champs. `federated` se lit sur `authMode`, jamais sur la
/// présence d'une URL — un déploiement repassé en `local` garde toute sa configuration dans son
/// env. `resync` choisit le délai selon la source, et **rend nul** là où rien n'est relu, ce qui
/// n'est pas un délai court. `mapping_setting` nomme la valeur du chart à corriger, qui n'est pas
/// la même d'une source à l'autre.
fn federation_json(f: &kdt::identity::Federation) -> serde_json::Value {
    let mut value = serde_json::to_value(f).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("federated".to_string(), f.federated().into());
        object.insert("resync".to_string(), f.resync().into());
        object.insert("mapping_setting".to_string(), f.mapping_setting().into());
    }
    value
}

/// Une ligne de comptes : le compte, ce que kdt en peint, et l'objet qu'elle désigne.
fn user_json(u: &IdentUser, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(u).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "user".into());
        object.insert("subject".to_string(), u.subject().into());
        object.insert("phase_label".to_string(), u.phase.label(st).into());
        object.insert("phase_tone".to_string(), tone_json(u.phase.tone()));
        object.insert(
            "invitation_label".to_string(),
            kdt::identity::invitation_label(&u.invitation, st).into(),
        );
        object.insert("invitation_tone".to_string(), tone_json(u.invitation_tone()));
        // `?` n'est pas `0` : un Secret de sessions illisible veut dire que kdt ne sait pas, et le
        // rendre par « personne n'est connecté » ferait paraître une révocation inutile.
        object.insert("sessions_cell".to_string(), u.sessions_cell().into());
        object.insert("sessions_tone".to_string(), tone_json(u.sessions_tone()));
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::identity::user_record(u, st))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

/// Une ligne de groupes. Le `subject` effectif est celui qu'un binding doit citer verbatim.
fn group_json(g: &IdentGroup, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(g).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "group".into());
        object.insert("subject".to_string(), g.effective_subject().into());
        object.insert("rights_tone".to_string(), tone_json(g.rights_tone()));
        object.insert(
            "bindings_labels".to_string(),
            serde_json::to_value(g.bindings.iter().map(|b| b.label()).collect::<Vec<_>>())
                .unwrap_or(serde_json::Value::Null),
        );
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::identity::group_record(g, st))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn tone_json(tone: kdt::events::LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

/// Ce que le navigateur demande d'écrire.
///
/// Une action nommée plutôt qu'un objet à patcher : l'appartenance passe **toujours** par un JSON
/// patch — un merge patch remplace le tableau `spec.members` entier, et c'est ainsi qu'on supprime
/// en silence les autres membres — et l'invitation n'est pas une écriture d'API du tout.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum WriteRequest {
    CreateUser {
        name: String,
        #[serde(default)]
        email: String,
        #[serde(default)]
        display_name: String,
    },
    CreateGroup {
        name: String,
        #[serde(default)]
        description: String,
    },
    SetDisabled {
        user: String,
        disabled: bool,
    },
    AddMember {
        group: String,
        user: String,
    },
    RemoveMember {
        group: String,
        user: String,
        /// L'index dans `spec.members`. Un index périmé ne retire pas le mauvais membre : le patch
        /// porte un `test` sur le nom, et l'apiserver refuse plutôt que d'obéir.
        index: usize,
    },
    Invite {
        user: String,
        #[serde(default)]
        validity: String,
    },
    Revoke {
        user: String,
    },
}

#[derive(Deserialize)]
pub struct WriteBody {
    #[serde(flatten)]
    request: WriteRequest,
    #[serde(default)]
    lang: String,
}

/// Applique une écriture sur l'annuaire, sous l'identité de la personne connectée.
pub async fn write(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<WriteBody>,
) -> Response {
    let Some(session) = auth::current(&state, &headers).await else {
        return unauthenticated();
    };
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&body.lang);

    // Les deux commandes qui tournent dans le pod ont besoin de ce pod. Il est résolu **ici**, par
    // les labels du chart : un nom de pod venu du navigateur ferait d'un `exec` une cible choisie
    // par l'appelant.
    let write = match body.request {
        WriteRequest::CreateUser { name, email, display_name } => {
            IdentityWrite::CreateUser { name, email, display_name }
        }
        WriteRequest::CreateGroup { name, description } => {
            IdentityWrite::CreateGroup { name, description }
        }
        WriteRequest::SetDisabled { user, disabled } => {
            IdentityWrite::SetDisabled { user, disabled }
        }
        WriteRequest::AddMember { group, user } => IdentityWrite::AddMember { group, user },
        WriteRequest::RemoveMember { group, user, index } => {
            IdentityWrite::RemoveMember { group, user, index }
        }
        WriteRequest::Invite { user, validity } => {
            let Some(controller) = kdt::identity::controller_ref(&client).await else {
                return refused(st.ident_invite_unavailable.to_string());
            };
            let validity = if validity.trim().is_empty() {
                kdt::identity::DEFAULT_VALIDITY.to_string()
            } else {
                validity
            };
            IdentityWrite::Invite { user, validity, controller: Box::new(controller) }
        }
        WriteRequest::Revoke { user } => {
            let Some(controller) = kdt::identity::controller_ref(&client).await else {
                return refused(st.ident_revoke_unavailable.to_string());
            };
            IdentityWrite::Revoke { user, controller: Box::new(controller) }
        }
    };

    info!(subject = %session.subject, cible = %write.target(), "écriture identity demandée");

    match kdt::identity::apply_identity_write(client, write).await {
        // Les trois issues d'une écriture ne sont pas interchangeables : une écriture d'API ne dit
        // rien, une invitation porte des valeurs qui n'existent qu'une fois, et une commande lancée
        // dans le pod a ses propres mots — combien de sessions fermées, et combien de temps
        // l'accès qu'elle n'a pas fermé vit encore.
        Ok(WriteOutcome::Done) => axum::Json(serde_json::json!({ "outcome": "done" })).into_response(),
        Ok(WriteOutcome::Invited(invite)) => axum::Json(serde_json::json!({
            "outcome": "invited",
            "invite": {
                "user": invite.user,
                "expires": invite.expires,
                // Le lien et le code n'existent que dans cette réponse : ils ne sont écrits ni dans
                // l'état, ni dans un log, ni sur disque — pas plus ici que dans le TUI.
                "link": invite.link,
                "code": invite.code,
                "raw": invite.raw,
            },
        }))
        .into_response(),
        Ok(WriteOutcome::Said(text)) => {
            axum::Json(serde_json::json!({ "outcome": "said", "message": text })).into_response()
        }
        Err(e) => refused(e),
    }
}

/// 409 et non 500 : la demande est arrivée, c'est l'objet, l'apiserver ou le déploiement qui la
/// repousse.
fn refused(e: String) -> Response {
    warn!(erreur = %e, "écriture identity refusée");
    (StatusCode::CONFLICT, axum::Json(serde_json::json!({ "error": e }))).into_response()
}

fn unauthenticated() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "aucune session", "reauthenticate": true })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdt::identity::{Invitation, Phase, SessionFacts};

    fn user() -> IdentUser {
        IdentUser {
            name: "alice".into(),
            email: "alice@example.com".into(),
            display_name: "Alice".into(),
            phase: Phase::Active,
            member_of: vec!["platform".into()],
            invitation: Invitation::None,
            sessions: Some(SessionFacts { open: 2, stale: 1, last_expiry: Some(1_800_000_000) }),
            age: "12d".into(),
            uid: "kdtuser|alice".into(),
            ..IdentUser::default()
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`. En renommer une côté serveur se
    // verrait ici plutôt qu'à l'écran, sous la forme d'une colonne vide.
    #[test]
    fn une_ligne_de_compte_porte_ce_que_le_navigateur_lit() {
        let v = user_json(&user(), lang_of("fr"));
        assert_eq!(v["row"], "user");
        assert_eq!(v["name"], "alice");
        assert_eq!(v["subject"], "kdt:alice");
        assert_eq!(v["phase_tone"], "ok");
        assert_eq!(v["sessions_cell"], "2");
        assert_eq!(v["sessions_tone"], "ok");
        assert_eq!(v["record"]["kind"], "KdtUser");
        assert_eq!(v["record"]["api_version"], "identity.kdt.sh/v1alpha1");
        // Le nom est cluster-scoped : le record ne vise aucun namespace, et les gestes génériques
        // doivent tomber sur l'objet et non à côté.
        assert_eq!(v["record"]["namespace"], "");
        assert_eq!(v["record"]["name"], "alice");
    }

    // La règle qui compte plus que toutes les autres sur cette vue : un Secret illisible n'est pas
    // un compte sans session. Les deux doivent se distinguer à l'écran.
    #[test]
    fn un_secret_de_sessions_illisible_ne_se_lit_pas_comme_zero() {
        let unknown = IdentUser { sessions: None, ..user() };
        let none = IdentUser {
            sessions: Some(SessionFacts::default()),
            ..user()
        };
        assert_eq!(user_json(&unknown, lang_of("fr"))["sessions_cell"], "?");
        assert_eq!(user_json(&none, lang_of("fr"))["sessions_cell"], "—");
        // Ni l'un ni l'autre ne se peint : seule une session ouverte est un fait à colorer.
        assert_eq!(user_json(&unknown, lang_of("fr"))["sessions_tone"], "dim");
        assert_eq!(user_json(&none, lang_of("fr"))["sessions_tone"], "dim");
    }

    // Un groupe que rien ne référence est le piège que la vue existe pour montrer : tout réconcilie,
    // et ses membres prennent 403 partout.
    #[test]
    fn un_groupe_sans_binding_est_signale() {
        let g = IdentGroup {
            name: "platform".into(),
            members: vec!["alice".into()],
            resolved: vec!["alice".into()],
            uid: "kdtgroup|platform".into(),
            ..IdentGroup::default()
        };
        let v = group_json(&g, lang_of("fr"));
        assert_eq!(v["row"], "group");
        assert_eq!(v["subject"], "kdt:platform");
        assert_eq!(v["rights_tone"], "warn");
        assert_eq!(v["record"]["reason"], "Unbound");
        assert!(v["bindings_labels"].as_array().unwrap().is_empty());
    }

    // Le second axe voyage entier : le front peint la colonne SOURCE, nomme la valeur épinglée et
    // dit ce qui alimente un group. Aucun de ces trois faits n'est sur l'objet que le navigateur
    // voit.
    #[test]
    fn le_second_axe_voyage_avec_la_regle_qui_le_lit() {
        use kdt::identity::{AuthMode, Federation, GroupMapping, LdapFacts, Source};

        let f = Federation {
            auth_mode: Some(AuthMode::Ldap),
            ldap: LdapFacts {
                url: Some("ldaps://dc01.example.com:636".into()),
                resync: Some("15m".into()),
                ..LdapFacts::default()
            },
            mappings: Some(vec![GroupMapping {
                key: "CN=K8s-Admins,OU=Groups,DC=example,DC=com".into(),
                group: "admins".into(),
            }]),
            ..Federation::default()
        };
        let v = federation_json(&f);
        assert_eq!(v["auth_mode"], "ldap");
        assert_eq!(v["federated"], true);
        assert_eq!(v["resync"], "15m");
        assert_eq!(v["mapping_setting"], "ldap.groupMappings");
        assert_eq!(v["mappings"][0]["group"], "admins");

        // Mode absent : ni `local`, ni `ldap`, ni `oidc`. C'est aussi ce à quoi ressemble un
        // déploiement antérieur à 1.2, et le front ne doit pas peindre un axe non déclaré.
        let silent = federation_json(&Federation::default());
        assert!(silent["auth_mode"].is_null());
        assert_eq!(silent["federated"], false);
        assert!(silent["mappings"].is_null());

        let u = user_json(
            &IdentUser {
                source: Source::Ldap,
                pin: "CN=Alice,DC=example,DC=com".into(),
                ..user()
            },
            lang_of("fr"),
        );
        assert_eq!(u["source"], "ldap");
        assert_eq!(u["pin"], "CN=Alice,DC=example,DC=com");

        let g = group_json(
            &IdentGroup {
                name: "admins".into(),
                source: Source::Ldap,
                source_keys: vec!["CN=K8s-Admins,OU=Groups,DC=example,DC=com".into()],
                ..IdentGroup::default()
            },
            lang_of("fr"),
        );
        assert_eq!(g["source"], "ldap");
        assert_eq!(g["source_keys"][0], "CN=K8s-Admins,OU=Groups,DC=example,DC=com");
    }

    // La seconde source, et la seule règle qui ne se lit pas comme celle de l'annuaire : sans accès
    // déclaré à l'API du fournisseur, il n'y a **aucune** relecture. Rendre un délai là serait en
    // inventer un, et le front peindrait une réconciliation qui n'existe pas.
    #[test]
    fn un_fournisseur_sans_api_declaree_ne_rend_aucun_delai_de_relecture() {
        use kdt::identity::{AuthMode, Federation, GraphFacts, GroupMapping, OidcFacts, Source};

        let provider = |graph: bool| Federation {
            auth_mode: Some(AuthMode::Oidc),
            oidc: OidcFacts {
                issuer: Some("https://login.microsoftonline.com/tenant/v2.0".into()),
                provider_name: Some("Entra ID".into()),
                subject_claim: Some("oid".into()),
                graph: graph.then(|| GraphFacts {
                    tenant_id: Some("tenant".into()),
                    resync: Some("15m".into()),
                    ..GraphFacts::default()
                }),
                ..OidcFacts::default()
            },
            mappings: Some(vec![GroupMapping {
                key: "8f4a1c2e-0b77-4e3b-9a21-2c5d8e7f0a11".into(),
                group: "admins".into(),
            }]),
            ..Federation::default()
        };

        let with = federation_json(&provider(true));
        assert_eq!(with["auth_mode"], "oidc");
        assert_eq!(with["federated"], true);
        assert_eq!(with["oidc"]["provider_name"], "Entra ID");
        assert_eq!(with["resync"], "15m");
        assert_eq!(with["mapping_setting"], "oidcAuth.groupMappings");

        let without = federation_json(&provider(false));
        assert!(without["oidc"]["graph"].is_null());
        assert!(without["resync"].is_null(), "aucune relecture n'est pas une relecture courte");

        // Le sujet épinglé voyage sous le même champ que le DN : c'est la même question — sur quoi
        // l'amont revérifie l'identité — et le front nomme la réponse selon la source.
        let u = user_json(
            &IdentUser { source: Source::Oidc, pin: "oid-1".into(), ..user() },
            lang_of("fr"),
        );
        assert_eq!(u["source"], "oidc");
        assert_eq!(u["pin"], "oid-1");
    }

    // Le mode absent n'est pas `certificate` : l'amont y défaute, mais l'absence décrit aussi un
    // déploiement 0.1 qui ne révoque rien, et les deux ne se lisent pas pareil.
    #[test]
    fn sans_mode_declare_aucune_fenetre_de_revocation_nest_affirmee() {
        let d = kdt::identity::Delivery { cert_ttl: Some("10m".into()), ..Default::default() };
        let v = delivery_json(&d);
        assert!(v["mode"].is_null());
        assert!(v["revocation_window"].is_null());
        assert_eq!(v["download_open"], false);
    }
}
