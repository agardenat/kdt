//! La vue Rancher : le couple *(identité Rancher `u-…`, identité réelle)*, sans ouvrir Rancher.
//!
//! Quatre mondes, comme dans le TUI, et ils n'ont rien en commun au-delà du cadre : les comptes,
//! les accès (les trois kinds de binding ramenés à la même question), les projects, et les tokens
//! précédés des réglages de TTL qui les gouvernent.
//!
//! # Ce qui est calculé ici, et ce qui ne l'est pas
//!
//! Rien de ce qui juge le cluster. La résolution d'un principal opaque, le rôle posé
//! automatiquement sur tout compte, le ton d'un provider `local`, le token sans expiration, la
//! portée d'un token vide qui vaut sur tous les clusters : tout vient de `kdt::rancher`. Ce module
//! joint la lecture et la rend.
//!
//! # Le cas downstream, qui décide de tout le reste
//!
//! Zéro `User` sur un cluster qui sert les CRD n'est **pas** un annuaire vide : les identités sont
//! en amont, et la vue bascule sur le RBAC projeté par l'agent. Une liste **refusée** ressemble
//! exactement à ça vue d'ici, et c'est pourquoi l'erreur est conservée et dite plutôt que lue comme
//! une absence. Conséquence pour les écritures : elles sont refusées sur un downstream — les objets
//! y sont des répliques.
//!
//! # Le secret d'un token émis n'existe qu'une fois
//!
//! `IssuedToken` porte le credential complet, et cette réponse est le seul endroit où il passe : il
//! n'est écrit ni dans l'état, ni dans un log, ni sur disque. Il n'est même pas promis utilisable
//! quand `token-hashing` est actif — Rancher n'en stocke alors qu'un condensé — et c'est dit
//! **avant** l'écriture, pas après.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kdt::rancher::{
    ClusterRole, RancherBinding, RancherProject, RancherToken, RancherUser, RancherWrite,
    TokenSetting,
};
use serde::Deserialize;
use tracing::{info, warn};

use crate::api::session_client;
use crate::lang::lang_of;
use crate::{auth, AppState};

#[derive(Deserialize)]
pub struct RancherQuery {
    #[serde(default)]
    lang: String,
}

/// Les quatre mondes de la vue, en une lecture.
///
/// Une seule requête et non quatre : les quatre listes viennent du même passage de découverte, et
/// les rejouer par monde ferait payer quatre fois la même chose — la résolution d'un GUID en nom
/// passe par **tous** les UserAttributes, y compris quand on ne regarde que les tokens.
///
/// Sans portée de namespace : la vue lit un annuaire, pas des objets d'un namespace, et les rares
/// kinds namespacés (Project, CRTB, PRTB) vivent dans le namespace de leur cluster ou de leur
/// projet — filtrer dessus n'aurait aucun sens pour qui regarde qui a accès à quoi.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RancherQuery>,
) -> Response {
    let client = match session_client(&state, &headers).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let st = lang_of(&query.lang);

    let inv = kdt::rancher::rancher_inventory(&client, st).await;

    axum::Json(serde_json::json!({
        "server": server_json(&inv.server, st),
        "error": inv.error,
        "token_hashing": inv.token_hashing,
        "orphan_namespaces": inv.orphan_namespaces,
        // Les écritures n'existent que sur le cluster local. Le dire dans la charge utile plutôt
        // que de laisser le navigateur le déduire du rôle : c'est la même règle que le TUI applique
        // avant d'ouvrir son menu.
        "writable": inv.server.role == ClusterRole::Local,
        "counts": {
            "users": inv.users.len(),
            "external": inv.external_users(),
            "admins": inv.admins(),
            "bindings": inv.bindings.len(),
            "projects": inv.projects.len(),
            "project_namespaces": inv.projects.iter().map(|p| p.namespaces.len()).sum::<usize>(),
            "orphan_namespaces": inv.orphan_namespaces,
            "tokens": inv.tokens.len(),
            "expired_tokens": inv.tokens.iter().filter(|t| t.expired).count(),
        },
        "users": inv.users.iter().map(|u| user_json(u, st)).collect::<Vec<_>>(),
        "bindings": inv.bindings.iter().map(|b| binding_json(b, st)).collect::<Vec<_>>(),
        "projects": inv.projects.iter().map(|p| project_json(p, st)).collect::<Vec<_>>(),
        // Les réglages **avant** les tokens, comme dans le TUI : ils sont la raison pour laquelle la
        // colonne TTL se lit comme elle se lit, et sur un cluster dont le défaut kubeconfig vaut 0
        // c'est le titre, pas une note de bas de page.
        "settings": inv.settings.iter().map(|s| setting_json(s, st)).collect::<Vec<_>>(),
        "tokens": inv.tokens.iter().map(|t| token_json(t, st)).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// L'installation elle-même : ce que ce cluster est pour Rancher, et qui peut s'y connecter.
///
/// C'est la réponse à la question que pose une liste de comptes vide — « les comptes sont ailleurs »
/// plutôt que « il n'y en a pas ».
fn server_json(s: &kdt::rancher::RancherServer, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "role_label".to_string(),
            match s.role {
                ClusterRole::Local => {
                    kdt::lang::fill(st.ranch_role_local, &[("version", &s.version)])
                }
                ClusterRole::Downstream => {
                    let target = if s.url.is_empty() { &s.cluster_id } else { &s.url };
                    kdt::lang::fill(st.ranch_role_downstream, &[("url", target)])
                }
                ClusterRole::Absent => st.ranch_absent.to_string(),
            }
            .into(),
        );
    }
    value
}

fn user_json(u: &RancherUser, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(u).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "user".into());
        // Un compte que ce cluster ne sait pas résoudre reçoit un tiret, pas son propre id répété :
        // la raison appartient au panneau de détail.
        object.insert("identity_cell".to_string(), u.identity_cell().into());
        object.insert("label".to_string(), kdt::rancher::user_label(u).into());
        object.insert("provider_tone".to_string(), tone_json(kdt::rancher::provider_tone(&u.provider)));
        object.insert("state_label".to_string(), u.state_label(st).into());
        object.insert("state_tone".to_string(), tone_json(u.state_tone()));
        object.insert("refresh_label".to_string(), kdt::rancher::format_refresh(&u.last_refresh).into());
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::rancher::user_record(u, st)).unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn binding_json(b: &RancherBinding, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(b).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "binding".into());
        object.insert(
            "scope_kind".to_string(),
            match b.scope {
                Some(s) => s.label().into(),
                None => "—".into(),
            },
        );
        object.insert("subject_kind_label".to_string(), b.subject_kind_label().into());
        object.insert("provider_tone".to_string(), tone_json(kdt::rancher::provider_tone(&b.provider)));
        object.insert("role_tone".to_string(), tone_json(b.role_tone()));
        // Les constats de la ligne, plus celui qu'elle porte elle-même : une ligne reconstruite
        // depuis le RBAC projeté d'un downstream le déclare.
        object.insert(
            "hints".to_string(),
            serde_json::to_value(b.display_hints(st)).unwrap_or(serde_json::Value::Null),
        );
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::rancher::binding_record(b, st))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn project_json(p: &RancherProject, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(p).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "project".into());
        // Une ligne reconstruite depuis les annotations d'un downstream ne désigne aucun objet local :
        // son enregistrement ne porte pas de kind, et les gestes génériques répondent « aucun objet »
        // plutôt que d'envoyer une requête vers ce que ce cluster n'a pas.
        object.insert("local_object".to_string(), (!p.namespace.is_empty()).into());
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::rancher::project_record(p, st))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn setting_json(s: &TokenSetting, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(s).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "setting".into());
        object.insert("value_text".to_string(), s.value_text(st).into());
        object.insert("value_tone".to_string(), tone_json(s.value_tone()));
        object.insert("default_text".to_string(), s.default_text(st).into());
        object.insert("minutes".to_string(), s.minutes().into());
        object.insert(
            "source_label".to_string(),
            if s.is_default { st.ranch_setting_default } else { st.ranch_setting_set }.into(),
        );
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::rancher::setting_record(s, st))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn token_json(t: &RancherToken, st: &'static kdt::lang::Strings) -> serde_json::Value {
    let mut value = serde_json::to_value(t).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("row".to_string(), "token".into());
        object.insert("owner_label".to_string(), t.owner_label().into());
        object.insert("provider_tone".to_string(), tone_json(kdt::rancher::provider_tone(&t.provider)));
        object.insert("ttl_label".to_string(), kdt::rancher::format_ttl(t.ttl_ms, st).into());
        object.insert("ttl_tone".to_string(), tone_json(t.ttl_tone()));
        object.insert("scope_label".to_string(), t.scope_label(st).into());
        object.insert("scope_tone".to_string(), tone_json(t.scope_tone()));
        object.insert("state_label".to_string(), t.state_label(st).into());
        object.insert("state_tone".to_string(), tone_json(t.state_tone()));
        object.insert(
            "record".to_string(),
            serde_json::to_value(kdt::rancher::token_record(t, st))
                .unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

fn tone_json(tone: kdt::events::LineColor) -> serde_json::Value {
    serde_json::to_value(tone).unwrap_or(serde_json::Value::Null)
}

/// Les quatre écritures. Tout le reste d'une identité — créer un compte, accorder un rôle — reste
/// dans Rancher, là où vivent la piste d'audit et l'approbation.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum WriteRequest {
    /// Émettre un token pour un compte. Le secret est rendu une fois et n'est stocké nulle part.
    IssueToken { user_id: String, ttl_minutes: i64 },
    SetTokenTtl { name: String, ttl_minutes: i64 },
    /// Supprimer l'objet Token — la seule vraie révocation.
    RevokeToken { name: String },
    SetSetting { name: String, value: String },
}

#[derive(Deserialize)]
pub struct WriteBody {
    #[serde(flatten)]
    request: WriteRequest,
    #[serde(default)]
    lang: String,
}

/// Applique une écriture, sous l'identité de la personne connectée.
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

    // La phrase de succès est celle de kdt, choisie avec l'action : le TUI et le web disent la
    // même chose de la même écriture.
    let (write, ok) = match body.request {
        // Le compte est **relu** ici et non repris du navigateur : le token porte le
        // `userPrincipal` reconstruit depuis le principal réel, et un principal fourni par
        // l'appelant ferait émettre un credential au nom de quelqu'un d'autre. La relecture donne
        // au passage le rôle du cluster, qui décide si l'écriture est possible du tout.
        WriteRequest::IssueToken { user_id, ttl_minutes } => {
            let inv = kdt::rancher::rancher_inventory(&client, st).await;
            if inv.server.role != ClusterRole::Local {
                return refused(st.ranch_write_downstream.to_string());
            }
            let Some(user) = inv.users.iter().find(|u| u.id == user_id).cloned() else {
                return refused(st.ranch_issue_no_user.to_string());
            };
            (
                RancherWrite::IssueToken { user: Box::new(user), ttl_minutes },
                st.msg_ranch_issued,
            )
        }
        WriteRequest::SetTokenTtl { name, ttl_minutes } => (
            RancherWrite::SetTokenTtl { name, ttl_minutes },
            st.msg_ranch_ttl_set,
        ),
        WriteRequest::RevokeToken { name } => {
            (RancherWrite::RevokeToken { name }, st.msg_ranch_revoked)
        }
        WriteRequest::SetSetting { name, value } => (
            RancherWrite::SetSetting { name, value },
            st.msg_ranch_setting_set,
        ),
    };
    let done = ok.replace("{name}", &write.target());

    info!(subject = %session.subject, cible = %write.target(), "écriture rancher demandée");

    match kdt::rancher::apply_rancher_write(client, write).await {
        Ok(Some(issued)) => axum::Json(serde_json::json!({
            "message": done,
            // Le credential complet, dans la seule forme qu'un client accepte. Il n'existe que dans
            // cette réponse — le navigateur le montre une fois puis le jette, comme l'overlay du TUI.
            "token": {
                "name": issued.name,
                "bearer": issued.bearer(),
                "user_id": issued.user_id,
                "user_label": issued.user_label,
                "ttl_minutes": issued.ttl_minutes,
            },
        }))
        .into_response(),
        Ok(None) => axum::Json(serde_json::json!({ "message": done })).into_response(),
        Err(e) => refused(e),
    }
}

/// 409 et non 500 : la demande est arrivée, c'est l'objet ou le cluster qui la repousse.
fn refused(e: String) -> Response {
    warn!(erreur = %e, "écriture rancher refusée");
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
    use kdt::rancher::{BindScope, PrincipalKind, SettingUnit};

    fn user() -> RancherUser {
        RancherUser {
            id: "u-4oivhvq2jk".into(),
            username: "jdoe".into(),
            display_name: "Jane Doe".into(),
            provider: "activedirectory".into(),
            principal: "activedirectory_user://CN=Jane Doe,OU=People,DC=example".into(),
            identity: "Jane Doe".into(),
            global_roles: vec!["user".into()],
            groups: vec!["platform".into()],
            binding_count: 3,
            token_count: 7,
            age: "412d".into(),
            uid: "ranch|user|u-4oivhvq2jk".into(),
            ..RancherUser::default()
        }
    }

    // Le front lit ces clés-là, nommément, dans `web/src/types.ts`.
    #[test]
    fn une_ligne_de_compte_porte_ce_que_le_navigateur_lit() {
        let v = user_json(&user(), lang_of("fr"));
        assert_eq!(v["row"], "user");
        assert_eq!(v["id"], "u-4oivhvq2jk");
        assert_eq!(v["identity_cell"], "Jane Doe");
        assert_eq!(v["label"], "Jane Doe");
        // Un provider d'annuaire n'est pas un compte local : c'est ce dernier qui se signale.
        assert_eq!(v["provider_tone"], "info");
        assert_eq!(v["state_tone"], "dim");
        assert_eq!(v["record"]["kind"], "User");
        // Le principal brut part dans le message, pour qu'un GUID copié d'un log retrouve le compte.
        assert!(v["record"]["message"].as_str().unwrap().contains("CN=Jane Doe"));
    }

    // Un compte local est le seul credential qu'aucun départ de l'annuaire ne révoque : il se lit
    // différemment d'un compte adossé à un annuaire, d'un coup d'œil.
    #[test]
    fn un_compte_local_se_signale() {
        let v = user_json(&RancherUser { provider: "local".into(), ..user() }, lang_of("fr"));
        assert_eq!(v["provider_tone"], "warn");
        // Et un compte que rien ne résout reçoit un tiret, pas son id répété.
        let opaque = user_json(
            &RancherUser { identity: String::new(), ..user() },
            lang_of("fr"),
        );
        assert_eq!(opaque["identity_cell"], "—");
    }

    // Un token sans portée vaut sur tous les clusters gérés *et* sur l'API Rancher ; un token sans
    // expiration ne s'éteint jamais. Ce sont les deux faits que la vue existe pour montrer.
    #[test]
    fn un_token_eternel_et_sans_portee_se_signale_deux_fois() {
        let t = RancherToken {
            name: "kubeconfig-u-abc".into(),
            user_id: "u-abc".into(),
            provider: "local".into(),
            kind: "kubeconfig".into(),
            kind_label: "kubeconfig".into(),
            ttl_ms: 0,
            age: "88d".into(),
            uid: "ranch|token|kubeconfig-u-abc".into(),
            ..RancherToken::default()
        };
        let v = token_json(&t, lang_of("fr"));
        assert_eq!(v["ttl_tone"], "warn");
        assert_eq!(v["scope_tone"], "warn");
        // Sans étiquette de compte lisible, la ligne montre l'id plutôt que rien.
        assert_eq!(v["owner_label"], "u-abc");
        assert_eq!(v["record"]["kind"], "Token");
    }

    // `0` minute veut dire « jamais d'expiration », et c'est la seule valeur d'un réglage qui mérite
    // d'être peinte : c'est elle qui explique une colonne entière de tokens éternels.
    #[test]
    fn un_reglage_a_zero_minute_est_le_seul_a_se_peindre() {
        let s = TokenSetting {
            name: "kubeconfig-default-token-ttl-minutes".into(),
            effective: "0".into(),
            default: "0".into(),
            is_default: true,
            unit: Some(SettingUnit::Minutes),
            uid: "ranch|setting|kubeconfig-default-token-ttl-minutes".into(),
            ..TokenSetting::default()
        };
        let v = setting_json(&s, lang_of("fr"));
        assert_eq!(v["row"], "setting");
        assert_eq!(v["value_tone"], "warn");
        assert_eq!(v["minutes"], 0);
        assert_eq!(v["record"]["kind"], "Setting");
    }

    // Une ligne de project reconstruite depuis les annotations d'un downstream ne désigne aucun
    // objet de ce cluster : les gestes génériques doivent le savoir avant d'envoyer une requête.
    #[test]
    fn seul_un_project_local_designe_un_objet() {
        let base = RancherProject {
            id: "local:p-dfg12".into(),
            display_name: "datasmart".into(),
            cluster: "local".into(),
            namespaces: vec!["blanche-prd".into()],
            members: 3,
            namespace: "c-m-abc".into(),
            name: "p-dfg12".into(),
            uid: "ranch|project|local:p-dfg12".into(),
            ..RancherProject::default()
        };
        let local = project_json(&base, lang_of("fr"));
        assert_eq!(local["local_object"], true);
        assert_eq!(local["record"]["kind"], "Project");

        let upstream = project_json(
            &RancherProject { namespace: String::new(), ..base },
            lang_of("fr"),
        );
        assert_eq!(upstream["local_object"], false);
        assert_eq!(upstream["record"]["kind"], "");
    }

    // Le monde des accès ramène trois kinds de binding à la même question. Le type du sujet est
    // nommé plutôt que déduit d'un champ vide : « aucun principal » n'est pas « local ».
    #[test]
    fn un_binding_sans_principal_ne_ment_pas_sur_son_sujet() {
        let b = RancherBinding {
            scope: Some(BindScope::Global),
            subject_kind: None,
            subject_label: "u-abc".into(),
            role: "user".into(),
            role_label: "Standard User".into(),
            kind: "GlobalRoleBinding".into(),
            api_version: kdt::rancher::API_MGMT.into(),
            name: "grb-xyz".into(),
            uid: "ranch|binding|grb-xyz".into(),
            ..RancherBinding::default()
        };
        let v = binding_json(&b, lang_of("fr"));
        assert_eq!(v["scope_kind"], "global");
        assert_eq!(v["subject_kind_label"], "—");
        assert_eq!(v["role_tone"], "dim");

        let owner = binding_json(
            &RancherBinding {
                owner_role: true,
                subject_kind: Some(PrincipalKind::Group),
                ..b
            },
            lang_of("fr"),
        );
        assert_eq!(owner["subject_kind_label"], "group");
        assert_eq!(owner["role_tone"], "warn");
    }
}
