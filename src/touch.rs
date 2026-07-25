//! One-key "touch": stamp the selected object with a fresh timestamp annotation.
//!
//! What matters is not the annotation but the write it causes. Admission webhooks — Kyverno and the
//! like — only run on a CREATE or an UPDATE, so re-evaluating a policy against an object nobody has
//! changed means changing something harmless about it. Two annotations under `kdt.io/` are exactly
//! that: no controller reads them, and they leave a trace of who asked and when.
//!
//! Unlike [`crate::edit`] and [`crate::delete`], this one fires straight away, with no panel and no
//! confirmation — a touch adds two metadata keys and takes nothing away, and the point of the key is
//! to be quick enough to walk a list of objects with it. The outcome lands in the footer toast.

use kube::api::{Patch, PatchParams};
use kube::Client;
use serde_json::{json, Value};

use crate::edit::api_error_text;
use crate::flux::SharedReconcile;
use crate::lang::Strings;
use crate::yaml::dynamic_api;

/// When the object was last touched, RFC 3339.
pub const TOUCHED_AT: &str = "kdt.io/touched-at";
/// Who asked for it, best effort.
pub const TOUCHED_BY: &str = "kdt.io/touched-by";

// An API error message can be a whole validation report; the toast is one footer line.
const MAX_ERROR: usize = 160;

// Milliseconds, not seconds. A merge patch that changes nothing is answered by the API server
// without bumping `resourceVersion` — and therefore without calling a single webhook. Two touches
// inside the same second would carry the same timestamp, and the second one would do exactly the
// nothing this feature exists to avoid.
pub fn stamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// Who is touching, best effort: the local account is what makes the annotation traceable back to a
// person. The Kubernetes identity would be more accurate, but a kubeconfig does not always know it
// (client certs, exec plugins, bare tokens), and a wrong name is worse than a shell one.
pub fn author() -> String {
    ["USER", "LOGNAME"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "kdt".to_string())
}

// A JSON merge patch on the annotations map: these two keys are added or replaced and every other
// one is left alone. No read-modify-write either, so there is nothing to lose to a concurrent edit.
pub fn patch_body(at: &str, by: &str) -> Value {
    json!({ "metadata": { "annotations": { TOUCHED_AT: at, TOUCHED_BY: by } } })
}

/// How the object is named in the toast, before and after the patch.
pub fn label(kind: &str, namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        format!("{} {}", kind, name)
    } else {
        format!("{} {}/{}", kind, namespace, name)
    }
}

/// Patch the object and publish the outcome for the footer toast.
pub async fn run_touch(
    client: Client,
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
    st: &'static Strings,
    status: SharedReconcile,
) {
    let at = stamp();
    let target = label(&kind, &namespace, &name);
    // The timestamp is not echoed: the toast shares its row with the shortcut bar, and `y` shows the
    // annotation that was actually written.
    let msg = match patch(&client, &api_version, &kind, &namespace, &name, &at).await {
        Ok(()) => st.touch_ok.replace("{d}", &target),
        Err(e) => st.touch_failed.replace("{d}", &target).replace("{e}", &clip(&e)),
    };
    if let Ok(mut s) = status.lock() {
        *s = Some((std::time::Instant::now(), msg));
    }
}

async fn patch(
    client: &Client,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    at: &str,
) -> Result<(), String> {
    let api = dynamic_api(client, api_version, kind, namespace).await?;
    let body = patch_body(at, &author());
    api.patch(name, &PatchParams::default(), &Patch::Merge(&body))
        .await
        .map(|_| ())
        .map_err(api_error_text)
}

// Keep the first line and cut it: the toast shares its row with the shortcuts, and a refusal that
// runs past the terminal width would push them off screen for nothing.
fn clip(text: &str) -> String {
    let line = text.lines().next().unwrap_or_default().trim();
    match line.char_indices().nth(MAX_ERROR) {
        Some((idx, _)) => format!("{}…", &line[..idx]),
        None => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stamp_carries_milliseconds_so_two_touches_never_collide_silently() {
        let s = stamp();
        assert!(s.ends_with('Z'), "{s}");
        let (_, frac) = s.rsplit_once('.').expect("pas de fraction de seconde");
        assert_eq!(frac.len(), 4, "attendu 3 chiffres + Z, obtenu {frac}");
        assert!(frac.trim_end_matches('Z').chars().all(|c| c.is_ascii_digit()), "{s}");
    }

    #[test]
    fn the_patch_only_ever_touches_two_annotations() {
        let body = patch_body("2026-07-25T18:19:13.875Z", "someone");
        assert_eq!(
            body,
            json!({"metadata": {"annotations": {
                "kdt.io/touched-at": "2026-07-25T18:19:13.875Z",
                "kdt.io/touched-by": "someone",
            }}})
        );
        // A merge patch names nothing else: no other annotation, label or field can be lost.
        let meta = body.get("metadata").and_then(Value::as_object).expect("metadata");
        assert_eq!(meta.len(), 1);
        assert_eq!(meta["annotations"].as_object().expect("annotations").len(), 2);
    }

    #[test]
    fn the_author_falls_back_to_kdt_when_the_environment_says_nothing() {
        std::env::set_var("USER", "alice");
        assert_eq!(author(), "alice");

        std::env::set_var("USER", "   ");
        std::env::remove_var("LOGNAME");
        assert_eq!(author(), "kdt");
        std::env::remove_var("USER");
    }

    #[test]
    fn a_refusal_is_cut_down_to_a_single_footer_line() {
        assert_eq!(clip("admission webhook denied\nstack trace"), "admission webhook denied");
        let long = "x".repeat(MAX_ERROR + 50);
        let cut = clip(&long);
        assert_eq!(cut.chars().count(), MAX_ERROR + 1);
        assert!(cut.ends_with('…'));
    }
}
