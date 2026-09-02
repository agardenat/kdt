//! `nodetool`, run as a Job that outlives the session.
//!
//! [`crate::mgmtapi`] reads a Cassandra node over the management API, and that covers what the
//! `:k8ssandra` view *shows* — the ring, the thread pools, the snapshots. It does not cover what an
//! operator needs to *run*: `garbagecollect -g ROW -j 1 <keyspace> <table>` has no endpoint, and the
//! endpoints that do exist stop at the handful of operations cass-operator drives itself.
//!
//! Three ways to run the real thing, two of them wrong:
//!
//! * `kubectl exec nodetool` inside the pod. JMX is behind SSL with client auth on a k8ssandra
//!   cluster (`-Dcom.sun.management.jmxremote.ssl=true`), so a bare `nodetool` in the container
//!   fails with `non-JRMP server at remote endpoint`; and an exec dies with the session that opened
//!   it, which is exactly what a six-hour `garbagecollect` must not do.
//! * a `CassandraTask`, which cass-operator runs for us — but its `jobs[].command` is a closed set
//!   of operations against the *whole datacenter*, with no room for a flag or a table name.
//! * a Job of our own, running the `nodetool` that ships in the cassandra container's own image and
//!   talking JMX to one named pod. It is scheduled by Kubernetes, so it survives kdt being closed,
//!   the laptop sleeping, and the network going away; its output is the pod's log, which is still
//!   there tomorrow.
//!
//! The third is what this module builds. Everything the Job needs is *read*, never guessed: the
//! image comes from the pod's own `cassandra` container, the host from the pod's `hostname` and
//! `subdomain` (cass-operator gives every Cassandra pod both, through the all-pods Service), and
//! whether JMX wants `--ssl` and credentials — plus the keystores that go with them — from the
//! `CassandraDatacenter`'s `additional-jvm-opts`, which is the same list the server itself was
//! started with. What cannot be read is reported as a warning next to the Job, not filled in with a
//! plausible default: a Job that fails with a legible log beats a Job that connects to the wrong
//! thing.
//!
//! Two deliberate restrictions. The command runs as `command: ["nodetool"]` with the words the user
//! typed as `args`, never through a shell: there is no line for a `;` to split, so a typed command
//! can only ever be a bad `nodetool` invocation. And the JMX password is passed with the `$(VAR)`
//! form Kubernetes expands from a `secretKeyRef`, so the superuser secret is never copied into the
//! Job. The *keystore* password is a different matter — it exists only as plain text inside
//! `additional-jvm-opts`, so reaching it means copying it there; the confirmation says so.

use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{Pod, Secret};
use kube::api::{Api, DynamicObject, ListParams, PostParams};
use kube::Client;
use serde_json::{json, Value};

use crate::k8ssandra::{K8cPanel, PanelKind, SharedK8cPanel};
use crate::lang::{self, Strings};
use crate::storage::{Hint, HintLevel};

/// Label every Job this module creates carries, and the selector the view lists them back with.
pub const LABEL: &str = "kdt.io/nodetool";
/// The command as it was typed, kept on the object so the row can name itself after a restart of
/// kdt. Reading it back off `args` would show the `-h`/`-u`/`--ssl` plumbing the user never typed.
pub const ANN_COMMAND: &str = "kdt.io/nodetool-command";
/// The pod the command was aimed at. Same reason: the Job runs anywhere, the answer is about a node.
pub const ANN_TARGET: &str = "kdt.io/nodetool-target";
/// The full command line as it was resolved — host, `--ssl`, credentials masked. Read back weeks
/// later it answers the question the typed command cannot: *how* did this reach the node.
pub const ANN_LINE: &str = "kdt.io/nodetool-line";

// The command is run once, and a failed `nodetool` is not retried: a blind rerun of a half-finished
// compaction or repair collides with the work still going on server-side.
const BACKOFF_LIMIT: i32 = 0;
// A day is long enough to read the output the morning after, short enough that a namespace does not
// silently accumulate a year of one-off Jobs. It is also what cass-operator defaults its own tasks
// to.
const TTL_SECONDS: i32 = 86_400;

const CASSANDRA_CONTAINER: &str = "cassandra";
const JMX_SSL_OPT: &str = "com.sun.management.jmxremote.ssl";
const JMX_AUTH_OPT: &str = "com.sun.management.jmxremote.authenticate";

// --- Plan -----------------------------------------------------------------------------------------

/// Everything the Job is built from, resolved against the cluster. Built by [`plan`], which is pure,
/// so the whole shape of the Job can be asserted in a test rather than tried against a cluster.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    pub namespace: String,
    /// The pod `nodetool -h` will address.
    pub pod: String,
    pub datacenter: String,
    /// Its stable DNS name, or its address when the pod carries no subdomain.
    pub host: String,
    pub image: String,
    /// The words the user typed, split on whitespace and never re-joined into a shell line.
    pub command: Vec<String>,
    /// The full argument vector, credentials included as `$(VAR)` references.
    pub args: Vec<String>,
    /// Empty when JMX asks for no credentials.
    pub superuser_secret: String,
    pub jvm_opts: Vec<String>,
    pub mounts: Vec<Value>,
    pub volumes: Vec<Value>,
    pub security_context: Value,
    /// What could not be read, in the user's language. Never fatal: they are shown next to the Job
    /// and the Job still runs, because a warning here is a guess this module refused to make.
    pub warnings: Vec<String>,
}

impl Plan {
    /// The line the confirmation shows: what will actually run, with the credentials left as the
    /// references they are. `-pw` is never printed with a value because it never has one here.
    pub fn display(&self) -> String {
        let mut out = String::from("nodetool");
        for a in &self.args {
            out.push(' ');
            out.push_str(match a.as_str() {
                "$(CASS_USER)" => "***",
                "$(CASS_PASS)" => "***",
                other => other,
            });
        }
        out
    }
}

/// Split a typed command into an argument vector. Whitespace only: there is no shell here, so there
/// is nothing for quotes to protect, and pretending to honour them would be a lie about how the
/// words reach `nodetool`.
pub fn split_command(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_string).collect()
}

/// Build the plan from the pod and the datacenter that owns it. `dc` is the `CassandraDatacenter`
/// object, read for its `additional-jvm-opts`: how the server was started is the only honest source
/// for how a client must connect to it.
pub fn plan(
    pod: &Pod,
    dc: &DynamicObject,
    command: &[String],
    st: &'static Strings,
) -> Result<Plan, String> {
    let namespace = pod.metadata.namespace.clone().unwrap_or_default();
    let pod_name = pod.metadata.name.clone().unwrap_or_default();
    let spec = pod.spec.as_ref().ok_or_else(|| st.nt_no_container.to_string())?;
    let container = spec
        .containers
        .iter()
        .find(|c| c.name == CASSANDRA_CONTAINER)
        .ok_or_else(|| st.nt_no_container.to_string())?;
    let image = container.image.clone().unwrap_or_default();
    if image.is_empty() {
        return Err(st.nt_no_image.to_string());
    }

    // `<hostname>.<subdomain>` is the per-pod DNS name the headless Service publishes, and it is
    // what survives the pod being recreated on another node. The pod address is the fallback, not
    // the default: it changes under the Job's feet the moment the pod restarts.
    let hostname = spec.hostname.clone().unwrap_or_default();
    let subdomain = spec.subdomain.clone().unwrap_or_default();
    let host = if !hostname.is_empty() && !subdomain.is_empty() {
        format!("{hostname}.{subdomain}.{namespace}.svc.cluster.local")
    } else {
        pod.status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .unwrap_or_default()
    };
    if host.is_empty() {
        return Err(st.nt_no_host.to_string());
    }

    let mut warnings: Vec<String> = Vec::new();

    // `LOCAL_JMX=no` is what opens JMX beyond the loopback. Anything else and a client in another
    // pod may find nothing listening — may, because the image is free to arrange it otherwise, so
    // this is said out loud and not turned into a refusal.
    let local_jmx = container
        .env
        .as_ref()
        .and_then(|env| env.iter().find(|e| e.name == "LOCAL_JMX"))
        .and_then(|e| e.value.clone())
        .unwrap_or_default();
    if local_jmx != "no" {
        warnings.push(st.nt_warn_local_jmx.to_string());
    }

    let opts = jvm_opts(dc);
    let ssl = opt_value(&opts, JMX_SSL_OPT).as_deref() == Some("true");
    let auth = opt_value(&opts, JMX_AUTH_OPT).as_deref() == Some("true");

    let mut jvm: Vec<String> = Vec::new();
    let mut mounts: Vec<Value> = Vec::new();
    let mut volumes: Vec<Value> = Vec::new();
    if ssl {
        // The management API image reads `JVM_OPTS` and hands it to the JVM `nodetool` runs in;
        // `ssl.enable` is what its own wrapper looks for.
        jvm.push("-Dssl.enable=true".to_string());
        for (path_opt, pass_opt) in [
            ("javax.net.ssl.keyStore", "javax.net.ssl.keyStorePassword"),
            ("javax.net.ssl.trustStore", "javax.net.ssl.trustStorePassword"),
        ] {
            let Some(path) = opt_value(&opts, path_opt) else { continue };
            jvm.push(format!("-D{path_opt}={path}"));
            if let Some(pass) = opt_value(&opts, pass_opt) {
                jvm.push(format!("-D{pass_opt}={pass}"));
            }
            // The store lives in a volume the cassandra container mounts. Carrying the same volume
            // over is the only way to hand the Job the same file — copying the secret would be a
            // second copy of a private key with a life of its own.
            match store_volume(pod, container, &path) {
                Some((mount, volume)) => {
                    if !mounts.iter().any(|m| m["name"] == mount["name"]) {
                        mounts.push(mount);
                        volumes.push(volume);
                    }
                }
                None => warnings.push(lang::fill(st.nt_warn_store, &[("path", &path)])),
            }
        }
    }

    let mut args: Vec<String> = vec!["-h".to_string(), host.clone()];
    let mut superuser_secret = String::new();
    if auth {
        superuser_secret = str_at(dc, &["spec", "superuserSecretName"]);
        if !superuser_secret.is_empty() {
            args.push("-u".to_string());
            args.push("$(CASS_USER)".to_string());
            args.push("-pw".to_string());
            args.push("$(CASS_PASS)".to_string());
        } else {
            warnings.push(st.nt_warn_no_superuser.to_string());
        }
    }
    if ssl {
        args.push("--ssl".to_string());
    }
    args.extend(command.iter().cloned());

    Ok(Plan {
        namespace,
        pod: pod_name,
        datacenter: str_at(dc, &["metadata", "name"]),
        host,
        image,
        command: command.to_vec(),
        args,
        superuser_secret,
        jvm_opts: jvm,
        mounts,
        volumes,
        // The pod's own file ownership: the keystores are mounted with the same group, and the
        // image expects to be the same user it runs as in the datacenter.
        security_context: pod
            .spec
            .as_ref()
            .and_then(|s| s.security_context.as_ref())
            .and_then(|sc| serde_json::to_value(sc).ok())
            .unwrap_or_else(|| json!({})),
        warnings,
    })
}

/// `spec.config.cassandra-env-sh.additional-jvm-opts`, the flags the server was started with.
fn jvm_opts(dc: &DynamicObject) -> Vec<String> {
    dc.data
        .get("spec")
        .and_then(|v| v.get("config"))
        .and_then(|v| v.get("cassandra-env-sh"))
        .and_then(|v| v.get("additional-jvm-opts"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

/// The value of `-D<key>=…` in that list. A flag given twice keeps the last one, as the JVM does.
fn opt_value(opts: &[String], key: &str) -> Option<String> {
    let prefix = format!("-D{key}=");
    opts.iter()
        .rev()
        .find_map(|o| o.strip_prefix(prefix.as_str()))
        .map(str::to_string)
}

/// The mount and volume that put `path` inside the cassandra container. The longest matching
/// `mountPath` wins: `/mnt` and `/mnt/client-keystore` can both be mounted, and only the deeper one
/// holds the file.
fn store_volume(
    pod: &Pod,
    container: &k8s_openapi::api::core::v1::Container,
    path: &str,
) -> Option<(Value, Value)> {
    let mount = container
        .volume_mounts
        .as_ref()?
        .iter()
        .filter(|m| {
            let base = m.mount_path.trim_end_matches('/');
            path == base || path.starts_with(&format!("{base}/"))
        })
        .max_by_key(|m| m.mount_path.len())?;
    let volume = pod
        .spec
        .as_ref()?
        .volumes
        .as_ref()?
        .iter()
        .find(|v| v.name == mount.name)?;
    Some((
        json!({ "name": mount.name, "mountPath": mount.mount_path, "readOnly": true }),
        serde_json::to_value(volume).ok()?,
    ))
}

// --- The Job ---------------------------------------------------------------------------------------

/// The object the plan produces. Pure, and asserted in the tests below.
pub fn job_payload(plan: &Plan) -> Value {
    let mut env: Vec<Value> = Vec::new();
    if !plan.superuser_secret.is_empty() {
        for (var, key) in [("CASS_USER", "username"), ("CASS_PASS", "password")] {
            env.push(json!({
                "name": var,
                "valueFrom": { "secretKeyRef": { "name": plan.superuser_secret, "key": key } },
            }));
        }
    }
    if !plan.jvm_opts.is_empty() {
        env.push(json!({ "name": "JVM_OPTS", "value": plan.jvm_opts.join(" ") }));
    }
    json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            // `generateName`, like every other write in the k8ssandra view: two operators running
            // the same command in the same second get two Jobs instead of one conflict.
            "generateName": "kdt-nodetool-",
            "namespace": plan.namespace,
            "labels": { LABEL: "true", "app.kubernetes.io/created-by": "kdt" },
            "annotations": {
                ANN_COMMAND: plan.command.join(" "),
                ANN_TARGET: plan.pod,
                ANN_LINE: plan.display(),
            },
        },
        "spec": {
            "backoffLimit": BACKOFF_LIMIT,
            "completions": 1,
            "parallelism": 1,
            "ttlSecondsAfterFinished": TTL_SECONDS,
            "template": {
                "metadata": {
                    "labels": { LABEL: "true" },
                    // A compaction or a repair driven from here can run for hours; letting the
                    // autoscaler take the node out from under it would leave the work half done
                    // server-side with nothing left to read the outcome from.
                    "annotations": { "cluster-autoscaler.kubernetes.io/safe-to-evict": "false" },
                },
                "spec": {
                    "restartPolicy": "Never",
                    "terminationGracePeriodSeconds": 30,
                    "securityContext": plan.security_context,
                    "containers": [{
                        "name": "nodetool",
                        "image": plan.image,
                        // No shell: the words the user typed are arguments, and there is no line for
                        // a `;` to split. `$(CASS_PASS)` is expanded by the kubelet, not by a shell.
                        "command": ["nodetool"],
                        "args": plan.args,
                        "env": env,
                        // Guaranteed QoS, so the Job is the last thing evicted under pressure. The
                        // JVM `nodetool` starts is small; the gigabyte is headroom for its heap.
                        "resources": {
                            "requests": { "cpu": "200m", "memory": "1Gi" },
                            "limits": { "cpu": "200m", "memory": "1Gi" },
                        },
                        "volumeMounts": plan.mounts,
                    }],
                    "volumes": plan.volumes,
                },
            },
        },
    })
}

/// Resolve the pod and its datacenter, then create the Job. Returns the Job's name and whatever the
/// plan could not read, which the caller shows next to the confirmation that it started.
pub async fn run(
    client: Client,
    namespace: String,
    pod_name: String,
    datacenter: String,
    command: Vec<String>,
) -> Result<(String, Vec<String>), String> {
    let st = lang::active();
    if command.is_empty() {
        return Err(st.nt_empty_command.to_string());
    }
    let pods: Api<Pod> = Api::namespaced(client.clone(), &namespace);
    let pod = pods.get(&pod_name).await.map_err(crate::edit::api_error_text)?;

    let (dc_api, _ar) = crate::yaml::dynamic_resource(
        &client,
        "cassandra.datastax.com/v1beta1",
        "CassandraDatacenter",
        &namespace,
    )
    .await?;
    let dc = dc_api.get(&datacenter).await.map_err(crate::edit::api_error_text)?;

    let mut plan = plan(&pod, &dc, &command, st)?;

    // The secret the datacenter names has to exist, or the Job stalls in `CreateContainerConfigError`
    // with the reason two levels down in an event. Checking here turns that into a warning and a
    // `nodetool` that at least tries.
    if !plan.superuser_secret.is_empty() {
        let secrets: Api<Secret> = Api::namespaced(client.clone(), &namespace);
        if secrets.get_metadata(&plan.superuser_secret).await.is_err() {
            plan.warnings.push(lang::fill(
                st.nt_warn_secret_missing,
                &[("name", &plan.superuser_secret)],
            ));
        }
    }

    let job: Job = serde_json::from_value(job_payload(&plan)).map_err(|e| e.to_string())?;
    let jobs: Api<Job> = Api::namespaced(client, &namespace);
    let created = jobs
        .create(&PostParams::default(), &job)
        .await
        .map_err(crate::edit::api_error_text)?;
    Ok((created.metadata.name.unwrap_or_default(), plan.warnings))
}

// --- What the view lists back -----------------------------------------------------------------------

/// One `nodetool` Job, as the Ops world shows it.
#[derive(Debug, Clone, Default)]
pub struct NtJob {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    /// The command as typed, from the annotation. Empty when someone created the Job by hand.
    pub command: String,
    pub target: String,
    /// The resolved command line, credentials masked. Empty on a Job created by hand.
    pub line: String,
    pub created: i64,
    pub start: Option<i64>,
    pub finish: Option<i64>,
    pub active: i32,
    pub succeeded: i32,
    pub failed: i32,
    /// The `Failed` condition's reason, e.g. `BackoffLimitExceeded` or `DeadlineExceeded`.
    pub reason: String,
    pub hints: Vec<Hint>,
}

impl NtJob {
    pub fn running(&self) -> bool {
        self.active > 0
    }
}

/// Every Job this module created, cluster-wide, in one call. `None` means the list could not be
/// read: the section says nothing rather than claiming there is nothing.
pub async fn list_jobs(client: &Client, st: &'static Strings) -> Option<Vec<NtJob>> {
    let api: Api<Job> = Api::all(client.clone());
    let list = api
        .list(&ListParams::default().labels(&format!("{LABEL}=true")))
        .await
        .ok()?;
    let mut out: Vec<NtJob> = list.items.iter().map(|j| parse_job(j, st)).collect();
    // Newest first: the one worth reading is the one just started.
    out.sort_by(|a, b| b.created.cmp(&a.created).then(a.name.cmp(&b.name)));
    Some(out)
}

fn parse_job(job: &Job, st: &'static Strings) -> NtJob {
    let namespace = job.metadata.namespace.clone().unwrap_or_default();
    let name = job.metadata.name.clone().unwrap_or_default();
    let ann = |k: &str| {
        job.metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(k))
            .cloned()
            .unwrap_or_default()
    };
    let status = job.status.as_ref();
    let stamp = |t: Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>| {
        t.map(|t| t.0.as_second())
    };
    let conditions = status.and_then(|s| s.conditions.as_ref());
    let reason = conditions
        .and_then(|cs| {
            cs.iter()
                .find(|c| c.type_ == "Failed" && c.status == "True")
                .and_then(|c| c.reason.clone())
        })
        .unwrap_or_default();
    let failed = status.and_then(|s| s.failed).unwrap_or(0);
    let succeeded = status.and_then(|s| s.succeeded).unwrap_or(0);

    let mut hints: Vec<Hint> = Vec::new();
    if failed > 0 {
        // A `nodetool` that came back non-zero: worth a colour, never worse than a warning. It is
        // the outcome of a command someone typed on purpose, not a fault of the cluster.
        hints.push(Hint {
            level: HintLevel::Warn,
            text: lang::fill(
                st.nt_hint_failed,
                &[("reason", if reason.is_empty() { "—" } else { &reason })],
            ),
        });
    }
    NtJob {
        uid: format!("k8c|nodetool|{namespace}/{name}"),
        namespace,
        name,
        command: ann(ANN_COMMAND),
        target: ann(ANN_TARGET),
        line: ann(ANN_LINE),
        created: job
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| t.0.as_second())
            .unwrap_or(0),
        start: stamp(status.and_then(|s| s.start_time.as_ref())),
        finish: stamp(status.and_then(|s| s.completion_time.as_ref())),
        active: status.and_then(|s| s.active).unwrap_or(0),
        succeeded,
        failed,
        reason,
        hints,
    }
}

// --- The output --------------------------------------------------------------------------------------

// What `nodetool` prints is small — a ring, a table of pools, a line of progress. The cap is there
// for `repair`, which prints one line per range and can reach thousands.
const OUTPUT_TAIL: i64 = 500;

/// The Job's output, which is the log of its pod. A Job whose pod has not started yet is a distinct
/// answer from a Job with no output: one is early, the other has nothing to say.
pub async fn fetch_output(
    client: Client,
    namespace: String,
    job: String,
    key: String,
    state: SharedK8cPanel,
) {
    let st = lang::active();
    {
        let mut s = state.lock().expect("k8ssandra panel poisoned");
        *s = K8cPanel {
            key: key.clone(),
            kind: Some(PanelKind::Nodetool),
            title: job.clone(),
            loading: true,
            ..K8cPanel::default()
        };
    }
    let pods: Api<Pod> = Api::namespaced(client, &namespace);
    // `job-name` is the label the Job controller puts on the pods it creates; it is how the pod is
    // found without reading the Job's own selector, which carries a generated uid.
    let found = pods
        .list(&ListParams::default().labels(&format!("job-name={job}")))
        .await;
    // The phase of the pod the output came from, kept so that an empty log can say which kind of
    // empty it is: a command still running has printed nothing *yet*.
    let mut phase = String::new();
    let result = match found {
        Err(e) => Err(crate::edit::api_error_text(e)),
        Ok(list) => {
            // The newest pod: `backoffLimit: 0` means there is normally exactly one, but a node
            // failure can leave an older, evicted one behind.
            let pod = list
                .items
                .into_iter()
                .max_by_key(|p| {
                    p.metadata
                        .creation_timestamp
                        .as_ref()
                        .map(|t| t.0.as_second())
                        .unwrap_or(0)
                })
                .map(|p| {
                    phase = p.status.as_ref().and_then(|s| s.phase.clone()).unwrap_or_default();
                    p.metadata.name.unwrap_or_default()
                });
            match pod {
                None => Err(st.nt_no_pod_yet.to_string()),
                Some(pod) => {
                    let params = kube::api::LogParams {
                        container: Some("nodetool".to_string()),
                        tail_lines: Some(OUTPUT_TAIL),
                        ..kube::api::LogParams::default()
                    };
                    pods.logs(&pod, &params).await.map_err(crate::edit::api_error_text)
                }
            }
        }
    };
    let mut s = state.lock().expect("k8ssandra panel poisoned");
    if s.key != key {
        return;
    }
    s.loading = false;
    match result {
        Ok(text) => {
            let lines: Vec<String> = text.lines().map(str::to_string).collect();
            s.lines = if !lines.is_empty() {
                lines
            } else if phase == "Pending" {
                vec![st.nt_no_pod_yet.to_string()]
            } else if phase == "Running" {
                // `nodetool` prints at the end of most of its work, so a running Job with an empty
                // log is the normal state of a compaction, not a Job that answered nothing.
                vec![st.nt_running_no_output.to_string()]
            } else {
                vec![st.nt_no_output.to_string()]
            };
        }
        Err(e) => s.error = Some(e),
    }
}

fn str_at(obj: &DynamicObject, path: &[&str]) -> String {
    // `metadata` is not part of `data` on a DynamicObject, so the one path that reaches into it is
    // answered from the typed field instead.
    if path == ["metadata", "name"] {
        return obj.metadata.name.clone().unwrap_or_default();
    }
    let mut cur = &Value::Null;
    let mut first = true;
    for key in path {
        let next = if first {
            first = false;
            obj.data.get(*key)
        } else {
            cur.get(*key)
        };
        match next {
            Some(v) => cur = v,
            None => return String::new(),
        }
    }
    cur.as_str().unwrap_or_default().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::FR;

    fn pod() -> Pod {
        serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "cc-dc1-default-sts-0", "namespace": "cass" },
            "spec": {
                "hostname": "cc-dc1-default-sts-0",
                "subdomain": "cc-dc1-all-pods-service",
                "securityContext": { "runAsUser": 999, "runAsGroup": 999, "fsGroup": 999 },
                "containers": [{
                    "name": "cassandra",
                    "image": "k8ssandra/cass-management-api:3.11.15",
                    "env": [{ "name": "LOCAL_JMX", "value": "no" }],
                    "volumeMounts": [
                        { "name": "client-keystore", "mountPath": "/mnt/client-keystore" },
                        { "name": "client-truststore", "mountPath": "/mnt/client-truststore" }
                    ]
                }],
                "volumes": [
                    { "name": "client-keystore",
                      "secret": { "secretName": "jks", "items": [{ "key": "keystore.jks", "path": "keystore" }] } },
                    { "name": "client-truststore",
                      "secret": { "secretName": "truststore", "items": [{ "key": "truststore.jks", "path": "truststore" }] } }
                ]
            },
            "status": { "podIP": "10.0.0.1" }
        }))
        .expect("pod")
    }

    fn datacenter(opts: Value) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "cassandra.datastax.com/v1beta1",
            "kind": "CassandraDatacenter",
            "metadata": { "name": "dc1", "namespace": "cass" },
            "spec": {
                "clusterName": "cc",
                "superuserSecretName": "cc-superuser",
                "config": { "cassandra-env-sh": { "additional-jvm-opts": opts } },
            }
        }))
        .expect("dc")
    }

    fn ssl_opts() -> Value {
        json!([
            "-Dcom.sun.management.jmxremote.authenticate=true",
            "-Dcom.sun.management.jmxremote.ssl=true",
            "-Djavax.net.ssl.keyStore=/mnt/client-keystore/keystore",
            "-Djavax.net.ssl.keyStorePassword=secret",
            "-Djavax.net.ssl.trustStore=/mnt/client-truststore/truststore",
            "-Djavax.net.ssl.trustStorePassword=changeit"
        ])
    }

    #[test]
    fn how_the_server_was_started_decides_how_the_client_connects() {
        let cmd = split_command("garbagecollect -g ROW -j 1 prod_csi_sells docrefconso2");
        let p = plan(&pod(), &datacenter(ssl_opts()), &cmd, &FR).expect("plan");
        assert_eq!(
            p.args,
            vec![
                "-h",
                "cc-dc1-default-sts-0.cc-dc1-all-pods-service.cass.svc.cluster.local",
                "-u",
                "$(CASS_USER)",
                "-pw",
                "$(CASS_PASS)",
                "--ssl",
                "garbagecollect",
                "-g",
                "ROW",
                "-j",
                "1",
                "prod_csi_sells",
                "docrefconso2",
            ]
        );
        assert_eq!(p.superuser_secret, "cc-superuser");
        // The two stores the server names, carried over as the volumes that hold them.
        assert_eq!(p.mounts.len(), 2);
        assert_eq!(p.volumes[0]["secret"]["secretName"], "jks");
        assert!(p.warnings.is_empty(), "nothing was guessed: {:?}", p.warnings);
    }

    #[test]
    fn a_datacenter_without_jmx_ssl_gets_a_bare_nodetool() {
        let p = plan(&pod(), &datacenter(json!([])), &split_command("status"), &FR).expect("plan");
        assert_eq!(
            p.args,
            vec!["-h", "cc-dc1-default-sts-0.cc-dc1-all-pods-service.cass.svc.cluster.local", "status"]
        );
        assert!(p.jvm_opts.is_empty());
        assert!(p.mounts.is_empty());
        assert!(p.superuser_secret.is_empty(), "no auth asked, no credentials sent");
    }

    #[test]
    fn a_store_no_volume_backs_is_a_warning_rather_than_a_silent_mount() {
        let opts = json!([
            "-Dcom.sun.management.jmxremote.ssl=true",
            "-Djavax.net.ssl.keyStore=/elsewhere/keystore",
            "-Djavax.net.ssl.keyStorePassword=secret"
        ]);
        let p = plan(&pod(), &datacenter(opts), &split_command("status"), &FR).expect("plan");
        assert!(p.mounts.is_empty());
        assert_eq!(p.warnings.len(), 1);
        // The flag is still passed: the Job fails with a legible JVM error instead of connecting
        // without the client certificate the server asks for.
        assert!(p.jvm_opts.iter().any(|o| o.contains("/elsewhere/keystore")));
    }

    #[test]
    fn a_pod_with_no_subdomain_falls_back_to_its_address() {
        let mut pod = pod();
        pod.spec.as_mut().expect("spec").subdomain = None;
        let p = plan(&pod, &datacenter(json!([])), &split_command("status"), &FR).expect("plan");
        assert_eq!(p.args[1], "10.0.0.1");
    }

    #[test]
    fn jmx_kept_to_the_loopback_is_said_out_loud_and_still_run() {
        let mut pod = pod();
        pod.spec.as_mut().expect("spec").containers[0].env = None;
        let p = plan(&pod, &datacenter(json!([])), &split_command("status"), &FR).expect("plan");
        assert_eq!(p.warnings.len(), 1);
        assert!(!p.args.is_empty(), "a warning is not a refusal");
    }

    #[test]
    fn the_password_never_appears_in_what_is_shown() {
        let p = plan(&pod(), &datacenter(ssl_opts()), &split_command("status"), &FR).expect("plan");
        let shown = p.display();
        assert!(shown.starts_with("nodetool -h "));
        assert!(shown.contains("-pw ***"), "{shown}");
        assert!(shown.ends_with("--ssl status"));
    }

    #[test]
    fn the_job_runs_the_words_that_were_typed_and_no_shell() {
        let p = plan(&pod(), &datacenter(ssl_opts()), &split_command("flush app"), &FR).expect("plan");
        let job = job_payload(&p);
        let container = &job["spec"]["template"]["spec"]["containers"][0];
        assert_eq!(container["command"], json!(["nodetool"]));
        assert_eq!(container["args"].as_array().expect("args").len(), p.args.len());
        // The secret is referenced, never copied.
        assert_eq!(
            container["env"][0]["valueFrom"]["secretKeyRef"]["name"],
            "cc-superuser"
        );
        assert_eq!(job["spec"]["backoffLimit"], 0, "a half-done compaction is not retried");
        assert_eq!(job["metadata"]["annotations"][ANN_COMMAND], "flush app");
        assert_eq!(job["metadata"]["annotations"][ANN_TARGET], "cc-dc1-default-sts-0");
        // The line kept on the object never carries the password, only the reference's placeholder.
        let line = job["metadata"]["annotations"][ANN_LINE].as_str().expect("line");
        assert!(line.contains("-pw ***") && line.ends_with("--ssl flush app"), "{line}");
    }

    #[test]
    fn a_command_is_split_on_whitespace_only() {
        assert_eq!(split_command("  status  "), vec!["status"]);
        assert_eq!(split_command(""), Vec::<String>::new());
        assert_eq!(
            split_command("compact app t1,t2"),
            vec!["compact", "app", "t1,t2"]
        );
    }

    #[test]
    fn a_job_is_read_back_from_its_annotations_and_its_counters() {
        let job: Job = serde_json::from_value(json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "kdt-nodetool-abcde",
                "namespace": "cass",
                "creationTimestamp": "2026-09-02T10:00:00Z",
                "annotations": {
                    ANN_COMMAND: "garbagecollect app events",
                    ANN_TARGET: "cc-dc1-default-sts-0",
                    ANN_LINE: "nodetool -h cc-dc1-default-sts-0 --ssl garbagecollect app events",
                },
            },
            "status": {
                "startTime": "2026-09-02T10:00:01Z",
                "failed": 1,
                "conditions": [
                    { "type": "Failed", "status": "True", "reason": "BackoffLimitExceeded" }
                ],
            },
        }))
        .expect("job");
        let nt = parse_job(&job, &FR);
        assert_eq!(nt.uid, "k8c|nodetool|cass/kdt-nodetool-abcde");
        assert_eq!(nt.command, "garbagecollect app events");
        assert_eq!(nt.target, "cc-dc1-default-sts-0");
        assert_eq!(nt.start, Some(1_788_343_201));
        assert_eq!(nt.finish, None, "a Job that failed has no completion time");
        assert!(!nt.running(), "nothing is active");
        // A command that came back non-zero is a warning, never worse: it is the outcome of
        // something someone typed on purpose.
        assert_eq!(nt.hints.len(), 1);
        assert_eq!(nt.hints[0].level, HintLevel::Warn);
        assert!(nt.hints[0].text.contains("BackoffLimitExceeded"));
    }

    #[test]
    fn a_job_created_by_hand_carries_no_command_and_no_hint() {
        // Someone else's Job wearing the label: the row still lists it rather than pretending the
        // annotations are there.
        let job: Job = serde_json::from_value(json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "mine", "namespace": "cass" },
            "status": { "active": 1 },
        }))
        .expect("job");
        let nt = parse_job(&job, &FR);
        assert!(nt.command.is_empty() && nt.line.is_empty() && nt.target.is_empty());
        assert!(nt.running());
        assert!(nt.hints.is_empty());
    }

    #[test]
    fn a_flag_given_twice_keeps_the_last_one() {
        let opts = vec![
            "-Dcom.sun.management.jmxremote.ssl=false".to_string(),
            "-Dcom.sun.management.jmxremote.ssl=true".to_string(),
        ];
        assert_eq!(opt_value(&opts, JMX_SSL_OPT).as_deref(), Some("true"));
        assert_eq!(opt_value(&opts, JMX_AUTH_OPT), None);
    }
}
