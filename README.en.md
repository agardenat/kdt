# kdt — Kubernetes Diagnostic Tools

A Rust TUI to watch Kubernetes events live, inspect the cluster view by view, run a diagnostic,
export a PDF report and ask an AI for an analysis.

📖 [Version française](README.md)

![kdt in action: live event stream, FluxCD tree, capacity headroom, Kyverno policies and RBAC tree](demo/hero.gif)

## Install

### Homebrew (macOS and Linux x86_64)

```bash
brew install agardenat/kdt/kdt
```

Serves the macOS universal binary (Apple Silicon + Intel) or the static Linux x86_64 binary
depending on the platform. Linux arm64 is not distributed through Homebrew.

### Linux packages (x86_64)

```bash
sudo dpkg -i kdt_<version>_amd64.deb      # Debian / Ubuntu
sudo rpm -i kdt-<version>-1.x86_64.rpm    # RHEL / Fedora / openSUSE
```

### Pre-built binary

Archives on the [Releases](https://github.com/agardenat/kdt/releases) page:

```bash
tar xzf kdt-linux-x86_64.tar.gz   # or kdt-macos-universal.tar.gz
sudo install -m 0755 kdt /usr/local/bin/kdt
```

### From source

```bash
cargo build --release   # → target/release/kdt
```

## Usage

```bash
kdt [OPTIONS]
```

| Option | Description | Default |
|---|---|---|
| `-n, --namespace <NS>` | Namespace to watch | all |
| `-A, --all-namespaces` | All namespaces | — |
| `--context <CTX>` | kubeconfig context | current context |
| `--buffer-size <N>` | Event buffer size | `5000` |

Connects through the standard kubeconfig. The app starts on the events view.

## Command palette (`:`)

`:` opens a k9s-style prompt: `Tab` completes, `Enter` runs, `Esc` cancels. `events`, `namespace`
and `workloads` take a namespace argument (`:ns kube-system`, `:pods istio-system`); `all` (or
`*`/`0`) targets every namespace.

| Command | Aliases | View |
|---|---|---|
| `events [ns]` | `ev`, `event` | Events |
| `namespace [ns]` | `ns`, `namespaces` | Namespace picker |
| `workloads [ns]` | `wl`, `pods`, `po`, `deploy` | Workloads / Pods |
| `nodes` | `no`, `node` | Nodes |
| `flux` | `fl`, `ks`, `hr` | FluxCD |
| `flux-logs` | `logs`, `fluxlogs` | Aggregated Flux controller logs |
| `rbac` | `rb`, `roles`, `bindings`, `sec` | RBAC |
| `vuln` | `cve`, `cves`, `vulns` | Vulnerabilities |
| `secrets` | `secret`, `se`, `tls` | Secrets and TLS certificates |
| `certs` | `certificates`, `issuers`, `challenges`, `acme` | cert-manager |
| `kyverno` | `ky`, `policies`, `polr`, `cpol`, `admission` | Kyverno |
| `reflector` | `refl`, `mirror`, `miroir` | Reflector |
| `velero` | `vel`, `backup`, `backups`, `schedules` | Velero, backups and schedules |
| `restores` | `restore`, `restauration` | Velero, restores |
| `bsl` | `backupstoragelocation`, `backuprepositories` | Velero, storage and repositories |
| `k8ssandra` | `k8c`, `cassandra`, `cass`, `datacenter` | K8ssandra / Cassandra, ring side |
| `medusa` | `med`, `medusabackup`, `cassbackup` | K8ssandra, Medusa backup side |
| `reaper` | `rea`, `repair`, `repairs` | K8ssandra, operations and Reaper |
| `rancher` | `ranch`, `cattle`, `users`, `identities` | Rancher, accounts and identities |
| `projects` | `project`, `proj` | Rancher, projects and namespaces |
| `tokens` | `token`, `apikey`, `kubeconfigs` | Rancher, tokens |
| `configmaps` | `cm`, `config` | ConfigMaps |
| `services` | `svc`, `service` | Services / Endpoints |
| `ingress` | `ing`, `ingressclass` | Ingress / IngressClass |
| `storage` | `stockage`, `pvc`, `claims` | Storage, claim side (PVC → PV) |
| `pv` | `sc`, `storageclass`, `persistentvolume` | Storage, volume side (SC → PV) |
| `capacity` | `cap`, `marge`, `headroom` | Capacity, node side |
| `quota` | `quotas`, `rq`, `resourcequota` | Capacity, quota side |
| `quit` | `q` | Quit |

## Keys

### Everywhere

| Key | Action |
|---|---|
| `↑` `↓` `PgUp` `PgDn` | Navigate |
| `Enter` | Full-screen detail (or fold/unfold in a tree) |
| `Shift-↑/↓`, `g` / `G` | Scroll the detail pane |
| `/` | Search (see below) |
| `y` | YAML of the selected object (`t`: neat ↔ raw) |
| `e` / `h` / `Ctrl-D` | Edit / touch / delete the object (guardrails) |
| `i` | AI pane |
| `c` | Copy the view (OSC 52, works over SSH) |
| `L` / `m` | Language FR/EN · next AI provider |
| `F5` | Refresh |
| `:` | Command palette |
| `Esc` | Back (clears the active search first) |
| `q` / `Ctrl-C` | Quit |

### Per view

| View | Keys |
|---|---|
| Events | `s` freeze scrolling · `Tab` Logs/Status/Related tab · `a`/`w`/`x` All/Warnings/Errors filter · `p`/`C`/`f` logs previous run/container/follow · `n`/`0` namespace filter · `N` nodes of the pod · `E` shell · `D` diagnostic · `X` PDF export |
| Workloads | `t` list ↔ tree · `Space` (or `→`/`←`) unfold the pod into its containers · `s` scale · `r` rescale/recycle/restart · `E` shell · `p`/`C`/`f` logs · `n`/`0` namespace |
| Nodes | `u` usage view · `s` sort · `o` cordon/uncordon/drain · `p`/`P` PDF export |
| Capacity | `g` world (nodes → workloads → quotas) · `f` problems only |
| FluxCD | `r` reconcile menu · `Ctrl-R` unblock · `z` suspend/resume · `t` table ↔ tree · `l` logs of every controller · `Tab` Logs/Status/Related/Inventory tab |
| Vulnerabilities | `f` severity floor (all → HIGH+ → CRIT) |
| cert-manager | `Space` fold/unfold · `t` tree ↔ list · `f` ALL/PROBLEMS/IN-FLIGHT · `s` jump to the Secret · `r` renew, restart ACME |
| Kyverno | `Space` fold/unfold · `t` by policy ↔ by resource · `f` ALL/PROBLEMS/ENFORCE |
| Reflector | `Space` fold/unfold · `g` sources → mirrors → orphans · `f` ALL/PROBLEMS · `s` jump to the source · `r` force re-reflection |
| K8ssandra | `Space` fold/unfold · `g` cluster → backups → operations · `f` ALL/PROBLEMS · `l` log of the container at fault · `s` node stats (tpstats, compactionstats, netstats) or Reaper repairs · `o` actions |
| Rancher | `g` users → access → projects → tokens · `f` ALL/PROBLEMS · `o` actions (issue a token, change a TTL, revoke, set a setting) · `e`, `h`, `Ctrl-D` deliberately absent |
| RBAC | `Space` fold/unfold · `t` flat → by subject → by binding → by role · `f` severity floor · `o` jump to the managing Flux object |
| Storage | `g` claims ↔ volumes · `t` parent/child nesting · `f` problems only · `n`/`0` namespace |
| Diagnostic | `r` re-run · `p`/`P` PDF export |
| YAML | `t` neat ↔ raw · `c` copy · `r` reload |

In the events view the cursor **follows** the stream by default (`↻` indicator); moving up anchors
it on a specific event, `Esc` resumes following.

### Search (`/`)

Available everywhere, case-insensitive, and **kept across view changes**. The status bar always
shows the query and its effect (`/coredns  (3)`).

- **table**: keeps only matching rows (namespace, name, kind, reason, message, plus whatever
  identifies the view: RBAC subjects, images, keys — never values — of secrets);
- **text pane** (logs, diagnostic, AI, YAML): highlights matches and jumps between them with
  `Ctrl-N` / `Ctrl-P`, position shown (`/glob  (3/500)`).

## The views

- **Events** — watches `Event` objects with an All / Warnings / Errors filter and a tabbed detail
  pane (Logs / Status / Related). `p` reads the container's **previous run**: on a
  `CrashLoopBackOff`, what killed the pod only lives there.
- **Workloads** — flat pod list or workload → pod tree (`t`, which also shows workloads scaled to
  0). Actions target the workload, even from one of its pod rows. `Space` unfolds a pod into its
  containers (init, regular, ephemeral): each with its own state, its share of the usage against
  *its* requests/limits, and the age of its last start. On a container row, `E` opens a shell in
  that container and the Logs tab narrows to it on its own.
- **Nodes** — list, detail, CPU/memory usage, and `o` operations: cordon/uncordon (one reversible
  patch) and a **drain that reports first** — pods no controller will recreate, PDBs that will
  refuse, no room elsewhere, `emptyDir` data lost, static pods left behind.
- **Capacity** (`:capacity`, `:quota`) — headroom, not state. Per node: the "if this node dies,
  these pods have nowhere to go" simulation (first-fit, largest pod first, on requests, honouring
  taints, `nodeSelector` and `required` node affinity). Per workload: pods with no requests
  (invisible to the scheduler), oversized ones, ones at their own limit. Per namespace: the
  `ResourceQuota` about to refuse the next creation.

  ![Capacity view](demo/capacity.gif)

- **FluxCD** — cluster-wide inventory, dependency tree (`t`), applied-object inventory with live
  state, controller logs filtered or aggregated. `r`: reconcile (resource, `--with-source`, root
  sync, plus **force upgrade** and **reset** on a HelmRelease). `Ctrl-R`: **unblock** — kdt derives
  leads from the controller message, **confirms each one against the cluster**, and offers the
  counter-move (delete an orphaned webhook, strip finalizers, `resetAt` then `forceAt` on a pending
  Helm release). One more reconcile is rarely the right move.

  ![FluxCD view](demo/flux.gif)

- **Vulnerabilities** — per-image CVEs from **Trivy Operator** `VulnerabilityReport`s (CVSS score,
  number of fixable CVEs) and the risk on the Kubernetes version itself (official feed, latest patch
  of the minor as target, `EOL` badge). Without Trivy the view falls back to the k8s version alone.
- **cert-manager** (`:certs`) — the issuance chain end to end: Issuer → Certificate →
  CertificateRequest → Order → Challenge → served Secret. Healthy chains fold themselves away,
  failing ones unfold. Diagnostics: slow DNS propagation, challenge not presented, ACME rate limit,
  late renewal, Secret out of sync.
- **Kyverno** — the join `kubectl get polr` won't do: a report names its rule with a plain string,
  and you have to go read the policy to know what was checked. Three things only visible here: the
  **`autogen-*` rules** (those are the ones reports name), the difference between `fail` (the
  resource violates) and `error` (the rule can't evaluate — a policy bug), and **admission
  denials**, which leave no trace in the reports and exist only as Events. A
  `kyverno-resource-*` webhook count of zero means Kyverno intercepts nothing at all, green
  controllers or not.

  ![Kyverno view](demo/kyverno.gif)

- **Reflector** ([kubernetes-reflector](https://github.com/emberstack/kubernetes-reflector)) — the
  controller is **silent whenever it decides to do nothing**. This view answers "why is this mirror
  missing, or stale?": a namespace blocked by a same-named object, a mirror edited by hand
  (reflector only compares `reflected-version`, never the content), the real scope of the anchored
  regexes (an empty list means *all namespaces*), and who is waiting for the copy.
- **RBAC** — flat audit list by default, plus three tree orientations (`t`): by subject ("what can
  this identity do in total"), by binding, by role. Severity is computed **per binding** — a Role
  alone is inert, and the same ClusterRole is harmless in a RoleBinding and critical in a
  ClusterRoleBinding. Shows template ClusterRoles rebound namespace by namespace, the composition of
  aggregated roles (`admin`, `edit`, `view`), bindings naming a non-existent ServiceAccount, and
  roles nobody binds.

  ![RBAC view](demo/rbac.gif)

- **Velero** (`:velero`, `:restores`, `:bsl`) — a backup is only ever asked one question: *if
  everything burns down right now, what comes back?* `PartiallyFailed` is shown as a failure,
  because it is one — the backup ran to the end without capturing everything. The view **evaluates
  the cron itself** to say that a schedule has stopped firing (velero reports this nowhere: it
  simply does not create a backup), flags a TTL shorter than the cron period, an unavailable
  location, a kopia repository with no maintenance, and above all the **namespaces holding PVCs
  that no schedule covers any more**. `o` opens the operations: run a backup from a schedule, pause
  it, restore, and *actually* delete a backup — through a `DeleteBackupRequest`, because deleting
  the object deletes nothing and the next sync brings it back. `l` fetches the run log. `+` unfolds
  what the backup really holds — namespaces, then kinds, then objects — and *Restore (options)*
  uses that to prefill a narrowed `Restore`: namespaces to tick, remapping into a fresh namespace,
  a filter by kind and by label, and the choice between stepping around what already exists and
  overwriting it. Velero cannot target an object by name, so the view stops where the API stops
  rather than promising a tick box per object.
- **K8ssandra / Cassandra** (`:k8ssandra`, `:medusa`, `:reaper`) — on a database only one question
  matters, and none of the surfaces that ought to answer it do. A `MedusaBackupSchedule` keeps a
  fresh `lastExecution` and a clean `nextSchedule` whether the run it fired succeeded or failed; the
  purge CronJob completes green while purging nothing; and the `MedusaBackup` objects, the catalogue
  itself, simply stop appearing — no event, no condition, no status field. So a cluster can run for
  months with everything green and not one restorable backup. This view puts that number in the
  title: **the age of the last backup that covers every node** of the datacenter, a partial run
  counting as a failure because it restores as if it were whole. It also reports successful runs
  missing from the catalogue (the `sync` MedusaTask never ran), and that a restore **stops the
  datacenter** — before you start it, not after.

  The ring comes from no CRD but from the `cassandra` container's management API, reached through
  the apiserver proxy: no port-forward, no `kubectl`, no exec. `nodetool status` and
  `describecluster` come out of it as typed data (UN/DN state, load, tokens, schema agreement), and
  `s` fetches `tpstats`, `compactionstats` and `netstats` for the selected node. A pod is joined to
  its ring entry on the **address**, not on the `hostID` in `status.nodeStatuses`: that field is the
  operator's memory and it goes stale — the view says so when the two disagree. `o` opens the
  operations: back up now, restore, purge or resync the Medusa catalogue, and the `CassandraTask`
  jobs (cleanup, upgradesstables, compaction, scrub, rolling restart).
- **Rancher** (`:rancher`, `:projects`, `:tokens`) — on a Rancher-managed cluster every human is a
  `u-4oivhvq2jk`. That id is what the RoleBindings carry, what the audit log carries, and what
  `kubectl get rolebinding -o yaml` shows; the person behind it lives in a `User` object nobody
  looks at and in a `UserAttribute` object nobody knows exists. This view puts **both identities
  side by side** — Rancher id and real identity (the CN of an LDAP/AD distinguished name, the
  FreeIPA `uid`), with the provider, the directory groups, the global roles and when those groups
  were last refreshed. `g` moves through the other three worlds: **access** (who has what, the three
  binding kinds collapsed into one subject → role → scope list, with the binding Rancher gives every
  account sorted last so it does not bury the grants someone actually made), **projects** (their
  namespaces, members, owners and quota) and **tokens** (kubeconfig, session, or an API key with no
  expiry).

  Two clusters look alike and only one holds the data: the **local** cluster, the one running the
  Rancher server, and a **downstream** cluster, where the same CRDs exist and are empty. Zero
  `User` objects on a downstream is not "no accounts" but "not here" — the view says so, and falls
  back on what the agent projected: the RoleBindings labelled with the Rancher binding that created
  them. Groups show up there in clear text (the full DN), accounts stay `u-…` ids that nothing on
  this cluster can resolve, and every row declares it instead of passing an identifier off as a name.

  The **tokens** world lists, above the tokens themselves, the settings that decide how long a
  credential lives — `auth-token-max-ttl-minutes` (the ceiling),
  `kubeconfig-default-token-ttl-minutes`, `auth-user-session-ttl-minutes` — with the value in force,
  the shipped default, and which of the two applies. That is what makes a column of tokens marked
  "never" readable: someone set the kubeconfig default to `0`, and Rancher reads `0` as "no expiry".

  `o` opens the only writes this view has, each behind a confirmation and then an entry whose unit is
  shown: **issue a token** for the selected account (a `Token` object shaped like the ones Rancher
  creates — same labels, `isDerived`, reconstructed `userPrincipal` — with a 54-character secret from
  `/dev/urandom`, shown **once** and never written to the state, a log or a file), **change the TTL**
  of an existing token, **revoke** it (deleting the `Token` object is the only thing that actually
  revokes a credential), and **set** a lifetime setting, whose cluster-wide scope is stated. All of
  it already requires an admin kubeconfig on the local cluster: these are the same objects one would
  `kubectl apply` by hand, and kdt adds no privilege. On a downstream the menu refuses and says why.
  An issued token authenticates **as that account** — which the overlay says before it closes.

  Everything else is read-only: `y` shows the YAML, `e`, `h` and `Ctrl-D` stay absent. A role or a
  binding is changed in Rancher.
- **Storage** (`:storage`, `:pv`) — `kubectl get pvc` says a PVC is `Pending`, never why. Here:
  missing StorageClass, no default class (or two), `WaitForFirstConsumer` waiting on a pod, class
  with no provisioner — and when the provisioner left a `ProvisioningFailed` event, **its** message
  wins. Also: `Released` PVs (data sitting idle), `reclaimPolicy: Delete` surfaced on the PVC, `RWO`
  PVCs mounted by several pods.
- **Secrets / ConfigMaps / Services / Ingress** — inventories, with TLS certificate expiry and their
  consumers.
- **Diagnostic** (`D`) — a battery of checks: version, system namespaces, CoreDNS, CNI, webhooks,
  Rancher, failing pods, PVs, recent warnings.
- **Extract** (`X`) — full PDF report of the cluster state into `~/Downloads`.
- **AI** (`i`) — sends the current context to an OpenAI-compatible API; the answer is streamed (SSE)
  and rendered as it arrives. `L` re-runs it in the other language.

## Writing to the cluster

All navigation is **read-only**. The only writes are the ones a key explicitly triggers, and they go
through guardrails.

| Key | Write | Guardrails |
|---|---|---|
| `e` | Full `PUT`, locked on `resourceVersion` | **Before**: GitOps-owned object that the next reconcile will overwrite, spec held by a controller, `can-i update` denied, object being deleted, spec frozen after creation. **After**: every changed field classified *applied* / *ignored* / *rejected by the API* |
| `Ctrl-D` | `delete` with *background* propagation | GitOps ownership, GitOps entry point (Kustomization/HelmRelease/Application), `Namespace` and CRD (cascade), `ownerReferences`, system namespace, finalizers |
| `h` | Merge patch of two annotations | None — it is the lightest gesture on this list |
| `o` (Nodes) | `spec.unschedulable` patch, then evictions | Full drain report before a single eviction |
| `r` / `z` | Reconcile, suspend, scale, restart, renew | Armed confirmation inside the menu |
| `Ctrl-R` | Delete an admission config, strip finalizers | Type the object's exact name |
| `o` (Rancher) | Create a `Token`, patch its `.ttl`, delete a `Token`, patch a `Setting` | Armed confirmation, then an entry whose unit is shown; refused on a downstream cluster; the issued secret is shown once and written nowhere |

**No warning blocks**, but **the default answer is no**: `Enter` and `Esc` both cancel, and only the
key that opened the pane moves towards the write. A ⛔ finding (`e`, `Ctrl-D`, drain) requires
**retyping the object's exact name** to override.

### Worth knowing

- **`e`** — editor picked in order: `$KDT_EDITOR`, `$KUBE_EDITOR`, `$VISUAL`, `$EDITOR`, else `vi`
  (arguments allowed: `KDT_EDITOR="nvim -u NONE"`). The temp file is `0600` (a `Secret` passes
  through it) and wiped when the pane closes. Invalid YAML or an API refusal sends you back to the
  editor with the buffer intact.
- **`h`** — sets `kdt.io/touched-at` (**millisecond** timestamp, and it matters: a patch that
  changes nothing doesn't bump `resourceVersion`, so it calls no webhook) and `kdt.io/touched-by`.
  Used to push an object back through admission: re-evaluate a Kyverno policy, wake a controller.
  **No confirmation** — in the events view, where the cursor follows the stream, freeze it (`s`)
  before touching; the status bar always names the object actually touched.
- **Targeting** — in the events view, `y`/`e`/`h`/`Ctrl-D` act on the object the **event is about**
  (its `involvedObject`), never on the Event. In Kyverno, a violation row targets the **offending
  resource**, a policy row targets the policy.
- **`E`** — shell into a pod: kdt **hands the terminal to `kubectl exec -it`** and takes it back
  afterwards, exactly as `e` hands it to `$EDITOR`. It is the only feature depending on an external
  binary, and a missing one is reported before the screen is given away.

## Configuration

Optional JSON file, looked up in order: `$KDT_CONFIG` (or `$KEV_CONFIG`),
`$XDG_CONFIG_HOME/kdt/config.json`, `~/.config/kdt/config.json`.

```json
{
  "language": "en",
  "active_provider": "openai",
  "providers": [
    {
      "name": "openai",
      "base_url": "https://api.openai.com/v1",
      "api_key": "sk-...",
      "model": "gpt-4o",
      "context_window": 128000
    },
    { "name": "local", "base_url": "http://localhost:11434/v1", "api_key": "ollama", "model": "qwen2.5-coder" }
  ]
}
```

`m` cycles through providers at runtime; the active one shows in the AI status bar (`[EN · openai]`).
The flat `openai_base_url` / `openai_api_key` / `openai_model` keys and the environment variables are
still supported as a `default` provider.

`context_window` is the model's window **in tokens**. When set, kdt bounds the prompt to fit: ~4096
tokens reserved for the answer, then the prompt is filled by priority (event and status first, logs,
then context), dropping the lowest-priority sections and saying so in the prompt. The value is never
sent to the API. Behind a multi-model proxy, declare the window of the **smallest** reachable model.

### Language

The whole UI is bilingual (panes, diagnostics, PDF reports, prompts). Selection order: the
`language` config key, then the system locale (`LC_ALL`, `LC_MESSAGES`, `LANG`, `LANGUAGE` — `fr*`
gives French, anything else English), else French.

`L` switches at runtime, even inside a view, and rewrites **only the `language` key** of the config
file (everything else, permissions included, is left alone). Kubernetes jargon stays in English on
both sides (`pod`, `node`, `taint`, `requests`…), as do column headers.

### Environment variables

| Variable | Role |
|---|---|
| `OPENAI_API_KEY` | AI API key |
| `OPENAI_BASE_URL` / `OPENAI_API_BASE` | OpenAI-compatible endpoint |
| `OPENAI_MODEL` | Model |
| `OPENAI_CONTEXT_WINDOW` | Context window of the `default` provider |
| `KDT_KUBECTL` | Binary used by `E` (default: `kubectl` from `PATH`) |
| `KDT_EXEC_SHELL` | Command passed to `sh -c` by `E` (default: `bash` if present, else `sh`) |
| `KDT_CONFIG` / `KEV_CONFIG` | Config file path |
| `KDT_LOG` / `KEV_LOG` | Log file path |
| `RUST_LOG` | Log filter (`warn` by default) |

## Security / privacy

- **Data sent to the AI**: `i` and `X` transmit the current cluster context — event message, **pod
  logs** (up to 200 lines), status, related resources. Logs may contain secrets: use trusted
  endpoints only. Only bookkeeping metadata is stripped, not application data.
- **Endpoint**: an `http://` `base_url` sends the key and the payload in the clear. Prefer `https://`
  or a local endpoint.
- **API key**: stored in clear text in `config.json` — `chmod 600`. It is never logged.
- **Cluster access**: read-only apart from the writes listed above, all of which the API refuses if
  the kubeconfig isn't allowed. Two shell-outs, both on demand: `$EDITOR` (`e`) and
  `kubectl exec -it` (`E`).
- **PDF rendering**: AI content is escaped before being evaluated as Typst markup, and code blocks
  go through `raw()` — no injection possible.

## Development

```bash
cargo build --release       # target/release/kdt
packaging/build-deb.sh      # → dist/kdt_<version>_amd64.deb
packaging/build-rpm.sh      # → dist/x86_64/kdt-<version>-1.x86_64.rpm
packaging/build-all.sh      # both
```

Release profile: `lto = thin`, `codegen-units = 1`, `panic = abort`, stripped symbols, `mimalloc`
allocator. A static musl target is configured (`target/x86_64-unknown-linux-musl`) and is what the
packages ship. The packaging scripts need no root, write into `dist/`, and read name and version
from `Cargo.toml`; they require `dpkg-deb` / `rpmbuild`.

Application logs: `$KDT_LOG`, `$XDG_STATE_HOME/kdt/kdt.log`, `~/.local/state/kdt/kdt.log`, else
`/tmp/kdt.log`. PDF reports: `~/Downloads/kdt-extract-<context>-<timestamp>.pdf`.

### Modules (`src/`)

| Module | Role |
|---|---|
| `main.rs` · `cli.rs` · `config.rs` | Bootstrap, arguments (clap), config file |
| `ui.rs` | ratatui TUI: modes, rendering, keyboard |
| `events.rs` | Event watcher, logs, status, nodes, usage |
| `pods.rs` · `svc.rs` · `configmaps.rs` | Workloads, Services/Ingress, ConfigMaps |
| `flux.rs` · `repair.rs` | FluxCD (inventory, reconcile, tree) and the `Ctrl-R` unblock |
| `rbac.rs` · `secrets.rs` · `certmanager.rs` | Scored RBAC, Secrets/TLS, cert-manager chain |
| `kyverno.rs` · `reflector.rs` · `vulnerabilities.rs` | Kyverno, Reflector, CVEs |
| `velero.rs` | Velero: backups, schedules (cron evaluated), restores, locations |
| `rancher.rs` | Rancher: accounts and their real identities, bindings, projects, tokens and TTL settings |
| `k8ssandra.rs` · `mgmtapi.rs` | K8ssandra/Medusa/Reaper, and the Cassandra management API through the apiserver proxy |
| `storage.rs` | PVC / PV / StorageClass and their diagnostic rules |
| `yaml.rs` · `edit.rs` · `delete.rs` · `touch.rs` | YAML, edit, delete, touch |
| `diagnostic.rs` · `extract.rs` · `pdf.rs` | Diagnostic, extraction, Typst rendering |
| `enrich.rs` · `ai.rs` | Context related to an event, OpenAI client |
| `lang.rs` · `clip.rs` | FR/EN string table, OSC 52 clipboard |

Stack: Rust 2021 · `kube` 3.1 (rustls, socks5) · `k8s-openapi` 0.27 · `ratatui` 0.30 · `tokio` ·
`reqwest` · `typst` 0.14.

## License

[Apache 2.0](LICENSE).
