// Ce que l'API rend, tel quel.
//
// Ces types suivent la sérialisation des structures de `kdt-core` : les noms de champs sont ceux
// de Rust, sans conversion. Renommer côté serveur pour faire joli en TypeScript ajouterait une
// couche de traduction où une divergence pourrait se cacher.

/** Sévérité d'un évènement, telle que Kubernetes la donne. */
export type Severity = "normal" | "warning";

/**
 * Le verdict, calculé par kdt côté serveur.
 *
 * Kubernetes n'a que deux sévérités ; le troisième niveau est une règle de kdt — un
 * `CrashLoopBackOff` n'est pas la même nouvelle qu'une sonde qui a hoqueté. Il arrive tout
 * calculé : le front le peint, il ne le rejuge pas, sinon les deux interfaces finiraient par
 * dire deux choses du même évènement.
 */
export type ToneVerdict = "ok" | "warn" | "err";

/** Un évènement, aplati par `EventRecord::from_k8s`. */
export interface EventRecord {
  uid: string;
  /** RFC 3339. L'horodatage le plus précis disponible, choisi côté serveur. */
  time: string;
  severity: Severity;
  reason: string;
  api_version: string;
  kind: string;
  namespace: string;
  name: string;
  message: string;
  component: string;
  host: string;
  count: number;
  tone: ToneVerdict;
}

export interface EventsPayload {
  /** La portée effectivement interrogée. Vide : tout le cluster. */
  scope: string[];
  rows: EventRecord[];
}

/**
 * La pression d'une consommation sur sa base, telle que kdt la juge.
 *
 * `over` sur une **limite** veut dire throttlé (CPU) ou tué (mémoire) ; sur une *requête*, c'est
 * banal — la requête est une réservation, pas un plafond. La bande dit la pression, c'est la base
 * qui dit comment la lire.
 */
export type Pressure = "ok" | "high" | "very-high" | "over";

/** Un ratio d'usage, ou `null` quand la mesure ou la base manque. */
export interface UsagePct {
  pct: number;
  pressure: Pressure;
}

/** Les quatre ratios que porte une ligne de pod ou de container. */
export interface UsageRatios {
  cpu_req_pct: UsagePct | null;
  cpu_lim_pct: UsagePct | null;
  mem_req_pct: UsagePct | null;
  mem_lim_pct: UsagePct | null;
}

/** Où un container se situe dans le cycle de vie du pod. */
export type ContainerKind = "init" | "regular" | "ephemeral";

/** Un container d'un pod, tel que la vue le montre : le spec joint au status, plus les métriques. */
export interface ContainerRow extends UsageRatios {
  uid: string;
  namespace: string;
  pod: string;
  name: string;
  /** Le nom préfixé par sa famille : `init:migrate`, `eph:debugger`. */
  display_name: string;
  image: string;
  kind: ContainerKind;
  ready: boolean;
  state: string;
  restarts: number;
  age: string;
  cpu_milli: number | null;
  mem_bytes: number | null;
  cpu_req: number | null;
  cpu_lim: number | null;
  mem_req: number | null;
  mem_lim: number | null;
  tone: LineTone;
  restarts_tone: LineTone;
  /** Seul un container qui tourne peut recevoir un `exec` — un init `Completed` n'en est pas un. */
  running: boolean;
  record: EventRecord;
}

/** Le workload dont un pod provient, après résolution ReplicaSet → Deployment. */
export interface OwnerRef {
  kind: string;
  name: string;
  namespace: string;
  api_version: string;
}

export interface PodRow extends UsageRatios {
  uid: string;
  namespace: string;
  name: string;
  /** `prêts/total` sur les containers, tel que kubectl le compte. */
  ready: string;
  status: string;
  restarts: number;
  age: string;
  node: string;
  ip: string;
  owner: OwnerRef | null;
  cpu_milli: number | null;
  mem_bytes: number | null;
  cpu_req: number | null;
  cpu_lim: number | null;
  mem_req: number | null;
  mem_lim: number | null;
  containers: ContainerRow[];
  status_tone: LineTone;
  row_tone: LineTone;
  restarts_tone: LineTone;
  /** L'uid du workload auquel kdt rattache ce pod. `null` = orphelin (pod nu, ReplicaSet seul). */
  group: string | null;
  record: EventRecord;
}

/** Où en est un Job, lu sur ses conditions comme `kubectl get jobs` les lit. */
export type JobStatus = "complete" | "failed" | "suspended" | "running";

export interface JobState {
  succeeded: number;
  /** `spec.completions`, laissé `null` quand le spec ne le fixe pas plutôt que supposé à 1. */
  completions: number | null;
  status: JobStatus;
}

export interface WorkloadRow {
  uid: string;
  kind: string;
  api_version: string;
  namespace: string;
  name: string;
  /** `spec.replicas` seulement : c'est aussi le témoin que ce kind se scale. */
  replicas: number | null;
  ready_replicas: number;
  /** Le nombre désiré d'un kind qui en a un sans `spec.replicas` (DaemonSet). */
  desired: number | null;
  job: JobState | null;
  age: string;
  /** READY comme ce kind le compte : répliques, pods programmés, ou complétions. */
  ready_label: string;
  /** Sans compteur de référence, la ligne se nomme au lieu de se juger : l'étiquette est le kind. */
  status_label: string;
  status_tone: LineTone;
  scalable: boolean;
  restartable: boolean;
  record: EventRecord;
}

export interface WorkloadsPayload {
  workloads: WorkloadRow[];
  pods: PodRow[];
  /** Les kinds que l'apiserver a refusés. « Aucun Job » et « pas le droit de regarder » diffèrent. */
  missing_kinds: string[];
}

/** Bande d'urgence d'un certificat TLS, calculée par kdt sur les jours restants. */
export type Expiry = "expired" | "critical" | "warn" | "ok";

export interface CaBundle {
  subject_cn: string;
  not_after: string;
  days_remaining: number;
}

/** Le certificat feuille d'un secret TLS. La clé privée n'est jamais lue ni transmise. */
export interface TlsCert {
  subject_cn: string;
  issuer_cn: string;
  self_signed: boolean;
  is_ca: boolean;
  sans: string[];
  not_before: string;
  not_after: string;
  days_remaining: number;
  expiry: Expiry;
  serial: string;
  key_algo: string;
  ca_bundle: CaBundle | null;
}

/**
 * Un Secret, **sans ses valeurs**.
 *
 * Ni `data` ni `manifest` ne traversent le réseau : le manifeste d'un Secret contient ses valeurs,
 * et une liste rafraîchie toutes les dix secondes les promènerait toutes. Une valeur se demande
 * une par une — voir `api.revealSecret`.
 */
export interface SecretRow {
  uid: string;
  namespace: string;
  name: string;
  type_: string;
  /** Les noms des clés seulement. Ce qu'elles contiennent n'est pas ici. */
  data_keys: string[];
  age: string;
  is_tls: boolean;
  tls: TlsCert | null;
  /** Secret de type TLS dont le certificat n'a pas pu être décodé, avec la raison. */
  tls_error: string | null;
  ingress_refs: string[];
  cert_manager: string | null;
  provenance_label: string;
  /** Le ton de l'échéance, ou `null` quand la ligne ne porte pas de certificat à juger. */
  expiry_tone: LineTone | null;
  record: EventRecord;
}

/** Le filtre de la vue, tel que kdt le cycle : tout, TLS seulement, ou ce qui n'est pas sain. */
export type SecretFilter = "all" | "tls" | "expiring";

export interface SecretsPayload {
  secrets: SecretRow[];
  cert_manager_present: boolean;
  counts: { total: number; tls: number; expired: number; expiring: number };
}

/** Une valeur révélée, dans les deux formes que le TUI propose sous `b` et `d`. */
export interface SecretValue {
  key: string;
  base64: string;
  /** `null` quand les octets ne sont pas du texte : une valeur binaire n'a pas de forme décodée. */
  text: string | null;
  bytes: number;
}

export interface ConfigMapRow {
  uid: string;
  namespace: string;
  name: string;
  /** Les clés texte avec leur valeur : une ConfigMap n'est pas un secret, elle s'affiche. */
  data: Array<[string, string]>;
  /** Les clés de `binaryData` — nom seulement, ce n'est pas du texte. */
  binary_keys: string[];
  keys: string[];
  age: string;
  total_bytes: number;
  provenance_label: string;
  record: EventRecord;
}

/**
 * Ce que ce cluster sait faire : les add-ons dont les CRD y sont enregistrés.
 *
 * Le rail ne montre que les vues qui ont un sujet. Un champ à `false` veut dire « ce cluster n'a
 * pas cet add-on », pas « vous n'y avez pas droit » : la sonde est la liste des groupes d'API,
 * couverte par `system:discovery`, donc elle répond la même chose à tout le monde.
 */
export interface Capabilities {
  flux: boolean;
  argocd: boolean;
  velero: boolean;
  certs: boolean;
  kyverno: boolean;
  identity: boolean;
  k8ssandra: boolean;
  rancher: boolean;
}

/**
 * Une ressource du bandeau : ce qui est alloué, ce qui est utilisé, et à quel point c'est tendu.
 *
 * `used`, `pct` et `tone` sont `null` sans metrics-server : l'allocation se lit sur les nodes et
 * reste vraie, l'usage ne se devine pas. Les quantités arrivent déjà formatées — `3.4`, `62Gi` —
 * parce que c'est le serveur qui sait les écrire comme Kubernetes les dit.
 */
export interface ClusterResource {
  used: string | null;
  alloc: string;
  pct: number | null;
  /** Le palier d'occupation, choisi par kdt. Le front le peint, il ne le rejuge pas. */
  tone: "ok" | "info" | "warn" | "err" | null;
}

/**
 * Le bandeau : quel cluster on regarde, et dans quel état il est.
 *
 * `nodes`, `cpu` et `mem` sont `null` ensemble quand la liste des nodes a été refusée — ils en
 * viennent tous les trois. Un `0/0 ready` vert affirmerait un cluster sain qu'on n'a pas regardé.
 */
export interface ClusterBanner {
  cluster: string;
  /** L'adresse de l'apiserver : ce qui rend un mauvais cluster évident. */
  apiserver: string;
  server_version: string | null;
  nodes: { ready: number; total: number; tone: "ok" | "warn" } | null;
  cpu: ClusterResource | null;
  mem: ClusterResource | null;
  metrics_available: boolean;
}

/** Qui est connecté. */
export interface Identity {
  authenticated: true;
  /** Identité vue par l'apiserver, préfixe compris. */
  subject: string;
  groups: string[];
  /** Ce que le cluster remet : `certificate` ou `oidc`. */
  mode: string;
}

/**
 * L'état de réconciliation d'une ressource Flux, tel que `kdt::flux::FluxReady` le juge.
 *
 * `not-applicable` n'est pas un trou dans la donnée : une HelmRepository OCI est une référence
 * statique que source-controller ne réconcilie pas, donc elle n'expose aucune condition Ready.
 * L'annoncer « inconnue » ferait chercher une panne là où il n'y a rien à réconcilier.
 */
export type FluxReady = "ready" | "reconciling" | "failed" | "unknown" | "not-applicable";

/** Une ligne de l'arbre Flux : la ressource, son verdict, et sa place dans l'arbre. */
export interface FluxRow {
  /** `kind|namespace/name` — l'identité stable d'une ligne d'un rafraîchissement à l'autre. */
  uid: string;
  kind: string;
  api_version: string;
  namespace: string;
  name: string;
  ready: FluxReady;
  suspended: boolean;
  message: string;
  revision: string;
  /** Forme compacte déjà calculée côté serveur : `3s`, `12m`, `4h`, `6d`. */
  age: string;
  /** `spec.prune` d'une Kustomization, `null` pour les kinds qui n'ont pas ce champ. */
  prune: boolean | null;
  /** Profondeur dans l'arbre. Les arêtes sont résolues par kdt ; ceci en est le résultat. */
  depth: number;
  has_children: boolean;
  /** L'étiquette READY, dans les mots du TUI. */
  ready_label: string;
  /** Le ton de cette étiquette. Jaune sur `Suspended` : l'état explique pourquoi rien ne bouge. */
  ready_tone: LineTone;
  /** Le ton de la ligne entière, qui n'est pas celui de l'étiquette. */
  row_tone: LineTone;
  /** Cette Kustomization laisse derrière elle ce qui a disparu de git. */
  no_prune: boolean;
  /** L'enregistrement que le panneau d'inspection ouvre, fabriqué par kdt. */
  record: EventRecord;
}

export interface FluxCounts {
  total: number;
  ready: number;
  failed: number;
  reconciling: number;
  unknown: number;
  suspended: number;
}

export interface FluxPayload {
  rows: FluxRow[];
  counts: FluxCounts;
  /** Un kind illisible — le RBAC, le plus souvent. Les autres lignes restent vraies. */
  error: string | null;
}

/** Un objet appliqué par une Kustomization, avec son état vivant. */
export interface InventoryItem {
  uid: string;
  api_version: string;
  kind: string;
  namespace: string;
  name: string;
  ready: boolean | null;
  reconciling: boolean;
  msg: string;
  ready_label: string;
  tone: LineTone;
  record: EventRecord;
}

export interface InventoryPayload {
  items: InventoryItem[];
  prune?: boolean;
  error?: string;
}

/**
 * Jusqu'où porte une demande de réconciliation.
 *
 * `force` et `reset` ne veulent dire quelque chose que pour helm-controller, et le serveur refuse
 * ailleurs plutôt que d'écrire une annotation que personne ne lit — un « ✓ » doit vouloir dire
 * qu'on a demandé quelque chose à un controller, pas qu'un patch est passé.
 */
export type ReconcileScope = "resource" | "with-source" | "root-sync" | "force" | "reset";

/**
 * Cet enregistrement a-t-il des logs à montrer ?
 *
 * Le serveur décide *lesquels* — les siens pour un Pod, ceux de son controller filtrés sur elle
 * pour une ressource Flux. Ici on ne décide que d'activer l'onglet, sur les deux mêmes critères,
 * pour ne pas proposer un onglet qui rendrait une page vide.
 */
export function hasLogs(record: EventRecord): boolean {
  if (!record.namespace || !record.name) return false;
  return record.kind === "Pod" || record.component === "flux";
}

/** Une réponse de l'API qui demande de repasser par le portail. */
export interface ApiRefusal {
  error: string;
  reauthenticate?: boolean;
}

/** L'étiquette que le TUI affiche pour ce ton, reprise telle quelle. */
export function toneLabel(tone: ToneVerdict): string {
  return tone === "err" ? "ERR" : tone === "warn" ? "WARN" : "OK";
}

/** Une section de contexte autour d'un évènement, rendue par `gather_extra_context`. */
export interface RelatedSection {
  title: string;
  /** JSON compact, ré-indenté à l'affichage. */
  body: string;
}

/** Le ton d'une ligne de status, tel que kdt le donne. */
export type LineTone = "plain" | "ok" | "warn" | "err" | "info" | "dim";

/** Une ligne de l'onglet Status, avec le ton que le TUI lui donne. */
export interface StatusLine {
  tone: LineTone;
  text: string;
}

export interface StatusPayload {
  lines: StatusLine[];
  /** L'objet a disparu, ou sa lecture est refusée. Ce n'est pas « aucun état ». */
  error?: string;
}

/** Les logs d'un pod, et les containers qu'il contient. */
export interface PodLogs {
  lines: string[];
  containers: string[];
}

/** L'âge d'un horodatage, dans la forme compacte du TUI : `3s`, `12m`, `4h`, `6d`. */
export function age(iso: string, now: number = Date.now()): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "—";
  const seconds = Math.max(0, Math.floor((now - then) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

// --- Vue certs (cert-manager) --------------------------------------------------------------------

/**
 * Où en est un objet cert-manager, tel que `kdt::certmanager::parse_ready` le juge.
 *
 * Le piège que ce verdict absorbe : Issuers, Certificates et CertificateRequests publient leur état
 * dans `status.conditions`, mais **Orders et Challenges portent un simple `status.state`**. Lire les
 * conditions seules afficherait tout l'ACME en `unknown` — précisément ce qu'on vient regarder.
 */
export type CmReady = "ready" | "in-progress" | "failed" | "unknown";

/** Un constat de la chaîne, rédigé par kdt. C'est ce que cette vue apporte de plus qu'un `get`. */
export interface CertHint {
  level: "info" | "warn" | "danger";
  text: string;
}

/**
 * Un fichier qu'un keystore doit produire dans le Secret.
 *
 * `present` à `null` veut dire que les clés du Secret ne sont pas connues — lecture refusée, ou
 * portée qui ne le couvre pas. Ni présent, ni absent : on ne sait pas, et on ne l'affirme pas.
 */
export interface KeystoreFile {
  key: string;
  present: boolean | null;
}

export interface KeystorePasswordRef {
  name: string;
  key: string;
  secret_found: boolean | null;
  key_found: boolean | null;
}

export interface CertKeystore {
  format: string;
  alias: string | null;
  files: KeystoreFile[];
  /** `null` quand le mot de passe est donné littéralement dans le spec : rien à résoudre. */
  password_ref: KeystorePasswordRef | null;
}

/** Le Secret qu'un Certificate produit, et ce que la vue Secrets en sait. */
export interface ProducedSecret {
  secret_name: string;
  namespace: string;
  /** Les faits sont-ils établis ? Faux = inconnu, ce qui n'est pas « absent ». */
  known: boolean;
  found: boolean | null;
  days_remaining: number | null;
  ingress_refs: number | null;
  keystores: CertKeystore[];
  renewal_time: string | null;
  not_after: string | null;
}

/** Une cible d'action, telle que le serveur l'a nommée. */
export interface CertActionTarget {
  apiVersion: string;
  namespace: string;
  name: string;
}

/**
 * Les deux leviers de la chaîne.
 *
 * `acme_retry` ne nomme une cible que s'il y a une demande vivante à relancer — et jamais sous quota
 * ACME, où réessayer ne fait que brûler ce qui reste. C'est kdt qui tranche, pas le bouton.
 */
export interface CertActions {
  renew: boolean;
  acme_retry: CertActionTarget | null;
  rate_limited: boolean;
}

export interface ChallengeInfo {
  type_: string;
  dns_name: string;
  /** Le solveur a-t-il réellement publié l'enregistrement ou la route ? */
  presented: boolean;
}

/** Une ligne de la chaîne : un objet cert-manager, avec sa place dans l'arbre et son verdict. */
export interface CertResourceRow {
  row: "resource";
  uid: string;
  kind: string;
  /** Le kind raccourci pour la colonne de l'arbre : `CertRequest` plutôt que `CertificateRequest`. */
  kind_short: string;
  api_version: string;
  namespace: string;
  name: string;
  ready: CmReady;
  ready_label: string;
  ready_glyph: string;
  ready_tone: LineTone;
  message: string;
  age: string;
  days_remaining: number | null;
  expiry_tone: LineTone | null;
  /** Ce que la ligne vise : ses DNS, le Secret qu'elle écrit, ou le challenge qu'elle valide. */
  target: string;
  keystore_formats: string[];
  depth: number;
  has_children: boolean;
  /** Le rang dans l'ordre de kdt : problèmes d'abord, puis l'échéance la plus proche. */
  rank: number;
  issuer_type: string | null;
  challenge: ChallengeInfo | null;
  dns_names: string[];
  secret_name: string | null;
  not_after: string | null;
  renewal_time: string | null;
  /** Le Certificate qui commande cette ligne, quel que soit l'étage de la chaîne où l'on est. */
  cert_uid: string | null;
  hints: CertHint[];
  /** Sur une ligne Certificate seulement : le Secret produit et ses keystores. */
  produced?: ProducedSecret | null;
  actions?: CertActions;
  record: EventRecord;
}

/** La feuille TLS qui ferme une chaîne : le Secret que l'Ingress sert réellement. */
export interface CertSecretRow {
  row: "secret";
  uid: string;
  namespace: string;
  name: string;
  depth: number;
  has_children: false;
  days_remaining: number | null;
  expiry_tone: LineTone | null;
  ingress_refs: number;
  record: EventRecord;
}

export type CertRow = CertResourceRow | CertSecretRow;

/** Le filtre de la vue, tel que kdt le cycle sur `f`. Il garde les ancêtres de ce qu'il retient. */
export type CertFilter = "all" | "problems" | "in-flight";

export interface CertsPayload {
  rows: CertRow[];
  counts: { total: number; ready: number; failed: number; in_flight: number; expiring: number };
  /** Les CRD cert-manager sont-elles là ? Absentes, la vue n'a pas de sujet. */
  installed: boolean;
  /** Le groupe ACME est absent d'un cluster qui n'émet que depuis une CA : ce n'est pas une panne. */
  acme_installed: boolean;
  error: string | null;
  /** Les Secrets n'ont pas pu être lus : les constats s'abstiennent au lieu d'affirmer une absence. */
  secrets_error: string | null;
}

// --- Vue Kyverno ----------------------------------------------------------------------------------
//
// La jointure que Kyverno ne fait pas lui-même : une policy, ses règles — y compris les `autogen-*`
// qu'il a dérivées et que les rapports sont seuls à nommer — et les ressources qui échouent dessus.
// Tout ce qui juge est calculé par `kdt::kyverno` ; ce qui suit n'est que la forme de ce qu'il rend.

/** Ce qu'une règle fait quand elle échoue. `Deny` du moteur CEL et `Enforce` sont la même posture. */
export type KyAction = "none" | "audit" | "warn" | "enforce";

/** Le verdict d'une ligne de rapport. `error` est une policy cassée, pas une ressource fautive. */
export type KyResult = "pass" | "skip" | "warn" | "fail" | "error";

export interface KyCounts {
  pass: number;
  fail: number;
  warn: number;
  error: number;
  skip: number;
}

/** Ce que chaque ligne de l'arbre porte, quel que soit ce qu'elle désigne. */
interface KyRowBase {
  uid: string;
  depth: number;
  has_children: boolean;
  /** Le pli que kdt poserait : sain replié, en peine ouvert. Un pli manuel gagne toujours. */
  fold_default: boolean;
  record: EventRecord;
}

export interface KyPolicyRow extends KyRowBase {
  row: "policy";
  kind: string;
  /** Le kind raccourci pour la colonne de l'arbre. */
  kind_short: string;
  api_version: string;
  namespace: string;
  name: string;
  title: string;
  action: KyAction;
  action_label: string;
  action_tone: LineTone;
  /** Vrai quand la policy refuse des écritures à l'admission. */
  blocks: boolean;
  background: boolean;
  admission: boolean;
  ready: "ready" | "not-ready" | "unknown";
  ready_label: string;
  ready_glyph: string;
  ready_tone: LineTone;
  ready_message: string;
  /** Elle ne peut pas s'évaluer, ou une règle est en erreur : elle ne protège rien. */
  alarming: boolean;
  /** À quoi elle s'applique, lu sur ses règles écrites — pas sur celles que Kyverno a dérivées. */
  scope: string;
  summary: string;
  counts: KyCounts;
  rules: KyRule[];
  exceptions: KyExceptionInfo[];
  overrides: KyOverride[];
  schedule: string | null;
  age: string;
}

export interface KyRule {
  name: string;
  /** validate | mutate | generate | verifyImages | cel — ce que la règle fait. */
  verb: string;
  /** Dérivée par Kyverno d'une règle sur Pod. Ce sont ces noms-là que les rapports emploient. */
  autogen: boolean;
  action: KyAction;
  match_summary: string;
  message: string;
  counts: KyCounts;
}

export interface KyRuleRow extends KyRowBase, KyRule {
  row: "rule";
  policy_uid: string;
  policy_name: string;
  action_label: string;
  action_tone: LineTone;
  /** Sa posture n'est pas celle de la policy : la colonne ACTION du dessus ne vaut pas pour elle. */
  differs: boolean;
  summary: string;
}

export interface KyExceptionInfo {
  api_version: string;
  namespace: string;
  name: string;
  /** Les règles excusées ; vide veut dire toutes. */
  rules: string[];
  match_summary: string;
}

export interface KyExceptionRow extends KyRowBase, KyExceptionInfo {
  row: "exception";
  policy_uid: string;
}

/** Une posture propre à certains namespaces : sans elle la colonne ACTION ment. */
export interface KyOverride {
  action: KyAction;
  namespaces: string[];
}

export interface KyViolation {
  policy_uid: string;
  policy: string;
  rule: string;
  result: KyResult;
  severity: string;
  category: string;
  message: string;
  api_version: string;
  kind: string;
  namespace: string;
  name: string;
  /** « background scan » ou « admission review request » : comment le constat a été produit. */
  process: string;
  age: string;
}

export interface KyViolationRow extends KyRowBase, KyViolation {
  row: "violation";
  result_label: string;
  result_glyph: string;
  /** La ressource fautive, en une étiquette. */
  target: string;
  is_problem: boolean;
}

export interface KyNamespaceRow extends KyRowBase {
  row: "namespace";
  name: string;
  counts: KyCounts;
  summary: string;
  alarming: boolean;
}

export interface KyResourceRow extends KyRowBase {
  row: "resource";
  kind: string;
  namespace: string;
  name: string;
  counts: KyCounts;
  summary: string;
}

export type KyRow =
  | KyPolicyRow
  | KyRuleRow
  | KyViolationRow
  | KyExceptionRow
  | KyNamespaceRow
  | KyResourceRow;

/**
 * L'état de l'installation, avant toute policy.
 *
 * `inactive` est le seul que rien d'autre ne rapporte : tous les controllers verts alors qu'aucun
 * webhook n'est enregistré veut dire que Kyverno n'intercepte rien du tout.
 */
export type KyHealthState = "unknown" | "degraded" | "inactive" | "ok";

export interface KyHealth {
  state: KyHealthState;
  version: string;
  controllers: Array<{ name: string; ready: number; desired: number; up: boolean }>;
  validating_webhooks: number;
  mutating_webhooks: number;
  /** Faux quand les webhooks n'ont pas pu être lus : zéro ne voudrait alors rien dire. */
  webhooks_known: boolean;
  reports: number;
}

/**
 * La file des `generate` / `mutateExisting`.
 *
 * Muette partout ailleurs : une file bloquée ne laisse ni PolicyReport ni refus d'admission, et
 * les règles qui en dépendent cessent silencieusement de produire quoi que ce soit.
 */
export interface KyBacklog {
  known: boolean;
  total: number;
  pending: number;
  failed: number;
  completed: number;
  skip: number;
  stuck: number;
  /** Au-delà du seuil de kdt : la file ne se draine plus, ce n'est plus un compte mais une panne. */
  pileup: boolean;
  by_policy: Array<[string, number]>;
  oldest_stuck: string | null;
  ephemeral_reports: number;
}

/** Un refus d'admission, tel que l'Event le raconte. Il n'existe nulle part ailleurs. */
export interface KyDenial {
  age: string;
  target: string;
  rule: string;
  message: string;
}

/** Le filtre des policies, tel que kdt le cycle sur `f`. */
export type KyFilter = "all" | "problems" | "enforce";

export interface KyvernoPayload {
  rows: KyRow[];
  counts: {
    policies: number;
    enforce: number;
    not_ready: number;
    fail: number;
    warn: number;
    error: number;
    violations: number;
  };
  health: KyHealth;
  backlog: KyBacklog;
  /** Les refus d'admission, par nom de policy. */
  denials: Record<string, KyDenial[]>;
  /** Les évènements n'ont pas pu être lus : la section se tait au lieu d'affirmer zéro refus. */
  denials_error: string | null;
  installed: boolean;
  /** Le moteur CEL est absent avant Kyverno 1.14 : ce n'est pas une panne. */
  cel_installed: boolean;
  error: string | null;
}

// --- Vue RBAC -------------------------------------------------------------------------------------
//
// Ce que cette vue apporte n'est pas la liste des liaisons mais le **score** et le **graphe** : un
// Role seul n'accorde rien tant qu'il n'est pas lié, et le même ClusterRole est anodin en
// RoleBinding et critique en ClusterRoleBinding. La sévérité, les constats et les arêtes viennent
// tous de `kdt::rbac`.

export type RbacSeverity = "info" | "low" | "medium" | "high" | "critical";

/** Par quel bout le graphe est lu. C'est le `t` du TUI. */
export type RbacOrient = "flat" | "subject" | "binding" | "role";

/**
 * D'où vient un objet, lu sur ses propres labels et ownerRefs.
 *
 * Kyverno, Rancher, les défauts du cluster et les gestionnaires d'add-ons posent des objets sans
 * passer par kubectl : ils sont **attribués**, donc jamais rangés avec les grants orphelins.
 */
export type RbacProvenance =
  | { source: "flux-kustomization"; namespace: string; name: string }
  | { source: "flux-helm-release"; namespace: string; name: string }
  | { source: "helm"; namespace: string; name: string }
  | { source: "argo"; app: string }
  | { source: "kyverno"; policy: string }
  | { source: "rancher"; binding: string }
  | { source: "bootstrap" }
  | { source: "addon"; by: string }
  | { source: "owner"; kind: string; name: string }
  | { source: "kubectl" }
  | { source: "unmanaged" };

/** Une règle résolue, telle qu'une colonne la montre. `—` quand le champ est vide. */
export interface RbacRule {
  verbs: string;
  resources: string;
  api_groups: string;
  resource_names: string[];
}

/** Un constat scoré, avec sa raison. */
export interface RbacFinding {
  sev: RbacSeverity;
  tag: string;
  detail: string;
}

/** Ce que chaque ligne de l'arbre porte, quel que soit ce qu'elle désigne. */
interface RbacRowBase {
  uid: string;
  depth: number;
  has_children: boolean;
  /** Le pli que kdt poserait : tout ce dont le pire nœud est sous HIGH se referme. */
  fold_default: boolean;
  /**
   * L'identité du **nœud**, à distinguer de `uid` qui est sa place dans la liste : un ClusterRole
   * atteint par deux liaisons se replie d'un seul geste, partout où il apparaît.
   */
  fold_key: string | null;
  record: EventRecord;
}

export interface RbacBindingRow extends RbacRowBase {
  row: "binding";
  binding_kind: string;
  binding_name: string;
  severity: RbacSeverity;
  sev_label: string;
  sev_icon: string;
  scope_label: string;
  /** Namespace critique : un pied dans la porte y escalade tout le cluster. */
  scope_alarming: boolean;
  role_label: string;
  /** Le premier sujet, et combien d'autres. Une ligne ne porte pas dix identités. */
  subject_label: string;
  subject_rows: Array<{ label: string; short_label: string; kind: string; missing: boolean }>;
  provenance: RbacProvenance;
  provenance_label: string;
  source: string | null;
  /** Le pire constat seul : la liste complète est dans le panneau. */
  risk_top: string;
  risk_tags: string;
  findings: RbacFinding[];
  rule_rows: RbacRule[];
  via_clusterrole: boolean;
  aggregated: boolean;
  age: string;
}

export interface RbacRoleRow extends RbacRowBase {
  row: "role" | "contributor";
  kind_label: string;
  kind_short: string;
  namespace: string;
  name: string;
  severity: RbacSeverity;
  sev_label: string;
  sev_icon: string;
  provenance: RbacProvenance;
  provenance_label: string;
  source: string | null;
  /** Le nombre de règles que l'objet déclare lui-même, avant que l'agrégation le remplisse. */
  own_rules: number;
  aggregated: boolean;
  /** L'union est une borne basse : un sélecteur en `matchExpressions` n'est pas évalué. */
  aggregation_partial: boolean;
  aggregates_names: Array<{ name: string; rules: number }>;
  aggregates_into_names: string[];
  bound_cluster: number;
  bound_namespaces: string[];
  /** Re-accordé dans plusieurs namespaces : édité une fois, il déplace des droits partout. */
  is_template: boolean;
  /** Personne ne le lie : il n'accorde rien aujourd'hui, mais l'offre reste posée. */
  is_unbound: boolean;
  findings: RbacFinding[];
  rule_rows: RbacRule[];
  age: string;
}

export interface RbacSubjectRow extends RbacRowBase {
  row: "subject";
  key: string;
  label: string;
  short_label: string;
  kind: string;
  namespace: string;
  name: string;
  severity: RbacSeverity;
  sev_label: string;
  sev_icon: string;
  /** Le nom est lié, mais aucun ServiceAccount ne porte ce nom. */
  missing: boolean;
  sa: {
    exists: boolean;
    automount: boolean | null;
    secrets: number;
    image_pull_secrets: number;
    provenance: RbacProvenance;
    provenance_label: string;
    source: string | null;
    age: string;
  } | null;
  grants: Array<{
    severity: RbacSeverity;
    sev_label: string;
    sev_icon: string;
    role_label: string;
    scope_label: string;
    risk_top: string;
  }>;
}

export interface RbacNsGroupRow extends RbacRowBase {
  row: "nsgroup";
  namespace: string;
  role_name: string;
  bindings: number;
}

export interface RbacRuleRow extends RbacRowBase, RbacRule {
  row: "rule";
  role_name: string;
}

export interface RbacSubjectLeafRow extends RbacRowBase {
  row: "subject-leaf";
  kind: string;
  name: string;
  label: string;
  short_label: string;
  missing: boolean;
}

export type RbacRow =
  | RbacBindingRow
  | RbacRoleRow
  | RbacSubjectRow
  | RbacNsGroupRow
  | RbacRuleRow
  | RbacSubjectLeafRow;

export interface RbacPayload {
  rows: RbacRow[];
  counts: {
    bindings: number;
    roles: number;
    service_accounts: number;
    info: number;
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  /**
   * La liste des ServiceAccounts n'a pas pu être lue.
   *
   * Tant que c'est vrai, aucun « ce compte n'existe pas » n'est prononcé : une lecture refusée
   * n'est pas une preuve d'absence.
   */
  sa_degraded: boolean;
  scope: string;
  error: string | null;
}

// --- Vue Velero -----------------------------------------------------------------------------------
//
// La question qu'une vue de sauvegarde doit trancher est « si le cluster brûle maintenant, qu'est-ce
// qui revient ? ». Elle est éparpillée sur six kinds et deux silences — un `PartiallyFailed` peint
// comme un succès, et un Schedule qui cesse de se déclencher sans rien dire. Les règles viennent de
// `kdt::velero` ; ce qui suit n'est que la forme de ce qu'il rend.

/** Le monde lu. Les trois partagent une seule lecture du cluster. */
export type VelWorld = "backups" | "restores" | "infra";

/** Un constat de kdt, avec son niveau. */
export interface VelHint {
  level: "info" | "warn" | "danger";
  text: string;
}

interface VelRowBase {
  uid: string;
  depth: number;
  has_problem: boolean;
  hints: VelHint[];
  record: EventRecord;
}

export interface VelScheduleRow extends VelRowBase {
  row: "schedule";
  namespace: string;
  name: string;
  cron: string;
  paused: boolean;
  phase: string;
  phase_tone: LineTone;
  validation_errors: string[];
  last_backup: number | null;
  last_skipped: number | null;
  ttl: number | null;
  included_ns: string[];
  excluded_ns: string[];
  has_selector: boolean;
  snapshot_volumes: boolean | null;
  fs_backup_default: boolean;
  snapshot_move_data: boolean;
  storage_location: string | null;
  /** Calculée par kdt, jamais lue : velero ne publie nulle part quand il déclenchera. */
  next_run: number | null;
  cron_ok: boolean;
  /** Le moteur GitOps qui possède ce Schedule : une pause posée ici y sera défaite. */
  gitops: string | null;
  backups: number;
  age: string;
}

export interface VelBackupRow extends VelRowBase {
  row: "backup";
  namespace: string;
  name: string;
  phase: string;
  phase_tone: LineTone;
  schedule: string | null;
  storage_location: string;
  started: number | null;
  completed: number | null;
  expiration: number | null;
  errors: number;
  warnings: number;
  items_backed_up: number;
  total_items: number;
  failure_reason: string;
  volume_snapshots_attempted: number;
  volume_snapshots_completed: number;
  included_ns: string[];
  excluded_ns: string[];
  ttl: number | null;
  /** Une demande de suppression est déjà en vol pour lui. */
  deleting: boolean;
  delete_errors: string[];
  pvb_total: number;
  pvb_failed: string[];
  restores: number;
  volumes: number;
  /** Il est allé au bout **sans** tout capturer : ce n'est pas une nuance de succès. */
  partially_failed: boolean;
  failed: boolean;
  running: boolean;
  usable: boolean;
  age: string;
}

export interface VelRestoreRow extends VelRowBase {
  row: "restore";
  namespace: string;
  name: string;
  backup: string;
  schedule: string | null;
  phase: string;
  phase_tone: LineTone;
  started: number | null;
  completed: number | null;
  errors: number;
  warnings: number;
  failure_reason: string;
  items_restored: number;
  total_items: number;
  existing_policy: string;
  running: boolean;
  age: string;
}

export interface VelLocationRow extends VelRowBase {
  row: "location";
  namespace: string;
  name: string;
  provider: string;
  bucket: string;
  prefix: string;
  phase: string;
  phase_tone: LineTone;
  default: boolean;
  access_mode: string;
  last_validated: number | null;
  s3_url: string;
  public_url: string;
  message: string;
  backups: number;
  read_only: boolean;
  available: boolean;
  age: string;
}

export interface VelSnapLocationRow extends VelRowBase {
  row: "snaploc";
  namespace: string;
  name: string;
  provider: string;
  phase: string;
  phase_tone: LineTone;
  message: string;
  age: string;
}

export interface VelRepoRow extends VelRowBase {
  row: "repo";
  namespace: string;
  name: string;
  volume_namespace: string;
  repo_type: string;
  phase: string;
  phase_tone: LineTone;
  message: string;
  last_maintenance: number | null;
  age: string;
}

/** L'en-tête des backups qu'aucun schedule ne réclame. Il ne désigne aucun objet. */
export interface VelOrphansRow extends VelRowBase {
  row: "orphans";
  name: string;
  backups: number;
}

export type VelRow =
  | VelScheduleRow
  | VelBackupRow
  | VelRestoreRow
  | VelLocationRow
  | VelSnapLocationRow
  | VelRepoRow
  | VelOrphansRow;

export interface VelServer {
  found: boolean;
  running: boolean;
  namespace: string;
  ready: number;
  desired: number;
  version: string;
  /** Le DaemonSet qui exécute les sauvegardes de système de fichiers. `null` = absent. */
  node_agent: { ready: number; desired: number } | null;
}

export interface VeleroPayload {
  rows: VelRow[];
  counts: { schedules: number; backups: number; restores: number; problems: number };
  /** Quand le dernier backup **réellement restaurable** s'est terminé, en secondes epoch. */
  last_success: number | null;
  server: VelServer;
  cluster_hints: VelHint[];
  /** Namespaces portant un PVC qu'aucun schedule ne couvre : des données que personne ne protège. */
  uncovered: string[];
  installed: boolean;
  error: string | null;
}

/** Un kind capturé, et les objets de ce kind dans un namespace du backup. */
export interface VelKindContent {
  api_version: string;
  kind: string;
  names: string[];
}

export interface VelNsContent {
  /** Vide pour les objets cluster-scoped : une chaîne vide ne peut pas heurter un vrai namespace. */
  namespace: string;
  kinds: VelKindContent[];
}

/**
 * Ce qu'un backup contient réellement.
 *
 * Pas de repli : la liste n'existe que dans le stockage objet. Un bucket injoignable est une erreur,
 * jamais un backup qui n'aurait rien capturé.
 */
export interface VelContentsPayload {
  key: string;
  namespaces: VelNsContent[];
  total: number;
  error: string | null;
  /** Un enregistrement par objet capturé, qui vise l'objet **vivant**. */
  records: EventRecord[];
}

/** D'où viennent les lignes d'un log de run. Les deux sources ne contiennent pas la même chose. */
export type VelLogSource = "download" | "server" | "none";

export interface VelLogPayload {
  lines: string[];
  source: VelLogSource;
  error: string | null;
}

/** Ce que le formulaire de restauration envoie. */
export interface VelRestoreRequest {
  namespaces: string[];
  kinds: Array<{ apiVersion: string; kind: string }>;
  target_ns: string;
  labels: string;
  overwrite: boolean;
}

// --- Gestes sur un objet quelconque ---------------------------------------------------------------

/** Les deux rendus du YAML, comme l'overlay `y` du TUI. */
export interface ObjectYaml {
  /** Tel que l'apiserver le donne — `kubectl get -o yaml`. */
  raw: string;
  /** Net de ce que le runtime a ajouté — à la manière de `kubectl neat`. */
  neat: string;
}

/**
 * Un garde-fou avant d'éditer, rédigé par kdt.
 *
 * Aucun ne bloque : ils disent ce qui va se passer — un objet appliqué par Flux est remis en place
 * à la réconciliation suivante — et la personne reste libre.
 */
export interface EditReason {
  level: "info" | "warn" | "danger";
  text: string;
}

export interface EditPreflight {
  text: string;
  reasons: EditReason[];
}

/** Ce qu'une édition changerait, trié par kdt. */
export interface EditDiff {
  paths: string[];
  /** Champs que l'apiserver possède : écrire dessus ne fait rien. */
  server_owned: string[];
  /** Champs figés une fois l'objet créé : l'apiserver refusera. */
  immutable: string[];
  /** Champs qui feraient pointer le document vers un **autre** objet. */
  identity: string[];
  empty: boolean;
  noop: boolean;
  rejected: boolean;
}

/** Un garde-fou avant de supprimer, rédigé par kdt. Aucun ne bloque : ils décident du coût. */
export interface DeleteReason {
  level: "info" | "warn" | "danger";
  text: string;
}

/**
 * Ce que les garde-fous ont trouvé, et le coût de la confirmation.
 *
 * `strict` veut dire qu'il faut retaper le nom : un constat de niveau `danger`, ou une
 * vérification qui n'a pas pu conclure — auquel cas `error` le dit. Rien ne garantit qu'une
 * suppression soit anodine quand on n'a pas pu regarder.
 */
export interface DeletePreflight {
  reasons: DeleteReason[];
  strict: boolean;
  /** La phrase de kdt quand rien ne s'est déclenché : le panneau ne reste jamais vide. */
  clear?: string | null;
  error?: string;
}

// --- Vue identity ---------------------------------------------------------------------------------

/** Un constat de kdt sur une ligne, tous modules confondus. */
export interface Hint {
  level: "info" | "warn" | "danger";
  text: string;
}

/** `locked` est le verdict propre à kdt : le controller ne l'écrit jamais. */
export type IdentPhase = "unknown" | "pending" | "active" | "disabled" | "locked";

/**
 * L'invitation en cours, telle que le Secret de credential la raconte.
 *
 * `unreadable` n'est **pas** `none` : un Secret qu'on n'a pas pu lire ne dit rien sur l'existence
 * d'une invitation, et les deux ne doivent pas se rendre pareil.
 */
export interface IdentInvitation {
  state: "none" | "pending" | "expired" | "unreadable";
  expires?: number;
}

/** Les sessions d'un compte : ce qu'une révocation fermerait réellement. */
export interface IdentSessions {
  open: number;
  /** Entrées périmées. L'amont les purge à la prochaine écriture : ce n'est pas de l'accès. */
  stale: number;
  last_expiry: number | null;
}

/** Les trois faits non secrets lus dans le Secret de credential. */
export interface IdentCredentials {
  invite_expires: number | null;
  locked_until: number | null;
  failed_attempts: number;
}

/** Un binding dont le sujet est un groupe de ce système. */
export interface IdentBinding {
  kind: string;
  namespace: string;
  name: string;
  role: string;
}

export interface IdentUserRow {
  row: "user";
  name: string;
  email: string;
  display_name: string;
  disabled: boolean;
  phase: IdentPhase;
  phase_label: string;
  phase_tone: LineTone;
  /** Ce que `status.phase` disait vraiment, gardé pour montrer le `Locked` de kdt à côté. */
  raw_phase: string;
  member_of: string[];
  invitation: IdentInvitation;
  invitation_label: string;
  invitation_tone: LineTone;
  creds: IdentCredentials | null;
  /** `null` = Secret de sessions illisible, ce qui n'est pas « aucune session ouverte ». */
  sessions: IdentSessions | null;
  sessions_cell: string;
  sessions_tone: LineTone;
  age: string;
  hints: Hint[];
  uid: string;
  /** L'identité que l'apiserver verra, préfixe compris. */
  subject: string;
  record: EventRecord;
}

export interface IdentGroupRow {
  row: "group";
  name: string;
  /** Le sujet à citer verbatim dans un binding. */
  subject: string;
  description: string;
  members: string[];
  resolved: string[];
  /** Membres listés qui ne correspondent à aucun compte. */
  unknown: string[];
  bindings: IdentBinding[];
  bindings_labels: string[];
  /** Un groupe que rien ne référence : tout réconcilie, et ses membres prennent 403 partout. */
  rights_tone: LineTone;
  age: string;
  hints: Hint[];
  uid: string;
  record: EventRecord;
}

/**
 * Ce que le déploiement déclare de la délivrance.
 *
 * Chaque champ peut être `null`, et c'est voulu : l'amont défaute `mode` à `certificate`, mais une
 * variable absente décrit aussi un déploiement 0.1 qui ne révoque rien. On n'affirme rien.
 */
export interface IdentDelivery {
  mode: "certificate" | "oidc" | null;
  cert_ttl: string | null;
  token_ttl: string | null;
  refresh_ttl: string | null;
  kubeconfig_download: boolean | null;
  /** Combien de temps un accès survit à sa révocation, selon le mode. */
  revocation_window: string | null;
  /** Le seul accès que ni `revoke` ni `spec.disabled` n'atteignent. */
  download_open: boolean;
}

export interface IdentityPayload {
  installed: boolean;
  error: string | null;
  /** Les Secrets de credential sont illisibles : la colonne INVITE se tait. */
  creds_error: string | null;
  /** Les Secrets de sessions sont illisibles : la colonne SESS se tait. Pas la même lecture. */
  sessions_error: string | null;
  controller: { namespace: string; pod: string; container: string } | null;
  delivery: IdentDelivery;
  counts: {
    users: number;
    active: number;
    pending: number;
    connected: number;
    groups: number;
    unbound: number;
  };
  users: IdentUserRow[];
  groups: IdentGroupRow[];
  install_command: string;
}

/** Une invitation, rendue **une seule fois**. Elle n'est écrite nulle part ailleurs. */
export interface IdentInvite {
  user: string;
  expires: string;
  link: string | null;
  code: string | null;
  /** Ce que la commande a réellement imprimé, si les deux champs n'ont pas pu en être tirés. */
  raw: string;
}

/**
 * Les trois issues d'une écriture, qui ne sont pas interchangeables : une écriture d'API ne dit
 * rien, une invitation porte des valeurs qui n'existent qu'une fois, et une commande lancée dans le
 * pod a ses propres mots — que kdt ne reformule pas.
 */
export type IdentityWriteResult =
  | { outcome: "done" }
  | { outcome: "invited"; invite: IdentInvite }
  | { outcome: "said"; message: string };

// --- Vue rancher ----------------------------------------------------------------------------------

export type RanchScope = "global" | "cluster" | "project";

export interface RanchUserRow {
  row: "user";
  /** L'identité Rancher `u-…`, celle que portent tous les bindings et les lignes d'audit. */
  id: string;
  username: string;
  display_name: string;
  provider: string;
  principal: string;
  identity: string;
  /** Le principal est un GUID : la valeur brute est montrée telle quelle, pas déguisée en nom. */
  identity_opaque: boolean;
  local_only: boolean;
  /** `null` = champ absent, ce qui veut dire **actif** chez Rancher. */
  enabled: boolean | null;
  must_change_password: boolean;
  global_roles: string[];
  is_admin: boolean;
  groups: string[];
  last_refresh: string;
  token_count: number;
  binding_count: number;
  age: string;
  hints: Hint[];
  uid: string;
  identity_cell: string;
  label: string;
  provider_tone: LineTone;
  state_label: string;
  state_tone: LineTone;
  refresh_label: string;
  record: EventRecord;
}

export interface RanchBindingRow {
  row: "binding";
  scope: RanchScope | null;
  scope_id: string;
  scope_label: string;
  scope_kind: string;
  subject_kind: "user" | "group" | null;
  subject_kind_label: string;
  subject_id: string;
  subject_label: string;
  provider: string;
  provider_tone: LineTone;
  role: string;
  role_label: string;
  role_tone: LineTone;
  owner_role: boolean;
  /** Faux quand la ligne vient du RBAC projeté d'un downstream, pas d'un objet Rancher. */
  authoritative: boolean;
  /** Le rôle global que Rancher pose sur tout compte : il ne grante rien que quelqu'un ait choisi. */
  automatic: boolean;
  kind: string;
  api_version: string;
  namespace: string;
  name: string;
  age: string;
  hints: Hint[];
  uid: string;
  record: EventRecord;
}

export interface RanchProjectRow {
  row: "project";
  id: string;
  display_name: string;
  cluster: string;
  namespaces: string[];
  members: number;
  owners: string[];
  quota: string;
  creator: string;
  age: string;
  hints: Hint[];
  uid: string;
  namespace: string;
  name: string;
  /** Faux pour un project reconstruit depuis les annotations : l'objet est en amont. */
  local_object: boolean;
  record: EventRecord;
}

export interface RanchSettingRow {
  row: "setting";
  name: string;
  effective: string;
  is_default: boolean;
  default: string;
  unit: "minutes" | "bool" | "duration" | null;
  /** `auth-token-max-ttl-minutes` : le plafond auquel tous les autres TTL sont ramenés. */
  ceiling: boolean;
  age: string;
  hints: Hint[];
  uid: string;
  value_text: string;
  value_tone: LineTone;
  /** Le défaut livré, écrit comme la valeur en vigueur : « quelqu'un a changé ça, et c'était ça ». */
  default_text: string;
  /** La valeur en minutes quand c'en est une. `0` veut dire « jamais d'expiration ». */
  minutes: number | null;
  source_label: string;
  record: EventRecord;
}

export interface RanchTokenRow {
  row: "token";
  name: string;
  user_id: string;
  user_label: string;
  owner_label: string;
  provider: string;
  provider_tone: LineTone;
  kind: string;
  kind_label: string;
  /** `false` = la session de connexion elle-même : la révoquer déconnecte. */
  derived: boolean;
  description: string;
  ttl_ms: number;
  ttl_label: string;
  ttl_tone: LineTone;
  expires_at: string;
  expired: boolean;
  cluster: string;
  scope_label: string;
  scope_tone: LineTone;
  state_label: string;
  state_tone: LineTone;
  age: string;
  hints: Hint[];
  uid: string;
  record: EventRecord;
}

export interface RancherPayload {
  server: {
    role: "local" | "downstream" | "absent";
    role_label: string;
    version: string;
    url: string;
    cluster_id: string;
    cluster_name: string;
    providers: { name: string; access_mode: string }[];
    hints: Hint[];
  };
  error: string | null;
  /** `token-hashing` actif : le secret d'un token émis n'est pas promis utilisable tel qu'affiché. */
  token_hashing: boolean;
  orphan_namespaces: number;
  /** Les écritures n'existent que sur le cluster local ; ailleurs les objets sont des répliques. */
  writable: boolean;
  counts: {
    users: number;
    external: number;
    admins: number;
    bindings: number;
    projects: number;
    project_namespaces: number;
    orphan_namespaces: number;
    tokens: number;
    expired_tokens: number;
  };
  users: RanchUserRow[];
  bindings: RanchBindingRow[];
  projects: RanchProjectRow[];
  settings: RanchSettingRow[];
  tokens: RanchTokenRow[];
}

/** Un token émis, rendu **une seule fois** : `bearer` n'existe que dans cette réponse. */
export interface IssuedToken {
  name: string;
  bearer: string;
  user_id: string;
  user_label: string;
  ttl_minutes: number;
}

// --- Vue capacité -------------------------------------------------------------------------------

/**
 * À quel point un taux est tendu, tel que `kdt::capacity::tension` le juge.
 *
 * Les seuils sont ceux des règles — 100 %, 90 %, 70 % — pour qu'une cellule colorée et un constat
 * ne se contredisent jamais. Le navigateur peint ce verdict, il ne refait pas la division.
 */
export type Tension = "ok" | "watch" | "high" | "over";

/** Une ressource rapportée à ce qui existe, écrite avec les unités de kdt. */
export interface CapRatio {
  text: string;
  total_text: string;
  pct: number;
  tension: Tension;
}

/** Pourquoi un pod n'aurait nulle part où aller. */
export type HomelessWhy = "no-room" | "taints" | "selector";

/**
 * Un pod que la simulation ne replace pas.
 *
 * La distinction porte tout : « pas de place » se règle en ajoutant de la capacité, un taint ou un
 * sélecteur se règle en changeant le pod — et aucun node neuf n'y changera rien.
 */
export interface HomelessPod {
  namespace: string;
  name: string;
  why: HomelessWhy;
  why_label: string;
  cpu: number;
  mem: number;
  cpu_text: string;
  mem_text: string;
}

/**
 * Ce que la perte d'un node coûterait, une fois ses pods replacés sur le papier.
 *
 * `alone` n'est pas un verdict : il n'y a personne d'autre, donc il n'y a pas de simulation à
 * faire. `pods` n'est présent que sur `homeless`.
 */
export interface CapLoss {
  kind: "alone" | "fits" | "tight" | "homeless";
  pods?: HomelessPod[];
  /** Le mot court de la colonne « IF LOST », dénombrement compris. */
  short: string;
  /** Le même verdict en un mot, celui que porte l'enregistrement de la ligne. */
  word: string;
  tone: LineTone;
  /** La phrase du panneau, rédigée par kdt : « tout se replace », « {n} pods sans place »… */
  note: string;
}

/** Un node : ce qu'il a, ce qui est réservé dessus, et ce que sa perte coûterait. */
export interface CapNodeRow {
  uid: string;
  name: string;
  ready: boolean;
  schedulable: boolean;
  pods: number;
  pod_capacity: number;
  /** `null` quand l'allocatable ne dit pas combien de pods ce node accepte. */
  pods_pct: number | null;
  cpu_reserved: CapRatio;
  mem_reserved: CapRatio;
  /** `null` sans metrics-server : un zéro se lirait comme un node inactif. */
  cpu_used: CapRatio | null;
  mem_used: CapRatio | null;
  cpu_limits_text: string;
  mem_limits_text: string;
  loss: CapLoss;
  hints: Hint[];
  record: EventRecord;
}

/** La classe de qualité de service que le kubelet donne aux pods d'un workload. */
export type Qos = "guaranteed" | "burstable" | "best-effort";

/** Un workload et son dimensionnement : réservé, permis, consommé. */
export interface CapWorkloadRow {
  uid: string;
  namespace: string;
  kind: string;
  name: string;
  pods: number;
  qos: Qos;
  qos_label: string;
  cpu_req_text: string;
  cpu_lim_text: string;
  mem_req_text: string;
  mem_lim_text: string;
  /** `null` sans metrics-server. */
  cpu_use_text: string | null;
  mem_use_text: string | null;
  no_cpu_request: boolean;
  no_mem_request: boolean;
  no_mem_limit: boolean;
  /** La tête du premier constat, coupée par kdt — la phrase entière est dans le panneau. */
  finding: string;
  hints: Hint[];
  record: EventRecord;
}

/** Un compteur d'un `ResourceQuota`. L'unité suit la clé : un quota compte des objets comme du CPU. */
export interface CapQuotaItem {
  resource: string;
  used_text: string;
  hard_text: string;
  pct: number;
  tension: Tension;
}

export interface CapQuotaRow {
  uid: string;
  namespace: string;
  name: string;
  items: CapQuotaItem[];
  /** Le compteur le plus tendu : celui qui refusera la prochaine création. */
  worst_pct: number;
  worst_tension: Tension;
  hints: Hint[];
  record: EventRecord;
}

export interface CapacityPayload {
  /** Cluster-scoped : les nodes ignorent la portée, la question « si celui-ci tombe » aussi. */
  nodes: CapNodeRow[];
  workloads: CapWorkloadRow[];
  quotas: CapQuotaRow[];
  cluster_hints: Hint[];
  /** Faux sans metrics-server : toute la colonne « utilisé » est alors `null`. */
  metrics_available: boolean;
  /** Ce que la simulation vaut : un first-fit honnête, qui ne se fait pas passer pour le scheduler. */
  simulation_note: string;
}

// --- Vue stockage -------------------------------------------------------------------------------

/** Une claim : ce qu'un workload a demandé, et s'il l'a obtenu. */
export interface PvcRow {
  row: "pvc";
  uid: string;
  namespace: string;
  name: string;
  phase: string;
  phase_tone: LineTone;
  /** Ce que le volume donne, sinon ce qui a été demandé — le panneau montre les deux. */
  size: string;
  capacity: string;
  requested: string;
  access_modes: string;
  volume_name: string | null;
  /**
   * `null` = champ absent (« prends la classe par défaut »). La chaîne vide est une décision :
   * Kubernetes écrit ainsi « aucun provisionnement dynamique ». Les deux expliquent très
   * différemment une claim Pending, donc elles restent distinctes.
   */
  storage_class: string | null;
  age: string;
  mounted_by: string[];
  /** La classe telle que kdt la nomme : le nom, « classe par défaut », ou le refus explicite. */
  class_label: string;
  /** Les pods qui montent la claim, ou la phrase de kdt quand il n'y en a aucun. */
  mounted_label: string;
  hints: Hint[];
  record: EventRecord;
}

/** Un volume : où vit la donnée, et ce qui lui arrivera quand la claim partira. */
export interface PvRow {
  row: "pv";
  uid: string;
  name: string;
  capacity: string;
  access_modes: string;
  reclaim_policy: string;
  /** `reclaimPolicy: Delete` : la politique qui perd la donnée sur un `kubectl delete pvc`. */
  reclaim_deletes: boolean;
  phase: string;
  phase_tone: LineTone;
  claim: string | null;
  storage_class: string;
  /** Où vivent les octets, en une ligne : `csi:driver`, `hostPath:/data`, `nfs:host:/export`… */
  source: string;
  /** La contrainte de `spec.nodeAffinity`, aplatie : la raison habituelle d'une claim Pending. */
  node_affinity: string;
  age: string;
  hints: Hint[];
  record: EventRecord;
}

/** Une classe : qui provisionne, et quand la liaison se fait. */
export interface ScRow {
  row: "sc";
  uid: string;
  name: string;
  provisioner: string;
  reclaim_policy: string;
  binding_mode: string;
  allow_expansion: boolean;
  is_default: boolean;
  age: string;
  hints: Hint[];
  record: EventRecord;
}

export type StorageRow = PvcRow | PvRow | ScRow;

export interface StoragePayload {
  pvcs: PvcRow[];
  pvs: PvRow[];
  classes: ScRow[];
  cluster_hints: Hint[];
  /** Les octets que plus personne ne peut atteindre et que quelqu'un paie quand même. */
  released_bytes: number;
  released_text: string;
  /** Faux quand les pods ont été refusés : « rien ne monte cette claim » n'est alors pas affirmé. */
  mounts_known: boolean;
}

// --- Vue network policies -----------------------------------------------------------------------

/** Le controller qui possède une politique. */
export type NetPolEngine = "k8s" | "cilium" | "calico";

/**
 * L'effet d'une direction pour les pods qu'une politique sélectionne.
 *
 * Seul le moteur natif rend autre chose qu'`unknown` : sa sémantique est spécifiée, celle des CNI
 * ne l'est pas, et l'affirmer serait deviner. `deny` est une **bonne** nouvelle — la direction est
 * gouvernée et rien n'y est autorisé.
 */
export type DirEffect = "unaffected" | "deny" | "allow-all" | "selective" | "unknown";

export interface NetPolRow {
  uid: string;
  engine: NetPolEngine;
  engine_label: string;
  kind: string;
  api_version: string;
  /** Vide pour les politiques cluster-scoped (CiliumClusterwide, GlobalNetworkPolicy). */
  namespace: string;
  cluster_scoped: boolean;
  name: string;
  /** Les pods/endpoints visés — « all pods » quand le sélecteur est vide. */
  target: string;
  /** Natif seulement : les `policyTypes` résolus. Vide pour les CRD. */
  types: string;
  ingress: string;
  egress: string;
  ingress_effect: DirEffect;
  egress_effect: DirEffect;
  ingress_tone: LineTone;
  egress_tone: LineTone;
  age: string;
  record: EventRecord;
}

export interface NetpolPayload {
  rows: NetPolRow[];
  counts: { k8s: number; cilium: number; calico: number };
  /** Seule l'erreur sur les natives : un CNI absent n'est pas une panne. */
  error: string | null;
}

/**
 * Un fournisseur d'IA déclaré par l'exploitant, tel que le serveur consent à le décrire.
 *
 * Pas de clé : c'est tout l'intérêt de la déclarer côté serveur. L'hôte, lui, est ce qui dit **où
 * part la donnée**, et c'est une question qu'on doit pouvoir se poser avant d'envoyer un log.
 */
export interface AiProviderInfo {
  name: string;
  model: string;
  host: string;
  context_window: number | null;
}

/** Ce que ce déploiement offre en matière d'IA. */
export interface AiConfigPayload {
  providers: AiProviderInfo[];
  /** Le serveur accepte-t-il qu'un navigateur lui nomme son propre endpoint. */
  allow_custom: boolean;
}

/**
 * Un fournisseur personnel, saisi dans l'interface et gardé par le navigateur.
 *
 * Il vit dans le `localStorage`, comme la clé du TUI vit dans le fichier de configuration de kdt :
 * le serveur ne la détient jamais, il ne fait que la porter le temps d'une analyse.
 */
export interface AiPersonalProvider {
  id: string;
  name: string;
  base_url: string;
  model: string;
  api_key: string;
  context_window: number | null;
}

/** Le fournisseur nommé dans une demande d'analyse. Le monde est dit, jamais deviné. */
export type AiProviderChoice =
  | { source: "server"; name: string }
  | {
      source: "custom";
      base_url: string;
      model: string;
      api_key: string;
      context_window: number | null;
    };

/* ------------------------------------------------------------------------ vue Nodes

   Les machines du cluster, l'usage par container de l'une d'elles, et les garde-fous d'un drain.
   Aucun de ces verdicts n'est calculé ici : le ton d'une ligne, la liste des alertes, les constats
   d'un container et le niveau d'un constat de drain arrivent tout faits de `kdt`. */

/** Un node du cluster, tel que la table le montre. */
export interface NodeRow {
  uid: string;
  name: string;
  /** La condition `Ready` telle quelle : `True`, `False` ou `Unknown`. */
  ready: string;
  roles: string;
  version: string;
  age: string;
  schedulable: boolean;
  /**
   * Les conditions anormales, précédées de `Cordoned` quand le node a été mis hors service.
   *
   * L'ordre est une règle : le cordon est le seul de la liste qui soit un geste et non un
   * symptôme, et c'est lui qu'on cherche quand rien ne se planifie plus ici.
   */
  alerts: string[];
  abnormal: string[];
  tone: LineTone;
  /** La condition `Ready` seule — un node cordonné mais sain reste vert de ce côté-là. */
  ready_tone: LineTone;
  record: EventRecord;
}

export interface NodesPayload {
  nodes: NodeRow[];
}

/** Ce qu'un container a de discutable dans son dimensionnement, nommé par kdt. */
export interface UsageIssue {
  kind: string;
  /** Le mot de la colonne `ISSUES`, le même dans les deux interfaces. */
  tag: string;
  /** Vrai pour ce qui coûte déjà — à la limite, sans requête, sans limite mémoire. */
  severe: boolean;
}

/**
 * Un container d'un node : ce qu'il réserve, ce qu'il a le droit de prendre, ce qu'il prend.
 *
 * Les six quantités sont `null` plutôt que zéro quand elles ne sont pas connues — pas de mesure
 * sans metrics-server, pas de requête quand rien n'est déclaré — et un zéro se lirait comme un
 * container au repos.
 */
export interface NodeUsageRow {
  uid: string;
  namespace: string;
  pod: string;
  container: string;
  /** Vrai pour ce que la plateforme héberge d'elle-même : le tri les garde en dernier. */
  is_system: boolean;
  ready: boolean;
  restarts: number;
  restarts_tone: LineTone;
  cpu_req_text: string | null;
  cpu_lim_text: string | null;
  cpu_use_text: string | null;
  mem_req_text: string | null;
  mem_lim_text: string | null;
  mem_use_text: string | null;
  cpu_use_tone: LineTone;
  mem_use_tone: LineTone;
  issues: UsageIssue[];
  issues_tone: LineTone;
}

/** Une quantité cumulée, et ce qu'elle pèse face à l'allocatable du node. */
export interface UsageRatio {
  text: string;
  pct: number;
  tone: LineTone;
}

/** Un cumul de la table : combien de containers, et les six quantités qu'ils totalisent. */
export interface UsageBucket {
  count: number;
  cpu_req: UsageRatio;
  cpu_lim: UsageRatio;
  cpu_use: UsageRatio;
  mem_req: UsageRatio;
  mem_lim: UsageRatio;
  mem_use: UsageRatio;
}

/**
 * Le bloc de diagnostic du bas.
 *
 * La séparation user/système en est le cœur : un node à 90 % dont 60 % sont des DaemonSets de la
 * plateforme ne se lit pas comme un node à 90 % d'applicatif.
 */
export interface UsageTotals {
  user: UsageBucket;
  system: UsageBucket;
  total: UsageBucket;
  cpu_waste_text: string;
  mem_waste_text: string;
  cpu_waste_pct: number;
  mem_waste_pct: number;
}

export interface NodeUsagePayload {
  node: string;
  rows: NodeUsageRow[];
  /** Faux sans metrics-server : toute la colonne « consommé » est alors `null`. */
  metrics_available: boolean;
  alloc: { cpu: number; mem: number; cpu_text: string; mem_text: string };
  totals: UsageTotals;
}

/** L'ordre de la table d'usage. Les trois gardent les containers système en dernier. */
export type NodeUsageSort = "mem-req" | "cpu-req" | "alpha";

/** Un pod du node, et ce que le drain compte en faire. `skip` non nul : il reste. */
export interface DrainCandidate {
  namespace: string;
  name: string;
  skip: "daemon-set" | "mirror" | "finished" | "terminating" | null;
}

/** Une raison de réfléchir avant de drainer, avec la phrase que kdt rédige. */
export interface DrainReason {
  kind: string;
  level: "info" | "warn" | "danger";
  text: string;
}

/**
 * Ce que les garde-fous ont trouvé.
 *
 * Aucun constat ne bloque : ils décident **combien** la confirmation coûte. `strict` est vrai dès
 * qu'un constat est grave — ou que la vérification n'a pas pu conclure, ce qui n'est pas un feu
 * vert. Le serveur rejoue tout cela juste avant d'évincer.
 */
export interface DrainPreflight {
  reasons: DrainReason[];
  candidates: DrainCandidate[];
  to_evict: number;
  skipped: number;
  strict: boolean;
  error: string | null;
  plan: string;
  skipped_label: string;
  no_finding: string;
}

/** L'avancement d'un drain, tel que le panneau du TUI l'affiche pendant qu'il tourne. */
export interface DrainProgress {
  evicted: string[];
  /** Les pods qu'un PodDisruptionBudget retient encore, et que le drain réessaie. */
  waiting: string[];
  failed: Array<{ pod: string; error: string }>;
  to_evict: number;
  running: boolean;
}

export interface DrainDone {
  ok: boolean;
  message: string;
}
