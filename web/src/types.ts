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
