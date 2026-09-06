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

/** Qui est connecté. */
export interface Identity {
  authenticated: true;
  /** Identité vue par l'apiserver, préfixe compris. */
  subject: string;
  groups: string[];
  /** Ce que le cluster remet : `certificate` ou `oidc`. */
  mode: string;
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
