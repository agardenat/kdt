// Ce que l'API rend, tel quel.
//
// Ces types suivent la sérialisation des structures de `kdt-core` : les noms de champs sont ceux
// de Rust, sans conversion. Renommer côté serveur pour faire joli en TypeScript ajouterait une
// couche de traduction où une divergence pourrait se cacher.

/** Sévérité d'un évènement, telle que Kubernetes la donne. */
export type Severity = "normal" | "warning";

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

/** Les tons d'affichage, repris de `LineColor` côté Rust. */
export type Tone = "ok" | "warn" | "err" | "info" | "dim";

export function toneOf(severity: Severity): Tone {
  return severity === "warning" ? "warn" : "dim";
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
