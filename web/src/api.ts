// Client de l'API de kdt-web.
//
// Une seule règle ici : un refus qui demande de se reconnecter n'est pas une erreur à afficher,
// c'est un aller au portail. Le distinguer évite qu'un droit de session expiré ressemble à une
// panne du cluster.

import type {
  Capabilities,
  CertActionTarget,
  CertFilter,
  CertsPayload,
  EventRecord,
  EventsPayload,
  FluxPayload,
  FluxRow,
  Identity,
  InventoryPayload,
  PodLogs,
  ReconcileScope,
  RelatedSection,
  ConfigMapRow,
  SecretsPayload,
  SecretValue,
  DeletePreflight,
  EditDiff,
  EditPreflight,
  IdentityPayload,
  IdentityWriteResult,
  IssuedToken,
  ObjectYaml,
  RancherPayload,
  StatusPayload,
  WorkloadRow,
  WorkloadsPayload,
} from "./types";
import type { Lang } from "./i18n";

/** Le serveur demande de repasser par le portail : la session n'est plus valide. */
export class NeedsAuth extends Error {}

/** Le serveur a refusé, et la raison mérite d'être lue — un refus RBAC, par exemple. */
export class ApiError extends Error {}

async function get<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: { accept: "application/json" },
    // Le cookie de session est `SameSite=Strict` et l'API est sur la même origine : rien à
    // ajouter, mais on le dit pour que personne ne le retire par erreur.
    credentials: "same-origin",
  });

  if (response.ok) return (await response.json()) as T;

  let detail = `le serveur a répondu ${response.status}`;
  let reauthenticate = false;
  try {
    const body = await response.json();
    if (typeof body?.error === "string") detail = body.error;
    reauthenticate = body?.reauthenticate === true;
  } catch {
    // Une réponse qui n'est pas du JSON reste une erreur : le statut suffit à la nommer.
  }

  if (reauthenticate || response.status === 401) throw new NeedsAuth(detail);
  throw new ApiError(detail);
}

/** Même traitement des refus que `get`, pour un corps posté. */
async function send<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body),
  });
  if (response.ok) return (await response.json()) as T;

  let detail = `le serveur a répondu ${response.status}`;
  let reauthenticate = false;
  try {
    const parsed = await response.json();
    if (typeof parsed?.error === "string") detail = parsed.error;
    reauthenticate = parsed?.reauthenticate === true;
  } catch {
    // Pas de JSON : le statut nomme déjà l'erreur.
  }
  if (reauthenticate || response.status === 401) throw new NeedsAuth(detail);
  throw new ApiError(detail);
}

export function identity(): Promise<Identity> {
  return get<Identity>("/api/v1/me");
}

/** Les add-ons installés sur ce cluster, qui décident des vues à proposer. */
export function capabilities(): Promise<Capabilities> {
  return get<Capabilities>("/api/v1/capabilities");
}

export function events(namespaces: string[]): Promise<EventsPayload> {
  const query = namespaces.length ? `?ns=${encodeURIComponent(namespaces.join(","))}` : "";
  return get<EventsPayload>(`/api/v1/events${query}`);
}

/** Les workloads et les pods de la portée. Un seul namespace, ou vide pour tout le cluster. */
export function workloads(namespace: string): Promise<WorkloadsPayload> {
  const query = namespace ? `?ns=${encodeURIComponent(namespace)}` : "";
  return get<WorkloadsPayload>(`/api/v1/workloads${query}`);
}

/** La cible d'une action sur un workload, telle que le serveur l'attend. */
function target(w: WorkloadRow, replicas?: number) {
  return {
    apiVersion: w.api_version,
    kind: w.kind,
    namespace: w.namespace,
    name: w.name,
    ...(replicas === undefined ? {} : { replicas }),
  };
}

/** Porte le nombre de répliques à une valeur absolue. */
export function scale(w: WorkloadRow, replicas: number): Promise<{ message: string }> {
  return send<{ message: string }>("/api/v1/workloads/scale", target(w, replicas));
}

/** Redémarrage progressif, sans coupure (`kubectl rollout restart`). */
export function restart(w: WorkloadRow): Promise<{ message: string }> {
  return send<{ message: string }>("/api/v1/workloads/restart", target(w));
}

/**
 * Descend à zéro puis remonte. **La requête met plusieurs secondes** : le serveur attend d'avoir
 * tenté la remontée avant de répondre, parce qu'une descente réussie suivie d'une remontée en
 * échec laisse le workload à zéro et que ça ne se découvre pas au rafraîchissement suivant.
 */
export function recycle(w: WorkloadRow, replicas: number): Promise<{ message: string }> {
  return send<{ message: string }>("/api/v1/workloads/recycle", target(w, replicas));
}

/** Les Secrets de la portée, sans leurs valeurs. */
export function secrets(namespace: string): Promise<SecretsPayload> {
  const query = namespace ? `?ns=${encodeURIComponent(namespace)}` : "";
  return get<SecretsPayload>(`/api/v1/secrets${query}`);
}

/**
 * Les valeurs d'un Secret, sur demande explicite.
 *
 * Un appel par secret : c'est ce qui garde les valeurs hors de la liste, et cette requête-là
 * laisse une trace nommée côté serveur. Ne jamais l'appeler en boucle sur une liste.
 */
export function revealSecret(
  namespace: string,
  name: string,
): Promise<{ values: SecretValue[] }> {
  const params = new URLSearchParams({ namespace, name });
  return get<{ values: SecretValue[] }>(`/api/v1/secrets/reveal?${params.toString()}`);
}

/** Les ConfigMaps de la portée, valeurs comprises — c'est du texte en clair. */
export function configmaps(namespace: string): Promise<{ configmaps: ConfigMapRow[] }> {
  const query = namespace ? `?ns=${encodeURIComponent(namespace)}` : "";
  return get<{ configmaps: ConfigMapRow[] }>(`/api/v1/configmaps${query}`);
}

/** Envoie le navigateur ouvrir une session. Le portail fait le reste. */
export function login(): void {
  window.location.href = "/auth/login";
}

/** Ferme la session ici et le droit de session côté portail. */
export async function logout(): Promise<void> {
  await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
  window.location.href = "/";
}

export function related(record: EventRecord): Promise<{ sections: RelatedSection[] }> {
  return send<{ sections: RelatedSection[] }>("/api/v1/related", record);
}

/**
 * Les logs de cet objet, quels qu'ils soient pour lui.
 *
 * L'enregistrement entier part dans la requête — kind et component compris — parce que c'est le
 * serveur qui sait ce que « les logs de cette ligne » veut dire : les siens pour un Pod, ceux de
 * son controller filtrés sur elle pour une ressource Flux. Poster un chemin déjà choisi ici
 * reviendrait à recopier cette règle dans le navigateur.
 */
export function logs(
  record: EventRecord,
  options: { container?: string; previous?: boolean } = {},
): Promise<PodLogs> {
  const params = new URLSearchParams({
    namespace: record.namespace,
    name: record.name,
    kind: record.kind,
    component: record.component,
  });
  if (options.container) params.set("container", options.container);
  if (options.previous) params.set("previous", "true");
  return get<PodLogs>(`/api/v1/logs?${params.toString()}`);
}

/** L'arbre Flux du cluster entier. Il n'a pas de portée : voir `crates/web/src/flux.rs`. */
export function fluxTree(): Promise<FluxPayload> {
  return get<FluxPayload>("/api/v1/flux");
}

/** Ce qu'une Kustomization a appliqué, avec l'état vivant de chaque objet. */
export function fluxInventory(row: FluxRow): Promise<InventoryPayload> {
  const params = new URLSearchParams({
    apiVersion: row.api_version,
    kind: row.kind,
    namespace: row.namespace,
    name: row.name,
  });
  return get<InventoryPayload>(`/api/v1/flux/inventory?${params.toString()}`);
}

/** Les logs agrégés de tous les controllers Flux. */
export function fluxLogs(): Promise<{ lines: string[]; error?: string }> {
  return get<{ lines: string[]; error?: string }>("/api/v1/flux/logs");
}

/**
 * Demande une réconciliation. Rend la phrase que kdt rédige, telle quelle.
 *
 * Un refus arrive en `ApiError` : la demande est bien passée, c'est l'état de l'objet qui la
 * repousse — suspendu, source suspendue, kind qui n'honore pas ce levier. Rien à réessayer tel
 * quel, donc la phrase est ce qui compte.
 */
export function fluxReconcile(row: FluxRow, scope: ReconcileScope): Promise<{ message: string }> {
  return send<{ message: string }>("/api/v1/flux/reconcile", {
    apiVersion: row.api_version,
    kind: row.kind,
    namespace: row.namespace,
    name: row.name,
    scope,
  });
}

/**
 * Bascule `spec.suspend`, et rend la valeur écrite.
 *
 * La direction n'est pas envoyée : elle se décide sur l'objet vivant, côté serveur. Le tableau
 * affiché a jusqu'à un rafraîchissement de retard, et agir sur cette lecture-là inverse
 * l'intention — le geste qui devait reprendre suspendrait à nouveau.
 */
export function fluxSuspend(row: FluxRow): Promise<{ suspended: boolean }> {
  return send<{ suspended: boolean }>("/api/v1/flux/suspend", {
    apiVersion: row.api_version,
    kind: row.kind,
    namespace: row.namespace,
    name: row.name,
  });
}

export function status(record: EventRecord): Promise<StatusPayload> {
  const params = new URLSearchParams({
    apiVersion: record.api_version,
    kind: record.kind,
    namespace: record.namespace,
    name: record.name,
  });
  return get<StatusPayload>(`/api/v1/status?${params.toString()}`);
}

/**
 * La chaîne cert-manager de la portée.
 *
 * Le filtre part au serveur et non au navigateur : il garde les **ancêtres** de ce qu'il retient —
 * un Certificate en échec sans son Issuer perdrait le contexte qu'on vient chercher — et cette
 * règle-là a besoin des arêtes, que seul kdt a.
 *
 * La langue voyage aussi : les constats de la chaîne sont rédigés côté serveur.
 */
export function certs(namespace: string, filter: CertFilter, lang: Lang): Promise<CertsPayload> {
  const params = new URLSearchParams({ filter, lang });
  if (namespace) params.set("ns", namespace);
  return get<CertsPayload>(`/api/v1/certs?${params.toString()}`);
}

/** Force la ré-émission d'un Certificate, comme `cmctl renew`. */
export function certRenew(
  target: CertActionTarget,
  lang: Lang,
): Promise<{ message: string }> {
  return send<{ message: string }>("/api/v1/certs/renew", { ...target, lang });
}

/**
 * Relance un cycle ACME bloqué en supprimant la CertificateRequest en cours.
 *
 * La cible est celle que le serveur a nommée : supprimer le Challenge ne servirait à rien, son
 * Order le recrée à l'identique.
 */
export function certAcmeRetry(
  target: CertActionTarget,
  lang: Lang,
): Promise<{ message: string }> {
  return send<{ message: string }>("/api/v1/certs/acme-retry", { ...target, lang });
}

/** Les coordonnées d'un objet, telles que les gestes génériques les attendent. */
function object(record: EventRecord) {
  return {
    apiVersion: record.api_version,
    kind: record.kind,
    namespace: record.namespace,
    name: record.name,
  };
}

/** Le YAML de l'objet, dans ses deux rendus. C'est le `y` du TUI. */
export function objectYaml(record: EventRecord): Promise<ObjectYaml> {
  const params = new URLSearchParams(object(record));
  return get<ObjectYaml>(`/api/v1/object/yaml?${params.toString()}`);
}

/** Le document à éditer et les garde-fous qui s'y appliquent. C'est le `e` du TUI, avant l'éditeur. */
export function objectEdit(record: EventRecord, lang: Lang): Promise<EditPreflight> {
  const params = new URLSearchParams({ ...object(record), lang });
  return get<EditPreflight>(`/api/v1/object/edit?${params.toString()}`);
}

/** Ce que ce document changerait, trié par kdt — demandé avant d'écrire, jamais après. */
export function objectDiff(record: EventRecord, doc: string, lang: Lang): Promise<EditDiff> {
  return send<EditDiff>("/api/v1/object/diff", { ...object(record), doc, lang });
}

/** Écrit le document retouché. Un PUT : l'apiserver refuse si l'objet a bougé entre-temps. */
export function objectApply(
  record: EventRecord,
  doc: string,
  lang: Lang,
): Promise<{ message: string }> {
  return send<{ message: string }>("/api/v1/object/apply", { ...object(record), doc, lang });
}

/**
 * Horodate l'objet pour provoquer une écriture, sans rien lui changer d'autre. C'est le `h` du TUI.
 *
 * Il part sans confirmation, comme dans kdt : deux annotations sous `kdt.io/` s'ajoutent et rien
 * n'est retiré. L'auteur inscrit est la personne connectée, décidé côté serveur.
 */
export function objectTouch(record: EventRecord, lang: Lang): Promise<{ message: string }> {
  return send<{ message: string }>("/api/v1/object/touch", { ...object(record), lang });
}

/**
 * Les garde-fous qui s'appliquent à cet objet, avant de supprimer. C'est le premier temps du
 * `Ctrl-D` du TUI.
 *
 * Une vérification qui n'aboutit pas n'est pas un refus : elle revient en 200 avec `strict` à vrai
 * et sa raison. Ne pas avoir pu regarder ne veut pas dire qu'il n'y a rien à voir.
 */
export function objectDeletePreflight(record: EventRecord, lang: Lang): Promise<DeletePreflight> {
  const params = new URLSearchParams({ ...object(record), lang });
  return get<DeletePreflight>(`/api/v1/object/delete-preflight?${params.toString()}`);
}

/**
 * Supprime l'objet, cascade en arrière-plan comme `kubectl delete`.
 *
 * `confirmName` n'est pas une formalité du navigateur : le serveur rejoue les garde-fous et refuse
 * si le nom retapé n'est pas celui de l'objet. Un garde-fou qui ne vivrait que dans la page se
 * contournerait en postant la requête à la main.
 */
export function objectDelete(
  record: EventRecord,
  confirmName: string,
  lang: Lang,
): Promise<{ message: string }> {
  return send<{ message: string }>("/api/v1/object/delete", {
    ...object(record),
    confirm_name: confirmName,
    lang,
  });
}

/**
 * L'annuaire kdt-identity : les comptes, les groupes, et ce que le déploiement dit de la
 * délivrance.
 *
 * Sans portée : les deux CRD sont cluster-scoped, un compte n'appartient à aucun namespace.
 */
export function identityDirectory(lang: Lang): Promise<IdentityPayload> {
  return get<IdentityPayload>(`/api/v1/identity?lang=${encodeURIComponent(lang)}`);
}

/**
 * Une écriture sur l'annuaire. L'action est nommée dans le corps.
 *
 * `invite` et `revoke` ne sont pas des écritures d'API : ce sont des commandes lancées dans le pod
 * controller, que le serveur résout lui-même. Leur sortie revient telle quelle — kdt ne la
 * reformule pas, et le navigateur non plus.
 */
export function identityWrite(
  request: Record<string, unknown>,
  lang: Lang,
): Promise<IdentityWriteResult> {
  return send<IdentityWriteResult>("/api/v1/identity/write", { ...request, lang });
}

/** Les quatre mondes de la vue Rancher, en une lecture. */
export function rancherDirectory(lang: Lang): Promise<RancherPayload> {
  return get<RancherPayload>(`/api/v1/rancher?lang=${encodeURIComponent(lang)}`);
}

/**
 * Une écriture Rancher : émettre un token, changer un TTL, révoquer, régler un setting.
 *
 * L'émission rend le credential **une seule fois** : il n'existe que dans cette réponse, et le
 * navigateur le montre puis le jette.
 */
export function rancherWrite(
  request: Record<string, unknown>,
  lang: Lang,
): Promise<{ message: string; token?: IssuedToken }> {
  return send<{ message: string; token?: IssuedToken }>("/api/v1/rancher/write", {
    ...request,
    lang,
  });
}
