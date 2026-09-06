// Client de l'API de kdt-web.
//
// Une seule règle ici : un refus qui demande de se reconnecter n'est pas une erreur à afficher,
// c'est un aller au portail. Le distinguer évite qu'un droit de session expiré ressemble à une
// panne du cluster.

import type { EventsPayload, Identity } from "./types";

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

export function identity(): Promise<Identity> {
  return get<Identity>("/api/v1/me");
}

export function events(namespaces: string[]): Promise<EventsPayload> {
  const query = namespaces.length ? `?ns=${encodeURIComponent(namespaces.join(","))}` : "";
  return get<EventsPayload>(`/api/v1/events${query}`);
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
