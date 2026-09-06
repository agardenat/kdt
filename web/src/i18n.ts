// Table de chaînes du chrome, FR/EN.
//
// Elle ne couvre que ce que le front rédige lui-même : rail, onglets, boutons, états vides.
// Les constats, verdicts et lignes de diagnostic sont rédigés par le serveur et arrivent déjà
// traduits — comme dans le TUI, où `toggle_language()` repasse par `refresh_current_view()`.
// Changer de langue ici bascule donc le chrome sur-le-champ et refetch le reste.
//
// Le jargon Kubernetes reste en anglais des deux côtés : on ne traduit ni « node », ni
// « container », ni « workload », parce que personne ne les dit en français.

export type Lang = "fr" | "en";

export interface Strings {
  scopeLabel: string;
  scopeAll: string;
  scopeTitle: string;
  filterPlaceholder: string;
  filterClear: string;
  views: string;
  themeToggle: string;
  langToggle: string;
  detailClose: string;
  tabDetail: string;
  tabLogs: string;
  tabStatus: string;
  tabRelated: string;
  sectionHints: string;
  sectionFields: string;
  sectionRelated: string;
  noLogs: string;
  actionYaml: string;
  actionEdit: string;
  actionTouch: string;
  actionDelete: string;
  emptyTitle: string;
  emptyScope: string;
  emptyFilter: string;
  notMockedTitle: string;
  notMockedBody: string;
  rows: string;
  nodes: string;
  refreshed: string;
  hintFilter: string;
  hintClose: string;
  ownerLabel: string;
  eventsLabel: string;
  secretsLabel: string;
}

const FR: Strings = {
  scopeLabel: "ns",
  scopeAll: "tous",
  scopeTitle: "tout le cluster",
  filterPlaceholder: "filtrer les lignes…",
  filterClear: "Effacer le filtre",
  views: "Vues",
  themeToggle: "Thème clair / sombre",
  langToggle: "Langue",
  detailClose: "Fermer le détail",
  tabDetail: "Détail",
  tabLogs: "Logs",
  tabStatus: "Status",
  tabRelated: "Related",
  sectionHints: "Constats",
  sectionFields: "Champs",
  sectionRelated: "Ressources liées",
  noLogs: "Cet objet ne porte pas de pod : rien à suivre ici.",
  actionYaml: "YAML",
  actionEdit: "Éditer",
  actionTouch: "Toucher",
  actionDelete: "Supprimer",
  emptyTitle: "Aucune ligne ne passe le filtre",
  emptyScope: "La portée est",
  emptyFilter: "le filtre est",
  notMockedTitle: "pas dans cette coquille",
  notMockedBody:
    "Quatre vues sont peuplées : Velero, Flux, Capacity et Identity. Le rail montre les treize pour qu'on juge s'il tient à cette longueur.",
  rows: "lignes",
  nodes: "nœuds",
  refreshed: "rafraîchi il y a 4s",
  hintFilter: "filtrer",
  hintClose: "fermer",
  ownerLabel: "Owner",
  eventsLabel: "Events",
  secretsLabel: "Secrets",
};

const EN: Strings = {
  scopeLabel: "ns",
  scopeAll: "all",
  scopeTitle: "whole cluster",
  filterPlaceholder: "filter rows…",
  filterClear: "Clear filter",
  views: "Views",
  themeToggle: "Light / dark theme",
  langToggle: "Language",
  detailClose: "Close detail",
  tabDetail: "Detail",
  tabLogs: "Logs",
  tabStatus: "Status",
  tabRelated: "Related",
  sectionHints: "Findings",
  sectionFields: "Fields",
  sectionRelated: "Related resources",
  noLogs: "This object carries no pod: nothing to follow here.",
  actionYaml: "YAML",
  actionEdit: "Edit",
  actionTouch: "Touch",
  actionDelete: "Delete",
  emptyTitle: "No row passes the filter",
  emptyScope: "Scope is",
  emptyFilter: "filter is",
  notMockedTitle: "not in this shell",
  notMockedBody:
    "Four views are populated: Velero, Flux, Capacity and Identity. The rail lists all thirteen so we can judge whether it holds at that length.",
  rows: "rows",
  nodes: "nodes",
  refreshed: "refreshed 4s ago",
  hintFilter: "filter",
  hintClose: "close",
  ownerLabel: "Owner",
  eventsLabel: "Events",
  secretsLabel: "Secrets",
};

export function strings(lang: Lang): Strings {
  return lang === "en" ? EN : FR;
}

const KEY = "kdt-lang";

export function storedLang(): Lang {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "fr" || v === "en") return v;
  } catch {
    // Navigation privée, stockage bloqué : la langue par défaut fait l'affaire.
  }
  return navigator.language.startsWith("en") ? "en" : "fr";
}

export function storeLang(lang: Lang): void {
  try {
    localStorage.setItem(KEY, lang);
  } catch {
    // Sans persistance, la langue vaut pour la session ouverte. Ce n'est pas une erreur.
  }
}
