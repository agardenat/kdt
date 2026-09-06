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

  // --- Vue Flux. Le jargon reste en anglais des deux côtés : `Kustomization`, `HelmRelease`,
  // `suspend`, `reconcile` ne se disent pas autrement, et les étiquettes READY viennent déjà du
  // serveur. Ce qui suit est ce que le navigateur rédige lui-même.
  fluxTree: string;
  fluxList: string;
  fluxReveal: string;
  fluxRevealHelp: string;
  fluxActions: string;
  fluxReconcile: string;
  fluxReconcileSrc: string;
  fluxForceUpgrade: string;
  fluxResetFailures: string;
  fluxSyncRoot: string;
  fluxSuspend: string;
  fluxResume: string;
  fluxDescReconcile: string;
  fluxDescReconcileSrc: string;
  fluxDescForceUpgrade: string;
  fluxDescResetFailures: string;
  fluxDescSyncRoot: string;
  fluxDescSuspend: string;
  fluxDescResume: string;
  fluxConfirm: string;
  fluxCancel: string;
  fluxScopeless: string;
  fluxEmpty: string;
  fluxInventory: string;
  fluxInventoryHelp: string;
  fluxNoPrune: string;
  fluxNoPruneTitle: string;
  fluxControllerLogs: string;
  fluxSelectRow: string;
  fluxFold: string;

  // --- Vue Workloads.
  wlGrouped: string;
  wlPods: string;
  wlRunning: string;
  wlBroken: string;
  wlWorking: string;
  wlEmpty: string;
  wlContainers: string;
  wlActions: string;
  wlScale: string;
  wlRestart: string;
  wlRecycle: string;
  wlDescScale: string;
  wlDescRestart: string;
  wlDescRecycle: string;
  wlReplicas: string;
  wlMissing: string;
  wlMissingHelp: string;
  wlRestarts: string;
  wlSelectWorkload: string;
  wlCpuReq: string;
  wlCpuLim: string;
  wlMemReq: string;
  wlMemLim: string;

  // --- Vues Secrets / ConfigMaps.
  dataEmpty: string;
  secKeys: string;
  secDetail: string;
  secOrigin: string;
  secAge: string;
  secCertificate: string;
  secConstraint: string;
  secKey: string;
  secIssuedOn: string;
  secExpiresOn: string;
  secConsumers: string;
  secNoIngress: string;
  secContent: string;
  cmText: string;
  cmBinary: string;
  cmSize: string;
  secFilter: string;
  secFilterAll: string;
  secFilterExpiring: string;
  secFilterHelp: string;
  secCopy: string;
  secCopied: string;
  secShowText: string;
  secVisible: string;
  secBinary: string;
  secBinaryKey: string;
  secTls: string;
  secExpired: string;
  secExpiring: string;
  secDays: string;
  secExpiredSince: string;
  secUndecodable: string;
  secIssuer: string;
  secSelfSigned: string;
  secValidity: string;
  secUsedBy: string;
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
  notMockedTitle: "pas encore branchée",
  notMockedBody:
    "Cette vue existe dans kdt et reste à porter ici. Le rail les montre toutes pour qu'on juge s'il tient à cette longueur.",
  rows: "lignes",
  nodes: "nœuds",
  refreshed: "rafraîchi il y a {age}",
  hintFilter: "filtrer",
  hintClose: "fermer",
  ownerLabel: "Owner",
  eventsLabel: "Events",
  secretsLabel: "Secrets",

  fluxTree: "Arbre",
  fluxList: "Liste",
  fluxReveal: "suivre les problèmes",
  fluxRevealHelp:
    "Ouvre d'office les branches qui mènent à une ressource en échec ou en cours de réconciliation, et les referme une fois l'incident réglé. Vos plis manuels ne sont pas touchés.",
  fluxActions: "Réconciliation Flux",
  fluxReconcile: "reconcile",
  fluxReconcileSrc: "+source",
  fluxForceUpgrade: "forcer l'upgrade",
  fluxResetFailures: "réarmer",
  fluxSyncRoot: "sync racine",
  fluxSuspend: "suspend",
  fluxResume: "resume",
  fluxDescReconcile: "Réconcilie la ressource sélectionnée (annotation reconcile.fluxcd.io).",
  fluxDescReconcileSrc: "Réconcilie d'abord la source (Git/Helm/OCI) puis la ressource.",
  fluxDescForceUpgrade: "Rejoue l'upgrade Helm même si le chart et les valeurs n'ont pas bougé.",
  fluxDescResetFailures: "Efface les compteurs d'échec d'une release en « retries exhausted ».",
  fluxDescSyncRoot: "Réconcilie la GitRepository racine flux-system (resync complet).",
  fluxDescSuspend: "Met la réconciliation en pause. Ne supprime rien.",
  fluxDescResume: "Relance la réconciliation mise en pause.",
  fluxConfirm: "Confirmer",
  fluxCancel: "Annuler",
  fluxScopeless: "L'arbre Flux couvre tout le cluster : le filtrer par namespace lui ferait perdre ses arêtes.",
  fluxEmpty: "Aucune ressource Flux lisible sur ce cluster.",
  fluxInventory: "objets",
  fluxInventoryHelp:
    "Les objets que cette Kustomization a appliqués, avec l'état de chacun (les touches +/- de kdt).",
  fluxNoPrune: "no-prune",
  fluxNoPruneTitle: "spec.prune: false — ce que cette Kustomization a appliqué survit à sa disparition de git.",
  fluxControllerLogs: "Logs des controllers",
  fluxSelectRow: "Choisissez une ligne pour agir dessus.",
  fluxFold: "Plier / déplier",

  wlGrouped: "Workloads",
  wlPods: "Pods",
  wlRunning: "pods en Running",
  wlBroken: "pods en panne",
  wlWorking: "en cours…",
  wlEmpty: "Aucun workload ni pod dans cette portée.",
  wlContainers: "Containers du pod",
  wlActions: "Actions sur le workload",
  wlScale: "scale",
  wlRestart: "restart",
  wlRecycle: "recycle",
  wlDescScale: "Porte le nombre de répliques à la valeur choisie.",
  wlDescRestart: "kubectl rollout restart : redémarrage progressif, sans coupure.",
  wlDescRecycle:
    "Descend à 0 puis remonte : recrée tous les pods d'un coup, avec une coupure brève. Prend quelques secondes, et si la remontée échoue le workload reste à 0.",
  wlReplicas: "répliques",
  wlMissing: "kinds illisibles",
  wlMissingHelp:
    "Ces kinds n'ont pas pu être listés : la vue en est incomplète, ce n'est pas qu'il n'y en a aucun.",
  wlRestarts: "redémarrages",
  wlSelectWorkload: "Choisissez un workload : un pod et un container ne se scalent pas.",
  wlCpuReq: "CPU consommé, en % de la requête. Au-dessus de 100 %, le pod prend plus qu'il n'a réservé — c'est permis.",
  wlCpuLim: "CPU consommé, en % de la limite. Au-dessus de 100 %, le container est throttlé.",
  wlMemReq: "Mémoire consommée, en % de la requête.",
  wlMemLim: "Mémoire consommée, en % de la limite. Au-dessus de 100 %, le container se fait tuer (OOMKilled).",

  dataEmpty: "Rien à montrer dans cette portée.",
  secKeys: "clés",
  secDetail: "Détail",
  secOrigin: "origine",
  secAge: "âge",
  secCertificate: "Certificat",
  secConstraint: "contrainte",
  secKey: "clé",
  secIssuedOn: "émis le",
  secExpiresOn: "expire le",
  secConsumers: "Consommateurs",
  secNoIngress: "aucun Ingress ne le référence",
  secContent: "Contenu",
  cmText: "texte",
  cmBinary: "binaires",
  cmSize: "taille",
  secFilter: "Filtre",
  secFilterAll: "tous",
  secFilterExpiring: "à renouveler",
  secFilterHelp:
    "« à renouveler » ne garde que les secrets porteurs d'un certificat dont l'échéance n'est pas saine — un certificat illisible n'y figure pas, puisqu'on ignore quand il expire.",
  secCopy: "Copier",
  secCopied: "copié",
  secShowText: "afficher",
  secVisible: "⚠ valeurs à l'écran",
  secBinary: "binaire, {n} octets",
  secBinaryKey: "binaire (binaryData)",
  secTls: "secrets TLS",
  secExpired: "certificats expirés",
  secExpiring: "certificats qui expirent sous 30 jours",
  secDays: "{n} j",
  secExpiredSince: "expiré depuis {n} j",
  secUndecodable: "certificat illisible",
  secIssuer: "Émetteur",
  secSelfSigned: "auto-signé",
  secValidity: "Validité",
  secUsedBy: "Utilisé par",
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
  notMockedTitle: "not wired up yet",
  notMockedBody:
    "This view exists in kdt and is still to be ported here. The rail lists them all so we can judge whether it holds at that length.",
  rows: "rows",
  nodes: "nodes",
  refreshed: "refreshed {age} ago",
  hintFilter: "filter",
  hintClose: "close",
  ownerLabel: "Owner",
  eventsLabel: "Events",
  secretsLabel: "Secrets",

  fluxTree: "Tree",
  fluxList: "List",
  fluxReveal: "follow problems",
  fluxRevealHelp:
    "Unfolds the branches leading to a failing or reconciling resource, and folds them back once it settles. Your manual folds are left alone.",
  fluxActions: "Flux reconcile",
  fluxReconcile: "reconcile",
  fluxReconcileSrc: "+source",
  fluxForceUpgrade: "force upgrade",
  fluxResetFailures: "reset failures",
  fluxSyncRoot: "root sync",
  fluxSuspend: "suspend",
  fluxResume: "resume",
  fluxDescReconcile: "Reconcile the selected resource (reconcile.fluxcd.io annotation).",
  fluxDescReconcileSrc: "Reconcile the source first (Git/Helm/OCI) then the resource.",
  fluxDescForceUpgrade: "Replay the Helm upgrade even when the chart and values are unchanged.",
  fluxDescResetFailures: "Clear the failure counters of a release stuck in \"retries exhausted\".",
  fluxDescSyncRoot: "Reconcile the root flux-system GitRepository (full resync).",
  fluxDescSuspend: "Pause reconciliation. Deletes nothing.",
  fluxDescResume: "Resume a paused reconciliation.",
  fluxConfirm: "Confirm",
  fluxCancel: "Cancel",
  fluxScopeless: "The Flux tree spans the whole cluster: filtering it by namespace would lose its edges.",
  fluxEmpty: "No readable Flux resource on this cluster.",
  fluxInventory: "objects",
  fluxInventoryHelp:
    "The objects this Kustomization applied, each with its own state (the +/- keys in kdt).",
  fluxNoPrune: "no-prune",
  fluxNoPruneTitle: "spec.prune: false — what this Kustomization applied outlives its removal from git.",
  fluxControllerLogs: "Controller logs",
  fluxSelectRow: "Pick a row to act on it.",
  fluxFold: "Fold / unfold",

  wlGrouped: "Workloads",
  wlPods: "Pods",
  wlRunning: "running pods",
  wlBroken: "broken pods",
  wlWorking: "working…",
  wlEmpty: "No workload or pod in this scope.",
  wlContainers: "Pod containers",
  wlActions: "Workload actions",
  wlScale: "scale",
  wlRestart: "restart",
  wlRecycle: "recycle",
  wlDescScale: "Set the replica count to the chosen value.",
  wlDescRestart: "kubectl rollout restart: gradual restart, no downtime.",
  wlDescRecycle:
    "Scale to 0 then back up: recreate all pods at once, with brief downtime. Takes a few seconds, and if the way back up fails the workload stays at 0.",
  wlReplicas: "replicas",
  wlMissing: "unreadable kinds",
  wlMissingHelp:
    "These kinds could not be listed: the view is incomplete, it does not mean there are none.",
  wlRestarts: "restarts",
  wlSelectWorkload: "Pick a workload: a pod or a container cannot be scaled.",
  wlCpuReq: "CPU used, as % of the request. Above 100% the pod takes more than it reserved — which is allowed.",
  wlCpuLim: "CPU used, as % of the limit. Above 100% the container is throttled.",
  wlMemReq: "Memory used, as % of the request.",
  wlMemLim: "Memory used, as % of the limit. Above 100% the container gets OOMKilled.",

  dataEmpty: "Nothing to show in this scope.",
  secKeys: "keys",
  secDetail: "Detail",
  secOrigin: "origin",
  secAge: "age",
  secCertificate: "Certificate",
  secConstraint: "constraint",
  secKey: "key",
  secIssuedOn: "issued on",
  secExpiresOn: "expires on",
  secConsumers: "Consumers",
  secNoIngress: "no Ingress references it",
  secContent: "Content",
  cmText: "text",
  cmBinary: "binary",
  cmSize: "size",
  secFilter: "Filter",
  secFilterAll: "all",
  secFilterExpiring: "to renew",
  secFilterHelp:
    "\"to renew\" keeps only secrets carrying a certificate whose expiry is not healthy — an undecodable certificate is not listed, since we cannot know when it expires.",
  secCopy: "Copy",
  secCopied: "copied",
  secShowText: "reveal",
  secVisible: "⚠ values on screen",
  secBinary: "binary, {n} bytes",
  secBinaryKey: "binary (binaryData)",
  secTls: "TLS secrets",
  secExpired: "expired certificates",
  secExpiring: "certificates expiring within 30 days",
  secDays: "{n}d",
  secExpiredSince: "expired {n}d ago",
  secUndecodable: "undecodable certificate",
  secIssuer: "Issuer",
  secSelfSigned: "self-signed",
  secValidity: "Validity",
  secUsedBy: "Used by",
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
