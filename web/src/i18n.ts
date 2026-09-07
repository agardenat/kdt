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
  secOpenChain: string;
  secOpenChainHelp: string;
  secNoOrigin: string;

  // --- Vue certs (cert-manager). Le jargon reste en anglais des deux côtés : `Issuer`,
  // `Challenge`, `keystore`, `renew` ne se disent pas autrement. Les constats de la chaîne, eux,
  // sont rédigés par le serveur et arrivent déjà traduits.
  certTree: string;
  certList: string;
  certFilterAll: string;
  certFilterProblems: string;
  certFilterFlight: string;
  certFilterHelp: string;
  certEmpty: string;
  certNotInstalled: string;
  certNoAcme: string;
  certSecretsUnreadable: string;
  certActions: string;
  certRenew: string;
  certDescRenew: string;
  certAcmeRetry: string;
  certDescAcmeRetry: string;
  certRateLimited: string;
  certSelectRow: string;
  certOpenSecret: string;
  certOpenSecretHelp: string;
  certChain: string;
  certProduced: string;
  certKeystores: string;
  certSecretAbsent: string;
  certSecretUnknown: string;
  certConsumersNone: string;
  certConsumersOne: string;
  certConsumersMany: string;
  certExpiresIn: string;
  certExpiredSince: string;
  certRenewalOn: string;
  certExpiresOn: string;
  certSignedBy: string;
  certKeystoreAlias: string;
  certKeystorePwRef: string;
  certKeystorePwInline: string;
  certDetail: string;
  certFold: string;
  certDays: string;

  // --- Gestes sur un objet quelconque : `y`, `e`, `h` dans le TUI.
  objActions: string;
  objSelectRow: string;
  objYamlRaw: string;
  objYamlNeat: string;
  objTouchHelp: string;
  objEditGuards: string;
  objEditApply: string;
  objEditReload: string;
  objEditChanges: string;
  objEditNoChange: string;
  objEditNoop: string;
  objEditServerOwned: string;
  objEditImmutable: string;
  objEditIdentity: string;
  objEditConfirm: string;
  objEditCancel: string;
  objEditReadOnlyHint: string;
  objWorking: string;

  // --- Suppression : le `Ctrl-D` du TUI, dans la grammaire du web. Aucune de ces chaînes ne nomme
  // une touche : le TUI n'a que le clavier, ici chaque geste a une cible visible.
  delTitle: string;
  delTarget: string;
  delChecking: string;
  delHelp: string;
  delCancel: string;
  delConfirm: string;
  delStrictHelp: string;
  delStrictPlaceholder: string;
  delStrictMismatch: string;
  delReload: string;

  // --- Vue identity. Le jargon reste en anglais des deux côtés (`KdtUser`, `KdtGroup`, `subject`),
  // et les phases, invitations et constats arrivent déjà rédigés du serveur.
  identUsers: string;
  identGroups: string;
  identDetail: string;
  identSelectRow: string;
  identActions: string;
  identInvite: string;
  identInviteHelp: string;
  identInviteValidity: string;
  identInviteOnce: string;
  identInviteLink: string;
  identInviteCode: string;
  identInviteRaw: string;
  identInviteClose: string;
  identRevoke: string;
  identRevokeHelp: string;
  identEnable: string;
  identDisable: string;
  identEnableHelp: string;
  identDisableHelp: string;
  identAddMember: string;
  identRemoveMember: string;
  identMemberHelp: string;
  identCreateUser: string;
  identCreateGroup: string;
  identName: string;
  identEmail: string;
  identDisplayName: string;
  identDescription: string;
  identCreate: string;
  identEmpty: string;
  identNotInstalled: string;
  identInstallHelp: string;
  identScopeless: string;
  identOperator: string;
  identMode: string;
  identModeUnknown: string;
  identRevocation: string;
  identRefresh: string;
  identDownload: string;
  identDownloadOpen: string;
  identDownloadClosed: string;
  identSubject: string;
  identGroupsLabel: string;
  identMembers: string;
  identUnknownMembers: string;
  identRights: string;
  identSessions: string;
  identNone: string;
  identNoController: string;

  // --- Vue rancher. Quatre mondes, et le vocabulaire de Rancher tel quel : `project`, `token`,
  // `setting`, `principal` ne se traduisent pas dans un annuaire Rancher.
  ranchUsers: string;
  ranchAccess: string;
  ranchProjects: string;
  ranchTokens: string;
  ranchDetail: string;
  ranchSelectRow: string;
  ranchActions: string;
  ranchIssue: string;
  ranchIssueHelp: string;
  ranchIssueTtl: string;
  ranchIssueHashing: string;
  ranchSetTtl: string;
  ranchSetTtlHelp: string;
  ranchRevoke: string;
  ranchRevokeHelp: string;
  ranchRevokeSession: string;
  ranchSetSetting: string;
  ranchSetSettingHelp: string;
  ranchApply: string;
  ranchCancel: string;
  ranchEmpty: string;
  ranchReadOnly: string;
  ranchScopeless: string;
  ranchTokenOnce: string;
  ranchTokenClose: string;
  ranchIdentity: string;
  ranchLogin: string;
  ranchProvider: string;
  ranchPrincipal: string;
  ranchGlobalRoles: string;
  ranchGroups: string;
  ranchNamespaces: string;
  ranchOwners: string;
  ranchAuth: string;
  ranchOrphanNs: string;
  ranchNotAuthoritative: string;

  // --- Vue Kyverno. Le jargon reste en anglais des deux côtés : `policy`, `rule`, `enforce`,
  // `audit`, `webhook` ne se disent pas autrement, et les constats viennent déjà du serveur.
  kyByPolicy: string;
  kyByResource: string;
  kyAxisHelp: string;
  kyFilterEnforce: string;
  kyFilterHelp: string;
  kyEmpty: string;
  kyNotInstalled: string;
  kyScopeless: string;
  kyDetail: string;
  kyResourceLabel: string;
  kySelectRow: string;
  kyFold: string;
  kyPolicies: string;
  kyEnforcing: string;
  kyNotReady: string;
  kyNoViolation: string;
  kyHealthOk: string;
  kyHealthDegraded: string;
  kyHealthInactive: string;
  kyHealthUnknown: string;
  kyNoControllers: string;
  kyWebhooks: string;
  kyNoWebhook: string;
  kyNoCel: string;
  kyReports: string;
  kyRequests: string;
  kyRequestsPending: string;
  kyRequestsFailed: string;
  kyRequestsOldest: string;
  kyRequestsTop: string;
  kyEphemeral: string;
  kyPurge: string;
  kyPurgeHelp: string;
  kyPurgeNone: string;
  kyPurgeConfirm: string;
  kyPosture: string;
  kyAdmission: string;
  kyBackground: string;
  kyBackgroundOnly: string;
  kyNoBackground: string;
  kySchedule: string;
  kyOverride: string;
  kyRules: string;
  kyAutogen: string;
  kyAppliesTo: string;
  kyExceptions: string;
  kyExcludes: string;
  kyForRules: string;
  kyAllRules: string;
  kyFailing: string;
  kyDenials: string;
  kyNoDenial: string;
  kyDenialsDenied: string;
  kyViolated: string;
  kyErrorNote: string;
  kyRetrigger: string;
  kyOrigin: string;
  kyEvaluated: string;
  kySeverity: string;
  kyCategory: string;
  kyNotReadyNote: string;

  // --- Vue RBAC. Le jargon reste en anglais des deux côtés : `binding`, `role`, `subject`,
  // `verb`, `namespace` n'ont pas d'équivalent qu'on emploierait vraiment.
  rbacFlat: string;
  rbacBySubject: string;
  rbacByBinding: string;
  rbacByRole: string;
  rbacOrientHelp: string;
  rbacMinSev: string;
  rbacMinSevHelp: string;
  rbacEmpty: string;
  rbacDetail: string;
  rbacFold: string;
  rbacBindings: string;
  rbacRoles: string;
  rbacAccounts: string;
  rbacSaDegraded: string;
  rbacSaMissing: string;
  rbacSaMissingDetail: string;
  rbacExternalSubject: string;
  rbacReadOnly: string;
  rbacNoRule: string;
  rbacNoGrant: string;
  rbacGrants: string;
  rbacFindings: string;
  rbacRules: string;
  rbacAggregation: string;
  rbacAggregatesNone: string;
  rbacAggregationPartial: string;
  rbacFeeds: string;
  rbacVia: string;
  rbacViaClusterrole: string;
  rbacAggregatedLabel: string;
  rbacBound: string;
  rbacBoundCluster: string;
  rbacBoundNs: string;
  rbacTemplate: string;
  rbacUnbound: string;
  rbacNRules: string;
  rbacNBindings: string;
  rbacAutomount: string;
  rbacAutomountOn: string;
  rbacAutomountOff: string;
  rbacAutomountDefault: string;
  rbacSecrets: string;
  rbacOrigin: string;
  rbacSource: string;
  rbacScopeLabel: string;
  rbacSubjects: string;
  rbacRoleLabel: string;
  rbacGrantedIn: string;

  // --- Filtre partagé par les vues d'inventaire, là où le TUI cycle une touche.
  filterAll: string;
  filterProblems: string;

  // --- Bandeau du cluster. Le jargon — nodes, CPU, MEM — n'est pas traduit : il ne se dit pas
  // autrement en français, et ces trois mots sont les mêmes dans le TUI.
  clusterUnknown: string;
  clusterVersionUnknown: string;
  clusterNodesDenied: string;
  clusterNoMetrics: string;

  // --- Sélecteur de portée : la liste des namespaces, et ce qu'il reste quand elle est refusée.
  nsSearch: string;
  nsLoading: string;
  nsDenied: string;
  nsNoMatch: string;
  nsAdd: string;
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
  secOpenChain: "voir la chaîne",
  secOpenChainHelp:
    "Ouvre la vue certs sur le Certificate qui produit ce Secret, avec la chaîne qui l'émet — issuer, demande, order, challenge.",
  secNoOrigin: "Ce Secret n'est pas produit par cert-manager",

  certTree: "Chaîne",
  certList: "Liste",
  certFilterAll: "tout",
  certFilterProblems: "problèmes",
  certFilterFlight: "en cours",
  certFilterHelp:
    "« problèmes » retient ce qui n'est pas Ready et ce qui expire sous 30 jours ; « en cours » ne garde que l'émission en vol. Les ancêtres d'une ligne retenue restent affichés : sans son Issuer, un Certificate en échec perd ce qui l'explique.",
  certEmpty: "Aucun objet cert-manager dans cette portée.",
  certNotInstalled: "cert-manager n'est pas installé sur ce cluster.",
  certNoAcme: "sans ACME",
  certSecretsUnreadable:
    "Secrets illisibles : le Secret produit et les keystores ne sont pas vérifiés ici.",
  certActions: "Actions cert-manager",
  certRenew: "renouveler",
  certDescRenew:
    "Force la ré-émission : la condition Issuing passe à True, comme le fait cmctl renew.",
  certAcmeRetry: "relancer ACME",
  certDescAcmeRetry:
    "Supprime la CertificateRequest en cours ; son Order et ses Challenges partent avec elle, et cert-manager en émet une nouvelle.",
  certRateLimited:
    "Quota ACME atteint : réessayer ne ferait que brûler ce qui reste. La relance est retirée.",
  certSelectRow: "Sélectionnez une ligne de la chaîne",
  certOpenSecret: "voir le Secret",
  certOpenSecretHelp:
    "Ouvre la vue Secrets sur le Secret produit, où le certificat est décodé et les valeurs se révèlent.",
  certChain: "Chaîne",
  certProduced: "Secret produit",
  certKeystores: "Keystores",
  certSecretAbsent: "Secret {ns}/{name} absent — le certificat est prêt mais rien ne le sert.",
  certSecretUnknown: "état du Secret inconnu dans cette portée",
  certConsumersNone: "aucun Ingress ne le référence",
  certConsumersOne: "référencé par 1 Ingress",
  certConsumersMany: "référencé par {n} Ingress",
  certExpiresIn: "expire dans {n} j",
  certExpiredSince: "expiré depuis {n} j",
  certRenewalOn: "renouvellement",
  certExpiresOn: "expiration",
  certSignedBy: "{n} certificat(s) signé(s) par cet issuer",
  certKeystoreAlias: "alias {alias}",
  certKeystorePwRef: "mot de passe : {name}/{key}",
  certKeystorePwInline: "mot de passe littéral",
  certDetail: "Chaîne",
  certFold: "Plier / déplier la chaîne",
  certDays: "{n} j",

  objActions: "Objet",
  objSelectRow: "Sélectionnez une ligne",
  objYamlRaw: "brut",
  objYamlNeat: "net",
  objTouchHelp:
    "Horodate l'objet sous kdt.io/ pour provoquer une écriture : c'est elle qui refait passer les webhooks d'admission. Rien d'autre n'est touché.",
  objEditGuards: "Avant d'écrire",
  objEditApply: "Appliquer",
  objEditReload: "Recharger",
  objEditChanges: "Ce que cela change",
  objEditNoChange: "Le document est identique à l'objet : rien à écrire.",
  objEditNoop:
    "Tout le changement porte sur des champs que l'apiserver possède : écrire laisserait l'objet tel quel.",
  objEditServerOwned: "possédés par l'apiserver, ignorés",
  objEditImmutable: "figés une fois l'objet créé, l'apiserver refusera",
  objEditIdentity: "identité de l'objet : ce document en viserait un autre",
  objEditConfirm: "Écrire",
  objEditCancel: "Annuler",
  objEditReadOnlyHint: "Retouchez le document, puis « Appliquer » montre ce que cela change.",
  objWorking: "en cours…",

  delTitle: "Suppression",
  delTarget: "Objet",
  delChecking: "vérifications en cours…",
  delHelp:
    "Aucun de ces constats ne bloque : ils disent ce qui va se passer. Un objet déployé par un moteur GitOps revient à la réconciliation suivante.",
  delCancel: "Ne rien supprimer",
  delConfirm: "Supprimer définitivement",
  delStrictHelp:
    "Un constat grave s'applique — ou les vérifications n'ont pas pu conclure. Retapez le nom de l'objet pour confirmer.",
  delStrictPlaceholder: "nom de l'objet",
  delStrictMismatch: "attendu : {name}",
  delReload: "Revérifier",

  identUsers: "Comptes",
  identGroups: "Groupes",
  identDetail: "Compte",
  identSelectRow: "Sélectionnez une ligne",
  identActions: "Annuaire",
  identInvite: "Inviter",
  identInviteHelp:
    "Lance `kdt-identity-server invite` dans le pod controller et rend un lien et un code, une seule fois.",
  identInviteValidity: "validité",
  identInviteOnce:
    "Ces valeurs ne seront plus affichées. Elles voyagent par deux canaux différents, d'où deux copies séparées.",
  identInviteLink: "Lien",
  identInviteCode: "Code",
  identInviteRaw: "Sortie de la commande",
  identInviteClose: "J'ai copié",
  identRevoke: "Fermer les sessions",
  identRevokeHelp:
    "Déconnecte le compte de toutes ses machines. Ce n'est pas le désactiver : il pourra se reconnecter.",
  identEnable: "Réactiver",
  identDisable: "Désactiver",
  identEnableHelp: "Réautorise la délivrance de nouveaux accès.",
  identDisableHelp:
    "Bloque toute nouvelle délivrance. Les credentials déjà remis vivent jusqu'à leur expiration.",
  identAddMember: "Ajouter au groupe",
  identRemoveMember: "Retirer",
  identMemberHelp:
    "L'appartenance est portée par le groupe, jamais par le compte : elle s'écrit sur `spec.members`.",
  identCreateUser: "Nouveau compte",
  identCreateGroup: "Nouveau groupe",
  identName: "nom",
  identEmail: "e-mail",
  identDisplayName: "nom affiché",
  identDescription: "description",
  identCreate: "Créer",
  identEmpty: "Aucun compte ni groupe local sur ce cluster.",
  identNotInstalled: "kdt-identity n'est pas installé sur ce cluster.",
  identInstallHelp: "Commande d'installation",
  identScopeless: "L'annuaire est cluster-scoped : la portée de namespace ne s'y applique pas.",
  identOperator: "opérateur",
  identMode: "délivrance",
  identModeUnknown: "non déclarée",
  identRevocation: "révocation",
  identRefresh: "renouvellement",
  identDownload: "kubeconfig",
  identDownloadOpen: "téléchargement ouvert — cet accès échappe à la révocation",
  identDownloadClosed: "téléchargement fermé",
  identSubject: "subject",
  identGroupsLabel: "groupes",
  identMembers: "membres",
  identUnknownMembers: "membres inconnus",
  identRights: "droits",
  identSessions: "sessions",
  identNone: "aucun",
  identNoController:
    "Le pod controller n'a pas été trouvé : inviter et fermer les sessions sont indisponibles.",

  ranchUsers: "Comptes",
  ranchAccess: "Accès",
  ranchProjects: "Projects",
  ranchTokens: "Tokens",
  ranchDetail: "Rancher",
  ranchSelectRow: "Sélectionnez une ligne",
  ranchActions: "Rancher",
  ranchIssue: "Émettre un token",
  ranchIssueHelp:
    "Crée un Token calqué sur ceux que Rancher émet pour un kubeconfig. Le credential est affiché une seule fois.",
  ranchIssueTtl: "durée de vie (minutes, 0 = jamais)",
  ranchIssueHashing:
    "`token-hashing` est actif : Rancher n'en stocke qu'un condensé, et le secret affiché n'est pas promis utilisable.",
  ranchSetTtl: "Changer la durée de vie",
  ranchSetTtlHelp: "Raccourcir un credential distribué trop généreusement, sans couper la session.",
  ranchRevoke: "Révoquer",
  ranchRevokeHelp: "Supprimer l'objet Token est la seule vraie révocation.",
  ranchRevokeSession: "Ce token est la session de connexion elle-même : la révoquer déconnecte.",
  ranchSetSetting: "Régler",
  ranchSetSettingHelp: "Vaut pour tout le cluster : gouverne chaque credential émis ensuite.",
  ranchApply: "Appliquer",
  ranchCancel: "Annuler",
  ranchEmpty: "Rien à afficher dans ce monde.",
  ranchReadOnly:
    "Ce cluster est un downstream : les objets d'identité y sont des répliques, et les écritures sont refusées.",
  ranchScopeless: "La vue lit un annuaire : la portée de namespace ne s'y applique pas.",
  ranchTokenOnce:
    "Ce credential ne sera plus affiché. Il n'est écrit ni dans un log, ni sur disque, ni dans l'état.",
  ranchTokenClose: "J'ai copié",
  ranchIdentity: "identité",
  ranchLogin: "login",
  ranchProvider: "provider",
  ranchPrincipal: "principal",
  ranchGlobalRoles: "rôles globaux",
  ranchGroups: "groupes",
  ranchNamespaces: "namespaces",
  ranchOwners: "owners",
  ranchAuth: "authentification",
  ranchOrphanNs: "namespaces sans project",
  ranchNotAuthoritative:
    "Ligne reconstruite depuis le RBAC projeté par l'agent : l'objet Rancher est en amont.",

  kyByPolicy: "par policy",
  kyByResource: "par ressource",
  kyAxisHelp:
    "La même jointure lue par un bout ou par l'autre : « que casse cette policy ? » ou « qu'est-ce qui ne va pas ici ? ».",
  kyFilterEnforce: "bloquantes",
  kyFilterHelp:
    "« problèmes » garde aussi les policies qui ne peuvent pas s'évaluer : elles ne protègent rien. « bloquantes » ne garde que celles qui refusent des écritures.",
  kyEmpty: "Aucune policy ne correspond.",
  kyNotInstalled: "Kyverno n'est pas installé sur ce cluster.",
  kyScopeless:
    "Les policies sont cluster-scoped, et l'axe par ressource groupe déjà par namespace : cette vue lit tout le cluster.",
  kyDetail: "Policy",
  kyResourceLabel: "ressource",
  kySelectRow: "Choisissez une ligne pour agir dessus.",
  kyFold: "Plier / déplier",
  kyPolicies: "policies",
  kyEnforcing: "enforce",
  kyNotReady: "not ready",
  kyNoViolation: "aucun constat",
  kyHealthOk: "kyverno",
  kyHealthDegraded: "kyverno dégradé",
  kyHealthInactive: "kyverno inactif",
  kyHealthUnknown: "kyverno non lu",
  kyNoControllers: "controllers introuvables dans le namespace kyverno",
  kyWebhooks: "webhooks",
  kyNoWebhook:
    "Aucun webhook enregistré : les controllers tournent, mais rien n'est intercepté.",
  kyNoCel: "moteur CEL absent (Kyverno < 1.14)",
  kyReports: "rapports",
  kyRequests: "requests",
  kyRequestsPending: "en attente",
  kyRequestsFailed: "en échec",
  kyRequestsOldest: "la plus ancienne : {age}",
  kyRequestsTop: "surtout :",
  kyEphemeral: "{n} rapports intermédiaires",
  kyPurge: "purger les requests bloquées",
  kyPurgeHelp:
    "Supprime les UpdateRequest Pending/Failed. Kyverno recrée ce qui est encore nécessaire via synchronize.",
  kyPurgeNone: "Aucune request bloquée à purger.",
  kyPurgeConfirm: "{n} requests bloquées seront supprimées.",
  kyPosture: "posture",
  kyAdmission: "admission",
  kyBackground: "background",
  kyBackgroundOnly: "background seulement",
  kyNoBackground: "non — rien n'est scanné hors admission",
  kySchedule: "schedule",
  kyOverride: "override",
  kyRules: "règles",
  kyAutogen: "autogen",
  kyAppliesTo: "s'applique à",
  kyExceptions: "exceptions",
  kyExcludes: "exclut",
  kyForRules: "pour les règles",
  kyAllRules: "toutes les règles",
  kyFailing: "ce qui échoue",
  kyDenials: "refus à l'admission",
  kyNoDenial: "aucun refus dans les évènements lus",
  kyDenialsDenied:
    "Les évènements vous sont refusés : les refus d'admission ne peuvent pas être affichés.",
  kyViolated: "policies enfreintes",
  kyErrorNote:
    "« error » veut dire que la règle n'a pas pu s'évaluer : c'est la policy qui est cassée, pas la ressource.",
  kyRetrigger:
    "Un constat de background scan est réévalué au prochain passage : toucher l'objet le refait immédiatement.",
  kyOrigin: "origine",
  kyEvaluated: "évalué",
  kySeverity: "severity",
  kyCategory: "category",
  kyNotReadyNote: "Cette policy ne peut pas s'évaluer : elle ne protège rien.",

  rbacFlat: "audit",
  rbacBySubject: "par identité",
  rbacByBinding: "par liaison",
  rbacByRole: "par rôle",
  rbacOrientHelp:
    "Le même graphe par quatre bouts. « par rôle » est la seule lecture qui montre un ClusterRole re-accordé namespace par namespace comme un seul nœud.",
  rbacMinSev: "sévérité",
  rbacMinSevHelp:
    "Le plancher : sur un vrai cluster l'essentiel des liaisons est de la plomberie en lecture seule, et tout afficher revient à ne rien montrer.",
  rbacEmpty: "Aucune liaison ne correspond.",
  rbacDetail: "RBAC",
  rbacFold: "Plier / déplier",
  rbacBindings: "liaisons",
  rbacRoles: "rôles",
  rbacAccounts: "comptes",
  rbacSaDegraded:
    "La liste des ServiceAccounts n'a pas pu être lue : aucun « ce compte n'existe pas » n'est affirmé.",
  rbacSaMissing: "compte absent",
  rbacSaMissingDetail:
    "Aucun ServiceAccount de ce nom : la liaison n'accorde rien aujourd'hui, et accordera tout dès que quelqu'un créera le compte.",
  rbacExternalSubject:
    "Identité extérieure : le cluster ne stocke rien de plus qu'un nom rendu par l'authentificateur.",
  rbacReadOnly: "lecture seule",
  rbacNoRule: "aucune règle",
  rbacNoGrant: "aucune liaison",
  rbacGrants: "Ce qu'elle détient",
  rbacFindings: "Constats",
  rbacRules: "Règles",
  rbacAggregation: "Composé de",
  rbacAggregatesNone: "aucun contributeur",
  rbacAggregationPartial:
    "Un sélecteur d'agrégation utilise matchExpressions, qui n'est pas évalué : l'union des règles est une borne basse.",
  rbacFeeds: "Alimente",
  rbacVia: "via",
  rbacViaClusterrole: "ClusterRole lié dans {scope}",
  rbacAggregatedLabel: "règles issues de l'agrégation",
  rbacBound: "lié",
  rbacBoundCluster: "{n} liaison(s) cluster",
  rbacBoundNs: "{n} namespace(s)",
  rbacTemplate: "modèle ×{n}",
  rbacUnbound: "personne ne le lie",
  rbacNRules: "{n} règles",
  rbacNBindings: "{n} liaisons",
  rbacAutomount: "automount",
  rbacAutomountOn: "oui",
  rbacAutomountOff: "non",
  rbacAutomountDefault: "défaut du namespace",
  rbacSecrets: "secrets",
  rbacOrigin: "origine",
  rbacSource: "source",
  rbacScopeLabel: "portée",
  rbacSubjects: "sujets",
  rbacRoleLabel: "rôle",
  rbacGrantedIn: "accordé dans",

  filterAll: "tout",
  filterProblems: "problèmes",

  clusterUnknown: "cluster : état non lu",
  clusterVersionUnknown: "L'apiserver n'a pas rendu sa version.",
  clusterNodesDenied:
    "La liste des nodes vous est refusée : ni compte de nodes, ni allocation CPU/mémoire.",
  clusterNoMetrics:
    "metrics-server ne répond pas : l'allocation est connue, l'usage ne l'est pas.",

  nsSearch: "chercher un namespace…",
  nsLoading: "lecture des namespaces…",
  nsDenied: "Lister les namespaces vous est refusé : tapez le nom, il sera pris tel quel.",
  nsNoMatch: "aucun namespace ne correspond",
  nsAdd: "ajouter tel quel",
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
  secOpenChain: "open the chain",
  secOpenChainHelp:
    "Opens the certs view on the Certificate that produces this Secret, with the chain issuing it — issuer, request, order, challenge.",
  secNoOrigin: "This Secret is not produced by cert-manager",

  certTree: "Chain",
  certList: "List",
  certFilterAll: "all",
  certFilterProblems: "problems",
  certFilterFlight: "in flight",
  certFilterHelp:
    "\"problems\" keeps whatever is not Ready and whatever expires within 30 days; \"in flight\" keeps only issuance under way. Ancestors of a kept row stay on screen: without its Issuer, a failing Certificate loses what explains it.",
  certEmpty: "No cert-manager object in this scope.",
  certNotInstalled: "cert-manager is not installed on this cluster.",
  certNoAcme: "no ACME",
  certSecretsUnreadable:
    "Secrets unreadable: the produced Secret and the keystores are not checked here.",
  certActions: "cert-manager actions",
  certRenew: "renew",
  certDescRenew: "Forces re-issuance: the Issuing condition goes True, the way cmctl renew does.",
  certAcmeRetry: "retry ACME",
  certDescAcmeRetry:
    "Deletes the in-flight CertificateRequest; its Order and Challenges go with it, and cert-manager issues a fresh one.",
  certRateLimited:
    "ACME rate limit hit: retrying would only burn what is left. The retry is withdrawn.",
  certSelectRow: "Select a row of the chain",
  certOpenSecret: "open the Secret",
  certOpenSecretHelp:
    "Opens the Secrets view on the produced Secret, where the certificate is decoded and values are revealed.",
  certChain: "Chain",
  certProduced: "Produced Secret",
  certKeystores: "Keystores",
  certSecretAbsent: "Secret {ns}/{name} missing — the certificate is ready but nothing serves it.",
  certSecretUnknown: "Secret state unknown in this scope",
  certConsumersNone: "no Ingress references it",
  certConsumersOne: "referenced by 1 Ingress",
  certConsumersMany: "referenced by {n} Ingresses",
  certExpiresIn: "expires in {n} d",
  certExpiredSince: "expired {n} d ago",
  certRenewalOn: "renewal",
  certExpiresOn: "expiry",
  certSignedBy: "{n} certificate(s) signed by this issuer",
  certKeystoreAlias: "alias {alias}",
  certKeystorePwRef: "password: {name}/{key}",
  certKeystorePwInline: "inline password",
  certDetail: "Chain",
  certFold: "Fold / unfold the chain",
  certDays: "{n} d",

  objActions: "Object",
  objSelectRow: "Select a row",
  objYamlRaw: "raw",
  objYamlNeat: "neat",
  objTouchHelp:
    "Stamps the object under kdt.io/ to cause a write: that write is what runs the admission webhooks again. Nothing else is touched.",
  objEditGuards: "Before writing",
  objEditApply: "Apply",
  objEditReload: "Reload",
  objEditChanges: "What this changes",
  objEditNoChange: "The document matches the object: nothing to write.",
  objEditNoop:
    "Every change lands on fields the API server owns: writing would leave the object as it is.",
  objEditServerOwned: "owned by the API server, ignored",
  objEditImmutable: "frozen once the object exists, the API server will refuse",
  objEditIdentity: "object identity: this document would point at another object",
  objEditConfirm: "Write",
  objEditCancel: "Cancel",
  objEditReadOnlyHint: "Edit the document, then \"Apply\" shows what it changes.",
  objWorking: "working…",

  delTitle: "Delete",
  delTarget: "Object",
  delChecking: "running checks…",
  delHelp:
    "None of these findings blocks anything: they say what will happen. An object deployed by a GitOps engine comes back at the next reconciliation.",
  delCancel: "Delete nothing",
  delConfirm: "Delete for good",
  delStrictHelp:
    "A serious finding applies — or the checks could not conclude. Retype the object name to confirm.",
  delStrictPlaceholder: "object name",
  delStrictMismatch: "expected: {name}",
  delReload: "Check again",

  identUsers: "Accounts",
  identGroups: "Groups",
  identDetail: "Account",
  identSelectRow: "Select a row",
  identActions: "Directory",
  identInvite: "Invite",
  identInviteHelp:
    "Runs `kdt-identity-server invite` in the controller pod and hands back a link and a code, once.",
  identInviteValidity: "validity",
  identInviteOnce:
    "These values will not be shown again. They travel through two separate channels, hence two separate copies.",
  identInviteLink: "Link",
  identInviteCode: "Code",
  identInviteRaw: "Command output",
  identInviteClose: "Copied",
  identRevoke: "Close sessions",
  identRevokeHelp:
    "Signs the account out of every machine. This is not disabling it: they can sign back in.",
  identEnable: "Re-enable",
  identDisable: "Disable",
  identEnableHelp: "Allows new accesses to be issued again.",
  identDisableHelp:
    "Blocks every new issuance. Credentials already handed out live until they expire.",
  identAddMember: "Add to group",
  identRemoveMember: "Remove",
  identMemberHelp:
    "Membership is held by the group, never by the account: it is written on `spec.members`.",
  identCreateUser: "New account",
  identCreateGroup: "New group",
  identName: "name",
  identEmail: "email",
  identDisplayName: "display name",
  identDescription: "description",
  identCreate: "Create",
  identEmpty: "No local account or group on this cluster.",
  identNotInstalled: "kdt-identity is not installed on this cluster.",
  identInstallHelp: "Install command",
  identScopeless: "The directory is cluster-scoped: the namespace scope does not apply.",
  identOperator: "operator",
  identMode: "delivery",
  identModeUnknown: "not declared",
  identRevocation: "revocation",
  identRefresh: "refresh",
  identDownload: "kubeconfig",
  identDownloadOpen: "download open — this access escapes revocation",
  identDownloadClosed: "download closed",
  identSubject: "subject",
  identGroupsLabel: "groups",
  identMembers: "members",
  identUnknownMembers: "unknown members",
  identRights: "rights",
  identSessions: "sessions",
  identNone: "none",
  identNoController:
    "The controller pod was not found: inviting and closing sessions are unavailable.",

  ranchUsers: "Accounts",
  ranchAccess: "Access",
  ranchProjects: "Projects",
  ranchTokens: "Tokens",
  ranchDetail: "Rancher",
  ranchSelectRow: "Select a row",
  ranchActions: "Rancher",
  ranchIssue: "Issue a token",
  ranchIssueHelp:
    "Creates a Token shaped like the ones Rancher issues for a kubeconfig. The credential is shown once.",
  ranchIssueTtl: "lifetime (minutes, 0 = never)",
  ranchIssueHashing:
    "`token-hashing` is on: Rancher stores only a digest, and the secret shown is not promised to work.",
  ranchSetTtl: "Change the lifetime",
  ranchSetTtlHelp: "Rein in a credential handed out too generously, without cutting the session.",
  ranchRevoke: "Revoke",
  ranchRevokeHelp: "Deleting the Token object is the only real revocation.",
  ranchRevokeSession: "This token is the login session itself: revoking it signs the person out.",
  ranchSetSetting: "Set",
  ranchSetSettingHelp: "Cluster-wide: it governs every credential issued afterwards.",
  ranchApply: "Apply",
  ranchCancel: "Cancel",
  ranchEmpty: "Nothing to show in this world.",
  ranchReadOnly:
    "This cluster is a downstream: its identity objects are replicas, and writes are refused.",
  ranchScopeless: "The view reads a directory: the namespace scope does not apply.",
  ranchTokenOnce:
    "This credential will not be shown again. It is written to no log, no disk and no state.",
  ranchTokenClose: "Copied",
  ranchIdentity: "identity",
  ranchLogin: "login",
  ranchProvider: "provider",
  ranchPrincipal: "principal",
  ranchGlobalRoles: "global roles",
  ranchGroups: "groups",
  ranchNamespaces: "namespaces",
  ranchOwners: "owners",
  ranchAuth: "authentication",
  ranchOrphanNs: "namespaces with no project",
  ranchNotAuthoritative:
    "Row rebuilt from the RBAC the cluster agent projected: the Rancher object lives upstream.",

  kyByPolicy: "by policy",
  kyByResource: "by resource",
  kyAxisHelp:
    "The same join read from either end: \u201cwhat does this policy break?\u201d or \u201cwhat is wrong here?\u201d.",
  kyFilterEnforce: "blocking",
  kyFilterHelp:
    "\u201cproblems\u201d also keeps the policies that cannot evaluate: they protect nothing. \u201cblocking\u201d keeps only those that reject writes.",
  kyEmpty: "No policy matches.",
  kyNotInstalled: "Kyverno is not installed on this cluster.",
  kyScopeless:
    "Policies are cluster-scoped, and the resource axis already groups by namespace: this view reads the whole cluster.",
  kyDetail: "Policy",
  kyResourceLabel: "resource",
  kySelectRow: "Pick a row to act on it.",
  kyFold: "Fold / unfold",
  kyPolicies: "policies",
  kyEnforcing: "enforce",
  kyNotReady: "not ready",
  kyNoViolation: "no finding",
  kyHealthOk: "kyverno",
  kyHealthDegraded: "kyverno degraded",
  kyHealthInactive: "kyverno inactive",
  kyHealthUnknown: "kyverno not read",
  kyNoControllers: "controllers not found in the kyverno namespace",
  kyWebhooks: "webhooks",
  kyNoWebhook: "No webhook registered: the controllers run, but nothing is intercepted.",
  kyNoCel: "CEL engine absent (Kyverno < 1.14)",
  kyReports: "reports",
  kyRequests: "requests",
  kyRequestsPending: "pending",
  kyRequestsFailed: "failed",
  kyRequestsOldest: "oldest: {age}",
  kyRequestsTop: "mostly:",
  kyEphemeral: "{n} intermediate reports",
  kyPurge: "purge stuck requests",
  kyPurgeHelp:
    "Deletes Pending/Failed UpdateRequests. Kyverno recreates what is still needed via synchronize.",
  kyPurgeNone: "No stuck request to purge.",
  kyPurgeConfirm: "{n} stuck requests will be deleted.",
  kyPosture: "posture",
  kyAdmission: "admission",
  kyBackground: "background",
  kyBackgroundOnly: "background only",
  kyNoBackground: "no \u2014 nothing is scanned outside admission",
  kySchedule: "schedule",
  kyOverride: "override",
  kyRules: "rules",
  kyAutogen: "autogen",
  kyAppliesTo: "applies to",
  kyExceptions: "exceptions",
  kyExcludes: "excludes",
  kyForRules: "for rules",
  kyAllRules: "every rule",
  kyFailing: "what fails",
  kyDenials: "admission denials",
  kyNoDenial: "no denial in the events read",
  kyDenialsDenied: "Events are denied to you: admission denials cannot be shown.",
  kyViolated: "policies violated",
  kyErrorNote:
    "\u201cerror\u201d means the rule could not be evaluated: the policy is broken, not the resource.",
  kyRetrigger:
    "A background-scan finding is re-evaluated on the next pass: touching the object redoes it now.",
  kyOrigin: "origin",
  kyEvaluated: "evaluated",
  kySeverity: "severity",
  kyCategory: "category",
  kyNotReadyNote: "This policy cannot evaluate: it protects nothing.",

  rbacFlat: "audit",
  rbacBySubject: "by identity",
  rbacByBinding: "by binding",
  rbacByRole: "by role",
  rbacOrientHelp:
    "The same graph from four ends. \u201cby role\u201d is the only reading that shows a ClusterRole re-granted namespace by namespace as one node.",
  rbacMinSev: "severity",
  rbacMinSevHelp:
    "The floor: on a real cluster most bindings are read-only plumbing, and showing everything amounts to showing nothing.",
  rbacEmpty: "No binding matches.",
  rbacDetail: "RBAC",
  rbacFold: "Fold / unfold",
  rbacBindings: "bindings",
  rbacRoles: "roles",
  rbacAccounts: "accounts",
  rbacSaDegraded:
    "The ServiceAccount list could not be read: no \u201cthis account does not exist\u201d is claimed.",
  rbacSaMissing: "account missing",
  rbacSaMissingDetail:
    "No ServiceAccount by that name: the binding grants nothing today, and grants everything the moment someone creates the account.",
  rbacExternalSubject:
    "External identity: the cluster stores nothing beyond a name handed over by the authenticator.",
  rbacReadOnly: "read-only",
  rbacNoRule: "no rule",
  rbacNoGrant: "no binding",
  rbacGrants: "What it holds",
  rbacFindings: "Findings",
  rbacRules: "Rules",
  rbacAggregation: "Composed of",
  rbacAggregatesNone: "no contributor",
  rbacAggregationPartial:
    "An aggregation selector uses matchExpressions, which is not evaluated: the rule union is a lower bound.",
  rbacFeeds: "Feeds",
  rbacVia: "via",
  rbacViaClusterrole: "ClusterRole bound in {scope}",
  rbacAggregatedLabel: "rules pulled in by aggregation",
  rbacBound: "bound",
  rbacBoundCluster: "{n} cluster binding(s)",
  rbacBoundNs: "{n} namespace(s)",
  rbacTemplate: "template \u00d7{n}",
  rbacUnbound: "nobody binds it",
  rbacNRules: "{n} rules",
  rbacNBindings: "{n} bindings",
  rbacAutomount: "automount",
  rbacAutomountOn: "yes",
  rbacAutomountOff: "no",
  rbacAutomountDefault: "namespace default",
  rbacSecrets: "secrets",
  rbacOrigin: "origin",
  rbacSource: "source",
  rbacScopeLabel: "scope",
  rbacSubjects: "subjects",
  rbacRoleLabel: "role",
  rbacGrantedIn: "granted in",

  filterAll: "all",
  filterProblems: "problems",

  clusterUnknown: "cluster: state not read",
  clusterVersionUnknown: "The apiserver did not report its version.",
  clusterNodesDenied:
    "Listing nodes is denied to you: no node count, no CPU/memory allocation.",
  clusterNoMetrics: "metrics-server is not answering: allocation is known, usage is not.",

  nsSearch: "search a namespace…",
  nsLoading: "reading namespaces…",
  nsDenied: "Listing namespaces is denied to you: type the name, it will be taken as is.",
  nsNoMatch: "no namespace matches",
  nsAdd: "add as typed",
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
