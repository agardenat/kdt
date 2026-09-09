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

  // --- Le geste `i` de kdt : envoyer ce qu'on regarde à un modèle. Ce que le serveur rédige —
  // le prompt, les étapes de l'enrichissement — arrive déjà traduit ; ce qui suit est ce que le
  // navigateur dit de lui-même.
  actionAi: string;
  aiHelp: string;
  aiNoProvider: string;
  aiNoProviderHelp: string;
  aiSettings: string;
  aiClose: string;
  aiPrivacy: string;
  aiServerProviders: string;
  aiNoServerProvider: string;
  aiPersonalProviders: string;
  aiCustomRefused: string;
  aiKeyStorage: string;
  aiEdit: string;
  aiForget: string;
  aiName: string;
  aiBaseUrl: string;
  aiModel: string;
  aiApiKey: string;
  aiContextWindow: string;
  aiContextHelp: string;
  aiCancel: string;
  aiSave: string;
  aiAdd: string;
  aiRerun: string;
  aiStop: string;
  aiWorking: string;
  aiElapsed: string;
  aiEmptyAnswer: string;
  aiOtherTarget: string;
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
  identAuth: string;
  identAuthUnknown: string;
  identSource: string;
  identLdapDn: string;
  identLdapUrl: string;
  identLdapProfile: string;
  identLdapBase: string;
  identLdapResync: string;
  identLdapMappings: string;
  identMappingsUnreadable: string;
  identMappingsMissing: string;
  identInviteLdap: string;
  identMembershipLdap: string;
  identEnableLdap: string;
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

  // --- Vue Velero. Le jargon reste en anglais des deux côtés : `backup`, `restore`, `schedule`,
  // `snapshot`, `bucket` ne se disent pas autrement, et les constats viennent du serveur.
  velBackups: string;
  velRestores: string;
  velInfra: string;
  velGroup: string;
  velGroupHelp: string;
  velEmpty: string;
  velNotInstalled: string;
  velDetail: string;
  velSelectRow: string;
  velFold: string;
  velRpo: string;
  velNoBackup: string;
  velProblems: string;
  velServer: string;
  velServerMissing: string;
  velNodeAgent: string;
  velNodeAgentAbsent: string;
  velUncovered: string;
  velUncoveredHelp: string;
  velActions: string;
  velBackupNow: string;
  velBackupNowHelp: string;
  velPause: string;
  velPauseHelp: string;
  velResume: string;
  velResumeHelp: string;
  velRestore: string;
  velRestoreHelp: string;
  velRestoreOpts: string;
  velRestoreOptsHelp: string;
  velDelete: string;
  velDeleteHelp: string;
  velNoAction: string;
  velContents: string;
  velContentsHelp: string;
  velContentsLoading: string;
  velContentsEmpty: string;
  velClusterScoped: string;
  velLogs: string;
  velLogsHelp: string;
  velLogsNoRun: string;
  velLogSourceDownload: string;
  velLogSourceServer: string;
  velLogEmpty: string;
  velRoNamespaces: string;
  velRoNsManual: string;
  velRoNsManualHelp: string;
  velRoKinds: string;
  velRoTarget: string;
  velRoTargetHelp: string;
  velRoLabels: string;
  velRoLabelsHelp: string;
  velRoOverwrite: string;
  velRoOverwriteHelp: string;
  velRoNoNs: string;
  velRoConfirm: string;
  velRoAll: string;
  velRoNone: string;
  velLblCron: string;
  velLblNextRun: string;
  velLblLastBackup: string;
  velLblLastSkipped: string;
  velLblTtl: string;
  velLblScope: string;
  velLblVolumes: string;
  velLblLocation: string;
  velLblPhase: string;
  velLblSchedule: string;
  velLblStarted: string;
  velLblDuration: string;
  velLblItems: string;
  velLblCaptured: string;
  velLblExpires: string;
  velLblErrors: string;
  velLblBackup: string;
  velLblProvider: string;
  velLblBucket: string;
  velLblAccess: string;
  velLblValidated: string;
  velLblRepoType: string;
  velLblMaintenance: string;
  velLblRestores: string;
  velLblFailedVolumes: string;
  velNever: string;
  velPaused: string;
  velAllNamespaces: string;
  velOverdue: string;
  velGitops: string;

  // --- Vues capacité, stockage et network policies. Le jargon reste en anglais des deux côtés —
  // node, workload, quota, claim, volume, class, ingress, egress — et les constats viennent du
  // serveur déjà rédigés. Ce qui suit est ce que le navigateur écrit lui-même.
  capEmpty: string;
  capNoMetrics: string;
  capReserved: string;
  capUsed: string;
  capIfLost: string;
  capHomeless: string;
  capOverview: string;
  capNodeCordoned: string;
  capNodeNotReady: string;
  capSlots: string;

  stoEmpty: string;
  stoReleased: string;
  stoMountsUnknown: string;
  stoDeletes: string;
  stoDefault: string;
  stoNoClass: string;
  stoMountedBy: string;
  stoBackend: string;

  // --- Vue Nodes. Le jargon reste en anglais des deux côtés — node, cordon, drain, container,
  // pod — et tout ce qui juge (alertes, constats de drain, constats de dimensionnement) est
  // rédigé par le serveur. Ce qui suit est ce que le navigateur écrit lui-même.
  ndEmpty: string;
  ndInventory: string;
  ndUsage: string;
  ndUsageOf: string;
  ndSelectNode: string;
  ndActions: string;
  ndCordon: string;
  ndUncordon: string;
  ndDrain: string;
  ndDescCordon: string;
  ndDescUncordon: string;
  ndDescDrain: string;
  ndSort: string;
  ndSortMemReq: string;
  ndSortCpuReq: string;
  ndSortAlpha: string;
  ndNoMetrics: string;
  ndAlloc: string;
  ndDiagnostic: string;
  ndUser: string;
  ndSystem: string;
  ndTotal: string;
  ndWaste: string;
  ndSystemRow: string;
  ndReadyShort: string;
  ndDrainTitle: string;
  ndDrainChecking: string;
  ndDrainTarget: string;
  ndDrainStays: string;
  ndDrainStrictHelp: string;
  ndDrainStrictPlaceholder: string;
  ndDrainStrictMismatch: string;
  ndDrainCancel: string;
  ndDrainConfirm: string;
  ndDrainReload: string;
  ndDrainRunning: string;
  ndDrainEvicted: string;
  ndDrainWaiting: string;
  ndDrainFailed: string;
  ndDrainHelp: string;
  ndScopeless: string;

  netpolEmpty: string;
  netpolCluster: string;
  netpolNoVerdict: string;
  netpolTarget: string;

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
  actionAi: "✨ IA",
  aiHelp: "Analyser cette ligne avec l'IA configurée",
  aiNoProvider: "Aucun fournisseur d'IA n'est configuré.",
  aiNoProviderHelp: "Aucun fournisseur d'IA configuré — cliquez pour en déclarer un",
  aiSettings: "Réglage de l'IA",
  aiClose: "Fermer",
  aiPrivacy:
    "L'analyse envoie à l'endpoint choisi le statut de l'objet, ses logs, ses évènements et les objets liés. Des logs peuvent contenir des secrets applicatifs : ne visez qu'un endpoint de confiance.",
  aiServerProviders: "Fournisseurs de ce serveur",
  aiNoServerProvider: "Ce serveur n'en déclare aucun.",
  aiPersonalProviders: "Vos fournisseurs",
  aiCustomRefused: "Ce serveur n'accepte que ses propres fournisseurs.",
  aiKeyStorage:
    "Votre clé reste dans ce navigateur et accompagne chaque analyse ; le serveur ne la conserve pas. Elle y est lisible par tout script qui s'exécuterait sur cette origine.",
  aiEdit: "Modifier",
  aiForget: "Oublier",
  aiName: "Nom",
  aiBaseUrl: "URL de base",
  aiModel: "Modèle",
  aiApiKey: "Clé API",
  aiContextWindow: "Fenêtre de contexte",
  aiContextHelp:
    "En tokens. Renseignée, le prompt est taillé pour tenir dedans ; vide, il part entier.",
  aiCancel: "Annuler",
  aiSave: "Enregistrer",
  aiAdd: "Ajouter un fournisseur",
  aiRerun: "Relancer",
  aiStop: "Arrêter",
  aiWorking: "Analyse en cours…",
  aiElapsed: "{s} s",
  aiEmptyAnswer: "Le modèle n'a rien répondu.",
  aiOtherTarget: "Cette analyse porte sur {target}.",
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
  identAuth: "authentification",
  identAuthUnknown:
    "non déclarée (déploiement antérieur à 1.2, ou variable absente du pod)",
  identSource: "source",
  identLdapDn: "DN épinglé",
  identLdapUrl: "annuaire",
  identLdapProfile: "profil",
  identLdapBase: "racine de recherche",
  identLdapResync: "relecture",
  identLdapMappings: "correspondances",
  identMappingsUnreadable:
    "Table de correspondance illisible : rien n'est affirmé sur ce qui alimente les groupes.",
  identMappingsMissing:
    "Déclarés dans la table sans exister ici — chacun sera créé à la première connexion d'un de ses membres :",
  identInviteLdap:
    "authMode ldap : les comptes naissent d'une connexion réussie contre l'annuaire, invite refuse de s'exécuter",
  identMembershipLdap:
    "sur un groupe alimenté depuis l'annuaire, l'écriture aboutit puis la relecture suivante la défait",
  identEnableLdap:
    "compte fédéré : si son entrée a disparu de l'annuaire, la relecture suivante le redésactivera",
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

  velBackups: "backups",
  velRestores: "restores",
  velInfra: "infra",
  velGroup: "sous leur schedule",
  velGroupHelp:
    "Regroupe chaque backup sous le Schedule qui l'a produit, et rassemble à part ceux qu'aucun schedule ne réclame.",
  velEmpty: "Rien à montrer dans cette portée.",
  velNotInstalled: "Velero n'est pas installé sur ce cluster.",
  velDetail: "Velero",
  velSelectRow: "Choisissez une ligne pour agir dessus.",
  velFold: "Plier / déplier",
  velRpo: "dernier backup restaurable",
  velNoBackup: "aucun backup restaurable",
  velProblems: "constats",
  velServer: "velero",
  velServerMissing: "controller introuvable",
  velNodeAgent: "node-agent",
  velNodeAgentAbsent: "node-agent absent : fs-backup ne capture rien",
  velUncovered: "namespaces non couverts",
  velUncoveredHelp:
    "Ces namespaces portent un PVC qu'aucun schedule ne couvre : leurs données ne sont pas sauvegardées, et rien d'autre ne le dit.",
  velActions: "Actions",
  velBackupNow: "lancer un backup",
  velBackupNowHelp:
    "Crée un Backup à partir du template du schedule, nommé et étiqueté comme le fait le contrôleur — y compris pour la rétention qui l'expirera.",
  velPause: "mettre en pause",
  velPauseHelp:
    "spec.paused : le contrôleur cesse de créer des backups. Rien d'existant n'est touché.",
  velResume: "reprendre",
  velResumeHelp: "Le contrôleur recommence à créer des backups aux heures du cron.",
  velRestore: "restaurer",
  velRestoreHelp:
    "Restaure tout le backup, là d'où il vient, en contournant les objets qui existent déjà.",
  velRestoreOpts: "restaurer à la carte",
  velRestoreOptsHelp:
    "Choisir les namespaces, les kinds, la cible et les labels avant de restaurer.",
  velDelete: "supprimer le backup",
  velDeleteHelp:
    "Dépose un DeleteBackupRequest : supprimer l'objet Backup ne supprime rien, le contrôleur de synchronisation le recrée depuis le bucket. La demande, elle, efface snapshots, fichiers et objet.",
  velNoAction: "Aucune action sur cette ligne.",
  velContents: "contenu",
  velContentsHelp:
    "Télécharge l'inventaire du backup depuis le stockage objet : ce qu'il contient réellement, namespace par namespace.",
  velContentsLoading: "téléchargement…",
  velContentsEmpty: "ce backup n'a rien capturé",
  velClusterScoped: "objets cluster",
  velLogs: "log du run",
  velLogsHelp:
    "Le seul endroit qui dise quel objet a produit l'avertissement qu'un backup « Completed » rapporte.",
  velLogsNoRun: "Cette ligne n'est pas un run : seuls un backup et une restauration en ont un.",
  velLogSourceDownload: "log du run",
  velLogSourceServer:
    "log du controller (repli) : l'URL signée n'était pas joignable, et ces lignes ne remontent qu'aussi loin que le pod courant.",
  velLogEmpty: "log vide",
  velRoNamespaces: "namespaces",
  velRoNsManual: "namespaces (séparés par des virgules)",
  velRoNsManualHelp:
    "L'inventaire n'a pas pu être téléchargé : les namespaces se tapent, et le formulaire reste utilisable — c'est précisément le cas pour lequel il existe.",
  velRoKinds: "kinds",
  velRoTarget: "namespace cible",
  velRoTargetHelp:
    "Restaurer ailleurs que là d'où ça vient. Velero mappe namespace par namespace : avec plusieurs sources cochées il n'y a pas de source unique, et le champ n'est pas appliqué.",
  velRoLabels: "labels",
  velRoLabelsHelp: "team=a, env=prod — ne garde que les objets qui les portent.",
  velRoOverwrite: "écraser ce qui existe",
  velRoOverwriteHelp:
    "existingResourcePolicy: update. Le seul réglage qui détruise quelque chose : il écrase les objets vivants au lieu de les contourner.",
  velRoNoNs:
    "Aucun namespace choisi. Une liste vide restaurerait tout le backup, ce qui est l'inverse de ce qu'une liste vidée demande.",
  velRoConfirm: "retapez le nom du backup pour confirmer",
  velRoAll: "tout",
  velRoNone: "rien",
  velLblCron: "cron",
  velLblNextRun: "prochaine exécution",
  velLblLastBackup: "dernier backup",
  velLblLastSkipped: "dernier saut",
  velLblTtl: "rétention",
  velLblScope: "portée",
  velLblVolumes: "volumes",
  velLblLocation: "location",
  velLblPhase: "phase",
  velLblSchedule: "schedule",
  velLblStarted: "démarré",
  velLblDuration: "durée",
  velLblItems: "objets",
  velLblCaptured: "capturé",
  velLblExpires: "expire",
  velLblErrors: "erreurs / warnings",
  velLblBackup: "backup",
  velLblProvider: "provider",
  velLblBucket: "bucket",
  velLblAccess: "accès",
  velLblValidated: "validé",
  velLblRepoType: "type",
  velLblMaintenance: "maintenance",
  velLblRestores: "restaurations",
  velLblFailedVolumes: "volumes en échec",
  velNever: "jamais",
  velPaused: "en pause",
  velAllNamespaces: "tous les namespaces",
  velOverdue: "en retard",
  velGitops: "possédé par {engine} : une pause posée ici sera défaite à la prochaine réconciliation.",

  capEmpty: "Rien à montrer dans cette portée.",
  capNoMetrics:
    "metrics-server ne répond pas : la réservation est connue, la consommation ne l'est pas.",
  capReserved: "réservé",
  capUsed: "consommé",
  capIfLost: "si ce node tombe",
  capHomeless: "Pods sans point de chute",
  capOverview: "Capacité",
  capNodeCordoned: "cordonné",
  capNodeNotReady: "NotReady",
  capSlots: "slots de pods",

  stoEmpty: "Rien à montrer dans cette portée.",
  stoReleased: "{size} dorment en Released",
  stoMountsUnknown:
    "La liste des pods vous est refusée : « rien ne monte cette claim » n'est donc jamais affirmé.",
  stoDeletes: "reclaimPolicy Delete : supprimer la claim supprime la donnée.",
  stoDefault: "défaut",
  stoNoClass: "(classe absente)",
  stoMountedBy: "monté par",
  stoBackend: "backend",

  ndEmpty: "Aucun node à montrer.",
  ndInventory: "Nodes",
  ndUsage: "Usage",
  ndUsageOf: "usage de",
  ndSelectNode: "Sélectionnez un node.",
  ndActions: "Actions node",
  ndCordon: "cordon",
  ndUncordon: "uncordon",
  ndDrain: "drain",
  ndDescCordon: "Le scheduler ne place plus rien ici. Ce qui tourne déjà reste.",
  ndDescUncordon: "Le node redevient éligible au scheduler.",
  ndDescDrain:
    "Cordonne le node puis évince ses pods. Les garde-fous disent d'abord ce que ça déplace.",
  ndSort: "tri",
  ndSortMemReq: "mem-req",
  ndSortCpuReq: "cpu-req",
  ndSortAlpha: "alpha",
  ndNoMetrics:
    "metrics-server ne répond pas : la réservation est connue, la consommation ne l'est pas.",
  ndAlloc: "allocatable",
  ndDiagnostic: "Diagnostic",
  ndUser: "USER",
  ndSystem: "SYS",
  ndTotal: "TOTAL",
  ndWaste: "réservé et jamais consommé",
  ndSystemRow: "container de la plateforme",
  ndReadyShort: "prêt",
  ndDrainTitle: "Drain",
  ndDrainChecking: "Vérification…",
  ndDrainTarget: "Node à drainer",
  ndDrainStays: "reste en place",
  ndDrainStrictHelp: "Retapez le nom du node pour confirmer.",
  ndDrainStrictPlaceholder: "nom du node",
  ndDrainStrictMismatch: "Ce n'est pas {name}.",
  ndDrainCancel: "Annuler",
  ndDrainConfirm: "Drainer",
  ndDrainReload: "Revérifier",
  ndDrainRunning: "Éviction en cours…",
  ndDrainEvicted: "évincés",
  ndDrainWaiting: "retenus par un budget, réessayés",
  ndDrainFailed: "en échec",
  ndDrainHelp:
    "Aucun constat ne bloque : ils disent ce qui va se passer, et de combien la confirmation coûte.",
  ndScopeless: "Un node n'a pas de namespace : cette vue ignore la portée.",

  netpolEmpty: "Aucune policy dans cette portée.",
  netpolCluster: "(cluster)",
  netpolNoVerdict:
    "Ce moteur n'a pas de verdict de posture : sa sémantique par défaut n'est pas celle du natif, et l'affirmer serait deviner.",
  netpolTarget: "cible",

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
  actionAi: "✨ AI",
  aiHelp: "Analyse this row with the configured AI",
  aiNoProvider: "No AI provider is configured.",
  aiNoProviderHelp: "No AI provider configured — click to declare one",
  aiSettings: "AI settings",
  aiClose: "Close",
  aiPrivacy:
    "The analysis sends the object's status, its logs, its events and related objects to the chosen endpoint. Logs may carry application secrets: only point at an endpoint you trust.",
  aiServerProviders: "This server's providers",
  aiNoServerProvider: "This server declares none.",
  aiPersonalProviders: "Your providers",
  aiCustomRefused: "This server only accepts its own providers.",
  aiKeyStorage:
    "Your key stays in this browser and travels with each analysis; the server does not keep it. Any script running on this origin can read it there.",
  aiEdit: "Edit",
  aiForget: "Forget",
  aiName: "Name",
  aiBaseUrl: "Base URL",
  aiModel: "Model",
  aiApiKey: "API key",
  aiContextWindow: "Context window",
  aiContextHelp:
    "In tokens. Set, the prompt is trimmed to fit; empty, it is sent whole.",
  aiCancel: "Cancel",
  aiSave: "Save",
  aiAdd: "Add a provider",
  aiRerun: "Run again",
  aiStop: "Stop",
  aiWorking: "Analysing…",
  aiElapsed: "{s}s",
  aiEmptyAnswer: "The model answered nothing.",
  aiOtherTarget: "This analysis is about {target}.",
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
  identAuth: "authentication",
  identAuthUnknown:
    "not declared (a pre-1.2 deployment, or the variable is absent from the pod)",
  identSource: "source",
  identLdapDn: "pinned DN",
  identLdapUrl: "directory",
  identLdapProfile: "profile",
  identLdapBase: "search base",
  identLdapResync: "re-read",
  identLdapMappings: "mappings",
  identMappingsUnreadable:
    "The mapping table cannot be read: nothing is stated about what feeds the groups.",
  identMappingsMissing:
    "Declared in the table and absent here — each is created at the first sign-in of one of its members:",
  identInviteLdap:
    "authMode ldap: accounts are born of a successful sign-in against the directory, and invite refuses to run",
  identMembershipLdap:
    "on a group fed from the directory, the write lands and the next re-read undoes it",
  identEnableLdap:
    "federated account: if its directory entry is gone, the next re-read disables it again",
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

  velBackups: "backups",
  velRestores: "restores",
  velInfra: "infra",
  velGroup: "under their schedule",
  velGroupHelp:
    "Groups every backup under the Schedule that produced it, and collects apart the ones no schedule claims.",
  velEmpty: "Nothing to show in this scope.",
  velNotInstalled: "Velero is not installed on this cluster.",
  velDetail: "Velero",
  velSelectRow: "Pick a row to act on it.",
  velFold: "Fold / unfold",
  velRpo: "last restorable backup",
  velNoBackup: "no restorable backup",
  velProblems: "findings",
  velServer: "velero",
  velServerMissing: "controller not found",
  velNodeAgent: "node-agent",
  velNodeAgentAbsent: "node-agent absent: fs-backup captures nothing",
  velUncovered: "uncovered namespaces",
  velUncoveredHelp:
    "These namespaces hold a PVC no schedule covers: their data is not backed up, and nothing else says so.",
  velActions: "Actions",
  velBackupNow: "run a backup",
  velBackupNowHelp:
    "Creates a Backup from the schedule template, named and labelled the way the controller does \u2014 including for the retention that will expire it.",
  velPause: "pause",
  velPauseHelp: "spec.paused: the controller stops creating backups. Nothing existing is touched.",
  velResume: "resume",
  velResumeHelp: "The controller starts creating backups again at the cron times.",
  velRestore: "restore",
  velRestoreHelp:
    "Restores the whole backup where it came from, stepping around the objects that already exist.",
  velRestoreOpts: "restore selectively",
  velRestoreOptsHelp: "Pick namespaces, kinds, target and labels before restoring.",
  velDelete: "delete the backup",
  velDeleteHelp:
    "Files a DeleteBackupRequest: deleting the Backup object deletes nothing, the sync controller recreates it from the bucket. The request removes snapshots, files and object.",
  velNoAction: "No action on this row.",
  velContents: "contents",
  velContentsHelp:
    "Downloads the backup inventory from object storage: what it actually holds, namespace by namespace.",
  velContentsLoading: "downloading\u2026",
  velContentsEmpty: "this backup captured nothing",
  velClusterScoped: "cluster objects",
  velLogs: "run log",
  velLogsHelp:
    "The only place that says which item produced the warning a \u201cCompleted\u201d backup reports.",
  velLogsNoRun: "This row is not a run: only a backup and a restore have one.",
  velLogSourceDownload: "run log",
  velLogSourceServer:
    "controller log (fallback): the signed URL was unreachable, and these lines only go back as far as the current pod.",
  velLogEmpty: "empty log",
  velRoNamespaces: "namespaces",
  velRoNsManual: "namespaces (comma separated)",
  velRoNsManualHelp:
    "The inventory could not be downloaded: namespaces are typed, and the form stays usable \u2014 which is exactly the case it exists for.",
  velRoKinds: "kinds",
  velRoTarget: "target namespace",
  velRoTargetHelp:
    "Restore somewhere else. Velero maps namespace by namespace: with several sources ticked there is no single source, and the field is not applied.",
  velRoLabels: "labels",
  velRoLabelsHelp: "team=a, env=prod \u2014 keeps only the objects carrying them.",
  velRoOverwrite: "overwrite what exists",
  velRoOverwriteHelp:
    "existingResourcePolicy: update. The only setting here that destroys anything: it overwrites live objects instead of stepping around them.",
  velRoNoNs:
    "No namespace picked. An empty list would restore the whole backup, which is the opposite of what an emptied list asks for.",
  velRoConfirm: "retype the backup name to confirm",
  velRoAll: "all",
  velRoNone: "none",
  velLblCron: "cron",
  velLblNextRun: "next run",
  velLblLastBackup: "last backup",
  velLblLastSkipped: "last skip",
  velLblTtl: "retention",
  velLblScope: "scope",
  velLblVolumes: "volumes",
  velLblLocation: "location",
  velLblPhase: "phase",
  velLblSchedule: "schedule",
  velLblStarted: "started",
  velLblDuration: "duration",
  velLblItems: "items",
  velLblCaptured: "captured",
  velLblExpires: "expires",
  velLblErrors: "errors / warnings",
  velLblBackup: "backup",
  velLblProvider: "provider",
  velLblBucket: "bucket",
  velLblAccess: "access",
  velLblValidated: "validated",
  velLblRepoType: "type",
  velLblMaintenance: "maintenance",
  velLblRestores: "restores",
  velLblFailedVolumes: "failed volumes",
  velNever: "never",
  velPaused: "paused",
  velAllNamespaces: "every namespace",
  velOverdue: "overdue",
  velGitops: "owned by {engine}: a pause set here is reverted at its next reconciliation.",

  capEmpty: "Nothing to show in this scope.",
  capNoMetrics: "metrics-server is not answering: reservation is known, consumption is not.",
  capReserved: "reserved",
  capUsed: "used",
  capIfLost: "if this node goes",
  capHomeless: "Pods with nowhere to go",
  capOverview: "Capacity",
  capNodeCordoned: "cordoned",
  capNodeNotReady: "NotReady",
  capSlots: "pod slots",

  stoEmpty: "Nothing to show in this scope.",
  stoReleased: "{size} sitting in Released",
  stoMountsUnknown:
    "Listing pods is denied to you: \"nothing mounts this claim\" is therefore never claimed.",
  stoDeletes: "reclaimPolicy Delete: deleting the claim deletes the data.",
  stoDefault: "default",
  stoNoClass: "(class missing)",
  stoMountedBy: "mounted by",
  stoBackend: "backend",

  ndEmpty: "No node to show.",
  ndInventory: "Nodes",
  ndUsage: "Usage",
  ndUsageOf: "usage of",
  ndSelectNode: "Select a node.",
  ndActions: "Node actions",
  ndCordon: "cordon",
  ndUncordon: "uncordon",
  ndDrain: "drain",
  ndDescCordon: "The scheduler places nothing here any more. What already runs stays.",
  ndDescUncordon: "The node is eligible to the scheduler again.",
  ndDescDrain:
    "Cordons the node, then evicts its pods. The guard-rails first say what that moves.",
  ndSort: "sort",
  ndSortMemReq: "mem-req",
  ndSortCpuReq: "cpu-req",
  ndSortAlpha: "alpha",
  ndNoMetrics: "metrics-server is not answering: reservation is known, consumption is not.",
  ndAlloc: "allocatable",
  ndDiagnostic: "Diagnosis",
  ndUser: "USER",
  ndSystem: "SYS",
  ndTotal: "TOTAL",
  ndWaste: "reserved and never used",
  ndSystemRow: "platform container",
  ndReadyShort: "ready",
  ndDrainTitle: "Drain",
  ndDrainChecking: "Checking…",
  ndDrainTarget: "Node to drain",
  ndDrainStays: "stay in place",
  ndDrainStrictHelp: "Type the node name again to confirm.",
  ndDrainStrictPlaceholder: "node name",
  ndDrainStrictMismatch: "That is not {name}.",
  ndDrainCancel: "Cancel",
  ndDrainConfirm: "Drain",
  ndDrainReload: "Check again",
  ndDrainRunning: "Evicting…",
  ndDrainEvicted: "evicted",
  ndDrainWaiting: "held by a budget, being retried",
  ndDrainFailed: "failed",
  ndDrainHelp:
    "No finding blocks anything: they say what is about to happen, and how much the confirmation costs.",
  ndScopeless: "A node has no namespace: this view ignores the scope.",

  netpolEmpty: "No policy in this scope.",
  netpolCluster: "(cluster)",
  netpolNoVerdict:
    "This engine gets no posture verdict: its default semantics are not the native ones, and asserting them would be guessing.",
  netpolTarget: "target",

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
