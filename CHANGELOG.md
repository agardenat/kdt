# Changelog

Toutes les versions publiées de kdt, la plus récente en premier. Chaque entrée reprend le
sujet du commit qui l'a apportée : type, portée, et ce qui change pour qui utilise l'outil.
Le versionnement suit [SemVer](https://semver.org/lang/fr/) et chaque version correspond au
tag `v<version>` qui a déclenché sa publication.

Les entrées jusqu'à la 1.24.0 incluse ont été reconstruites après coup depuis l'historique git :
elles disent ce que chaque version a apporté, pas ce qui en avait été annoncé à l'époque.

## [1.25.0] — 2026-09-02

- **feat(k8ssandra)** — `x` sur un node : commande `nodetool` libre lancée dans un Job qui survit à la fermeture de kdt
- **feat(rbac)** — SOURCE nomme Kyverno et Rancher, RISK ne garde que le pire constat
- **docs(changelog)** — CHANGELOG reconstruit depuis v1.0.0, et les notes de release publiées à partir de sa section

## [1.24.0] — 2026-09-02

- **feat(rbac)** — `:rbac <ns>` cible un namespace sans amputer le graphe lu
- **feat(rancher)** — `h` touche un Project, seule écriture de la vue et seulement sur le cluster local
- **feat(ui)** — `:cm kube-system` — la palette ouvre une vue déjà scopée sur un namespace
- **fix(ui)** — la palette ne dessine plus les évènements derrière la vue rancher

## [1.23.0] — 2026-09-01

- **feat(ui)** — le pli du panneau du haut (`²`) survit à la session
- **fix(ui)** — la ligne sélectionnée garde son contraste quel que soit le thème du terminal
- **fix(workloads)** — un Job terminé annonce ses complétions et son verdict, un DaemonSet son effectif

## [1.22.1] — 2026-09-01

- **feat(ui)** — le curseur parcourt la liste, elle ne défile qu'aux extrémités
- **feat(ui)** — `²` replie le panneau du haut pour laisser toute la place à la table
- **fix(flux)** — la chaîne Helm rejoint l'arbre, `a` déplie ce qui réconcilie et un pli annonce ce qu'il cache
- **fix(ui)** — `²` rejoint la liste des glyphes approuvés du garde-fou
- **fix(workloads)** — `:workloads` ouvre l'arbre (Jobs compris), `:pods` la liste plate, et un kind non listable est nommé

## [1.22.0] — 2026-08-24

- **feat(argocd)** — vue `:argocd` — sync et health côte à côte, le `Unknown` qui périme le vert, sets, projects et repos

## [1.21.0] — 2026-08-18

- **feat(svc)** — port-forward des Services ouvert par kdt lui-même, sans kubectl

## [1.20.7] — 2026-08-18

- **feat(nodes)** — annotations, labels et taints du nœud en fin de panneau, dans la partie visible du détail
- **fix(ui)** — le panneau de détail comptait ses lignes avant wrap et laissait son dernier bloc hors cadre

## [1.20.6] — 2026-08-18

- **feat(ui)** — le nom de nœud trop long garde son début et sa fin au lieu d'être coupé à la fin
- **style(ui)** — la colonne NODE s'élargit jusqu'à la place disponible avant d'élider

## [1.20.5] — 2026-08-17

- **fix(ui)** — la ligne sélectionnée grossissait au lieu de laisser défiler son message

## [1.20.4] — 2026-08-17

- **fix(flux)** — z annonce « resume » quand la ressource est déjà suspendue, et le badge marque le no-prune au lieu du prune

## [1.20.3] — 2026-08-17

- **fix(k8ssandra)** — le panneau S/l/m restait accroché à la vue, gardant le snapshot du nœud précédent

## [1.20.2] — 2026-08-14

- **fix(connexion)** — l'IPv4 essayée avant l'IPv6 quand le DNS renvoie les deux, contre le NAT64 qui avale le handshake TLS
- **docs** — README recentré sur l'usage — vues, touches et détections, sans argumentaire

## [1.20.1] — 2026-08-14

- **feat(rancher)** — portée du token en colonne, et la famille déduite quand Rancher ne la nomme pas

## [1.20.0] — 2026-08-14

- **feat(rancher)** — monde tokens avec les settings de TTL, émission/révocation par `o`, et le nom lisible d'une identité opaque en ligne
- **feat(rancher)** — vue `:rancher` — l'identité réelle derrière chaque `u-…`, l'access, les projects et les tokens, en lecture seule
- **docs(rancher)** — documenter le monde tokens, les settings de TTL et les écritures de `o`

## [1.19.1] — 2026-08-13

- **fix(namespace)** — `n` et `0` restent sur la vue courante au lieu de retomber sur les events

## [1.19.0] — 2026-08-13

- **feat(workloads)** — niveau container sous le pod — dépliage `x`, shell `E` et logs ciblés sur le container choisi
- **fix(workloads)** — le dépliage des containers passe sur `Espace`, la touche de pliage local des six autres vues

## [1.18.0] — 2026-08-13

- **feat(k8ssandra)** — snapshots par node via listsnapshots, taille réellement récupérable, et backupType vide qui ne casse plus le déclenchement manuel
- **feat(certs)** — keystores JKS/PKCS12 dans la vue certs, badge de ligne et vérification des fichiers réellement écrits dans le Secret

## [1.17.1] — 2026-08-13

- **fix(ui)** — Shift+flèches pilote le panneau du haut dans toutes les vues, via un arm global au lieu de seize copies par mode

## [1.17.0] — 2026-08-12

- **feat(k8ssandra)** — vue Cassandra/Medusa/Reaper, RPO par couverture de nodes, ring lu via l'API de management, actions backup/restore/task

## [1.16.0] — 2026-08-11

- **feat(reflector)** — arbre replié par défaut, portée allowed vide en Info (permission ≠ action), purge des destinations seulement permises, wrap du panneau de détail
- **feat(diag)** — étend le diagnostic aux modules flux/cert-manager/kyverno (UR)/velero/stockage/capacité/rbac/reflector

## [1.15.0] — 2026-08-11

- **feat(netpol)** — vue network policies (natives + CRDs Cilium/Calico) en 3e monde réseau, verdict posture ingress/egress

## [1.14.0] — 2026-08-11

- **feat(ns)** — vue namespaces à part entière (liste + yaml/touch/edit/delete, Entrée pour entrer dans le ns), remplace le picker modal

## [1.13.0] — 2026-08-10

- **feat(velero)** — verdict dégradé exploitable, garde-fou Ctrl-D backup en cours, scroll Shift+↑↓

## [1.12.1] — 2026-08-10

- **perf(kyverno)** — purge des requests bloquées en parallèle

## [1.12.0] — 2026-08-10

- **feat(kyverno)** — backlog des UpdateRequest visible et purge sur P

## [1.11.0] — 2026-07-31

- **feat(velero)** — inspection du contenu d'un backup et restauration à la carte

## [1.10.1] — 2026-07-31

- **feat(velero)** — vue :velero — backups, schedules avec cron évalué, restaurations, locations et opérations
- **refactor(ui)** — 'l' pour les logs partout, 'L' pour la bascule de langue

## [1.10.0] — 2026-07-30

- **feat** — mire de connexion au démarrage et prompt IA resserré
- **docs(readme)** — allègement du README et version anglaise

## [1.9.1] — 2026-07-29

- **fix(i18n)** — littéraux français en UI anglaise et bandeaux Kyverno illisibles
- **docs(readme)** — films de démonstration VHS — GIF de tête et un par vue

## [1.9.0] — 2026-07-28

- **feat(rbac)** — arbre complet — roles, ClusterRoles agrégés, templates et ServiceAccounts en nœuds, 4 orientations

## [1.8.2] — 2026-07-28

- **fix(deps)** — RUSTSEC — crossbeam-epoch 0.9.20, quinn-proto 0.11.16, quick-xml 0.41 via plist
- **fix(security)** — fichier d'édition en O_EXCL et timeouts sur les flux dl.k8s.io
- **chore(lang)** — purge de 30 clés de traduction orphelines, garde dead_code réactivée

## [1.8.1] — 2026-07-28

- **feat(i18n)** — interface réellement bilingue, jargon k8s en anglais des deux côtés

## [1.8.0] — 2026-07-27

- **feat(reflector)** — vue `:reflector` — dire ce que reflector fait, et ce qu'il tait

## [1.7.0] — 2026-07-27

- **feat(flux)** — déblocage `Ctrl-R` — nommer ce qui coince, proposer le contre-coup
- **fix(repair)** — rendre la confirmation suivable, et ne pas dire bloquant ce qui ne l'est pas
- **docs** — remettre le README au niveau du code
- **chore** — supprimer le fichier TODO, vide depuis sa création

## [1.6.0] — 2026-07-26

- **feat(capacity)** — vue `:capacity` — la marge de manœuvre, pas l'usage
- **feat(nodes)** — cordon/uncordon/drain à garde-fous, shell `E`, et recherche dans la vue Nodes
- **feat(storage)** — vue `:storage` / `:pv` — pourquoi un PVC ne se lie pas
- **feat(search)** — recherche `/` dans toutes les vues, et logs `previous`/container/suivi
- **feat(kyverno)** — vue `:kyverno` — policies, règles appliquées et refus d'admission
- **docs(touch)** — la barre annonce `h  toucher l'objet` dans la vue évènements

## [1.5.0] — 2026-07-25

- **feat(touch)** — touche `h` — annotation horodatée pour relancer l'admission
- **feat(edit)** — touche `e` — édition d'objet dans $EDITOR avec garde-fous
- **fix(delete)** — Ctrl-D — la réponse par défaut est « non »

## [1.4.0] — 2026-07-25

- **feat(certs)** — module cert-manager — remontée de la chaîne d'émission
- **feat(delete)** — touche `Ctrl-D` — suppression d'objet avec garde-fous GitOps
- **feat(yaml)** — touche `y` — manifeste de l'objet courant, brut ou neat
- **feat(footer)** — raccourcis regroupés par famille sur les 2 lignes
- **fix(ui)** — glyphes à chasse fixe — fin de bordure droite alignée
- **refactor(lint)** — zéro warning clippy sur toutes les cibles

## [1.3.2] — 2026-07-09

- **feat(footer)** — grille 2 lignes équilibrée + tri des pods stable

## [1.3.1] — 2026-07-08

- publication technique : aucun changement de code

## [1.3.0] — 2026-07-07

- **feat(ai)** — réponse IA en streaming SSE (affichage au fil de l'eau)
- **feat(palette)** — navigation ↑/↓ dans le menu ':'

## [1.2.0] — 2026-06-27

- **feat(svc)** — vue Services/Ingress + vue pods par défaut avec toggle

## [1.1.6] — 2026-06-24

- **feat(workloads)** — vue unifiée workloads+pods avec logs agrégés
- **feat(secrets,configmaps)** — vues Secrets (TLS) et ConfigMaps
- **feat(vuln)** — vue vulnérabilités (images Trivy + version k8s) et OCI HelmRepository en N/A
- **feat(flux)** — message d'échec lisible et copie de la zone de détail

## [1.1.5] — 2026-06-22

- **build(release)** — bottle Homebrew macOS + formule macOS-only

## [1.1.4] — 2026-06-21

- **feat(ai)** — compaction du prompt et budget de contexte par fournisseur
- **docs(license)** — ajout de la licence Apache-2.0
- **ci(release)** — formula Homebrew multi-plateforme + rubrique Installation

## [1.1.3] — 2026-06-21

- **feat(rbac,flux,pods)** — volet sécurité RBAC, inventaire Flux en arbre, métriques pods k9s

## [1.1.2] — 2026-06-20

- **feat(pods,flux,ns)** — menus d'actions, scale, et filtre ns direct
- **feat(pods)** — vue :pods, bascule vers l'objet d'origine, scale/restart

## [1.1.0] — 2026-06-20

- **feat(flux)** — réconciliation, suspend, logs controllers, inventaire & arbre
- **docs(code, ci)** — commente le code, note sécurité, publie rpm/deb/tarball Linux

## [1.0.3] — 2026-06-19

- **fix(ui)** — résout le vrai nom du contexte/cluster depuis le kubeconfig

## [1.0.2] — 2026-06-19

- **feat(ui)** — palette de commandes, vue FluxCD et bandeau cluster
- **feat(ui)** — unifie la vue évènements avec défilement live navigable
- **feat(packaging, ui)** — add packaging scripts & provider copy feedback

## [1.0.0] — 2026-05-18

- **feat(ai)** — add multi‑provider configuration and UI selector
- **refactor(enrich)** — strip Kubernetes noise from JSON output
- **docs(readme)** — add project overview and usage guide
- **chore(ci)** — separate Homebrew update job and fix tap & URL
- **chore(ci)** — add write permission for contents in release workflow
- **chore(ci)** — rename workflow directory to .github/workflows
- **chore(ci)** — add macOS universal binary release workflow
- **chore(gitignore)** — add .claude to ignore list


[1.25.0]: https://github.com/agardenat/kdt/compare/v1.24.0...v1.25.0
[1.24.0]: https://github.com/agardenat/kdt/compare/v1.23.0...v1.24.0
[1.23.0]: https://github.com/agardenat/kdt/compare/v1.22.1...v1.23.0
[1.22.1]: https://github.com/agardenat/kdt/compare/v1.22.0...v1.22.1
[1.22.0]: https://github.com/agardenat/kdt/compare/v1.21.0...v1.22.0
[1.21.0]: https://github.com/agardenat/kdt/compare/v1.20.7...v1.21.0
[1.20.7]: https://github.com/agardenat/kdt/compare/v1.20.6...v1.20.7
[1.20.6]: https://github.com/agardenat/kdt/compare/v1.20.5...v1.20.6
[1.20.5]: https://github.com/agardenat/kdt/compare/v1.20.4...v1.20.5
[1.20.4]: https://github.com/agardenat/kdt/compare/v1.20.3...v1.20.4
[1.20.3]: https://github.com/agardenat/kdt/compare/v1.20.2...v1.20.3
[1.20.2]: https://github.com/agardenat/kdt/compare/v1.20.1...v1.20.2
[1.20.1]: https://github.com/agardenat/kdt/compare/v1.20.0...v1.20.1
[1.20.0]: https://github.com/agardenat/kdt/compare/v1.19.1...v1.20.0
[1.19.1]: https://github.com/agardenat/kdt/compare/v1.19.0...v1.19.1
[1.19.0]: https://github.com/agardenat/kdt/compare/v1.18.0...v1.19.0
[1.18.0]: https://github.com/agardenat/kdt/compare/v1.17.1...v1.18.0
[1.17.1]: https://github.com/agardenat/kdt/compare/v1.17.0...v1.17.1
[1.17.0]: https://github.com/agardenat/kdt/compare/v1.16.0...v1.17.0
[1.16.0]: https://github.com/agardenat/kdt/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/agardenat/kdt/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/agardenat/kdt/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/agardenat/kdt/compare/v1.12.1...v1.13.0
[1.12.1]: https://github.com/agardenat/kdt/compare/v1.12.0...v1.12.1
[1.12.0]: https://github.com/agardenat/kdt/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/agardenat/kdt/compare/v1.10.1...v1.11.0
[1.10.1]: https://github.com/agardenat/kdt/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/agardenat/kdt/compare/v1.9.1...v1.10.0
[1.9.1]: https://github.com/agardenat/kdt/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/agardenat/kdt/compare/v1.8.2...v1.9.0
[1.8.2]: https://github.com/agardenat/kdt/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/agardenat/kdt/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/agardenat/kdt/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/agardenat/kdt/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/agardenat/kdt/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/agardenat/kdt/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/agardenat/kdt/compare/v1.3.2...v1.4.0
[1.3.2]: https://github.com/agardenat/kdt/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/agardenat/kdt/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/agardenat/kdt/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/agardenat/kdt/compare/v1.1.6...v1.2.0
[1.1.6]: https://github.com/agardenat/kdt/compare/v1.1.5...v1.1.6
[1.1.5]: https://github.com/agardenat/kdt/compare/v1.1.4...v1.1.5
[1.1.4]: https://github.com/agardenat/kdt/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/agardenat/kdt/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/agardenat/kdt/compare/v1.1.0...v1.1.2
[1.1.0]: https://github.com/agardenat/kdt/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/agardenat/kdt/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/agardenat/kdt/compare/v1.0.0...v1.0.2
[1.0.0]: https://github.com/agardenat/kdt/releases/tag/v1.0.0
