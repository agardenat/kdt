# kdt — Kubernetes Diagnostic Tools

TUI Rust pour surveiller les évènements Kubernetes en temps réel, inspecter le cluster vue par
vue, lancer un diagnostic, exporter un rapport PDF et demander une analyse à une IA.

📖 [English version](README.en.md) · 🗒️ [Changelog](CHANGELOG.md)

![kdt en action : flux d'évènements live, arbre FluxCD, marge de capacité, policies Kyverno et arbre RBAC](demo/hero.gif)

## Installation

### Homebrew (macOS et Linux x86_64)

```bash
brew install agardenat/kdt/kdt
```

Binaire universel macOS (Apple Silicon + Intel) ou binaire statique Linux x86_64 selon la
plateforme. Linux arm64 n'est pas distribué via Homebrew.

### Paquets Linux (x86_64)

```bash
sudo dpkg -i kdt_<version>_amd64.deb      # Debian / Ubuntu
sudo rpm -i kdt-<version>-1.x86_64.rpm    # RHEL / Fedora / openSUSE
```

### Binaire pré-compilé

Archives sur la page [Releases](https://github.com/agardenat/kdt/releases) :

```bash
tar xzf kdt-linux-x86_64.tar.gz   # ou kdt-macos-universal.tar.gz
sudo install -m 0755 kdt /usr/local/bin/kdt
```

### Depuis les sources

```bash
cargo build --release   # → target/release/kdt
```

### Mise à jour

Homebrew — `brew update` rafraîchit le tap, sans quoi `upgrade` ne voit pas la nouvelle version :

```bash
brew update
brew upgrade agardenat/kdt/kdt
```

Paquets et archives : réinstaller la nouvelle version par-dessus l'ancienne avec les mêmes
commandes que ci-dessus. `kdt --version` donne la version en place.

## Utilisation

```bash
kdt [OPTIONS]
```

| Option | Description | Défaut |
|---|---|---|
| `-n, --namespace <NS>` | Namespace à surveiller | tous |
| `-A, --all-namespaces` | Tous les namespaces | — |
| `--context <CTX>` | Contexte kubeconfig | contexte courant |
| `--buffer-size <N>` | Taille du buffer d'évènements | `5000` |

La connexion utilise le kubeconfig standard, `proxy-url` compris. Quand le DNS renvoie à la fois
de l'IPv4 et de l'IPv6 pour l'API server, l'IPv4 est essayée d'abord. L'application démarre sur la
vue évènements.

## Palette de commandes (`:`)

`:` ouvre une invite façon k9s : `Tab` complète, `Entrée` valide, `Esc` annule. Toute vue dont les
lignes sont des objets namespacés accepte un namespace en argument (`:cm kube-system`, `:pods
istio-system`, `:certs prod`) — marquées `[ns]` ci-dessous ; `all` (ou `*`/`0`) cible tous les
namespaces. Le namespace ainsi choisi devient la portée de la session, affichée dans le bandeau
`ns=`. Les vues cluster (`nodes`, `capacity`, `pv`, `rancher`) et celles construites en graphe entre
namespaces (`flux`, `reflector`, `argocd`, `kyverno`) n'acceptent pas d'argument et le disent
si on leur en donne un. `rbac` prend un namespace tout en continuant de lire tout le cluster : la
portée choisit les lignes affichées, pas ce qui est lu (voir la vue RBAC).

| Commande | Alias | Vue |
|---|---|---|
| `events [ns]` | `ev`, `event` | Évènements |
| `namespace [ns]` | `ns`, `namespaces` | Sélecteur de namespace |
| `workloads [ns]` | `wl`, `pods`, `po`, `deploy` | Workloads / Pods |
| `nodes` | `no`, `node` | Nodes |
| `flux` | `fl`, `ks`, `hr` | FluxCD |
| `flux-logs` | `logs`, `fluxlogs` | Logs agrégés des controllers Flux |
| `rbac [ns]` | `rb`, `roles`, `bindings`, `sec` | RBAC |
| `vuln [ns]` | `cve`, `cves`, `vulns` | Vulnérabilités |
| `secrets [ns]` | `secret`, `se`, `tls` | Secrets et certificats TLS |
| `certs [ns]` | `certificates`, `issuers`, `challenges`, `acme` | cert-manager |
| `kyverno` | `ky`, `policies`, `polr`, `cpol`, `admission` | Kyverno |
| `reflector` | `refl`, `mirror`, `miroir` | Reflector |
| `velero [ns]` | `vel`, `backup`, `backups`, `schedules` | Velero, côté backups et schedules |
| `restores [ns]` | `restore`, `restauration` | Velero, côté restaurations |
| `bsl [ns]` | `backupstoragelocation`, `backuprepositories` | Velero, côté stockage et dépôts |
| `k8ssandra [ns]` | `k8c`, `cassandra`, `cass`, `datacenter` | K8ssandra / Cassandra, côté ring |
| `medusa [ns]` | `med`, `medusabackup`, `cassbackup` | K8ssandra, côté sauvegardes Medusa |
| `reaper [ns]` | `rea`, `repair`, `réparation` | K8ssandra, côté opérations et Reaper |
| `rancher` | `ranch`, `cattle`, `users`, `identities` | Rancher, côté comptes et identités |
| `projects` | `project`, `proj` | Rancher, côté projects et namespaces |
| `tokens` | `token`, `apikey`, `kubeconfigs` | Rancher, côté jetons |
| `argocd` | `argo`, `acd`, `apps`, `applications` | Argo CD, côté Applications |
| `appsets` | `appset`, `applicationsets` | Argo CD, côté ApplicationSets |
| `appprojects` | `appproject`, `appproj` | Argo CD, côté AppProjects |
| `argorepos` | `argorepo`, `argoclusters` | Argo CD, côté repositories et clusters enregistrés |
| `configmaps [ns]` | `cm`, `config` | ConfigMaps |
| `services [ns]` | `svc`, `service` | Services / Endpoints |
| `forward` | `pf`, `portforward`, `tunnels` | Port-forwards en cours (superposé à la vue courante) |
| `ingress [ns]` | `ing`, `ingressclass` | Ingress / IngressClass |
| `netpol [ns]` | `np`, `networkpolicies`, `cilium`, `calico` | NetworkPolicies (natives, Cilium, Calico) |
| `storage [ns]` | `stockage`, `pvc`, `claims` | Stockage, côté demandes (PVC → PV) |
| `pv` | `sc`, `storageclass`, `persistentvolume` | Stockage, côté volumes (SC → PV) |
| `capacity` | `cap`, `marge`, `headroom` | Capacité, côté nœuds |
| `quota [ns]` | `quotas`, `rq`, `resourcequota` | Capacité, côté quotas |
| `quit` | `q` | Quitter |

## Raccourcis

### Communs à toutes les vues

| Touche | Action |
|---|---|
| `↑` `↓` `PgUp` `PgDn` | Navigation |
| `Enter` | Détail plein écran (ou plier/déplier dans un arbre) |
| `Shift-↑/↓`, `g` / `G` | Scroll du panneau de détail |
| `²` (ou `=`) | Masquer / réafficher le panneau du haut : la table prend tout l'écran (état conservé d'une session à l'autre) |
| `/` | Recherche (voir plus bas) |
| `y` | YAML de l'objet sélectionné (`t` : neat ↔ brut) |
| `e` / `h` / `Ctrl-D` | Éditer / toucher / supprimer l'objet (garde-fous) |
| `i` | Panneau IA |
| `c` | Copier la vue (OSC 52, fonctionne à travers SSH) |
| `L` / `m` | Langue FR/EN · fournisseur IA suivant |
| `F5` | Rafraîchir |
| `:` | Palette de commandes |
| `Esc` | Retour (retire d'abord la recherche active) |
| `q` / `Ctrl-C` | Quitter |

### Propres à chaque vue

| Vue | Touches |
|---|---|
| Évènements | `s` geler le défilement · `Tab` onglet Logs/Status/Related · `a`/`w`/`x` filtre All/Warnings/Errors · `p`/`C`/`f` logs run précédent/container/suivi · `n`/`0` filtre namespace · `N` nodes du pod · `E` shell · `D` diagnostic · `X` export PDF |
| Workloads | `t` liste ↔ arbre · `Space` (ou `→`/`←`) déplier le pod en containers · `s` scale · `r` rescale/recyclage/restart · `E` shell · `p`/`C`/`f` logs · `n`/`0` namespace |
| Nodes | `u` vue usage · `s` tri · `o` cordon/uncordon/drain · `p`/`P` export PDF |
| Capacité | `g` monde (nœuds → workloads → quotas) · `f` problèmes seulement · `n`/`0` namespace (mondes workloads et quotas) |
| FluxCD | `r` menu réconciliation · `Ctrl-R` déblocage · `z` suspend/reprise · `t` table ↔ arbre · `Space` plier/déplier · `a` suivi auto des branches en cours ou en échec · `←`/`→` faire défiler le message de la ligne sélectionnée (`Home` remet à zéro) · `l` logs de tous les controllers · `Tab` onglet Logs/Status/Related/Inventory |
| Vulnérabilités | `f` seuil de sévérité (tous → HIGH+ → CRIT) · `n`/`0` namespace |
| cert-manager | `Space` plier/déplier · `t` arbre ↔ liste · `←`/`→` faire défiler le message · `f` ALL/PROBLEMS/IN-FLIGHT · `s` aller au Secret · `r` renouveler, relancer ACME · `n`/`0` namespace |
| Kyverno | `Space` plier/déplier · `t` par policy ↔ par ressource · `←`/`→` faire défiler le message · `f` ALL/PROBLEMS/ENFORCE · `P` actions (purge des `UpdateRequest` bloqués) |
| Reflector | `Space` plier/déplier · `g` sources → miroirs → orphelins · `f` ALL/PROBLEMS · `s` aller à la source · `r` forcer la re-réflexion |
| Velero | `g` backups → restaurations → stockage · `t` regroupement · `f` filtre · `+`/`-` contenu du backup · `o` actions · `l` log du run · `n`/`0` namespace |
| K8ssandra | `Space` plier/déplier · `g` cluster → sauvegardes → opérations · `f` ALL/PROBLEMS · `l` logs du container fautif · `s` stats du node (tpstats, compactionstats, netstats) ou repairs Reaper · `S` snapshots du node (listsnapshots) · `x` commande nodetool en Job · `o` actions |
| Rancher | `g` users → access → projects → tokens · `f` ALL/PROBLEMS · `o` actions (émettre un token, changer un TTL, révoquer, régler un setting) · `h` touch sur un Project · `e` et `Ctrl-D` volontairement absents |
| Argo CD | `g` apps → sets → projects → repos · `f` ALL/PROBLEMS · `r` actions (refresh, hard refresh, sync, sync + prune, terminate) |
| RBAC | `Space` plier/déplier · `t` plat → par sujet → par binding → par rôle · `f` plancher de sévérité · `o` saut vers l'objet Flux gérant · `n`/`0` namespace |
| Réseau | `g` services → ingress → netpol · `t` regroupement (services/ingress) · `f` port-forward du Service · `F` port-forwards en cours · `n`/`0` namespace |
| Stockage | `g` claims ↔ volumes · `t` imbrication parent/enfant · `f` problèmes seulement · `n`/`0` namespace |
| Diagnostic | `r` relancer · `p`/`P` export PDF |
| YAML | `t` neat ↔ brut · `c` copier · `r` recharger |

Dans la vue évènements, le curseur **suit** le flux par défaut (indicateur `↻`) ; remonter dans la
liste l'ancre sur un évènement précis, `Esc` réactive le suivi.

### Recherche (`/`)

Disponible partout, insensible à la casse, et **conservée en changeant de vue**. Le bandeau
affiche toujours la requête et son effet (`/coredns  (3)`).

- **table** : ne garde que les lignes correspondantes (namespace, nom, kind, reason, message, plus
  ce qui identifie la vue : sujets RBAC, images, clés — jamais les valeurs — des secrets) ;
- **panneau texte** (logs, diagnostic, IA, YAML) : surligne et saute d'une occurrence à l'autre
  avec `Ctrl-N` / `Ctrl-P`, position affichée (`/glob  (3/500)`).

## Les vues

- **Évènements** — watch des `Event`. `a`/`w`/`x` filtrent All / Warnings / Errors, `s` gèle le
  défilement, `Tab` change d'onglet dans le panneau de détail (Logs / Status / Related). Côté logs :
  `p` affiche le run précédent du container (seul endroit où subsistent les logs d'un pod en
  `CrashLoopBackOff`), `C` change de container, `f` suit en continu. `N` liste les nodes du pod,
  `E` ouvre un shell, `D` lance le diagnostic, `X` exporte le PDF.
- **Workloads** — arbre workloads → pods (Deployment, StatefulSet, DaemonSet, Job ; l'arbre montre
  aussi les Jobs terminés et les workloads scalés à 0), ou liste plate des pods avec `t` — `:pods`
  ouvre directement la liste plate, `:workloads` l'arbre. `Space`, `→` et `←` déplient un pod en ses containers (init, réguliers,
  éphémères) : état, consommation face à *leurs* requests/limits, âge du dernier démarrage. Les
  actions visent le workload même depuis la ligne d'un de ses pods : `s` scale, `r` rescale /
  recyclage / restart. Sur une ligne container, `E` ouvre un shell dans ce container et l'onglet
  Logs s'y restreint automatiquement. `n`/`0` changent de namespace.
- **Nodes** — liste, détail, usage CPU/mémoire (`u`), tri (`s`), export PDF (`p`/`P`). Le détail
  donne conditions, capacity/allocatable, system info, adresses, réservations et OOM récents, puis
  annotations, labels et taints en fin de panneau — la partie affichée quand le curseur change de
  nœud. `o` ouvre les opérations : cordon, uncordon, drain. Le drain affiche un rapport avant toute éviction : pods
  qu'aucun contrôleur ne recréera, PDB qui refuseront, pods sans place ailleurs, `emptyDir` perdus,
  pods statiques.
- **Capacité** (`:capacity`, `:quota`) — trois mondes par `g`, `f` ne garde que les problèmes.
  - *nœuds* : simulation de la perte d'un nœud (first-fit, plus gros pod d'abord, sur les requests,
    en respectant taints, `nodeSelector` et node affinity `required`) et pods sans point de chute ;
  - *workloads* : pods sans requests (invisibles au scheduler), pods surdimensionnés, pods au
    plafond de leur limite ;
  - *quotas* : `ResourceQuota` proches de refuser la prochaine création.

  ![Vue capacité](demo/capacity.gif)

- **FluxCD** — inventaire cluster-wide, arbre de dépendances (`t`), objets appliqués et leur état
  live (onglet Inventory), logs des controllers (`l`, ou `:flux-logs` pour l'agrégat). L'arbre suit
  les dépendances réelles, chaîne Helm comprise : HelmRepository → HelmChart (celui que
  `status.helmChart` désigne) → HelmRelease. Un nœud plié annonce ce qu'il cache — `✗n` échecs,
  `↻n` réconciliations en cours. `a` règle le suivi automatique : par défaut les branches qui
  réconcilient ou qui échouent se déplient seules et se replient une fois revenues à Ready, les plis
  posés à la main étant conservés en dessous. `z` suspend / reprend. `r` ouvre le menu de réconciliation : ressource, `--with-source`, sync racine, plus force
  upgrade et reset sur une HelmRelease. `Ctrl-R` ouvre le déblocage : kdt tire des pistes du message
  du contrôleur, les vérifie contre le cluster et propose l'action correspondante — supprimer un
  webhook orphelin, retirer des finalizers, `resetAt` puis `forceAt` sur une release Helm bloquée en
  pending.

  ![Vue FluxCD](demo/flux.gif)

- **Vulnérabilités** — CVE par image depuis les `VulnerabilityReport` de **Trivy Operator** (score
  CVSS, nombre de CVE corrigibles) et risque sur la version de Kubernetes elle-même (feed officiel,
  dernier patch de la mineure comme cible, badge `EOL`). `f` règle le seuil (tous → HIGH+ → CRIT).
  Sans Trivy Operator, seule la partie version k8s s'affiche.
- **cert-manager** (`:certs`) — chaîne d'émission Issuer → Certificate → CertificateRequest → Order
  → Challenge → Secret servi. `Space` plie/déplie (chaînes saines repliées, chaînes en échec
  dépliées), `t` bascule arbre/liste, `f` filtre ALL / PROBLEMS / IN-FLIGHT, `s` saute au Secret,
  `r` renouvelle ou relance le challenge ACME. Détections : propagation DNS incomplète, challenge
  non présenté, rate limit ACME, renouvellement en retard, Secret désynchronisé, keystore
  JKS/PKCS12 demandé mais absent du Secret, truststore absent, `passwordSecretRef` introuvable.
- **Kyverno** — policies et rapports joints : un rapport nomme sa règle par une chaîne, la vue va
  chercher la règle correspondante dans la policy. `t` bascule par policy / par ressource, `Space`
  plie/déplie, `f` filtre ALL / PROBLEMS / ENFORCE, `P` ouvre le menu d'actions (purge des
  `UpdateRequest` bloqués en Pending/Failed). Sont affichés : les règles `autogen-*` (celles que
  nomment les rapports), la distinction entre `fail` (la ressource viole) et `error` (la règle ne
  s'évalue pas — bug de policy), les refus d'admission (absents des rapports, présents seulement
  sous forme d'Event), le backlog d'`UpdateRequest` et le compteur des webhooks
  `kyverno-resource-*` (à zéro, Kyverno n'intercepte plus rien).

  ![Vue Kyverno](demo/kyverno.gif)

- **Reflector** ([kubernetes-reflector](https://github.com/emberstack/kubernetes-reflector)) —
  sources, miroirs et orphelins par `g`, `f` filtre ALL / PROBLEMS, `s` saute à la source, `r` force
  la re-réflexion. Détections : namespace bloqué par un objet homonyme, miroir modifié à la main
  (reflector ne compare que `reflected-version`, jamais le contenu), portée réelle des regex ancrées
  (liste vide = tous les namespaces), miroirs en attente de la copie.
- **RBAC** — liste plate d'audit par défaut, trois orientations d'arbre par `t` (par sujet, par
  binding, par rôle), `f` règle le plancher de sévérité, `o` saute à l'objet Flux gérant. La
  sévérité est calculée **par binding** : un Role seul est inerte, et le même ClusterRole est anodin
  en RoleBinding, critique en ClusterRoleBinding. Affiche les ClusterRoles-templates rebindés
  namespace par namespace, la composition des rôles agrégés (`admin`, `edit`, `view`), les bindings
  nommant un ServiceAccount inexistant, les rôles que personne ne lie.

  La colonne `SOURCE` attribue chaque binding à ce qui l'a posé : Flux (Kustomization ou
  HelmRelease, avec la source Git/OCI/Helm chaînée), Helm, Argo CD, une règle `generate` Kyverno
  (`kyverno:<policy>`), un binding projeté par Rancher (`rancher:<binding>`), les défauts RBAC de
  l'API server (`rbac-defaults`), un addon manager (`addon:<by>`), un contrôleur propriétaire,
  `kubectl`. Un binding ne reste `unmanaged` que si rien ne le revendique ; seuls `unmanaged`,
  `kubectl` et un simple ownerRef portent le constat « hors GitOps ». `RISK` affiche le constat le
  plus grave et le nombre des autres (`impersonate +8`) ; la liste complète est dans le panneau du
  haut.

  `:rbac <ns>` (ou `n` sur une ligne, `0` pour revenir au cluster) restreint la vue à un namespace.
  Tout le cluster reste lu — sinon une arête d'agrégation, un compte de template ou un « rôle que
  personne ne lie » serait faux — et la portée ne décide que des lignes affichées : les RoleBindings
  du namespace, et les bindings cluster (ClusterRoleBinding compris) accordés à un ServiceAccount de
  ce namespace. Un ClusterRoleBinding qui ne nomme que des comptes d'ailleurs n'est pas listé. Les
  compteurs du titre suivent la portée, qui est rappelée par `ns=` dans ce même titre.

  ![Vue RBAC](demo/rbac.gif)

- **Velero** (`:velero`, `:restores`, `:bsl`) — backups et schedules, restaurations, locations et
  dépôts.
  - `PartiallyFailed` est compté comme un échec.
  - Le cron des schedules est évalué par kdt : schedule qui ne tourne plus (velero ne le signale
    nulle part, il ne crée simplement pas de backup), TTL plus court que la période du cron,
    location indisponible, dépôt kopia sans maintenance, namespaces à PVC que plus aucun schedule ne
    couvre.
  - `o` : lancer un backup depuis un schedule, mettre en pause, restaurer, supprimer un backup via
    une `DeleteBackupRequest` (supprimer l'objet ne supprime rien, la resynchronisation le recrée).
    `l` récupère le log du run.
  - `+` déplie le contenu réel du backup — namespaces, puis types, puis objets. *Restaurer
    (options)* s'en sert pour préremplir un `Restore` restreint : namespaces à cocher, remapping
    vers un autre namespace, filtre par type et par labels, choix entre ignorer et écraser
    l'existant. Velero ne cible pas un objet par son nom : la sélection s'arrête au type.
- **K8ssandra / Cassandra** (`:k8ssandra`, `:medusa`, `:reaper`) — trois mondes par `g` : ring du
  cluster, sauvegardes Medusa, opérations et Reaper. `f` filtre ALL / PROBLEMS, `Space` plie/déplie,
  `l` ouvre les logs du container fautif.
  - Le titre du monde sauvegardes affiche l'âge de la dernière sauvegarde couvrant **tous les
    nodes** du datacenter, un run partiel comptant comme un échec. Détections : schedule dont le
    `lastExecution`/`nextSchedule` reste propre alors que le run a échoué, CronJob de purge terminé
    en vert sans rien purger, runs réussis absents du catalogue (`MedusaTask sync` non exécutée).
    Une restauration arrête le datacenter, ce qui est annoncé avant de la lancer.
  - Le ring vient de l'API de management du container `cassandra`, atteinte par le proxy de pod de
    l'apiserver (ni port-forward, ni `kubectl`, ni exec) : `nodetool status` et `describecluster` en
    données typées — état UN/DN, load, tokens, accord de schéma. La jointure pod ↔ entrée de ring se
    fait sur l'adresse, pas sur le `hostID` de `status.nodeStatuses` : ce champ périme, la vue le
    signale quand les deux divergent.
  - `s` : `tpstats`, `compactionstats` et `netstats` du node sélectionné (repairs Reaper dans le
    monde opérations). `S` : `listsnapshots`, replié par tag, avec les deux tailles — le poids total
    (répertoire de hard links, partagé avec les SSTables vivantes) et `True size`, seul espace rendu
    par la suppression du tag. Sur un node 3.11, qui ne date pas ses snapshots, la date des tags
    `truncated-`/`dropped-` est lue dans le tag lui-même.
  - `o` : sauvegarder maintenant, restaurer, purger ou resynchroniser le catalogue Medusa, et les
    `CassandraTask` (cleanup, upgradesstables, compaction, scrub, restart roulant).
  - `x` sur un node : commande `nodetool` libre (`garbagecollect -g ROW -j 1 <keyspace> <table>`,
    `flush`, `tablestats`…), lancée dans un Job qui continue après la fermeture de kdt. La ligne est
    saisie puis confirmée. Le Job est construit à partir du pod et de son `CassandraDatacenter` :
    image du container `cassandra`, hôte `<pod>.<all-pods-service>`, `--ssl` et `-u/-pw` seulement
    si `additional-jvm-opts` les demande, keystores repris des volumes du pod, identifiants
    référencés dans le secret superuser (jamais recopiés). Ce qui n'a pas pu être lu est annoncé
    (JMX local, magasin introuvable, secret absent) au lieu d'être deviné. Les Jobs apparaissent en
    tête du monde opérations, `l` affiche leur sortie, `Ctrl-D` les supprime ; sinon ils expirent au
    bout de 24 h.
- **Rancher** (`:rancher`, `:projects`, `:tokens`) — quatre mondes par `g`, `f` filtre ALL /
  PROBLEMS. Lecture seule sauf `o` et `h` (touch, sur un Project de ce cluster uniquement) ; `e` et
  `Ctrl-D` sont absents.
  - *users* : l'identifiant Rancher (`u-4oivhvq2jk`, celui que portent les RoleBindings et les logs
    d'audit) et l'identité réelle en regard — CN d'un DN LDAP/AD, `uid` FreeIPA — lus dans les
    objets `User` et `UserAttribute`, avec le provider, les groupes d'annuaire, les global roles et
    la date du dernier rafraîchissement des groupes.
  - *access* : les trois sortes de binding fondues en une liste sujet → rôle → portée ; le binding
    que Rancher pose sur tout compte est trié en dernier.
  - *projects* : namespaces, membres, owners, quota.
  - *tokens* : d'abord les settings de durée de vie — `auth-token-max-ttl-minutes` (le plafond),
    `kubeconfig-default-token-ttl-minutes`, `auth-user-session-ttl-minutes` — avec la valeur en
    force, le défaut d'origine et lequel des deux s'applique (Rancher lit `0` comme « pas
    d'expiration »). Puis les tokens, avec la colonne `SCOPE` (`clusterName` vide = tous les
    clusters gérés *et* l'API Rancher ; renseigné = ce cluster seulement) et la colonne `KIND` :
    `kubeconfig` (un par téléchargement), `session` (la connexion — la révoquer déconnecte), `api`
    (clé créée dans *Account & API Keys*, sans label et `isDerived`), `provisioning`, `telemetry`.
  - Sur un cluster **downstream**, les CRD Rancher existent mais sont vides : la vue le dit et
    bascule sur ce que l'agent a projeté, les RoleBindings étiquetés du binding Rancher qui les a
    créés. Les groupes y apparaissent en clair (DN complet), les comptes restent des `u-…` que rien
    sur ce cluster ne résout, et chaque ligne le déclare.
  - `o`, sur le cluster local uniquement (refusé et expliqué sur un downstream) : **émettre un
    token** pour le compte sélectionné (objet `Token` calqué sur ceux de Rancher — mêmes labels,
    `isDerived`, `userPrincipal` reconstruit — secret de 54 caractères tiré de `/dev/urandom`,
    affiché une seule fois et écrit nulle part), **changer le TTL** d'un token, **le révoquer**
    (supprimer l'objet `Token` est la seule révocation réelle), **régler un setting** de durée de
    vie. Ce sont les mêmes objets qu'un `kubectl apply` à la main ; kdt n'ajoute aucun privilège.
- **Argo CD** (`:argocd`, `:appsets`, `:appprojects`, `:argorepos`) — quatre mondes par `g`, `f`
  filtre ALL / PROBLEMS.
  - *apps* : chaque `Application` avec **ses deux états côte à côte**, `sync` et `health`. Un
    `sync: Unknown` signale que le controller n'a pas pu construire l'état désiré (credential git
    expiré, dépôt Helm injoignable, plugin en erreur) : le `health` affiché à côté a été calculé
    *avant* l'échec, et la vue le dit et le grise au lieu de le montrer en vert. La colonne `POLICY`
    lit `syncPolicy.automated` tel qu'il se comporte — `automated: { enabled: false }` est un
    auto-sync déclaré et éteint, affiché `manual`. Puis le project, la destination (nom du cluster
    enregistré, pas son URL), la revision, le nombre de resources hors sync, la dernière opération
    et son âge, et l'âge de la dernière comparaison.
  - Le panneau de détail donne le diagnostic **avant** l'inventaire : conditions Argo (`*Error` en
    rouge, `OrphanedResourceWarning` en info — c'est un réglage du project), opération en échec avec
    son message et son nombre de tentatives, project inexistant, destination absente des clusters
    enregistrés, absence de comparaison depuis plus de trois périodes (`timeout.reconciliation` lu
    dans `argocd-cm`), et la présence ou non du finalizer de cascade — c'est-à-dire si supprimer
    l'Application supprime aussi ce qu'elle a déployé. Suivent les resources hors état attendu,
    l'historique des revisions déployées et les images.
  - *sets* : `ApplicationSet` avec ses generators, les Applications qu'il a réellement générées
    (lues par `ownerReferences`), leur état, `syncPolicy.applicationsSync`,
    `preserveResourcesOnDeletion`, `goTemplate` et les conditions du controller.
  - *projects* : `AppProject` avec le nombre d'Applications, `sourceRepos` (`*` affiché comme tel),
    destinations, listes de resources autorisées/interdites, sync windows, et les roles avec la
    distinction lecture / écriture calculée sur le verbe de chaque policy Casbin.
  - *repos* : les repositories, credentials templates et clusters, qui ne sont pas des CRD mais des
    `Secret` étiquetés `argocd.argoproj.io/secret-type`. kdt en décode l'**adressage** (url, nom,
    type, project, portée) et déduit la méthode d'authentification de la **présence** des clés —
    aucun credential n'est lu. La colonne `USED` compte les Applications qui s'y réfèrent.
  - Sans lien avec un CRD : la ligne du haut du panneau nomme l'installation (namespace découvert
    via `argocd-cm`, URL de l'UI, période de comparaison, état des composants) et signale les
    Applications posées hors des namespaces que le controller honore (`application.namespaces`).
  - `r` : **refresh** et **hard refresh** (annotation `argocd.argoproj.io/refresh`), **sync** et
    **sync + prune** (champ `.operation`, sans revision figée : le controller résout le
    `targetRevision` de l'Application), **terminate** quand une opération tourne. Ce sont les
    écritures que fait le CLI `argocd` ; kdt n'ajoute aucun privilège.
- **Réseau** (`:services`, `:ingress`, `:netpol`) — trois mondes par `g` : Services/Endpoints,
  Ingress/IngressClass, NetworkPolicies. Les policies natives sont affichées avec leur cible, leurs
  `policyTypes` et l'effet par direction : `Deny` (direction gouvernée, aucune règle n'autorise),
  `AllowAll` (`from`/`to` vide), `Selective` (pairs explicites), `Unaffected` (direction hors
  `policyTypes`). Les CRD Cilium et Calico sont listées telles quelles, sans verdict.
- **Port-forward** (`f` sur un Service, `F` ou `:forward` pour la liste) — tunnel ouvert par kdt
  lui-même, sans `kubectl` : le formulaire liste les ports du Service, propose le même numéro en
  port local (`0` en prend un libre au hasard), `Entrée` démarre ou arrête. L'écoute est sur
  `127.0.0.1` et la colonne `FORWARD` de la table indique le port local (`→ :8080`, `+n` s'il y en
  a plusieurs). La cible est résolue par les EndpointSlices : le premier endpoint **ready**, et le
  port du conteneur qu'il déclare (un `targetPort` nommé est donc suivi). Les cas refusés sont
  nommés : Service `ExternalName`, port non-TCP, aucun endpoint, aucun endpoint ready. La liste `F`
  donne le pod atteint, l'état, le nombre de connexions ouvertes et servies, et `d` arrête. Les
  tunnels vivent dans le processus kdt : ils suivent les changements de vue et de namespace, et
  disparaissent avec lui.
- **Stockage** (`:storage`, `:pv`) — deux mondes par `g` (PVC → PV, SC → PV), `t` imbrique
  parent/enfant, `f` ne garde que les problèmes, `n`/`0` changent de namespace. Détections :
  StorageClass introuvable, aucune classe par défaut (ou deux), `WaitForFirstConsumer` en attente
  d'un pod, classe sans provisioner, `ProvisioningFailed` laissé par le provisioner (son message
  prime), PV `Released`, `reclaimPolicy: Delete` rappelé sur le PVC, PVC `RWO` monté par plusieurs
  pods.
- **Secrets / ConfigMaps** — inventaires, avec l'expiration des certificats TLS et leurs
  consommateurs. Les deux vues suivent la portée namespace de la session (`:cm <ns>`, `n`/`0`) et
  ne listent alors que ce namespace.
- **Diagnostic** (`D`) — batterie de vérifications : santé de l'API, version, nodes, namespaces
  système, pods de `kube-system`, CoreDNS, CNI, webhooks validating et mutating, Rancher, pods en
  erreur, PV, stockage, capacité, Flux, cert-manager, Kyverno, Velero, Reflector, K8ssandra, RBAC,
  warnings récents. Un module absent du cluster est rapporté en Info. `r` relance, `p`/`P`
  exportent en PDF.
- **Extraction** (`X`) — rapport PDF complet de l'état du cluster dans `~/Downloads`.
- **IA** (`i`) — envoie le contexte courant à une API compatible OpenAI ; la réponse est streamée
  (SSE) et s'affiche au fil de l'eau. `L` relance dans l'autre langue, `m` change de fournisseur.

## Écrire dans le cluster

Toute la navigation est en **lecture seule**. Les seules écritures sont celles qu'une touche
déclenche explicitement, et elles passent par des garde-fous.

| Touche | Écriture | Garde-fous |
|---|---|---|
| `e` | `PUT` complet, verrouillé sur le `resourceVersion` | **Avant** : objet GitOps réécrit au prochain reconcile, spec tenue par un contrôleur, `can-i update` refusé, objet en cours de suppression, spec figée après création. **Après** : chaque champ modifié classé *appliqué* / *ignoré* / *rejeté par l'API* |
| `Ctrl-D` | `delete` en propagation *background* | GitOps, point d'entrée GitOps (Kustomization/HelmRelease/Application), `Namespace` et CRD (cascade), `ownerReferences`, namespace système, finalizers |
| `h` | Merge patch de deux annotations | Aucun |
| `o` (Nodes) | Patch `spec.unschedulable`, puis évictions | Rapport de drain complet avant la moindre éviction |
| `r` / `z` | Reconcile, suspend, scale, restart, renew | Confirmation armée dans le menu |
| `Ctrl-R` | Suppression d'une config d'admission, retrait de finalizers | Saisie du nom exact de l'objet |
| `r` (Argo CD) | Annotation `argocd.argoproj.io/refresh`, champ `.operation`, `status.operationState.phase` | Confirmation armée dans le menu ; le prune est une entrée distincte, jamais une option cochée |
| `o` (Rancher) | Création d'un `Token`, patch de son `.ttl`, suppression d'un `Token`, patch d'un `Setting` | Confirmation armée, puis saisie dont l'unité est affichée ; refusé sur un cluster downstream ; le secret émis n'est montré qu'une fois et n'est écrit nulle part |

**Aucun avertissement ne bloque**, mais **la réponse par défaut est non** : `Entrée` et `Esc`
annulent, seule la touche qui a ouvert le panneau avance vers l'écriture. Un constat ⛔ (`e`,
`Ctrl-D`, drain) impose de **retaper le nom exact** de l'objet pour passer outre.

### Détails utiles

- **`e`** — éditeur choisi dans l'ordre `$KDT_EDITOR`, `$KUBE_EDITOR`, `$VISUAL`, `$EDITOR`, sinon
  `vi` (arguments acceptés : `KDT_EDITOR="nvim -u NONE"`). Le fichier temporaire est en `0600` (un
  `Secret` y transite) et effacé à la fermeture. Un YAML invalide ou un refus de l'API renvoie dans
  l'éditeur avec le tampon intact.
- **`h`** — pose `kdt.io/touched-at` (horodatage à la **milliseconde**, nécessaire : un patch qui
  ne change rien n'incrémente pas le `resourceVersion`, donc n'appelle aucun webhook) et
  `kdt.io/touched-by`. Sert à refaire traverser l'admission : réévaluer une policy Kyverno, réveiller
  un contrôleur. **Sans confirmation** — dans la vue évènements, où le curseur suit le flux, geler
  (`s`) avant de toucher ; le bandeau nomme toujours l'objet effectivement touché.
- **Ciblage** — dans la vue évènements, `y`/`e`/`h`/`Ctrl-D` visent l'objet **dont parle
  l'évènement** (son `involvedObject`), jamais l'Event. Dans Kyverno, une ligne de violation vise la
  **ressource fautive**, une ligne de policy vise la policy.
- **`E`** — shell dans un pod : kdt **rend le terminal à `kubectl exec -it`** puis le reprend, comme
  `e` le rend à `$EDITOR`. C'est la seule fonction qui dépend d'un binaire externe ; son absence est
  dite avant que l'écran ne soit rendu.

## Configuration

Fichier JSON optionnel, cherché dans l'ordre : `$KDT_CONFIG` (ou `$KEV_CONFIG`),
`$XDG_CONFIG_HOME/kdt/config.json`, `~/.config/kdt/config.json`.

```json
{
  "language": "fr",
  "active_provider": "openai",
  "providers": [
    {
      "name": "openai",
      "base_url": "https://api.openai.com/v1",
      "api_key": "sk-...",
      "model": "gpt-4o",
      "context_window": 128000
    },
    { "name": "local", "base_url": "http://localhost:11434/v1", "api_key": "ollama", "model": "qwen2.5-coder" }
  ]
}
```

`m` fait défiler les fournisseurs à chaud ; l'actif est affiché dans le bandeau IA (`[FR · openai]`).
Les clés à plat `openai_base_url` / `openai_api_key` / `openai_model` et les variables
d'environnement restent prises en charge comme fournisseur `default`.

`context_window` est la fenêtre du modèle **en tokens**. Renseignée, kdt borne le prompt pour qu'il
tienne dedans : ~4096 tokens réservés à la réponse, puis remplissage par priorité (évènement et
status d'abord, logs, puis contexte) en omettant les sections de plus basse priorité, ce qui est
signalé dans le prompt. La valeur n'est jamais transmise à l'API. Derrière un proxy multi-modèles,
déclarer la fenêtre du **plus petit** modèle atteignable.

La clé `hide_top_panel` retient le dernier pli du panneau du haut (`²`) : elle est réécrite seule à
chaque appui, comme `language`, et relit l'interface dans le même état à la session suivante.

### Langue

Toute l'interface est bilingue (panneaux, diagnostics, rapports PDF, prompts). L'ordre de choix :
clé `language` du fichier de config, puis la locale système (`LC_ALL`, `LC_MESSAGES`, `LANG`,
`LANGUAGE` — `fr*` donne le français, le reste l'anglais), sinon le français.

`L` bascule à chaud, y compris à l'intérieur d'une vue, et réécrit **la seule clé `language`** du
fichier de config (le reste et les permissions sont laissés tels quels). Le jargon Kubernetes reste
en anglais des deux côtés (`pod`, `node`, `taint`, `requests`…), comme les en-têtes de colonnes.

### Variables d'environnement

| Variable | Rôle |
|---|---|
| `OPENAI_API_KEY` | Clé API IA |
| `OPENAI_BASE_URL` / `OPENAI_API_BASE` | Endpoint compatible OpenAI |
| `OPENAI_MODEL` | Modèle |
| `OPENAI_CONTEXT_WINDOW` | Fenêtre de contexte du fournisseur `default` |
| `KDT_KUBECTL` | Binaire utilisé par `E` (défaut : `kubectl` dans le `PATH`) |
| `KDT_EXEC_SHELL` | Commande passée à `sh -c` par `E` (défaut : `bash` s'il existe, sinon `sh`) |
| `KDT_CONFIG` / `KEV_CONFIG` | Chemin du fichier de config |
| `KDT_LOG` / `KEV_LOG` | Chemin du fichier de log |
| `RUST_LOG` | Filtre de logs (`warn` par défaut) |

## Sécurité / confidentialité

- **Données envoyées à l'IA** : `i` et `X` transmettent le contexte cluster courant — message de
  l'évènement, **logs du pod** (jusqu'à 200 lignes), status, ressources liées. Les logs peuvent
  contenir des secrets : n'utiliser que des endpoints de confiance. Seules les métadonnées de
  bookkeeping sont retirées, pas les données applicatives.
- **Endpoint** : un `base_url` en `http://` envoie la clé et le payload en clair. Préférer `https://`
  ou un endpoint local.
- **Clé API** : en clair dans `config.json` — `chmod 600`. Elle n'est jamais journalisée.
- **Accès cluster** : lecture seule sauf les écritures listées plus haut, toutes refusées par l'API
  si le kubeconfig n'en a pas le droit. Deux shell-out, à la demande : `$EDITOR` (`e`) et
  `kubectl exec -it` (`E`).
- **Rendu PDF** : le contenu IA est échappé avant évaluation comme markup Typst, les blocs de code
  passent par `raw()` — pas d'injection possible.

## Développement

```bash
cargo build --release       # target/release/kdt
packaging/build-deb.sh      # → dist/kdt_<version>_amd64.deb
packaging/build-rpm.sh      # → dist/x86_64/kdt-<version>-1.x86_64.rpm
packaging/build-all.sh      # les deux
```

Profil release : `lto = thin`, `codegen-units = 1`, `panic = abort`, symboles strippés, allocateur
`mimalloc`. Une cible musl statique est configurée (`target/x86_64-unknown-linux-musl`), c'est elle
que les paquets embarquent. Les scripts de packaging tournent sans root, écrivent dans `dist/` et
lisent nom et version depuis `Cargo.toml` ; prérequis `dpkg-deb` / `rpmbuild`.

Logs applicatifs : `$KDT_LOG`, `$XDG_STATE_HOME/kdt/kdt.log`, `~/.local/state/kdt/kdt.log`, sinon
`/tmp/kdt.log`. Rapports PDF : `~/Downloads/kdt-extract-<contexte>-<timestamp>.pdf`.

### Modules (`src/`)

| Module | Rôle |
|---|---|
| `main.rs` · `cli.rs` · `config.rs` | Bootstrap, arguments (clap), fichier de configuration |
| `ui.rs` | TUI ratatui : modes, rendu, clavier |
| `events.rs` | Watcher d'évènements, logs, status, nœuds, usage |
| `pods.rs` · `svc.rs` · `configmaps.rs` | Workloads, Services/Ingress, ConfigMaps |
| `portfwd.rs` | Port-forward des Services (résolution EndpointSlice, écoute locale) |
| `flux.rs` · `repair.rs` | FluxCD (inventaire, reconcile, arbre) et déblocage `Ctrl-R` |
| `rbac.rs` · `secrets.rs` · `certmanager.rs` | RBAC scoré, Secrets/TLS, chaîne cert-manager |
| `kyverno.rs` · `reflector.rs` · `vulnerabilities.rs` | Kyverno, Reflector, CVE |
| `velero.rs` | Velero : backups, schedules (cron évalué), restaurations, locations |
| `argocd.rs` | Argo CD : Applications, ApplicationSets, AppProjects, repositories et clusters |
| `rancher.rs` | Rancher : comptes et identités réelles, bindings, projects, tokens et settings de TTL |
| `k8ssandra.rs` · `mgmtapi.rs` · `nodetool.rs` | K8ssandra/Medusa/Reaper, l'API de management Cassandra via le proxy apiserver, et `nodetool` lancé en Job |
| `storage.rs` | PVC / PV / StorageClass et règles de diagnostic |
| `yaml.rs` · `edit.rs` · `delete.rs` · `touch.rs` | YAML, édition, suppression, touch |
| `diagnostic.rs` · `extract.rs` · `pdf.rs` | Diagnostic, extraction, rendu Typst |
| `enrich.rs` · `ai.rs` | Contexte lié à un évènement, client OpenAI |
| `lang.rs` · `clip.rs` | Table de chaînes FR/EN, presse-papier OSC 52 |

Stack : Rust 2021 · `kube` 3.1 (rustls, socks5) · `k8s-openapi` 0.27 · `ratatui` 0.30 · `tokio` ·
`reqwest` · `typst` 0.14.

## Licence

[Apache 2.0](LICENSE).
