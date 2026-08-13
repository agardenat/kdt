# kdt — Kubernetes Diagnostic Tools

TUI Rust pour surveiller les évènements Kubernetes en temps réel, inspecter le cluster vue par
vue, lancer un diagnostic, exporter un rapport PDF et demander une analyse à une IA.

📖 [English version](README.en.md)

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

La connexion utilise le kubeconfig standard. L'application démarre sur la vue évènements.

## Palette de commandes (`:`)

`:` ouvre une invite façon k9s : `Tab` complète, `Entrée` valide, `Esc` annule. `events`,
`namespace` et `workloads` acceptent un namespace en argument (`:ns kube-system`, `:pods
istio-system`) ; `all` (ou `*`/`0`) cible tous les namespaces.

| Commande | Alias | Vue |
|---|---|---|
| `events [ns]` | `ev`, `event` | Évènements |
| `namespace [ns]` | `ns`, `namespaces` | Sélecteur de namespace |
| `workloads [ns]` | `wl`, `pods`, `po`, `deploy` | Workloads / Pods |
| `nodes` | `no`, `node` | Nodes |
| `flux` | `fl`, `ks`, `hr` | FluxCD |
| `flux-logs` | `logs`, `fluxlogs` | Logs agrégés des controllers Flux |
| `rbac` | `rb`, `roles`, `bindings`, `sec` | RBAC |
| `vuln` | `cve`, `cves`, `vulns` | Vulnérabilités |
| `secrets` | `secret`, `se`, `tls` | Secrets et certificats TLS |
| `certs` | `certificates`, `issuers`, `challenges`, `acme` | cert-manager |
| `kyverno` | `ky`, `policies`, `polr`, `cpol`, `admission` | Kyverno |
| `reflector` | `refl`, `mirror`, `miroir` | Reflector |
| `velero` | `vel`, `backup`, `backups`, `schedules` | Velero, côté backups et schedules |
| `restores` | `restore`, `restauration` | Velero, côté restaurations |
| `bsl` | `backupstoragelocation`, `backuprepositories` | Velero, côté stockage et dépôts |
| `k8ssandra` | `k8c`, `cassandra`, `cass`, `datacenter` | K8ssandra / Cassandra, côté ring |
| `medusa` | `med`, `medusabackup`, `cassbackup` | K8ssandra, côté sauvegardes Medusa |
| `reaper` | `rea`, `repair`, `réparation` | K8ssandra, côté opérations et Reaper |
| `configmaps` | `cm`, `config` | ConfigMaps |
| `services` | `svc`, `service` | Services / Endpoints |
| `ingress` | `ing`, `ingressclass` | Ingress / IngressClass |
| `storage` | `stockage`, `pvc`, `claims` | Stockage, côté demandes (PVC → PV) |
| `pv` | `sc`, `storageclass`, `persistentvolume` | Stockage, côté volumes (SC → PV) |
| `capacity` | `cap`, `marge`, `headroom` | Capacité, côté nœuds |
| `quota` | `quotas`, `rq`, `resourcequota` | Capacité, côté quotas |
| `quit` | `q` | Quitter |

## Raccourcis

### Communs à toutes les vues

| Touche | Action |
|---|---|
| `↑` `↓` `PgUp` `PgDn` | Navigation |
| `Enter` | Détail plein écran (ou plier/déplier dans un arbre) |
| `Shift-↑/↓`, `g` / `G` | Scroll du panneau de détail |
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
| Workloads | `t` liste ↔ arbre · `s` scale · `r` rescale/recyclage/restart · `E` shell · `p`/`C`/`f` logs · `n`/`0` namespace |
| Nodes | `u` vue usage · `s` tri · `o` cordon/uncordon/drain · `p`/`P` export PDF |
| Capacité | `g` monde (nœuds → workloads → quotas) · `f` problèmes seulement |
| FluxCD | `r` menu réconciliation · `Ctrl-R` déblocage · `z` suspend/reprise · `t` table ↔ arbre · `l` logs de tous les controllers · `Tab` onglet Logs/Status/Related/Inventory |
| Vulnérabilités | `f` seuil de sévérité (tous → HIGH+ → CRIT) |
| cert-manager | `Space` plier/déplier · `t` arbre ↔ liste · `f` ALL/PROBLEMS/IN-FLIGHT · `s` aller au Secret · `r` renouveler, relancer ACME |
| Kyverno | `Space` plier/déplier · `t` par policy ↔ par ressource · `f` ALL/PROBLEMS/ENFORCE |
| Reflector | `Space` plier/déplier · `g` sources → miroirs → orphelins · `f` ALL/PROBLEMS · `s` aller à la source · `r` forcer la re-réflexion |
| K8ssandra | `Space` plier/déplier · `g` cluster → sauvegardes → opérations · `f` ALL/PROBLEMS · `l` logs du container fautif · `s` stats du node (tpstats, compactionstats, netstats) ou repairs Reaper · `S` snapshots du node (listsnapshots) · `o` actions |
| RBAC | `Space` plier/déplier · `t` plat → par sujet → par binding → par rôle · `f` plancher de sévérité · `o` saut vers l'objet Flux gérant |
| Stockage | `g` claims ↔ volumes · `t` imbrication parent/enfant · `f` problèmes seulement · `n`/`0` namespace |
| Diagnostic | `r` relancer · `p`/`P` export PDF |
| YAML | `t` neat ↔ brut · `c` copier · `r` recharger |

Dans la vue évènements, le curseur **suit** le flux par défaut (indicateur `↻`) ; remonter l'ancre
sur un évènement précis, `Esc` réactive le suivi.

### Recherche (`/`)

Disponible partout, insensible à la casse, et **conservée en changeant de vue**. Le bandeau
affiche toujours la requête et son effet (`/coredns  (3)`).

- **table** : ne garde que les lignes correspondantes (namespace, nom, kind, reason, message, plus
  ce qui identifie la vue : sujets RBAC, images, clés — jamais les valeurs — des secrets) ;
- **panneau texte** (logs, diagnostic, IA, YAML) : surligne et saute d'une occurrence à l'autre
  avec `Ctrl-N` / `Ctrl-P`, position affichée (`/glob  (3/500)`).

## Les vues

- **Évènements** — watch des `Event` avec filtre All / Warnings / Errors, panneau détail à onglets
  Logs / Status / Related. `p` lit le **run précédent** du container : sur un `CrashLoopBackOff`,
  ce qui a tué le pod n'est que là.
- **Workloads** — liste plate des pods ou arbre workloads → pods (`t`, qui montre aussi les
  workloads scalés à 0). Les actions visent le workload, même depuis la ligne d'un de ses pods.
- **Nodes** — liste, détail, usage CPU/mémoire, et opérations `o` : cordon/uncordon (un patch
  réversible) et **drain avec rapport préalable** — pods qu'aucun contrôleur ne recréera, PDB qui
  refusera, place inexistante ailleurs, `emptyDir` perdus, pods statiques.
- **Capacité** (`:capacity`, `:quota`) — la marge, pas l'état. Par nœud : la simulation
  « si ce nœud tombe, ces pods n'ont nulle part où aller » (first-fit le plus gros d'abord, sur les
  requests, en respectant taints, `nodeSelector` et node affinity `required`). Par workload : les
  pods sans requests (invisibles au scheduler), les surdimensionnés, ceux au plafond de leur
  limite. Par namespace : le `ResourceQuota` sur le point de refuser la prochaine création.

  ![Vue capacité](demo/capacity.gif)

- **FluxCD** — inventaire cluster-wide, arbre de dépendances (`t`), inventaire des objets appliqués
  avec leur état live, logs des controllers filtrés ou agrégés. `r` : reconcile (ressource,
  `--with-source`, sync racine, plus **force upgrade** et **reset** sur une HelmRelease). `Ctrl-R` :
  **déblocage** — kdt tire des pistes du message du contrôleur, les **confirme contre le cluster**,
  et propose le contre-coup (supprimer un webhook orphelin, retirer des finalizers, `resetAt` puis
  `forceAt` sur une release Helm en pending). Un reconcile de plus est rarement le bon geste.

  ![Vue FluxCD](demo/flux.gif)

- **Vulnérabilités** — CVE par image depuis les `VulnerabilityReport` de **Trivy Operator** (score
  CVSS, nombre de CVE corrigibles) et risque sur la version de Kubernetes elle-même (feed officiel,
  dernier patch de la mineure comme cible, badge `EOL`). Sans Trivy, la vue se replie sur la seule
  version k8s.
- **cert-manager** (`:certs`) — la chaîne d'émission de bout en bout : Issuer → Certificate →
  CertificateRequest → Order → Challenge → Secret servi. Les chaînes saines sont repliées, celles
  en échec dépliées. Diagnostics : propagation DNS lente, challenge non présenté, rate limit ACME,
  renouvellement en retard, Secret désynchronisé.
- **Kyverno** — la jointure que `kubectl get polr` ne fait pas : un rapport nomme sa règle par une
  chaîne, il faut relire la policy pour savoir ce qui était vérifié. Trois choses qu'on ne voit
  qu'ici : les règles **`autogen-*`** (ce sont elles que nomment les rapports), la différence entre
  `fail` (la ressource viole) et `error` (la règle ne s'évalue pas — un bug de policy), et les
  **refus d'admission**, qui ne laissent aucune trace dans les rapports et n'existent que sous forme
  d'Event. Le compteur de webhooks `kyverno-resource-*` à zéro veut dire que Kyverno n'intercepte
  plus rien, contrôleurs verts ou non.

  ![Vue Kyverno](demo/kyverno.gif)

- **Reflector** ([kubernetes-reflector](https://github.com/emberstack/kubernetes-reflector)) — le
  contrôleur est **muet quand il décide de ne rien faire**. La vue répond à « pourquoi ce miroir
  n'est-il pas là, ou plus à jour ? » : namespace bloqué par un objet homonyme, miroir modifié à la
  main (reflector ne compare que `reflected-version`, jamais le contenu), portée réelle des regex
  ancrées (une liste vide vaut « tous les namespaces »), et qui attend la copie.
- **RBAC** — liste plate d'audit par défaut, plus trois orientations d'arbre (`t`) : par sujet
  (« que peut faire cette identité au total »), par binding, par rôle. La sévérité est calculée
  **par binding** — un Role seul est inerte, et le même ClusterRole est anodin en RoleBinding et
  critique en ClusterRoleBinding. Montre les ClusterRoles-templates rebindés namespace par
  namespace, la composition des rôles agrégés (`admin`, `edit`, `view`), les bindings qui nomment un
  ServiceAccount inexistant, et les rôles que personne ne lie.

  ![Vue RBAC](demo/rbac.gif)

- **Velero** (`:velero`, `:restores`, `:bsl`) — un backup n'a qu'une question : *si tout brûle
  maintenant, qu'est-ce qui revient ?* `PartiallyFailed` est affiché comme un échec, parce que c'en
  est un — le backup est allé au bout sans tout capturer. La vue évalue le **cron elle-même** pour
  dire qu'un schedule a cessé de tourner (velero ne le signale nulle part : il ne crée simplement
  pas de backup), signale un TTL plus court que la période du cron, une location indisponible, un
  dépôt kopia sans maintenance, et surtout les **namespaces à PVC que plus aucun schedule ne
  couvre**. `o` ouvre les opérations : lancer un backup depuis un schedule, mettre en pause,
  restaurer, et supprimer *vraiment* un backup — via une `DeleteBackupRequest`, parce que supprimer
  l'objet ne supprime rien et que la resynchronisation le recrée. `l` va chercher le log du run.
  `+` déplie ce que le backup contient réellement — namespaces, puis types, puis objets — et
  *Restaurer (options)* s'en sert pour préremplir un `Restore` restreint : namespaces à cocher,
  remapping vers un namespace neuf, filtre par type et par labels, et le choix d'ignorer ou
  d'écraser ce qui existe déjà. Velero ne sait pas cibler un objet par son nom : la vue s'arrête
  donc là où l'API s'arrête, sans promettre une case à cocher par objet.
- **K8ssandra / Cassandra** (`:k8ssandra`, `:medusa`, `:reaper`) — sur une base de données une
  seule question compte, et aucune des surfaces qui devraient y répondre ne le fait. Un
  `MedusaBackupSchedule` garde un `lastExecution` frais et un `nextSchedule` propre que le run qu'il
  a déclenché ait réussi ou échoué ; le CronJob de purge se termine en vert en ne purgeant rien ; et
  les `MedusaBackup`, le catalogue lui-même, cessent simplement d'apparaître — sans évènement, sans
  condition, sans champ de status. Un cluster peut donc tourner des mois avec tout au vert et pas
  une sauvegarde restaurable. La vue met ce chiffre en titre : **l'âge de la dernière sauvegarde qui
  couvre tous les nodes** du datacenter, un run partiel étant compté comme un échec parce qu'il se
  restaure comme s'il était entier. Elle signale aussi les runs réussis absents du catalogue (la
  `MedusaTask sync` n'a pas tourné), et qu'une restauration **arrête le datacenter** — avant de la
  lancer, pas après.

  Le ring ne vient d'aucune CRD mais de l'API de management du container `cassandra`, atteinte par
  le proxy de l'apiserver : ni port-forward, ni `kubectl`, ni exec. `nodetool status` et
  `describecluster` en sortent en données typées (état UN/DN, load, tokens, accord de schéma), et
  `s` va chercher `tpstats`, `compactionstats` et `netstats` du node sélectionné, `S` ses snapshots
  (`listsnapshots`) — la seule chose qui explique un volume de données qui se remplit alors que les
  tables ne grossissent pas : un run Medusa mort avant l'upload laisse son tag, un `TRUNCATE` laisse
  le sien pour toujours. Les lignes sont repliées par tag, et les **deux** tailles sont montrées :
  un snapshot est un répertoire de hard links, donc l'essentiel de son poids reste partagé avec les
  SSTables vivantes et ne rend rien — seul `True size`, les fichiers que plus aucune SSTable vivante
  ne référence, revient quand on efface le tag. Sur un node 3.11, qui ne date aucun snapshot, la date
  des tags `truncated-`/`dropped-` est lue dans le tag lui-même. La jointure entre
  un pod et son entrée de ring se fait sur l'**adresse**, pas sur le `hostID` de
  `status.nodeStatuses` : ce champ est la mémoire de l'operator et il périme — la vue le dit quand
  les deux divergent. `o` ouvre les opérations : sauvegarder maintenant, restaurer, purger ou
  resynchroniser le catalogue Medusa, et les `CassandraTask` (cleanup, upgradesstables, compaction,
  scrub, restart roulant).
- **Stockage** (`:storage`, `:pv`) — `kubectl get pvc` dit qu'un PVC est `Pending`, jamais
  pourquoi. Ici : StorageClass introuvable, aucune classe par défaut (ou deux), `WaitForFirstConsumer`
  qui attend un pod, classe sans provisioner — et si le provisioner a laissé un `ProvisioningFailed`,
  c'est **son** message qui prime. Aussi : PV `Released` (de la donnée qui dort), `reclaimPolicy:
  Delete` rappelé sur le PVC, PVC `RWO` monté par plusieurs pods.
- **Secrets / ConfigMaps / Services / Ingress** — inventaires, avec expiration des certificats TLS
  et leurs consommateurs.
- **Diagnostic** (`D`) — batterie de vérifications : version, namespaces système, CoreDNS, CNI,
  webhooks, Rancher, pods en erreur, PV, warnings récents.
- **Extraction** (`X`) — rapport PDF complet de l'état du cluster dans `~/Downloads`.
- **IA** (`i`) — envoie le contexte courant à une API compatible OpenAI ; la réponse est streamée
  (SSE) et s'affiche au fil de l'eau. `L` relance dans l'autre langue.

## Écrire dans le cluster

Toute la navigation est en **lecture seule**. Les seules écritures sont celles qu'une touche
déclenche explicitement, et elles passent par des garde-fous.

| Touche | Écriture | Garde-fous |
|---|---|---|
| `e` | `PUT` complet, verrouillé sur le `resourceVersion` | **Avant** : objet GitOps réécrit au prochain reconcile, spec tenue par un contrôleur, `can-i update` refusé, objet en cours de suppression, spec figée après création. **Après** : chaque champ modifié classé *appliqué* / *ignoré* / *rejeté par l'API* |
| `Ctrl-D` | `delete` en propagation *background* | GitOps, point d'entrée GitOps (Kustomization/HelmRelease/Application), `Namespace` et CRD (cascade), `ownerReferences`, namespace système, finalizers |
| `h` | Merge patch de deux annotations | Aucun — c'est le geste le plus léger de la liste |
| `o` (Nodes) | Patch `spec.unschedulable`, puis évictions | Rapport de drain complet avant la moindre éviction |
| `r` / `z` | Reconcile, suspend, scale, restart, renew | Confirmation armée dans le menu |
| `Ctrl-R` | Suppression d'une config d'admission, retrait de finalizers | Saisie du nom exact de l'objet |

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
| `flux.rs` · `repair.rs` | FluxCD (inventaire, reconcile, arbre) et déblocage `Ctrl-R` |
| `rbac.rs` · `secrets.rs` · `certmanager.rs` | RBAC scoré, Secrets/TLS, chaîne cert-manager |
| `kyverno.rs` · `reflector.rs` · `vulnerabilities.rs` | Kyverno, Reflector, CVE |
| `velero.rs` | Velero : backups, schedules (cron évalué), restaurations, locations |
| `k8ssandra.rs` · `mgmtapi.rs` | K8ssandra/Medusa/Reaper, et l'API de management Cassandra via le proxy apiserver |
| `storage.rs` | PVC / PV / StorageClass et règles de diagnostic |
| `yaml.rs` · `edit.rs` · `delete.rs` · `touch.rs` | YAML, édition, suppression, touch |
| `diagnostic.rs` · `extract.rs` · `pdf.rs` | Diagnostic, extraction, rendu Typst |
| `enrich.rs` · `ai.rs` | Contexte lié à un évènement, client OpenAI |
| `lang.rs` · `clip.rs` | Table de chaînes FR/EN, presse-papier OSC 52 |

Stack : Rust 2021 · `kube` 3.1 (rustls, socks5) · `k8s-openapi` 0.27 · `ratatui` 0.30 · `tokio` ·
`reqwest` · `typst` 0.14.

## Licence

[Apache 2.0](LICENSE).
