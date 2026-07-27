# kdt — Kubernetes Diagnostic Tools

TUI Rust pour surveiller les évènements Kubernetes en temps réel, inspecter les nœuds, lancer un diagnostic complet du cluster, exporter des rapports PDF et obtenir une analyse assistée par IA.

## Fonctionnalités

- **Flux d'évènements live** : watch des `Event` Kubernetes avec filtrage All / Warnings / Errors et mise en évidence des `reason` critiques.
- **Vue détail** : logs du pod concerné, status de l'objet, et ressources liées (onglets Logs / Status / Related). Les logs se lisent sur le **run précédent** (`p` — le cas du `CrashLoopBackOff`, où le container qui tourne ne dit rien), container par container (`C`), et en **suivi** (`f`).
- **Recherche (`/`)** : depuis toutes les vues. Dans une table elle ne garde que les lignes qui correspondent ; dans un panneau texte (logs, diagnostic, IA, YAML) elle surligne et saute d'une occurrence à l'autre (`Ctrl-N`/`Ctrl-P`). Le bandeau annonce toujours la requête active et son effet.
- **Vue Nodes** : liste des nœuds (recherche `/` comprise), détail plein écran, vue d'usage (CPU/mémoire requests, tri configurable) et opérations `o` (voir plus bas).
- **Diagnostic cluster** : batterie de vérifications (version, namespaces système, kube-system, CoreDNS, CNI, webhooks, Rancher, pods en erreur, PV, évènements warning récents…).
- **Extraction complète** : génère un rapport PDF de l'état du cluster dans `~/Downloads`.
- **Analyse IA** : envoie le contexte courant (évènement, diagnostic, usage) à une API compatible OpenAI pour explication/recommandation, en français ou anglais. La réponse est **streamée** (SSE) et s'affiche au fil de l'eau.
- **FluxCD** : inventaire cluster-wide, réconciliation (ressource / + source / sync racine, plus force et reset sur une HelmRelease), suspend-reprise, **déblocage** (`Ctrl-R` : nomme ce qui bloque une ressource — webhook orphelin, finalizer, release Helm en pending — et propose le contre-coup), logs des controllers (filtrés ou agrégés), inventaire d'objets appliqués et vue arborescente des dépendances.
- **Vulnérabilités** : liste les images scannées (CVE + score CVSS, nombre de correctifs disponibles) à partir des `VulnerabilityReport` de Trivy Operator, et le risque sur la version de Kubernetes elle-même (CVE du feed officiel + dernier patch de la mineure comme cible). Le scan d'images requiert Trivy Operator ; sans lui, la vue se replie sur les seules infos de version k8s.
- **YAML de l'objet (`y`)** : depuis n'importe quelle vue, le manifeste de l'objet sélectionné, en brut (`kubectl get -o yaml`) ou en **neat** — sans les attributs de run (`managedFields`, `status`, `resourceVersion`, valeurs par défaut des pod specs…).
- **Édition avec garde-fous (`e`)** : l'objet part dans `$EDITOR` (vim &co.) puis revient par un `PUT` verrouillé sur son `resourceVersion`. Avant, kdt dit ce qui rendra l'édition vaine — objet GitOps réécrit au prochain reconcile, spec tenue par un contrôleur, `can-i update` refusé ; après, il classe chaque champ modifié entre *appliqué*, *ignoré* et *rejeté par l'API*.
- **Suppression avec garde-fous (`Ctrl-D`)** : relit l'objet avant tout, avertit s'il est déployé par un moteur GitOps (Flux, Argo CD, Helm) ou si la suppression cascade (namespace, CRD, point d'entrée GitOps) ; l'avertissement se passe outre, mais en retapant le nom de l'objet.
- **Capacité et marge de manœuvre (`:capacity`)** : la vue qui répond à « qu'est-ce qui va casser », pas à « voici l'usage ». Par nœud : ce qui est réservé contre ce qui existe, et surtout la simulation **« si ce nœud tombe, ces pods n'ont nulle part où aller »** (requests, taints, sélecteurs). Par workload : les pods invisibles au scheduler (sans requests), ceux qui réservent bien plus qu'ils n'utilisent, ceux qui touchent leur propre limite. Par namespace : le `ResourceQuota` sur le point de refuser le prochain déploiement.
- **Opérations sur les nœuds (`o`)** : `cordon` / `uncordon` en un patch réversible, et un **drain avec garde-fous** — avant la moindre éviction, kdt dit ce qui va coincer : pods qu'aucun contrôleur ne recréera, `PodDisruptionBudget` qui refusera, place qui n'existe pas ailleurs, données `emptyDir` perdues, pods statiques qui resteront.
- **Shell dans un pod (`E`)** : ouvre `kubectl exec -it` en rendant le terminal, comme `e` le rend à `$EDITOR`.
- **Touch (`h`)** : pose `kdt.io/touched-at` (horodatage à la milliseconde) et `kdt.io/touched-by` sur l'objet sélectionné, pour lui faire retraverser la chaîne d'admission — réévaluer une règle Kyverno, réveiller un contrôleur. Sans confirmation : c'est un merge patch de deux annotations, et le bandeau nomme l'objet touché.
- **Copie presse-papier** : via séquence OSC 52 (fonctionne à travers SSH/terminal compatible).

## Installation

### Homebrew (macOS et Linux x86_64)

```bash
brew install agardenat/kdt/kdt
```

Équivaut à `brew tap agardenat/kdt && brew install kdt`. La formula sert le binaire universel macOS (Apple Silicon + Intel) et le binaire statique Linux x86_64 selon la plateforme. Linux arm64 n'est pas distribué via Homebrew (voir packaging).

### Paquets Linux (.deb / .rpm)

Chaque release publie des paquets pour x86_64 :

```bash
# Debian / Ubuntu
sudo dpkg -i kdt_<version>_amd64.deb

# RHEL / Fedora / openSUSE
sudo rpm -i kdt-<version>-1.x86_64.rpm
```

### Binaire pré-compilé

Télécharger l'archive correspondant à la plateforme depuis la page [Releases](https://github.com/agardenat/kdt/releases), puis :

```bash
tar xzf kdt-linux-x86_64.tar.gz   # ou kdt-macos-universal.tar.gz
sudo install -m 0755 kdt /usr/local/bin/kdt
```

### Depuis les sources

Voir [Build](#build) (nécessite une toolchain Rust stable).

## Build

```bash
cargo build --release
```

Le binaire est produit dans `target/release/kdt`. Une cible musl statique est également configurée (`target/x86_64-unknown-linux-musl`).

Profil release : `lto = thin`, `codegen-units = 1`, `panic = abort`, symboles strippés, allocateur `mimalloc`.

## Utilisation

```bash
kdt [OPTIONS]
```

| Option | Description | Défaut |
|---|---|---|
| `-n, --namespace <NS>` | Namespace à surveiller | tous si non précisé |
| `-A, --all-namespaces` | Tous les namespaces | — |
| `--context <CTX>` | Contexte kubeconfig à utiliser | contexte courant |
| `--buffer-size <N>` | Taille du buffer d'évènements | `5000` |

La connexion au cluster utilise le kubeconfig standard (inféré, ou contexte explicite).

## Raccourcis clavier

### Vue principale (évènements + détail)

L'application démarre directement sur cette vue : le tableau des évènements défile en
direct et le panneau détail (Logs / Status / Related) est toujours affiché. Par défaut
le curseur **suit** l'évènement le plus récent. Naviguer vers le haut **ancre** le curseur
sur un évènement précis (qui reste sélectionné même quand le flux continue de défiler) ;
revenir tout en bas réactive le suivi. L'indicateur `↻` du bandeau signale que le
défilement live est actif.

| Touche | Action |
|---|---|
| `↑` / `↓` / `PgUp` / `PgDn` | Navigation (ancre le curseur en remontant) |
| `s` | Geler / dégeler le défilement |
| `Esc` | Revenir au suivi du plus récent (et dégeler) |
| `Enter` | Détail plein écran |
| `Tab` / `Shift-Tab` | Changer d'onglet (Logs / Status / Related) |
| `Shift-↑/↓`, `Ctrl-U/F` | Scroll du détail |
| `g` / `G` | Haut / bas du détail |
| `a` / `w` / `x` | Filtre All / Warnings / Errors |
| `:` | Palette de commandes (style k9s) |
| `/` | Recherche |
| `p` / `C` / `f` | Logs : run précédent / container / suivi (onglet Logs) |
| `n` | Filtrer sur le namespace de l'évènement sélectionné |
| `0` | Retirer le filtre namespace (tous namespaces confondus) |
| `N` | Nodes du pod sélectionné |
| `y` | YAML de l'objet sélectionné |
| `e` | Éditer l'objet sélectionné dans `$EDITOR` (avec garde-fous) |
| `h` | Toucher l'objet sélectionné (annotation horodatée, sans confirmation) |
| `Ctrl-D` | Supprimer l'objet sélectionné (avec garde-fous) |
| `E` | Shell dans le pod sélectionné (`kubectl exec -it`) |
| `D` | Diagnostic cluster |
| `X` | Extraction complète (PDF) |
| `i` | Panneau IA |
| `l` | Bascule langue IA (FR/EN) |
| `m` | Fournisseur IA suivant |
| `←` / `→` / `Home` | Scroll horizontal |
| `q` / `Ctrl-C` | Quitter |

### Recherche (`/`)

Disponible depuis **toutes les vues**. `/` ouvre une invite, `Entrée` valide, `Esc` annule.
La requête est insensible à la casse et **survit au changement de vue** : c'est le cas utile
quand on suit un objet d'une vue à l'autre. Le bandeau affiche la requête active et son effet
(`/coredns  (3)`) — une vue qui cache des lignes doit le dire, sinon un objet manquant se lit
comme un problème de cluster. `Esc` retire la recherche **avant** de faire quoi que ce soit
d'autre.

Ce que `/` fait dépend de ce qui est affiché :

- **Vue tabulaire** : ne garde que les lignes qui correspondent. Sont testés le namespace, le
  nom, le kind, la `reason` et le message — et, selon la vue, ce qui l'identifie : sujets et
  rôles en RBAC, image et workload en vulnérabilités, clés (jamais les valeurs) en
  secrets/configmaps. Dans les vues arborescentes, un parent qui ne correspond pas disparaît et
  ses enfants s'affichent à plat.
- **Panneau texte** (détail plein écran, logs Flux, diagnostic, panneau IA, YAML) : surligne les
  lignes correspondantes et saute de l'une à l'autre avec `Ctrl-N` / `Ctrl-P` (avec bouclage).
  Le bandeau indique la position (`/glob  (3/500)`). `n`/`N` ne sont pas utilisés : ils sont déjà
  pris par le filtre namespace et la vue Nodes.

Les deux requêtes sont indépendantes : filtrer une table sur `coredns` puis chercher `image`
dans son YAML ne mélange pas les deux.

### Logs d'un pod (`p` / `C` / `f`)

Dans l'onglet **Logs** du panneau détail (vue évènements, workloads, et leurs plein écran) :

| Touche | Action |
|---|---|
| `p` | Bascule sur le **run précédent** du container (`--previous`) |
| `C` | Restreint à **un container** (ordre du spec, init d'abord), puis retour à tous |
| `f` | **Suivi** : relit la fin des logs toutes les ~3 s |

`p` est le raccourci qui compte sur un `CrashLoopBackOff` : le container qui tourne vient d'être
relancé et ne dit rien, ce qui l'a tué n'est que dans le run qui s'est terminé. Quand ce run
n'existe pas, kdt le dit (`pas de run précédent`) au lieu de remonter une erreur d'API.

L'état courant est affiché en badge à côté des onglets (` previous `, le nom du container,
` ↻ follow `) : un panneau vide ne veut pas dire la même chose sur un container qui tourne et sur
un run terminé. Le suivi est refusé sur un run précédent, qui par définition ne grossit plus.

`C` ne fait rien sur un pod à un seul container. Si la sélection passe à un pod qui n'a pas le
container demandé, kdt le signale plutôt que d'afficher silencieusement autre chose.

### YAML de l'objet (`y`)

Disponible depuis **toutes les vues** (évènements, nodes, workloads, flux, services/ingress,
stockage, RBAC, secrets, configmaps) : `y` ouvre le manifeste de l'objet sous le curseur, récupéré en
direct via l'API (découverte de GVK, donc les CRD marchent comme les kinds natifs).

Deux affichages, bascule par `t` :

- **neat** (par défaut) : sans les attributs de run — `managedFields`, `resourceVersion`, `uid`,
  `generation`, `creationTimestamp`, `status`, l'annotation `last-applied-configuration`, ainsi que
  les valeurs par défaut injectées dans les pod specs (`dnsPolicy`, `schedulerName`,
  `terminationMessagePath`, tolérations et volumes `kube-api-access-*`…). Ce qui reste est
  ré-appliquable.
- **brut** : exactement ce que renvoie l'API, comme `kubectl get -o yaml`.

| Touche | Action |
|---|---|
| `y` | Ouvrir (depuis une vue) / fermer |
| `t` | Basculer **neat** ↔ **brut** |
| `/` | Rechercher dans le manifeste (`Ctrl-N`/`Ctrl-P` d'une occurrence à l'autre) |
| `c` | Copier le YAML affiché |
| `↑/↓`, `PgUp/PgDn`, `g`/`G` | Scroll |
| `←` / `→` / `Home` | Scroll horizontal |
| `r` / `F5` | Recharger l'objet |
| `Esc` / `q` | Fermer (`Esc` retire d'abord la recherche) |

> Sur un `Secret`, le manifeste contient les valeurs `data` en base64, comme `kubectl get -o yaml`.

### Édition d'un objet (`e`)

Disponible depuis les mêmes vues que `y`, et depuis le panneau YAML lui-même. Le manifeste part
dans **votre** éditeur — kdt rend la main au terminal le temps de l'édition, puis la reprend :

```
e  →  vérifications  →  $EDITOR  →  diff + verdict  →  Entrée  →  PUT
```

L'éditeur est choisi dans cet ordre : `$KDT_EDITOR`, `$KUBE_EDITOR`, `$VISUAL`, `$EDITOR`, sinon
`vi`. La valeur peut porter des arguments (`KDT_EDITOR="nvim -u NONE"`). Le fichier temporaire est
créé en `0600` (un `Secret` y transite) et effacé à la fermeture du panneau.

**Avant** d'ouvrir l'éditeur, l'objet est relu et passé au crible. Si rien n'est à signaler
l'éditeur s'ouvre directement ; sinon le panneau affiche d'abord ses constats :

| Constat | Niveau |
|---|---|
| Déployé par un moteur GitOps (Flux, Argo CD, Helm) : la modification sera écrasée au prochain reconcile — c'est le dépôt Git qu'il faut éditer | ⛔ |
| Objet en cours de suppression (`deletionTimestamp`), ou pod terminé (`Succeeded`/`Failed`) | ⛔ |
| L'API répond « non » à un `can-i update` sur cet objet | ⛔ |
| Spec tenue par un contrôleur (`ownerReferences`) : perdue à la prochaine recréation | ⚠ |
| Pod en cours d'exécution : seule l'image des conteneurs est modifiable à chaud | ⚠ |
| `Job`, `PersistentVolumeClaim`, `StatefulSet` : spec en grande partie figée après création | ⚠ |
| `ConfigMap`/`Secret` marqué `immutable: true` | ⚠ |

**Au retour** de l'éditeur, le document est comparé à celui qui est parti et chaque champ modifié
est classé — c'est là que se voit une édition qui ne servira à rien :

| Verdict | Ce qui se passe |
|---|---|
| Document inchangé | Le panneau se ferme, rien n'est envoyé (c'est aussi comme ça qu'on annule) |
| Seuls des champs gérés par l'API changent (`status`, `resourceVersion`, `managedFields`…) | ⛔ appliquer ne modifierait rien |
| Champs figés après création (`spec.nodeName` d'un pod, `spec.serviceName` d'un StatefulSet, `spec.clusterIP` d'un Service, `data` d'un objet immutable…) | ⛔ l'API rejettera |
| `apiVersion`, `kind`, `metadata.name`/`namespace`/`uid` modifiés | ⛔ ce n'est plus le même objet |

Les champs sont listés par chemin (`spec.containers[0].image`), colorés selon leur sort : cyan pour
ce qui sera appliqué, rouge pour ce qui sera rejeté, gris pour ce qui sera ignoré. Les constats de
la pré-vérification restent affichés — on revient d'un autre programme, et « Flux va l'écraser »
mérite d'être relu au moment d'appliquer.

**Aucun avertissement ne bloque** : `Entrée` applique, `e` ré-ouvre l'éditeur, `Esc` abandonne.

| Touche | Action |
|---|---|
| `e` | Ouvrir (depuis une vue ou depuis le panneau YAML) / ré-éditer |
| `Entrée` | Éditer quand même (constats) · appliquer (revue) · ré-éditer (refus de l'API) |
| `Esc` / `q` | Fermer sans rien appliquer |

L'écriture est un `PUT` complet, comme `kubectl edit` : le `resourceVersion` du document sert de
verrou optimiste, donc une modification concurrente fait échouer la requête au lieu d'écraser le
travail d'un autre. Un YAML invalide ou un refus de l'API n'est jamais une perte : `Entrée` renvoie
dans l'éditeur avec le tampon tel qu'il était. La vue sous-jacente est rafraîchie dès que l'API a
accepté.

### Touch d'un objet (`h`)

Disponible depuis les mêmes vues que `y`. `h` pose deux annotations sur l'objet sélectionné :

```yaml
metadata:
  annotations:
    kdt.io/touched-at: "2026-07-25T18:32:28.070Z"
    kdt.io/touched-by: agardenat
```

Ce qui compte n'est pas l'annotation mais **l'écriture** qu'elle provoque. Les webhooks d'admission
— Kyverno et consorts — ne tournent qu'à la création et à la mise à jour : pour faire réévaluer une
politique sur un objet que personne n'a modifié, il faut lui changer quelque chose d'inoffensif.
C'est aussi ce qui fait repasser un contrôleur qui *watch* l'objet.

L'horodatage est à la **milliseconde**, et c'est nécessaire : un merge patch qui ne change rien est
absorbé par l'API sans incrémenter le `resourceVersion`, donc sans appeler le moindre webhook. Deux
touches dans la même seconde porteraient la même valeur et la seconde ne ferait rien du tout.
`kdt.io/touched-by` reprend `$USER` (à défaut `$LOGNAME`, sinon `kdt`).

Le patch est un **merge patch** sur la seule map `annotations` : les autres annotations, les labels
et le reste de l'objet ne sont ni relus ni réécrits, il n'y a donc rien à perdre face à une
modification concurrente.

> ⚠ **Aucune confirmation, aucun garde-fou** : contrairement à `e` et `Ctrl-D`, `h` part
> immédiatement. Dans la vue évènements, où le curseur **suit** le flux, l'objet touché est celui qui
> était sélectionné au moment de la frappe — geler le défilement (`s`) ou ancrer le curseur avant de
> toucher. Le bandeau du footer nomme toujours l'objet effectivement touché (`✓ touché
> ConfigMap default/exemple`), ou affiche le refus de l'API (`✗ touch … is forbidden…`).

Dans la vue évènements, une ligne est un Event, mais `h` patche **l'objet dont l'évènement parle**
(son `involvedObject`, celui des colonnes `KIND`/`NAME`) — jamais l'Event lui-même. C'est le seul
ciblage utile : aucun contrôleur ne réagit à un Event, le toucher ne rejouerait donc aucune
admission, et l'objet est éphémère (ramassé au bout d'une heure) — l'annotation partirait avec lui.
C'est aussi ce que font déjà `y`, `e`, `Ctrl-D` et les onglets Logs/Status/Related du panneau de
détail. Comme `h` est la seule de ces touches à écrire sans panneau pour nommer sa cible d'abord, la
barre de raccourcis l'annonce dans ces vues : `h  toucher l'objet` au lieu de `h  toucher`.

Un objet piloté par GitOps se touche sans problème — l'annotation n'est pas dans le dépôt, donc rien
ne la revendique, et Flux ou Argo la laissent en place jusqu'à ce qu'ils réécrivent l'objet.

### Suppression d'un objet (`Ctrl-D`)

Disponible depuis les mêmes vues que `y`. Rien n'est supprimé avant que l'objet n'ait été relu et
passé au crible : le panneau affiche d'abord ce que les garde-fous ont trouvé, puis demande une
confirmation dont l'exigence dépend de la gravité.

Ce qui est vérifié :

| Constat | Niveau |
|---|---|
| Déployé par un moteur GitOps — Kustomization ou HelmRelease Flux, Application Argo CD, release Helm | ⛔ |
| L'objet **est** un point d'entrée GitOps (`Kustomization`, `HelmRelease`, `Application`) : sa suppression emporte tout ce qu'il déploie | ⛔ |
| `Namespace` (suppression en cascade) et `CustomResourceDefinition` (toutes les instances du cluster) | ⛔ |
| Objet piloté par un contrôleur (`ownerReferences`) : recréé aussitôt | ⚠ |
| Namespace système (`kube-system`, `flux-system`, `argocd`…), `Node` à drainer, `PersistentVolume(Claim)` | ⚠ |
| `finalizers` présents : la suppression peut rester bloquée en `Terminating` | · |

L'appartenance GitOps se lit sur les labels/annotations posés par les contrôleurs
(`kustomize.toolkit.fluxcd.io/*`, `helm.toolkit.fluxcd.io/*`, `argocd.argoproj.io/tracking-id` ou
`/instance`, `meta.helm.sh/release-*`) : peu importe l'outil, tant qu'il signe ce qu'il applique.

**Aucun avertissement ne bloque** — mais plus le constat est grave, plus le geste est engageant :

| Situation | Confirmation |
|---|---|
| Aucun constat, ou constats ⚠ / · uniquement | `Ctrl-D` pour armer, `Ctrl-D` pour confirmer |
| Au moins un constat ⛔, ou vérifications impossibles (objet disparu, RBAC) | `Ctrl-D` pour passer outre, puis **saisie du nom exact de l'objet** avant que `Ctrl-D` ne supprime |

**La réponse par défaut est « non »** : seul `Ctrl-D` — la touche qui a ouvert le panneau — avance
vers la suppression. `Entrée` et `Esc` annulent toutes les deux et referment le panneau, quel que
soit l'avancement du geste : la touche réflexe ne détruit jamais. La suppression utilise la
propagation *background*, comme `kubectl delete`, et la vue sous-jacente est rafraîchie dès que
l'API a accepté la demande.

### Palette de commandes (`:`)

Inspirée de k9s : `:` ouvre une invite où l'on tape le nom d'une vue. `Tab` complète,
`Enter` valide, `Esc` annule.

`events`, `namespace` et `workloads` acceptent un **nom de namespace** en argument
(`:ns kube-system`, `:pods istio-system`, `:events monitoring`) avec autocomplétion (`Tab`).
`all` (ou `*`/`0`) cible tous les namespaces.

| Commande | Alias | Action |
|---|---|---|
| `events [ns]` | `ev`, `event` | Vue évènements (optionnellement filtrée sur `ns`) |
| `namespace [ns]` | `ns`, `namespaces` | Sélecteur de namespace (ou bascule directe sur `ns`) |
| `workloads [ns]` | `wl`, `pods`, `po`, `deploy` | Vue Workloads / Pods (optionnellement filtrée sur `ns`) |
| `nodes` | `no`, `node` | Vue Nodes |
| `flux` | `fl`, `ks`, `hr` | Vue FluxCD |
| `flux-logs` | `logs`, `fluxlogs` | Logs agrégés des controllers Flux |
| `rbac` | `rb`, `roles`, `bindings`, `sec` | Vue sécurité RBAC (bindings scorés par sévérité) |
| `vuln` | `cve`, `cves`, `vulns` | Vue vulnérabilités (images + version k8s) |
| `secrets` | `secret`, `se`, `tls` | Vue Secrets et certificats TLS |
| `certs` | `certificates`, `issuers`, `challenges`, `acme` | Vue cert-manager (chaîne d'émission) |
| `kyverno` | `ky`, `policies`, `polr`, `cpol`, `admission` | Vue Kyverno (policies, règles, violations) |
| `configmaps` | `cm`, `config` | Vue ConfigMaps |
| `services` | `svc`, `service` | Vue Services / Endpoints |
| `ingress` | `ing`, `ingressclass` | Vue Ingress / IngressClass |
| `storage` | `stockage`, `pvc`, `claims` | Vue stockage, côté demandes (PVC → PV) |
| `pv` | `sc`, `storageclass`, `persistentvolume` | Vue stockage, côté volumes (StorageClass → PV) |
| `capacity` | `cap`, `marge`, `headroom` | Vue capacité, côté nœuds (marge et perte d'un nœud) |
| `quota` | `quotas`, `rq`, `resourcequota` | Vue capacité, côté quotas |
| `quit` | `q` | Quitter |

### FluxCD (`:flux`)

Vue globale de l'état Flux sur tout le cluster : `Kustomization`, `HelmRelease` et sources
(`GitRepository`, `OCIRepository`, `HelmRepository`, `HelmChart`, `Bucket`). Les ressources
en échec sont remontées en tête, puis `Unknown`, puis suspendues, puis `Ready`. Le bandeau
résume `✓ready ✗failed ?unknown ⏸suspended`.

Panneau de détail à onglets **Logs / Status / Related / Inventory** :

- **Logs** : pour une ressource Flux (qui n'est pas un Pod), affiche les logs du *controller*
  correspondant (`kustomize-controller`, `helm-controller`, `source-controller`…) filtrés sur
  l'objet sélectionné.
- **Status** : le `status` de l'objet (conditions, révision…).
- **Related** : l'objet et sa source référencée.
- **Inventory** : pour une `Kustomization`, la liste des objets réellement appliqués
  (`status.inventory`) avec leur état live (✓ ready / ✗ échec / · inconnu), rafraîchie en continu
  pour suivre un déploiement. Un `⚠ prune` signale les Kustomizations avec `spec.prune: true`
  (les objets retirés du git sont supprimés du cluster) — visible aussi dans la table/l'arbre.

#### Réconciliation, suspend, logs

La réconciliation pose l'annotation `reconcile.fluxcd.io/requestedAt` via l'API (pas besoin du
binaire `flux`) ; le suspend/reprise bascule `spec.suspend` (non destructif). Sur une HelmRelease,
deux leviers supplémentaires apparaissent dans le menu : **forcer l'upgrade**
(`reconcile.fluxcd.io/forceAt`, rejoue l'upgrade Helm même sans changement de chart) et **réarmer**
(`reconcile.fluxcd.io/resetAt`, efface les compteurs d'échec d'une release en *retries exhausted*).
Les deux annotations ne sont honorées que si elles portent la même valeur que `requestedAt` : kdt les
écrit dans le même patch, avec le même horodatage.

| Touche | Action |
|---|---|
| `↑` / `↓` / `PgUp` / `PgDn` | Navigation |
| `Tab` / `Shift-Tab` | Changer d'onglet (Logs / Status / Related / Inventory) |
| `Enter` | Détail plein écran (en mode arbre : plier/déplier le nœud) |
| `Shift-↑/↓`, `g` / `G` | Scroll du détail |
| `r` | Menu de réconciliation : ressource / **+source** (`--with-source`) / sync racine (`GitRepository/flux-system`), plus **forcer l'upgrade** et **réarmer** sur une HelmRelease, avec confirmation |
| `Ctrl-R` | Déblocage : nomme ce qui bloque la ressource et propose le contre-coup (voir plus bas) |
| `z` | Suspendre / reprendre la ressource (`spec.suspend`) |
| `t` | Basculer table ↔ vue arborescente |
| `L` | Logs globaux de tous les controllers Flux (suivi) |
| `i` | Panneau IA |
| `F5` | Rafraîchir (auto toutes les 10 s) |
| `Esc` | Retour |

#### Vue arborescente (`t`)

Affiche la hiérarchie de dépendances : **source → Kustomization/HelmRelease → workloads
dépendants** (`dependsOn`). `Enter` / `Espace` plie/déplie un nœud ; les actions `r` (menu
réconciliation) et `z` s'appliquent au nœud sélectionné. Le contenu appliqué d'une `Kustomization` reste visible dans
l'onglet **Inventory**.

#### Déblocage (`Ctrl-R`)

Un contrôleur en échec dit *ce qui* n'a pas marché, rarement *quoi faire*, et le geste qui débloque
n'est presque jamais un reconcile de plus. Le cas d'école : un opérateur est désinstallé, ses
webhooks d'admission survivent en pointant vers un service qui n'existe plus, et à partir de là
chaque `apply` du contrôleur est rejeté par l'API server. Flux répète une erreur de webhook
indéfiniment ; ce qu'il faut réparer est à trois namespaces de là.

kdt lit d'abord le message du contrôleur pour en tirer des **pistes** (webhook injoignable, opération
Helm déjà en cours, tentatives épuisées, dépendance non prête, CRD absente, champ immuable,
namespace en cours de suppression), puis il **confirme chaque piste contre le cluster** — une erreur
qui nomme un webhook ne prouve pas que ce webhook soit cassé. Seuls les constats confirmés sont
affichés, et seuls eux portent des actions. Quand le message ne donne aucune piste, un balayage des
configurations d'admission cherche l'orphelin en `failurePolicy: Fail` — la seule panne qui casse
les applies sans jamais se nommer dans l'objet qu'elle casse.

| Constat | Action proposée |
|---|---|
| Webhook orphelin (service, ou namespace, disparu ; aucun endpoint prêt) | Supprimer la configuration |
| Configuration d'admission sans aucun webhook (résidu d'un opérateur) | Supprimer la configuration |
| Objet bloqué en `Terminating` par un finalizer | Retirer les finalizers de force |
| Release Helm en `pending-*` | `resetAt`, puis `forceAt` — jamais une écriture dans le stockage Helm |
| Tentatives épuisées | `resetAt`, ou cycle suspend/resume |
| Dépendance non prête, CRD absente, champ immuable, refus d'admission | *Constat seul* : rien à automatiser |

Les deux actions irréversibles — supprimer une configuration d'admission, retirer des finalizers —
passent par la confirmation stricte : il faut **retaper le nom** de l'objet. Les autres demandent
deux fois `Ctrl-R`. Dans tous les cas `Entrée` **annule** : refuser est la réponse par défaut, donc
la touche réflexe n'est jamais celle qui détruit. Un état de release Helm est lu dans les *labels*
du secret `sh.helm.release.v1.*`, sans décompresser quoi que ce soit.

#### Logs Flux (`L` ou `:flux-logs`)

Vue plein écran agrégeant les logs de tous les controllers de `flux-system` (suivi ~3 s),
triés par horodatage. `Esc` pour revenir.

### Workloads (`:workloads`, alias `:pods`)

Par défaut une **liste plate des pods** du namespace courant ; `t` bascule sur l'arbre
workloads → pods, où chaque Deployment/StatefulSet/DaemonSet/Job porte ses pods en dessous. Un
workload scalé à 0 reste visible dans l'arbre, ce qu'une liste de pods ne peut pas montrer.

Les actions visent le **workload**, qu'on soit sur sa ligne ou sur celle d'un de ses pods : c'est
l'objet qui se scale et se redémarre. Les logs d'une ligne de workload sont l'agrégat de ceux de
ses pods, avec un en-tête par pod.

| Touche | Action |
|---|---|
| `↑` / `↓` / `PgUp` / `PgDn` | Navigation |
| `Enter` / `Tab` | Détail plein écran / changer d'onglet |
| `t` | Basculer liste plate ↔ arbre workloads → pods |
| `n` | Filtrer sur le namespace du pod sélectionné |
| `0` | Retirer le filtre namespace |
| `s` | Menu **scale** : `+1` / `-1` / `0` / définir un nombre exact de répliques |
| `r` | Menu **actions** : `rescale` / `recyclage` / `restart`, avec confirmation |
| `E` | Shell dans le pod (`kubectl exec -it`) |
| `p` / `C` / `f` | Logs : run précédent / container / suivi (onglet Logs) |
| `i` | Panneau IA |

Le menu `r` propose, avec explication et confirmation : **rescale** (rétablit le nombre de
répliques initial mémorisé), **recyclage** (scale 0 puis remonte, recrée tous les pods) et
**restart** (`rollout restart` progressif). Le menu `s` permet le scaling incrémental ou la saisie
directe d'un nombre de répliques.

### Shell dans un pod (`E`)

`E` ouvre un shell interactif dans le pod sélectionné, depuis la vue évènements comme depuis la
vue workloads. Sur une ligne de workload, kdt descend dans le **premier pod** qu'il possède ; le
container est celui sur lequel l'onglet Logs est réglé (`C`), pour que les deux touches parlent du
même container.

kdt n'implémente pas le protocole exec : il **rend le terminal à `kubectl exec -it`**, exactement
comme `e` le rend à `$EDITOR`, et le reprend quand le shell se termine. Un TUI ne peut pas
multiplexer un PTY dans un panneau sans devenir un émulateur de terminal, et `kubectl` sait déjà
négocier l'upgrade, la taille de fenêtre et le TTY.

C'est la seule fonction de kdt qui a besoin d'un binaire à côté de lui : son absence est dite
**avant** de rendre l'écran (`shell : kubectl introuvable dans le PATH`), pas après un aller-retour
sur un écran noir. Un pod qui n'est pas `Running` est refusé de la même façon, avec son état.

| Variable | Effet |
|---|---|
| `KDT_KUBECTL` | Binaire à utiliser (défaut : `kubectl`, cherché dans le `PATH`) |
| `KDT_EXEC_SHELL` | Commande passée à `sh -c` dans le container (défaut : `bash` s'il existe, sinon `sh`) |

Le `--context` passé à kdt est repassé à `kubectl`, pour que le shell atterrisse dans le cluster
affiché et non dans celui que le kubeconfig désigne à cet instant.

> Le repli par défaut est `command -v bash >/dev/null 2>&1 && exec bash || exec sh` : un `exec`
> qui échoue **tue** le shell au lieu de passer à la suite, donc le choix se fait avant l'exec, pas
> après.

### Vulnérabilités (`:vuln`)

Vue de la surface d'attaque connue du cluster. Le **scan d'images** repose sur **Trivy Operator** ;
s'il n'est pas installé, la vue bascule en **repli léger** n'affichant que le risque sur la version
de Kubernetes (qui ne dépend que de la version serveur et du feed officiel).

- **Images** (Trivy requis) : une ligne par image scannée (`VulnerabilityReport` / `ClusterVulnerabilityReport`),
  avec le namespace, le workload, le tag, le décompte CVE par sévérité (`crit/high/med/low`) et le
  nombre de CVE **corrigibles** par une mise à jour. Tri par sévérité maximale décroissante.
- **Version Kubernetes** : première ligne (magenta) — version serveur, cible de patch
  (`→ dernier patch de la mineure` si en retard, `✓` si à jour), badge `EOL` si la mineure est hors
  fenêtre de support, et les CVE récentes du **feed officiel Kubernetes**. Cette partie demande un
  accès réseau sortant et se dégrade proprement (les images restent affichées) s'il est coupé.

Le détail (`Enter`) liste chaque CVE : `SÉV  score  ID  paquet  installé → corrigé` (image) ou
`SÉV  score  ID  résumé  lien` (k8s).

> Les CVE et scores viennent de Trivy / du feed k8s ; le feed officiel n'étant pas filtré par
> version, la liste k8s montre les CVE récentes et s'appuie sur le retard de patch comme signal
> actionnable.

| Touche | Action |
|---|---|
| `↑` / `↓` / `PgUp` / `PgDn` | Navigation |
| `Enter` | Détail plein écran (CVE du composant) |
| `Shift-↑/↓`, `g` | Scroll du détail |
| `f` | Filtrer le seuil de sévérité (tous → HIGH+ → CRIT) |
| `F5` | Rafraîchir (auto toutes les 60 s) |
| `i` | Panneau IA (synthèse des CVE et chemin de mise à jour) |
| `Esc` | Retour |

### Nodes / Node usage
| Touche | Action |
|---|---|
| `:nodes` ou `N` | Entrer dans la vue Nodes |
| `u` | Vue usage (CPU/mémoire) |
| `s` | Changer le tri (usage) |
| `r` | Rafraîchir |
| `/` | Recherche (nom, rôles, version, alertes — `/cordoned` isole les nœuds cordonnés) |
| `o` | Menu **opérations** : `cordon` / `uncordon` / `drain` |
| `Enter` | Détail nœud plein écran |
| `i` | Panneau IA |
| `p` / `P` | Export PDF (depuis usage/diagnostic) |

#### Opérations sur un nœud (`o`)

**`cordon` / `uncordon`** passent `spec.unschedulable` et rien d'autre : un champ, réversible depuis
le même menu, sans panneau — le bandeau dit ce qui a été fait. Un nœud déjà dans l'état demandé est
répondu depuis ce qui est à l'écran, sans écriture.

**`drain`** ouvre un panneau qui ne draine rien : il relit le cluster et affiche ce qui va coincer.
Les constats sont classés par gravité, et rien ne bloque — mais un constat rouge impose de **retaper
le nom du nœud** avant de passer outre.

| Constat | Gravité | Ce qu'il dit |
|---|---|---|
| Pods sans contrôleur | ✗ | L'éviction les supprime pour de bon : rien ne les recréera ailleurs |
| PDB à 0 disruption autorisée | ✗ | L'API refusera l'éviction, le drain n'avancera pas |
| Dernier nœud ordonnançable | ✗ | Les pods évincés resteront `Pending` : il n'y a nulle part où aller |
| PDB plus étroit que le nombre de pods | ▲ | Le drain avancera au rythme des redémarrages |
| Place manquante ailleurs | ▲ | La somme des requests à déplacer dépasse ce qui reste sur les autres nœuds |
| Pod trop gros | ▲ | Aucun nœud restant ne peut le prendre à lui seul (les totaux ne suffisent pas : un pod atterrit sur **un** nœud) |
| Données `emptyDir` | ▲ | Elles partent avec le pod |
| Pods statiques | ▲ | L'API ne peut pas les évincer, ils resteront en place |
| Nœud du plan de contrôle | ▲ | — |
| Déjà cordonné / `NotReady` / pods DaemonSet | · | Contexte : le drain saute le cordon, et laisse les DaemonSets |

La place restante est comptée sur les **requests** (c'est ce que le scheduler empile), nœud par
nœud, en ne comptant que ceux qui pourraient réellement prendre un pod — ni `NotReady`, ni déjà
cordonnés. Un `PodDisruptionBudget` dont le `status` n'a pas encore été calculé ne dit rien plutôt
que de crier au loup.

Le drain lui-même cordonne d'abord (pour que rien ne revienne se poser derrière l'éviction), puis
évince, en **réessayant** les pods qu'un budget retient — le panneau devient alors le rapport
d'avancement (`n/m pods évincés`, pods retenus, échecs). Comme `kubectl drain --ignore-daemonsets`,
les pods de DaemonSet, les pods statiques et les pods terminés sont laissés en place.

> `Ctrl-O` avance dans la confirmation, `Entrée`/`Esc` annulent — la réponse par défaut est non,
> comme pour `Ctrl-D`. Ce doit être un accord de touches : l'invite stricte, elle, reçoit chaque
> caractère tapé.

### Capacité / marge de manœuvre (`:capacity`, `:quota`)

Toutes les autres vues disent l'état ; celle-ci dit **la marge**. Un seul fetch alimente trois
mondes, `g` passe de l'un à l'autre :

**noeuds** (`:capacity`) — ce que chaque nœud a de réservé (requests, ce que le scheduler empile),
de limité, et d'effectivement utilisé. La colonne qui compte est la dernière, **SI PERDU** :

| Verdict | Ce qu'il dit |
|---|---|
| `absorbé ailleurs` | Tous ses pods se replacent, avec de la marge |
| `absorbé, il ne reste rien` | Ils se replacent, et le cluster est ensuite à sec |
| `n pod(s) sans place` | Ces pods-là n'ont **nulle part** où aller — le détail les nomme, avec leur taille et la raison |
| `seul noeud` | Il n'y a pas d'ailleurs à simuler |

La simulation est un **first-fit, le plus gros pod d'abord** (placer les petits en premier est
précisément ce qui échoue à caser le gros). Elle compte les requests, décrémente la place à mesure
qu'elle place, et respecte les règles dures : taints/tolérations, `nodeSelector`, node affinity
`required`. Elle ignore les règles souples (affinité `preferred`, spread, affinité inter-pods), qui
ne peuvent que **dégrader** le résultat réel — donc « ça passe » est la borne optimiste, et c'est
le bon sens de l'erreur. Les pods de DaemonSet, les pods statiques et les pods terminés ne sont pas
replacés, comme au drain.

Trois raisons distinctes de n'avoir nulle part où aller, parce qu'elles ne se corrigent pas
pareil : **aucune place** (ajouter de la capacité), **taints** ou **sélecteur** (changer le pod —
aucun nœud supplémentaire n'y changera rien).

**workloads** (`g`) — une ligne par workload, `requests → utilisé` sur les deux axes :

- **pas de requests** : invisible au scheduler, qui le place comme s'il ne coûtait rien, et premier
  évincé quand le nœud manque. C'est aussi ce qui fausse tous les autres calculs de la vue, d'où le
  constat au niveau cluster ;
- **QoS BestEffort** : premier de la file des évictions ;
- **surdimensionné** : réserve ≥ 4× ce qu'il utilise — mais seulement au-delà d'un plancher absolu
  (200m CPU, 512Mi), sinon chaque sidecar à 50m se ferait épingler pour rien ;
- **au plafond de sa propre limite** (≥ 90%) : throttling côté CPU (avertissement), OOMKill côté
  mémoire (alerte rouge — au plafond ce n'est pas un ralentissement).

**quotas** (`:quota`) — les `ResourceQuota` triés par le compteur le plus tendu, celui qui refusera
la prochaine création. Le détail les liste tous.

| Touche | Action |
|---|---|
| `↑` / `↓` / `PgUp` / `PgDn` | Navigation |
| `Enter` | Détail plein écran |
| `Shift+↑↓` | Scroll du détail |
| `g` | Monde suivant (noeuds → workloads → quotas) |
| `f` | Ne garder que les lignes à problème |
| `/` | Recherche |
| `F5` | Rafraîchir (auto toutes les 30 s) |
| `i` | Panneau IA |

> Sans **metrics-server**, la moitié des règles n'a rien à comparer : elles se taisent au lieu de
> lire une mesure absente comme un zéro, et le bandeau le dit. Les colonnes `utilisé` affichent `—`.

### Diagnostic
| Touche | Action |
|---|---|
| `D` / `Esc` | Entrer / sortir |
| `r` | Relancer |
| `↑/↓`, `PgUp/PgDn`, `g`/`G` | Scroll |
| `i` | Panneau IA |
| `p` / `P` | Export PDF |
| `c` | Copier la vue |

### Panneau IA
| Touche | Action |
|---|---|
| `i` / `Esc` / `q` | Fermer |
| `↑/↓`, `PgUp/PgDn`, `g`/`G` | Scroll |
| `c` | Copier le contenu |
| `l` | Bascule langue |

La réponse du modèle est reçue en streaming (SSE, format OpenAI `chat/completions`) : le texte apparaît progressivement à mesure qu'il est généré, sans attendre la fin de la réponse. Relancer une analyse (`i`) pendant qu'une autre streame interrompt proprement la précédente.

## Configuration

Fichier JSON optionnel chargé depuis (par ordre de priorité) :

1. `$KDT_CONFIG` (ou `$KEV_CONFIG`)
2. `$XDG_CONFIG_HOME/kdt/config.json`
3. `~/.config/kdt/config.json`

```json
{
  "openai_base_url": "https://api.openai.com/v1",
  "openai_api_key": "sk-...",
  "openai_model": "gpt-4o",
  "language": "fr"
}
```

`language` accepte `fr`/`french`/`français` ou `en`/`english`/`anglais`.

### Plusieurs fournisseurs IA

Définir une liste `providers` permet de basculer entre plusieurs modèles/endpoints. Chaque entrée a un `name`, et optionnellement `base_url`, `api_key`, `model` (valeurs par défaut : `https://api.openai.com/v1` et `gpt-4o-mini`), et `context_window`. `active_provider` choisit le fournisseur utilisé au démarrage (sinon le premier de la liste).

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
    {
      "name": "local",
      "base_url": "http://localhost:11434/v1",
      "api_key": "ollama",
      "model": "qwen2.5-coder"
    }
  ]
}
```

En cours d'exécution, la touche `m` fait défiler les fournisseurs configurés ; le fournisseur actif est affiché dans le bandeau du panneau IA (`[FR · openai]`). Les champs `openai_*` et les variables d'environnement restent pris en charge comme fournisseur `default` (rétrocompatibilité) ; ils s'ajoutent à la liste si présents.

#### `context_window` : budget de contexte

`context_window` est la fenêtre de contexte du modèle **en tokens** (prompt + réponse). Quand il est défini, kdt borne la taille totale du prompt pour qu'elle tienne dans cette limite : il réserve ~4096 tokens pour la réponse et la marge, puis remplit le prompt par priorité (événement et status d'abord, logs, puis ressources contextuelles) et **omet les sections d'enrichissement de plus basse priorité** si le budget est atteint, en le signalant dans le prompt. Sans ce champ, seuls les plafonds par section s'appliquent (comportement historique).

La valeur n'est jamais transmise à l'API : elle ne sert qu'au rognage local. Renseigne la fenêtre **réelle** du modèle ciblé. Avec un proxy qui multiplexe plusieurs modèles (p. ex. Claude Code Router), déclare la fenêtre du **plus petit** modèle que la route peut atteindre — ou crée une entrée provider par route à fenêtre homogène —, car la limite réelle est celle du modèle final, pas celle du proxy. L'estimation chars→tokens est volontairement prudente (≈3 chars/token pour du JSON Kubernetes), donc kdt rogne légèrement tôt plutôt que de risquer un dépassement.

### Variables d'environnement

| Variable | Rôle |
|---|---|
| `OPENAI_API_KEY` | Clé API IA (sinon `openai_api_key` du config) |
| `OPENAI_BASE_URL` / `OPENAI_API_BASE` | Endpoint compatible OpenAI |
| `OPENAI_MODEL` | Modèle à utiliser |
| `OPENAI_CONTEXT_WINDOW` | Fenêtre de contexte en tokens du fournisseur `default` (budget de prompt) |
| `KDT_KUBECTL` | Binaire utilisé par le shell `E` (défaut : `kubectl`, cherché dans le `PATH`) |
| `KDT_EXEC_SHELL` | Commande passée à `sh -c` dans le container par `E` (défaut : `bash` s'il existe, sinon `sh`) |
| `KDT_CONFIG` / `KEV_CONFIG` | Chemin du fichier de config |
| `KDT_LOG` / `KEV_LOG` | Chemin du fichier de log |
| `RUST_LOG` | Filtre de logs (`warn` par défaut) |

## Sécurité / confidentialité

- **Données envoyées à l'IA** : la fonction d'analyse (`i`) et l'extraction (`X`) transmettent à l'endpoint configuré le contexte cluster courant : message de l'évènement, **logs du pod** (jusqu'à 200 lignes), status de l'objet, et ressources liées (RBAC, Ingress, PV/PVC, sources Flux/Argo, etc.). Les logs peuvent contenir des secrets. N'utilise que des endpoints de confiance. `enrich.rs` ne retire que les métadonnées de bookkeeping (`managedFields`, `uid`…), pas les données applicatives. Le payload est compacté avant envoi (JSON sans espaces, lignes répétées des logs/status fusionnées, événements liés dédupliqués) et borné par section, ainsi que globalement quand `context_window` est défini.
- **Endpoint** : un `base_url` en `http://` envoie la clé `Authorization: Bearer` et le payload en clair. Préfère `https://` (ou un endpoint local pour de l'inférence offline).
- **Clé API** : stockée en clair dans `config.json` ; restreins les permissions du fichier (`chmod 600`). La clé n'est jamais journalisée.
- **Accès cluster** : toute la navigation est en lecture seule (`get`/`list`/`watch`/`logs`). Les seules écritures sont celles qu'une touche déclenche explicitement — scale / restart / recyclage, reconcile / force / reset et suspend Flux, déblocage (`Ctrl-R` : suppression d'une configuration d'admission orphaline, ou retrait de finalizers — les deux derrière une confirmation stricte), renew cert-manager, édition (`e`, un `PUT`), suppression (`Ctrl-D`), touch (`h`, un patch de deux annotations), cordon/uncordon et drain d'un nœud (`o` : un patch de `spec.unschedulable`, puis des évictions) — et elles sont refusées par l'API si le kubeconfig n'en a pas le droit. Deux shell-out, tous deux à la demande : `$EDITOR` lancé par `e`, et `kubectl exec -it` lancé par `E` — ce dernier est la seule dépendance de kdt à un binaire externe, et son absence est dite avant que l'écran ne soit rendu.
- **Rendu PDF** : le contenu IA est échappé avant d'être évalué comme markup Typst (`convert_inline_md`), ce qui neutralise l'injection de code Typst ; les blocs de code passent par `raw()` (jamais évalué).

## Logs

Écrits dans (par ordre de priorité) :

1. `$KDT_LOG`
2. `$XDG_STATE_HOME/kdt/kdt.log`
3. `~/.local/state/kdt/kdt.log`
4. `/tmp/kdt.log`

## Packaging (RPM / DEB)

Scripts dans [packaging/](packaging/) — tout se déroule dans le répertoire du projet, sortie dans `dist/`, aucun privilège root requis.

```bash
packaging/build-deb.sh     # → dist/kdt_<version>_amd64.deb
packaging/build-rpm.sh     # → dist/x86_64/kdt-<version>-1.x86_64.rpm
packaging/build-all.sh     # les deux
```

Chaque script lance `cargo build --release`, récupère le binaire statique musl, et assemble le paquet (`/usr/bin/kdt`). Nom/version sont lus depuis `Cargo.toml`. Prérequis : `dpkg-deb` (deb), `rpmbuild` (rpm) — `rpmbuild` utilise un `_topdir` sous `dist/rpmbuild`, rien n'est écrit dans `~/rpmbuild`.

## Exports

Les rapports PDF (diagnostic et extraction complète) sont écrits dans `~/Downloads`, nommés `kdt-extract-<contexte>-<timestamp>.pdf`. Le rendu PDF est généré via Typst (`typst` / `typst-pdf` / `typst-as-lib`, polices embarquées).

### cert-manager (`:certs`)

Vue dédiée à la chaîne d'émission cert-manager, pensée pour répondre à « pourquoi ce certificat
est-il cassé / sur le point d'expirer ? » sans sortir de kdt. L'arbre part des émetteurs et descend
jusqu'au Secret réellement servi :

```
▾ ClusterIssuer letsencrypt-prod            ✓ Ready · acme
  ▾ Certificate monitoring/grafana-tls      ✗ Failed        12 j
      CertRequest grafana-tls-2             ⟳ Issuing
        Order grafana-tls-2-2891044         ⟳ pending
          Challenge …-2891044-1867          ✗ dns-01 grafana.exemple.fr
      → Secret grafana-tls                  TLS  ←1 ingress  12 j
  ▸ Certificate web/site-tls                ✓ Ready         68 j
```

Les chaînes saines sont repliées automatiquement, celles en échec ou en cours d'émission sont
dépliées : l'arbre montre d'emblée ce qui ne va pas. Un pli/dépli manuel (`Space`) est définitif,
le repli automatique ne revient jamais dessus.

Le panneau du haut affiche la chaîne complète depuis l'ancre de confiance jusqu'aux Ingress
consommateurs, quelle que soit la ligne sélectionnée, suivie de diagnostics : propagation DNS
lente, challenge http-01 non présenté, rate limit ACME, renouvellement en retard, Secret absent
ou désynchronisé du Certificate, émetteur non prêt.

| Touche | Action |
|---|---|
| `↑↓` / `PgUp` `PgDn` | Navigation |
| `Space` | Plier / déplier la chaîne |
| `t` | Bascule arbre ⇄ liste plate |
| `f` | Filtre : `ALL` → `PROBLEMS` → `IN-FLIGHT` |
| `Enter` | Plein écran sur la chaîne |
| `s` | Ouvrir le Secret produit dans la vue Secrets |
| `r` | Actions : renouveler, relancer le cycle ACME |
| `F5` | Rafraîchir |
| `Shift+↑↓` | Défilement du panneau de chaîne |

Depuis la vue Secrets, `o` fait le chemin inverse : il ouvre la chaîne cert-manager qui produit le
secret sélectionné (message explicite si le secret n'en vient pas).

**Actions (`r`)**, toutes derrière la confirmation armée du menu :

- **renouveler** — pose la condition `Issuing=True` sur le Certificate, l'équivalent de
  `cmctl renew`. La liste de conditions est relue puis réécrite complète : un merge patch remplace
  un tableau, écrire la seule condition `Issuing` effacerait `Ready`.
- **relancer ACME** — supprime la `CertificateRequest` en cours, ce qui emporte son `Order` et ses
  `Challenge` en cascade et fait repartir cert-manager sur une requête neuve. Supprimer le seul
  Challenge ne sert à rien : son Order le recrée à l'identique. L'action n'est proposée que s'il y a
  une requête en vol, et **refusée si un rate limit ACME est détecté** — relancer dans ce cas ne
  ferait que consommer le quota restant.

La vue fonctionne aussi sans cert-manager (message explicite) et sur un cluster sans le groupe
`acme.cert-manager.io` (émetteurs CA / selfSigned uniquement), signalé par `· sans ACME` dans le
bandeau.

### Kyverno (`:kyverno`)

Vue dédiée au moteur d'admission, pensée pour répondre à « qu'est-ce que Kyverno applique, à quoi,
et qu'est-ce qui casse ? » sans faire la jointure à la main. Un `PolicyReport` ne nomme sa policy et
sa règle que par une chaîne de caractères : pour savoir ce qui était vérifié il faut aller relire la
policy. Cette jointure est faite une fois pour toutes ici.

```
▾ ClusterPolicy require-limits                Enforce   ✓ Ready    Pod · ns prod      ✗9 ✓3
  ▾ validate-resources                        validate             Pod · ns prod      ✗3 ✓1
      ✗ prod/api-7f9c-x2k                     fail      Pod        medium             validation error: …
  ▾ autogen-validate-resources                validate  (autogen)  DaemonSet, Deploy  ✗6 ✓2
      ✗ prod/api                              fail      Deployment medium             validation error: …
  – polex legacy-allow                        exception            Deployment · ns …  validate-resources
▾ ValidatingPolicy no-latest-tag              Audit     ✗ NotReady compilation CEL    ×4
```

`t` bascule vers la lecture inverse — namespace → ressource → policies violées — quand la question
n'est plus « que casse cette policy ? » mais « qu'est-ce qui cloche dans ce namespace ? ». Les
policies saines sont repliées automatiquement, celles en échec sont dépliées ; un pli manuel
(`Space`) est définitif.

Trois choses que cette vue montre et qu'un `kubectl get polr` ne donne pas :

- **Les règles autogen.** Une règle qui matche des `Pod` fait générer par Kyverno des règles
  `autogen-*` pour Deployment, StatefulSet, Job, CronJob… Ce sont **elles** que les rapports
  nomment. Elles sont chargées, marquées, et les résultats leur sont rattachés — sans quoi la
  jointure échoue silencieusement sur exactement les objets qu'on regarde.
- **La différence entre `fail` et `error`.** `fail` = la ressource viole la règle ; `error` = la
  règle n'a pas pu s'évaluer (CEL invalide, contexte manquant). C'est un bug de policy, pas un
  problème de ressource : couleur distincte, tri plus haut, et une note explicite dans le détail.
- **Les refus d'admission.** Une policy `Enforce` qui bloque une création ne laisse **aucune trace
  dans les PolicyReports** : la ressource refusée n'existe pas, donc rien ne la décrit. Elle
  n'existe que sous forme d'Event. Le panneau de détail les joint depuis le tampon d'events déjà en
  mémoire, sous « refus d'admission récents ».

Le bandeau de tête du panneau de détail répond au « est-ce que ça tourne ? » : version, état des
quatre contrôleurs, et le nombre de webhooks `kyverno-resource-*` enregistrés. **Ce dernier compteur
à zéro veut dire que Kyverno n'intercepte plus rien** — tous les contrôleurs peuvent être verts
pendant qu'aucune policy n'est appliquée, et rien d'autre sur le cluster ne le dit.

| Touche | Action |
|---|---|
| `↑↓` / `PgUp` `PgDn` | Navigation |
| `Space` | Plier / déplier |
| `t` | Bascule par policy ⇄ par ressource |
| `f` | Filtre : `ALL` → `PROBLEMS` → `ENFORCE` |
| `Enter` | Plein écran sur le détail |
| `F5` | Rafraîchir |
| `Shift+↑↓` | Défilement du panneau de détail |

Les actions communes portent sur ce que désigne la ligne : `y`/`e`/`Ctrl-D` sur une ligne de policy
ou de règle visent la policy, sur une ligne de violation ils visent **la ressource fautive**. C'est
ce qui rend `h` utile ici : toucher la ressource en échec la fait retraverser l'admission, et
Kyverno la réévalue sur le champ.

La vue fonctionne sans Kyverno (message explicite), sur un cluster où il est installé mais sans
aucune policy, et sur un cluster antérieur à Kyverno 1.14 dépourvu du moteur CEL
`policies.kyverno.io` (signalé par `moteur CEL absent` dans le bandeau).

Le jeu de manifestes de `test/kyverno/` produit chacun de ces cas sur un cluster de test.

### Stockage (`:storage`, `:pv`)

Le stockage est la deuxième source d'incidents après le réseau, et `kubectl get pvc` sait dire
qu'un PVC est `Pending` sans jamais dire **pourquoi**. Cette vue répond à la deuxième question.

Deux mondes, `g` bascule de l'un à l'autre :

- **claims** (`:storage`, `:pvc`) — les `PersistentVolumeClaim`, avec le `PersistentVolume` auquel
  chacun est lié imbriqué en dessous (`t`), et les pods qui le montent ;
- **volumes** (`:pv`, `:sc`) — les `PersistentVolume` groupés sous la `StorageClass` qui les
  provisionne, celles-ci portant leur provisioner, leur `reclaimPolicy` et leur `bindingMode`.

Le panneau de détail donne les faits de l'objet puis le **diagnostic**, et termine par les constats
qui appartiennent au cluster et non à une ligne. Ce que les règles savent dire :

- un PVC `Pending` **et sa cause** : StorageClass nommée introuvable, aucune classe par défaut,
  `storageClassName: ""` (provisionnement dynamique explicitement refusé), classe en
  `WaitForFirstConsumer` qui attend un pod — ce dernier cas est un simple constat, pas une alerte —
  ou classe sans provisioner, avec alors le décompte des PV `Available` assez grands pour convenir.
  Quand le provisioner a laissé un évènement (`ProvisioningFailed`), c'est **son** message qui est
  affiché en premier : il bat toute déduction ;
- les PV `Released` : de la donnée gardée pour des PVC qui n'existent plus, dont le total est
  rappelé dans le bandeau de la table (`3.0Gi dorment en Released`) ;
- `reclaimPolicy: Delete`, rappelé **sur le PVC** — l'objet qu'on supprime — et pas seulement sur le
  PV où l'information vit ;
- un PVC lié que plus aucun pod ne monte ; un PVC `RWO` monté par plusieurs pods ;
- l'absence de StorageClass par défaut, ou la présence de deux, qui rend indéterminée la classe
  qu'obtient un PVC qui n'en nomme aucune ;
- les classes sans `allowVolumeExpansion`, où agrandir un volume impose de le recréer ;
- la `nodeAffinity` d'un PV, qui explique pourquoi un volume ne se lie que d'un côté du cluster.

`f` ne garde que les lignes qui portent un vrai problème (les constats en `·` ne comptent pas) :
sur un cluster sain la vue se vide, ce qui est la réponse attendue.

| Touche | Action |
|---|---|
| `g` | Bascule claims ↔ volumes |
| `t` | Imbrication parent/enfant |
| `f` | Filtre : tout / problèmes seulement |
| `n` / `0` | Filtrer sur le namespace de la ligne / revenir à tous |
| `Enter` | Détail plein écran |
| `Shift+↑↓` | Défilement du panneau de détail |

La vue est en lecture seule ; `y`, `e` et `Ctrl-D` restent disponibles et passent par les garde-fous
habituels, qui traitent déjà PVC et PV comme de la donnée persistante.

## Architecture (`src/`)

| Module | Rôle |
|---|---|
| `main.rs` | Bootstrap : client kube, logging, lancement TUI |
| `cli.rs` | Parsing des arguments (clap) |
| `events.rs` | Watcher d'évènements, logs (pods + controllers Flux), status, nœuds, usage |
| `flux.rs` | FluxCD : inventaire, réconciliation (dont force / reset), suspend, inventaire d'objets, arbre de dépendances |
| `repair.rs` | Déblocage : classification du message du contrôleur, sondes live, actions réparatrices |
| `pods.rs` | Workloads et pods : inventaire, scale, restart, recyclage |
| `svc.rs` | Services / Endpoints / Ingress / IngressClass |
| `rbac.rs` | Bindings RBAC scorés par sévérité |
| `vulnerabilities.rs` | CVE images (Trivy Operator) + risque version Kubernetes |
| `secrets.rs` | Secrets et certificats TLS (expiration, consommateurs) |
| `certmanager.rs` | cert-manager : chaîne Issuer → Certificate → Order → Challenge, diagnostics ACME |
| `kyverno.rs` | Kyverno : policies, règles (dont autogen), PolicyReports, exceptions, santé des contrôleurs |
| `configmaps.rs` | ConfigMaps et leur contenu |
| `storage.rs` | Stockage : PVC / PV / StorageClass et les règles de diagnostic associées |
| `yaml.rs` | Manifeste YAML d'un objet (formes brute et *neat*) |
| `edit.rs` | Édition d'un objet via `$EDITOR` : garde-fous, diff, écriture |
| `delete.rs` | Suppression d'un objet : garde-fous et exécution |
| `touch.rs` | Touch d'un objet : annotation horodatée pour relancer l'admission |
| `ui.rs` | TUI ratatui : modes, rendu, gestion clavier |
| `diagnostic.rs` | Étapes de diagnostic cluster |
| `extract.rs` | Extraction complète → rapport |
| `enrich.rs` | Récupération du contexte lié à un évènement |
| `ai.rs` | Client API compatible OpenAI |
| `pdf.rs` | Génération PDF via Typst |
| `lang.rs` | Chaînes FR/EN |
| `config.rs` | Chargement du fichier de configuration |
| `clip.rs` | Copie presse-papier OSC 52 |

## Stack

Rust 2021 · `kube` 3.1 (rustls, socks5) · `k8s-openapi` 0.27 · `ratatui` 0.30 · `tokio` · `reqwest` · `typst` 0.14.

## Licence

Distribué sous licence [Apache 2.0](LICENSE).
