# kdt — Kubernetes Diagnostic Tools

TUI Rust pour surveiller les évènements Kubernetes en temps réel, inspecter les nœuds, lancer un diagnostic complet du cluster, exporter des rapports PDF et obtenir une analyse assistée par IA.

## Fonctionnalités

- **Flux d'évènements live** : watch des `Event` Kubernetes avec filtrage All / Warnings / Errors et mise en évidence des `reason` critiques.
- **Vue détail** : logs du pod concerné, status de l'objet, et ressources liées (onglets Logs / Status / Related).
- **Vue Nodes** : liste des nœuds, détail plein écran, et vue d'usage (CPU/mémoire requests, tri configurable).
- **Diagnostic cluster** : batterie de vérifications (version, namespaces système, kube-system, CoreDNS, CNI, webhooks, Rancher, pods en erreur, PV, évènements warning récents…).
- **Extraction complète** : génère un rapport PDF de l'état du cluster dans `~/Downloads`.
- **Analyse IA** : envoie le contexte courant (évènement, diagnostic, usage) à une API compatible OpenAI pour explication/recommandation, en français ou anglais. La réponse est **streamée** (SSE) et s'affiche au fil de l'eau.
- **FluxCD** : inventaire cluster-wide, réconciliation (ressource / + source / sync racine), suspend-reprise, logs des controllers (filtrés ou agrégés), inventaire d'objets appliqués et vue arborescente des dépendances.
- **Vulnérabilités** : liste les images scannées (CVE + score CVSS, nombre de correctifs disponibles) à partir des `VulnerabilityReport` de Trivy Operator, et le risque sur la version de Kubernetes elle-même (CVE du feed officiel + dernier patch de la mineure comme cible). Le scan d'images requiert Trivy Operator ; sans lui, la vue se replie sur les seules infos de version k8s.
- **YAML de l'objet (`y`)** : depuis n'importe quelle vue, le manifeste de l'objet sélectionné, en brut (`kubectl get -o yaml`) ou en **neat** — sans les attributs de run (`managedFields`, `status`, `resourceVersion`, valeurs par défaut des pod specs…).
- **Édition avec garde-fous (`e`)** : l'objet part dans `$EDITOR` (vim &co.) puis revient par un `PUT` verrouillé sur son `resourceVersion`. Avant, kdt dit ce qui rendra l'édition vaine — objet GitOps réécrit au prochain reconcile, spec tenue par un contrôleur, `can-i update` refusé ; après, il classe chaque champ modifié entre *appliqué*, *ignoré* et *rejeté par l'API*.
- **Suppression avec garde-fous (`Ctrl-D`)** : relit l'objet avant tout, avertit s'il est déployé par un moteur GitOps (Flux, Argo CD, Helm) ou si la suppression cascade (namespace, CRD, point d'entrée GitOps) ; l'avertissement se passe outre, mais en retapant le nom de l'objet.
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
| `n` | Filtrer sur le namespace de l'évènement sélectionné |
| `0` | Retirer le filtre namespace (tous namespaces confondus) |
| `N` | Nodes du pod sélectionné |
| `y` | YAML de l'objet sélectionné |
| `e` | Éditer l'objet sélectionné dans `$EDITOR` (avec garde-fous) |
| `h` | Toucher l'objet sélectionné (annotation horodatée, sans confirmation) |
| `Ctrl-D` | Supprimer l'objet sélectionné (avec garde-fous) |
| `D` | Diagnostic cluster |
| `X` | Extraction complète (PDF) |
| `i` | Panneau IA |
| `l` | Bascule langue IA (FR/EN) |
| `m` | Fournisseur IA suivant |
| `←` / `→` / `Home` | Scroll horizontal |
| `q` / `Ctrl-C` | Quitter |

### YAML de l'objet (`y`)

Disponible depuis **toutes les vues** (évènements, nodes, workloads, flux, services/ingress,
RBAC, secrets, configmaps) : `y` ouvre le manifeste de l'objet sous le curseur, récupéré en
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
| `c` | Copier le YAML affiché |
| `↑/↓`, `PgUp/PgDn`, `g`/`G` | Scroll |
| `←` / `→` / `Home` | Scroll horizontal |
| `r` / `F5` | Recharger l'objet |
| `Esc` / `q` | Fermer |

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

`events`, `namespace` et `pods` acceptent un **nom de namespace** en argument
(`:ns kube-system`, `:pods istio-system`, `:events monitoring`) avec autocomplétion (`Tab`).
`all` (ou `*`/`0`) cible tous les namespaces.

| Commande | Alias | Action |
|---|---|---|
| `events [ns]` | `ev` | Vue évènements (optionnellement filtrée sur `ns`) |
| `namespace [ns]` | `ns` | Sélecteur de namespace (ou bascule directe sur `ns`) |
| `pods [ns]` | `po`, `pod` | Vue Pods (optionnellement filtrée sur `ns`) |
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
binaire `flux`) ; le suspend/reprise bascule `spec.suspend` (non destructif).

| Touche | Action |
|---|---|
| `↑` / `↓` / `PgUp` / `PgDn` | Navigation |
| `Tab` / `Shift-Tab` | Changer d'onglet (Logs / Status / Related / Inventory) |
| `Enter` | Détail plein écran (en mode arbre : plier/déplier le nœud) |
| `Shift-↑/↓`, `g` / `G` | Scroll du détail |
| `r` | Menu de réconciliation : ressource / **+source** (`--with-source`) / sync racine (`GitRepository/flux-system`), avec confirmation |
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

#### Logs Flux (`L` ou `:flux-logs`)

Vue plein écran agrégeant les logs de tous les controllers de `flux-system` (suivi ~3 s),
triés par horodatage. `Esc` pour revenir.

### Pods (`:pods`)

Liste des pods du namespace courant ; `o` bascule sur l'**objet d'origine** (workload propriétaire)
pour le piloter, `Esc`/`o` revient à la liste.

| Touche | Action |
|---|---|
| `↑` / `↓` / `PgUp` / `PgDn` | Navigation |
| `Enter` / `Tab` | Détail plein écran / changer d'onglet |
| `o` | Basculer sur l'objet d'origine (workload) |
| `n` | Filtrer sur le namespace du pod sélectionné |
| `0` | Retirer le filtre namespace |
| `s` | Menu **scale** : `+1` / `-1` / `0` / définir un nombre exact de répliques |
| `r` | Menu **actions** : `rescale` / `recyclage` / `restart`, avec confirmation |
| `i` | Panneau IA |

Le menu `r` (sur l'objet d'origine) propose, avec explication et confirmation :
**rescale** (rétablit le nombre de répliques initial mémorisé), **recyclage** (scale 0 puis remonte,
recrée tous les pods) et **restart** (`rollout restart` progressif). Le menu `s` permet le scaling
incrémental ou la saisie directe d'un nombre de répliques.

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
| `Enter` | Détail nœud plein écran |
| `i` | Panneau IA |
| `p` / `P` | Export PDF (depuis usage/diagnostic) |

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
| `KDT_CONFIG` / `KEV_CONFIG` | Chemin du fichier de config |
| `KDT_LOG` / `KEV_LOG` | Chemin du fichier de log |
| `RUST_LOG` | Filtre de logs (`warn` par défaut) |

## Sécurité / confidentialité

- **Données envoyées à l'IA** : la fonction d'analyse (`i`) et l'extraction (`X`) transmettent à l'endpoint configuré le contexte cluster courant : message de l'évènement, **logs du pod** (jusqu'à 200 lignes), status de l'objet, et ressources liées (RBAC, Ingress, PV/PVC, sources Flux/Argo, etc.). Les logs peuvent contenir des secrets. N'utilise que des endpoints de confiance. `enrich.rs` ne retire que les métadonnées de bookkeeping (`managedFields`, `uid`…), pas les données applicatives. Le payload est compacté avant envoi (JSON sans espaces, lignes répétées des logs/status fusionnées, événements liés dédupliqués) et borné par section, ainsi que globalement quand `context_window` est défini.
- **Endpoint** : un `base_url` en `http://` envoie la clé `Authorization: Bearer` et le payload en clair. Préfère `https://` (ou un endpoint local pour de l'inférence offline).
- **Clé API** : stockée en clair dans `config.json` ; restreins les permissions du fichier (`chmod 600`). La clé n'est jamais journalisée.
- **Accès cluster** : toute la navigation est en lecture seule (`get`/`list`/`watch`/`logs`). Les seules écritures sont celles qu'une touche déclenche explicitement — scale / restart / recyclage, reconcile et suspend Flux, renew cert-manager, édition (`e`, un `PUT`), suppression (`Ctrl-D`), touch (`h`, un patch de deux annotations) — et elles sont refusées par l'API si le kubeconfig n'en a pas le droit. Un seul shell-out : `$EDITOR`, lancé par `e`.
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

## Architecture (`src/`)

| Module | Rôle |
|---|---|
| `main.rs` | Bootstrap : client kube, logging, lancement TUI |
| `cli.rs` | Parsing des arguments (clap) |
| `events.rs` | Watcher d'évènements, logs (pods + controllers Flux), status, nœuds, usage |
| `flux.rs` | FluxCD : inventaire, réconciliation, suspend, inventaire d'objets, arbre de dépendances |
| `pods.rs` | Workloads et pods : inventaire, scale, restart, recyclage |
| `svc.rs` | Services / Endpoints / Ingress / IngressClass |
| `rbac.rs` | Bindings RBAC scorés par sévérité |
| `vulnerabilities.rs` | CVE images (Trivy Operator) + risque version Kubernetes |
| `secrets.rs` | Secrets et certificats TLS (expiration, consommateurs) |
| `certmanager.rs` | cert-manager : chaîne Issuer → Certificate → Order → Challenge, diagnostics ACME |
| `kyverno.rs` | Kyverno : policies, règles (dont autogen), PolicyReports, exceptions, santé des contrôleurs |
| `configmaps.rs` | ConfigMaps et leur contenu |
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
