# kdt — Kubernetes Diagnostic Tools

TUI Rust pour surveiller les évènements Kubernetes en temps réel, inspecter les nœuds, lancer un diagnostic complet du cluster, exporter des rapports PDF et obtenir une analyse assistée par IA.

## Fonctionnalités

- **Flux d'évènements live** : watch des `Event` Kubernetes avec filtrage All / Warnings / Errors et mise en évidence des `reason` critiques.
- **Vue détail** : logs du pod concerné, status de l'objet, et ressources liées (onglets Logs / Status / Related).
- **Vue Nodes** : liste des nœuds, détail plein écran, et vue d'usage (CPU/mémoire requests, tri configurable).
- **Diagnostic cluster** : batterie de vérifications (version, namespaces système, kube-system, CoreDNS, CNI, webhooks, Rancher, pods en erreur, PV, évènements warning récents…).
- **Extraction complète** : génère un rapport PDF de l'état du cluster dans `~/Downloads`.
- **Analyse IA** : envoie le contexte courant (évènement, diagnostic, usage) à une API compatible OpenAI pour explication/recommandation, en français ou anglais.
- **FluxCD** : inventaire cluster-wide, réconciliation (ressource / + source / sync racine), suspend-reprise, logs des controllers (filtrés ou agrégés), inventaire d'objets appliqués et vue arborescente des dépendances.
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
| `Shift-↑/↓`, `Ctrl-U/D` | Scroll du détail |
| `g` / `G` | Haut / bas du détail |
| `a` / `w` / `e` | Filtre All / Warnings / Errors |
| `:` | Palette de commandes (style k9s) |
| `n` | Filtrer sur le namespace de l'évènement sélectionné |
| `0` | Retirer le filtre namespace (tous namespaces confondus) |
| `N` | Nodes du pod sélectionné |
| `D` | Diagnostic cluster |
| `X` | Extraction complète (PDF) |
| `i` | Panneau IA |
| `l` | Bascule langue IA (FR/EN) |
| `m` | Fournisseur IA suivant |
| `←` / `→` / `Home` | Scroll horizontal |
| `q` / `Ctrl-C` | Quitter |

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
- **Accès cluster** : toutes les requêtes Kubernetes sont en lecture seule (`get`/`list`/`watch`/`logs`) ; aucune mutation, aucun shell-out.
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

## Architecture (`src/`)

| Module | Rôle |
|---|---|
| `main.rs` | Bootstrap : client kube, logging, lancement TUI |
| `cli.rs` | Parsing des arguments (clap) |
| `events.rs` | Watcher d'évènements, logs (pods + controllers Flux), status, nœuds, usage |
| `flux.rs` | FluxCD : inventaire, réconciliation, suspend, inventaire d'objets, arbre de dépendances |
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
