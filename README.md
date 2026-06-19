# kdt — Kubernetes Diagnostic Tools

TUI Rust pour surveiller les évènements Kubernetes en temps réel, inspecter les nœuds, lancer un diagnostic complet du cluster, exporter des rapports PDF et obtenir une analyse assistée par IA.

## Fonctionnalités

- **Flux d'évènements live** : watch des `Event` Kubernetes avec filtrage All / Warnings / Errors et mise en évidence des `reason` critiques.
- **Vue détail** : logs du pod concerné, status de l'objet, et ressources liées (onglets Logs / Status / Related).
- **Vue Nodes** : liste des nœuds, détail plein écran, et vue d'usage (CPU/mémoire requests, tri configurable).
- **Diagnostic cluster** : batterie de vérifications (version, namespaces système, kube-system, CoreDNS, CNI, webhooks, Rancher, pods en erreur, PV, évènements warning récents…).
- **Extraction complète** : génère un rapport PDF de l'état du cluster dans `~/Downloads`.
- **Analyse IA** : envoie le contexte courant (évènement, diagnostic, usage) à une API compatible OpenAI pour explication/recommandation, en français ou anglais.
- **Copie presse-papier** : via séquence OSC 52 (fonctionne à travers SSH/terminal compatible).

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
| `n` | Sélecteur de namespace |
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

| Commande | Alias | Action |
|---|---|---|
| `events` | `ev` | Revenir à la vue évènements |
| `namespace` | `ns` | Sélecteur de namespace |
| `nodes` | `no`, `node` | Vue Nodes |
| `flux` | `fl`, `ks`, `hr` | Vue FluxCD |
| `quit` | `q` | Quitter |

### FluxCD (`:flux`)

Vue globale de l'état Flux sur tout le cluster : `Kustomization`, `HelmRelease` et sources
(`GitRepository`, `OCIRepository`, `HelmRepository`, `HelmChart`, `Bucket`). Les ressources
en échec sont remontées en tête, puis `Unknown`, puis suspendues, puis `Ready`. Le bandeau
résume `✓ready ✗failed ?unknown ⏸suspended`.

Même logique de détail que la vue évènements : panneau à onglets **Logs / Status / Related**,
scroll, et envoi à l'IA (`i`) sur la ressource sélectionnée (utile pour analyser une
`HelmRelease` ou `Kustomization` en échec).

| Touche | Action |
|---|---|
| `↑` / `↓` / `PgUp` / `PgDn` | Navigation |
| `Tab` / `Shift-Tab` | Changer d'onglet (Logs / Status / Related) |
| `Enter` | Détail plein écran |
| `Shift-↑/↓`, `g` / `G` | Scroll du détail |
| `i` | Panneau IA |
| `r` | Rafraîchir (auto toutes les 10 s) |
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

Définir une liste `providers` permet de basculer entre plusieurs modèles/endpoints. Chaque entrée a un `name`, et optionnellement `base_url`, `api_key`, `model` (valeurs par défaut : `https://api.openai.com/v1` et `gpt-4o-mini`). `active_provider` choisit le fournisseur utilisé au démarrage (sinon le premier de la liste).

```json
{
  "language": "fr",
  "active_provider": "openai",
  "providers": [
    {
      "name": "openai",
      "base_url": "https://api.openai.com/v1",
      "api_key": "sk-...",
      "model": "gpt-4o"
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

### Variables d'environnement

| Variable | Rôle |
|---|---|
| `OPENAI_API_KEY` | Clé API IA (sinon `openai_api_key` du config) |
| `OPENAI_BASE_URL` / `OPENAI_API_BASE` | Endpoint compatible OpenAI |
| `OPENAI_MODEL` | Modèle à utiliser |
| `KDT_CONFIG` / `KEV_CONFIG` | Chemin du fichier de config |
| `KDT_LOG` / `KEV_LOG` | Chemin du fichier de log |
| `RUST_LOG` | Filtre de logs (`warn` par défaut) |

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
| `events.rs` | Watcher d'évènements, logs, status, nœuds, usage |
| `flux.rs` | Inventaire FluxCD (Kustomizations, HelmReleases, sources) |
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
