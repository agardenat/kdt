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

### Vue live
| Touche | Action |
|---|---|
| `a` / `w` / `e` | Filtre All / Warnings / Errors |
| `n` | Sélecteur de namespace |
| `s` | Mode sélection |
| `N` | Vue Nodes |
| `D` | Diagnostic cluster |
| `X` | Extraction complète (PDF) |
| `l` | Bascule langue IA (FR/EN) |
| `←` / `→` / `Home` | Scroll horizontal |
| `q` / `Ctrl-C` | Quitter |

### Mode sélection / détail
| Touche | Action |
|---|---|
| `↑` / `↓` / `PgUp` / `PgDn` | Navigation |
| `Enter` | Détail plein écran |
| `Tab` / `Shift-Tab` | Changer d'onglet (Logs / Status / Related) |
| `Shift-↑/↓`, `Ctrl-U/D` | Scroll du détail |
| `g` / `G` | Haut / bas |
| `N` | Nodes du pod sélectionné |
| `i` | Panneau IA |
| `s` / `Esc` | Quitter le mode |

### Nodes / Node usage
| Touche | Action |
|---|---|
| `N` | Entrer / sortir de la vue Nodes |
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

## Exports

Les rapports PDF (diagnostic et extraction complète) sont écrits dans `~/Downloads`, nommés `kdt-extract-<contexte>-<timestamp>.pdf`. Le rendu PDF est généré via Typst (`typst` / `typst-pdf` / `typst-as-lib`, polices embarquées).

## Architecture (`src/`)

| Module | Rôle |
|---|---|
| `main.rs` | Bootstrap : client kube, logging, lancement TUI |
| `cli.rs` | Parsing des arguments (clap) |
| `events.rs` | Watcher d'évènements, logs, status, nœuds, usage |
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
