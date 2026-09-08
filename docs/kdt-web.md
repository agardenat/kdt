# kdt-web — une interface web pour kdt, adossée à kdt-identity

Note d'architecture. Ce qui est constaté est daté et vérifiable dans les deux dépôts ; ce qui
reste à trancher est dit comme tel. Aucun code n'existe encore.

État au 2026-09-06 : l'interface est arrêtée (§4), rien d'autre n'est commencé.

## 1. Le problème, et pourquoi il se résout maintenant

kdt suppose un kubeconfig sur le poste. Un navigateur n'en a pas, et c'est le seul vrai obstacle
à une interface web : tout le reste — les vues, les règles, les verdicts — existe déjà.

Un dashboard résout habituellement ce problème par un service account partagé, puis réimplémente
par-dessus une notion de « qui a le droit de voir quoi » qui n'a plus rien à voir avec le RBAC du
cluster. kdt-identity permet de ne pas en passer par là.

Depuis sa 1.0, kdt-identity expose un contrat HTTP machine-à-machine dont le plugin `kubectl` est
le premier client. kdt-web en serait le second :

| Route | Entrée | Sortie |
|---|---|---|
| `POST /api/v1/session` | `user` + `password` + `totp`, **ou** `user` + `refreshToken` | `token` (quelques secondes), `subject` (`kdt:alice`), `groups`, `mode`, et un `refreshToken` de 7 j à la seule authentification par mot de passe |
| `POST /api/v1/credentials` | `token` + CSR PEM | certificat PEM + `expiresAt` (10 min) |
| `POST /api/v1/token` | `token` | `idToken` + `expiresAt` (5 min), mode OIDC seulement |
| `POST /api/v1/revoke` | `user` + `refreshToken` | ferme la session |

Les types sont dans `kdt-identity-api` (`crates/api/src/portal.rs`), qui compile **sans la feature
`crd`** — ni `kube` ni `k8s-openapi` — et fournit `csr::generate(&Subject, &[Subject])`. Le
couplage entre les deux produits est donc une dépendance de crate à épingler par tag, pas une
image commune ni un protocole à réinventer. `crates/cli/src/main.rs` est l'implémentation de
référence du flux.

Le montage : session web → credential utilisateur court → `kube::Config` (certificat client et
clé, ou jeton bearer en mode OIDC) → `connect::build(config)`, déjà écrit dans `src/connect.rs` →
**un `kube::Client` par session**. `kube::Client` est `Clone`, et tous les `fetch_*` de kdt le
prennent en argument : rien à changer dans les modules métier.

Trois conséquences :

- **Le RBAC du cluster s'applique nativement.** Identité `kdt:<user>`, groupes `kdt:<group>` :
  aucune impersonation, aucun service account partagé, aucune autorisation à réimplémenter. Le
  service account du pod kdt-web n'a besoin d'aucun droit sur les ressources.
- **La révocation couvre l'interface web.** `kdt-identity-server revoke` et `spec.disabled`
  coupent le renouvellement : l'accès web s'arrête au renouvellement suivant, soit 10 min au plus
  en mode certificat et 5 min en OIDC.
- **Le portail devient une dépendance de disponibilité** de kdt-web, comme il l'est déjà des
  postes de travail. Deux répliques au moins, et un accès de secours qui ne dépende pas de
  kdt-identity.

## 2. Ce qui manque à kdt-identity : un flow d'autorisation

Les routes du portail sont `/`, `/activate`, `/login`, `/logout`, `/kubeconfig`, les quatre
`/api/v1/*` et la découverte OIDC (`crates/server/src/web/mod.rs:96-118`). Il n'y a **ni
`/authorize`, ni PKCE, ni échange de code** : le mode « OIDC » désigne l'émission de jetons que
l'apiserver valide, pas un fournisseur d'autorisation pour applications tierces.

Tel quel, kdt-web devrait donc collecter lui-même le mot de passe et le code TOTP pour les relayer
sur `/api/v1/session`. C'est un second endroit qui voit les mots de passe du cluster, et cela
contredit la logique du portail — qui ne journalise rien de sensible et ne distingue même pas
« compte inconnu » de « mot de passe faux ».

**La voie retenue** : ajouter un flow d'autorisation à kdt-identity. `GET /authorize` s'appuie sur
le cookie `kdt_identity_session` (12 h) qui existe déjà, rend un code à usage unique, échangé
ensuite avec PKCE contre un `refreshToken` de portée restreinte. Le mot de passe ne quitte jamais
le portail. Le chantier est délimité : `crates/server/src/web/mod.rs`, `web/signer.rs` — dont les
jetons signés à usage typé (`purpose::SESSION` / `CSRF` / `API_CREDENTIAL`) sont exactement le
mécanisme nécessaire — et un type de plus dans `portal.rs`.

Le relais direct reste acceptable pour un essai sur cluster de test. Il ne se déploie pas.

### Le point d'entrée depuis le portail

La page `/` du portail rend `views::Account { user, subject, groups, cluster, csrf, error, mode,
portal_url, download }`. Y ajouter un `web_url: Option<&str>` est une modification de quelques
lignes, et le dépôt a le précédent exact : `download` n'apparaît que s'il est ouvert, avec son
test (`le_telechargement_n_apparait_que_s_il_est_ouvert`). La CSP du portail
(`default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'`) n'interdit
pas un lien sortant.

**kdt-web reste une installation facultative, et le lien doit le refléter :**

- La valeur est explicite — `webUrl` dans les valeurs du chart, `KDT_IDENTITY_WEB_URL` dans
  l'environnement, lue par `ServerConfig` — et **jamais une détection**. Vide par défaut : aucun
  lien, aucune mention. Un lien affiché parce qu'un Service existe serait une supposition, et le
  portail est précisément le composant qui ne suppose rien.
- Le chart de kdt-identity ne déploie jamais kdt-web, et rien dans le portail ne l'appelle : pas
  de sonde, pas de dépendance de démarrage. Un kdt-web éteint n'a aucun effet observable sur le
  portail.
- Une fois le flow d'autorisation en place, ce lien cesse d'être décoratif : il ouvre kdt-web
  depuis une session déjà authentifiée, sans seconde saisie. C'est la seule bonne raison de
  l'ajouter — un simple `href` peut attendre.

## 3. Ce que kdt-web détient, et comment le tenir

- Le `refreshToken` (7 j) est le secret de longue durée. Il ne touche **ni le disque ni un
  `Secret`** : en mémoire du processus, perdu au redémarrage — on se reconnecte. Le cookie de
  session est `Secure`, `HttpOnly`, `SameSite=Strict` et signé. Variante possible : chiffrer le
  refresh avec une clé portée par le cookie, pour que le serveur seul ne puisse pas le déchiffrer.
- **Le mode OIDC convient mieux au web.** On n'y manipule que des jetons de 5 min, là où le mode
  certificat obligerait kdt-web à générer la clé privée de l'utilisateur — ce que kdt-identity ne
  fait que pour le kubeconfig téléchargeable, et qu'il documente comme le chemin le moins bon
  (`crates/api/src/csr.rs:31-40`). Mais `credentialMode` est une propriété du cluster, pas un
  choix de kdt-web : AKS ne prend pas d'émetteur OIDC tiers, EKS ne signe pas de certificat
  client. Les deux modes doivent fonctionner.
- kdt-web n'est **pas** équivalent cluster-admin, contrairement à kdt-identity qui approuve des
  CSR. Sa dangerosité vient uniquement des credentials qu'on lui confie. Il se déploie tout de
  même en namespace dédié avec NetworkPolicy — et **pas** dans kdt-identity : mélanger une
  interface riche avec le composant qui signe les identités serait le seul vrai contresens de
  sécurité du projet.

## 4. L'interface

Arrêtée sur maquette le 2026-09-06. Front en React + Vite + TypeScript, dans `web/`.

```
┌───────────────────────────────────────────────────────────────┐
│  [ns: kube-system ▾ +2]   / filtre…              kdt:alice    │  barre persistante
├──────┬────────────────────────────────────────────────────────┤
│ work │ Backups │ Schedules │ Restores │ … │   drawer détail →  │  onglets = « mondes »
│ flux │────────────────────────────────────┤   ┌──────────────┐ │
│ argo │ NAME       STATUS     ITEMS   AGE  │   │ daily-02     │ │
│ velo │ daily-01   ✓ Done     1 284   2h   │   │ Phase …      │ │
│ rbac │ daily-02   ! Partial    903   1d   │   │ Logs Status  │ │
│ …    │                                    │   └──────────────┘ │
└──────┴────────────────────────────────────────────────────────┘
```

- **Barre supérieure persistante**, qui survit au changement de vue : sélecteur de namespace en
  **multi-sélection** (un, plusieurs, ou tout le cluster) et champ de filtre — l'équivalent du `/`
  de kdt. Le sélecteur **propose la liste** des namespaces (`GET /api/v1/namespaces`) et la
  resserre à la frappe ; la saisie libre reste la porte de sortie quand lister est refusé — ce
  droit est cluster-scoped, et beaucoup travaillent dans un namespace qu'ils nomment très bien
  sans l'avoir. Dans le TUI ce sont des modes (`n` / `0` changent la portée, `/` ouvre la recherche) ;
  ici ce sont deux contrôles toujours visibles, ce qui supprime au passage le piège du titre qui
  ment quand la portée change.
- **Le bandeau du cluster**, dans cette même barre : le nom du cluster, la version de l'apiserver,
  ses nodes prêts et la pression CPU/mémoire — la deuxième ligne du bandeau de kdt, aux mêmes
  règles. Le nom vient de `KDT_WEB_CLUSTER`, sinon du `--context` visé, sinon de l'hôte de
  l'apiserver ; l'adresse complète est sous le nom, parce que c'est elle qui rend un mauvais
  cluster évident. Ce qui n'a pas été lu n'est pas peint : sans le droit de lister les nodes il
  n'y a ni compte ni allocation, et le bandeau affiche un tiret au lieu d'un `0/0` vert.
- **Rail vertical** : les vues, toutes visibles en permanence. C'est la palette `:` rendue
  explicite.
- **Onglets horizontaux dans le panneau** : les « mondes » d'une vue, qui dans kdt se cyclent à la
  touche (`t`, `g`, `Espace`). Claims / Volumes pour storage — les deux mondes du `g` de kdt, les
  StorageClass étant les parents du second et non un troisième monde — Nodes / Workloads / Quotas
  pour capacity, Backups / Schedules / Restaurations / Locations pour velero. Le mapping est exact.
- **Drawer à droite** pour le détail d'une ligne, avec les onglets Logs / Status / Related / YAML.
  La liste reste visible, on enchaîne les sélections.
- **Les arbres passent en graphique** : arbre Flux, workloads → pods → containers, chaîne
  cert-manager. Le travail est fait côté données — `build_flux_tree` rend un `Vec<FlatTreeNode>`
  avec `depth` et `last_sibling`, le TUI ne choisit que les caractères `├─` / `└─`. Les badges
  `✗n` / `↻n` sur un nœud replié sont conservés. `rbac` est un **graphe**, pas un arbre : ses
  liens sont positionnels, ne jamais trier `roles` ni `service_accounts`.
- **Sévérité encodée deux fois** : pastille colorée et liseré à gauche de la ligne, pour qu'une
  ligne à problème se repère sans être lue.

Conséquence du multi-namespace à ne pas rater : la portée devient un paramètre de requête, et
**les vues en graphe font exception** — `rbac` lit tout le cluster et ne filtre que les lignes
affichées, sous peine de produire un graphe faux.

Design : les tokens CSS du portail kdt-identity (`views.rs`) plutôt qu'une palette inventée — les
deux pages se suivent dans le même parcours. `LineColor { Plain, Ok, Warn, Err, Info, Dim }`
devient six classes CSS. Clair et sombre, avec les trois états de thème (choix explicite, choix
explicite inverse, et le cas non stampé où seul `prefers-color-scheme` tranche).

La langue se bascule comme dans le TUI, par un bouton de la barre supérieure : le chrome change
sur-le-champ, les phrases calculées suivent au refetch — voir §7.

### L'analyse par une IA, et où vit sa configuration

Le `i` de kdt est le cinquième geste générique : un bouton dans la barre d'actions, la réponse en
flux dans le panneau du haut, et l'onglet qui n'existe que tant qu'on le regarde. Le prompt est
celui du TUI — `kdt::ai::build_ai_prompt`, sorti de `ui.rs` pour l'occasion, parce qu'un second
prompt aurait donné deux réponses différentes du même cluster.

La question qui décide de tout est **où vit la clé**. Trois réponses possibles :

1. *dans le serveur, pour tout le monde* — simple, mais tout le monde partage la même clé, le même
   quota et la même trace côté fournisseur ;
2. *dans le navigateur, qui appelle l'endpoint lui-même* — la clé ne traverse rien, mais l'appel
   direct dépend du CORS du fournisseur, qu'aucun des grands n'ouvre, et le prompt doit de toute
   façon être assemblé côté serveur, seul endroit où le credential de la personne lit le cluster ;
3. *dans le navigateur, le serveur relayant* — la clé reste à la personne, le prompt reste assemblé
   là où il peut l'être.

Les deux mondes retenus sont **1 et 3**, ensemble. L'exploitant déclare ses fournisseurs dans
`KDT_WEB_AI_PROVIDERS` — même forme que le tableau `providers` du fichier de configuration de kdt,
littéralement le même type — et leurs clés ne sortent jamais du pod : le navigateur n'en apprend que
le nom, le modèle et l'hôte joint. Chacun peut par ailleurs déclarer le sien depuis le réglage de
l'interface ; il vit dans le `localStorage` et accompagne la requête.

Ce troisième monde a un prix, qu'on nomme plutôt que de le découvrir : un endpoint choisi par un
navigateur fait émettre une requête sortante **au pod**, ce qui est la définition d'une SSRF.
`https` exigé, adresses de bouclage, privées et de lien-local refusées — ce qui écarte au passage le
service de métadonnées du cloud. Un **nom** qui résout vers l'intérieur passerait : le vérifier
demanderait de résoudre soi-même puis de garantir qu'on joint la même adresse, ce que la pile HTTP
ne permet pas. `KDT_WEB_AI_ALLOW_CUSTOM=false` retire ce risque et ne laisse que les fournisseurs du
déploiement.

Reste à trancher, plus tard : une palette de commandes (⌘K) reprenant la grammaire `:`, et le sort
de la grammaire clavier en général.

## 5. Ce qui se porte de kdt, et ce qui ne se porte pas

`ratatui` et `crossterm` n'apparaissent que dans **4 fichiers sur 44** — `ui.rs`, `splash.rs`,
`glyphs.rs`, `exec.rs` — soit 33 523 lignes couplées au terminal contre 45 033 portables. Les 22
modules métier n'en contiennent aucune occurrence.

Deux consommateurs non-terminal du même état métier existent déjà : `pdf.rs` (1 032 lignes, ses
propres DTO `Report` / `DiagDoc` / `NodeSection`) et `format_diagnostic_for_ai()`. Ce qui les rend
possibles est `LineColor` (`events.rs:476`), abstraction de couleur neutre. Un troisième
consommateur n'est pas un pari.

| | Lignes | Sort |
|---|---|---|
| `ui.rs` — rendu (l. 14192-33142) | ~19 000 | ne se porte pas : la SPA le réécrit |
| `ui.rs` — `impl App` + `handle_event` (l. 2068-14191) | ~12 000 | zéro ratatui mais forme TUI ; à extraire en modèle, réutilisable en partie |
| modules métier (velero, rancher, k8ssandra, kyverno, diagnostic, argocd, reflector, identity, rbac, certmanager, events, flux, capacity, pods, nodeops, storage, netpol, repair, secrets…) | ~39 000 | `kdt-core`, quasi tels quels |
| `lang.rs` | 5 904 | `kdt-core`, mais la langue devient une propriété de la session HTTP et non plus du process (`lang::active()` est à revoir) |
| `pdf.rs` / `extract.rs` | 1 561 | se portent : le PDF devient un téléchargement |
| `exec.rs` (shell-out `kubectl exec -it`) | 139 | ne se porte pas — mais l'exec natif par websocket existe déjà (`identity.rs:1263`, `pods.exec` + `AttachParams`) : c'est la base d'un terminal xterm.js |
| `edit.rs` (shell-out `$EDITOR`) | 749 | la moitié se porte (`preflight`, `apply`, `parse`) ; le shell-out devient un éditeur web |
| `portfwd.rs` | 475 | n'a aucun sens depuis un serveur : hors périmètre |
| `clip.rs`, `splash.rs`, `glyphs.rs` | 400 | propres au terminal |

Le vrai chantier est la zone grise : `impl App` (10 734 lignes) et `handle_event` (1 184 lignes)
ne contiennent aucune ligne de ratatui, mais sont de forme TUI — index de curseur, alignement par
index entre `snapshot` et `*_rows`, « mondes » cyclés par une touche, 721 occurrences de
`KeyCode`. Ni à jeter ni à réutiliser tel quel : à extraire en modèle. **Ce n'est pas un préalable
bloquant** — c'est une amélioration autonome de `ui.rs`, qui peut se faire avant, après, ou jamais.

Les `fetch_*` n'ont pas de valeur de retour : elles écrivent dans un `Arc<Mutex<XxxState>>` défini
dans le module métier. Ce n'est pas un obstacle — `diagnostic.rs` montre déjà le chemin qu'un
handler HTTP suivrait : créer un état éphémère (`new_storage_state()`, jamais l'état partagé d'une
vue), `await` le `fetch_*`, lire le `Mutex`, agréger. La scission en
`load_x(&Client) -> Result<XState>` plus un mince wrapper pour le TUI reste souhaitable — une
quarantaine de fonctions, mécanique — mais c'est une propreté, pas un prérequis.

Les 21 tickers d'auto-refresh (de 3 s pour les logs Flux à 60 s pour rancher et identity,
`MissedTickBehavior::Skip`) deviennent des tâches serveur qui poussent des deltas. Leur cadence
est déjà calibrée sur le coût réel de chaque fetch : elle se reprend telle quelle.

## 6. Découpage en workspace

```
kdt/
  Cargo.toml                [workspace] members = ["crates/core", "crates/tui", "crates/web"]
  crates/core/              modules métier + lang.rs + connect.rs + yaml.rs (dynamic_api)
  crates/tui/               ui.rs, exec.rs, splash.rs, glyphs.rs, main.rs, cli.rs, config.rs → bin kdt
  crates/web/               axum, sessions, client kube par session, API JSON → bin kdt-web
  web/                      front React + Vite + TypeScript
```

Pièges qui cassent la chaîne de livraison existante :

- `packaging/common.sh` lit `NAME` et `VERSION` par `sed` sur le `Cargo.toml` racine. En
  workspace, `^version =` reste matché sous `[workspace.package]`, mais **`^name =` n'existe
  plus** : `NAME` devient vide et `build_binary` échoue. C'est `NAME` le piège, pas la version.
- Au même endroit, `build_binary` fait `cargo build --release` sans `-p` : il construirait aussi
  kdt-web. Il faut `-p kdt`.
- `.cargo/config.toml` force `x86_64-unknown-linux-musl` avec `crt-static` — c'est la cible que
  les paquets embarquent, et la raison d'être du resolver IPv4-first de `connect.rs`.
- `clippy` est à zéro warning depuis la v1.4.0 : l'extraction doit le rester.

## 7. L'API

Une route par vue, miroir des `fetch_*` : `GET /api/v1/{diagnostic,flux,velero,capacity,storage,
certs,rbac,kyverno,argocd,identity,k8ssandra,netpol,…}`, rendant le `XxxState` sérialisé. **Les
verdicts, sévérités et abstentions restent calculés côté serveur** : c'est la valeur de kdt, pas
la couleur du texte. Le flux d'évènements (`events::spawn_watcher`), les logs et le `follow`
passent en SSE ; l'exec en websocket.

Quatre frictions, qui se paient à l'entrée :

1. **Aucun `#[derive(Serialize)]`** sur les types du domaine, nulle part. Ajout mécanique, sur
   toute la surface.
2. **L'i18n est résolue au calcul, pas au rendu** : `Hint.text` est une `String` déjà traduite,
   `DiagnosticStep.lines` un `Vec<(LineColor, String)>` de phrases faites. La SPA reçoit donc des
   phrases, pas des clés — et **c'est déjà le fonctionnement du TUI** : `toggle_language()`
   (`ui.rs:3985`) pose la langue, l'écrit dans la config, puis appelle `refresh_current_view()`.
   La bascule a toujours coûté un refetch.

   Le web reprend le même mécanisme, en un peu mieux : le chrome — rail, onglets, en-têtes de
   colonnes, boutons — vit dans la SPA et bascule instantanément, sans aller-retour ; seules les
   phrases calculées repassent par le serveur, avec la langue en propriété de la session
   (`Accept-Language`, `st: &'static Strings` passé aux fonctions de règles comme aujourd'hui).
   La seule différence avec le TUI est la latence réseau du refetch.

   Ce qui reste vrai : passer les `Hint` en `(clé, params)` pour traduire côté client refait la
   signature de toutes les règles et de leurs tests. Ça ne vaut pas ce prix, puisque le refetch
   suffit.
3. **Trois `Hint` / `HintLevel` dupliqués** (`storage.rs:43`, `certmanager.rs:847`,
   `velero.rs:39`) et deux `Severity` (`rbac.rs:57`, `events.rs:25`) : à unifier **avant**
   d'exposer une API, sans quoi la duplication se fige dans le contrat JSON.
4. `diagnostic.rs` produit des lignes de texte, pas des données structurées : une API qui les sert
   telles quelles interdit tout tri ou filtre côté client. À trancher au moment de la vue
   diagnostic, pas avant.

Les écritures (`apply_identity_write`, `apply_rancher_write`, `apply_argo_write`,
`apply_k8c_write`, `apply_write` velero, `run_scale`, `run_drain`, `set_cordon`, `run_touch`,
`run_delete`, `edit::apply`, `repair::apply`) sont déjà découplées et prennent un `Client` : elles
deviennent des POST sans réécriture. Les garde-fous — préflights, constats ⛔, confirmations
armées, saisie du nom exact — sont côté données et se portent. C'est leur présentation qui est à
refaire, et **la règle « la réponse par défaut est non » doit survivre au changement de média**.

## 8. Distribution, déploiement, versionnage

Constaté : les deux dépôts GitHub sont publics, et `ghcr.io/agardenat/kdt-identity` est tirable
anonymement. C'est pourquoi `deploy/helm/kdt-identity` n'a aucun `imagePullSecrets`.

kdt-web : image sur **ghcr public**, déploiement par **Flux `GitRepository`** sur le dépôt kdt,
public — donc pas de `secretRef`, pas de `imagePullSecrets`.

- **GHCR crée les packages en privé au premier push.** La visibilité ne suit celle du dépôt
  qu'une fois réglée à la main ; le `LABEL org.opencontainers.image.source` du Dockerfile **lie**
  le package au dépôt, il ne le rend pas public.
- Hors GitHub Actions, un push exige un PAT **classic** avec `write:packages` : « GitHub Packages
  only supports authentication using a personal access token (classic) ». Les scopes d'un classic
  valent pour le compte, pas pour un dépôt — un même token couvre donc les deux chaînes de
  publication, et le révoquer les casse ensemble.
- En Actions, ce PAT disparaît : `permissions: packages: write` et `GITHUB_TOKEN`. Le job `image`
  de `release.yml` construit et pousse ainsi, sur le même tag `v*` que les binaires, en
  `linux/amd64` seulement — kdt tire plus de six cents crates, typst compris, et une seconde
  architecture émulée par QEMU dépasserait la limite de six heures d'un runner. Deux réserves,
  toutes deux vérifiées le 2026-09-07 sur kdt-identity : le premier push crée le package en privé,
  et `GITHUB_TOKEN` est refusé sur un package que le dépôt n'a pas le droit d'écrire —
  `denied: permission_denied: write_package`, après le build complet, puisque le push est la
  dernière étape. Un package né d'un `podman push` au PAT est dans ce cas : le label le rattache
  au dépôt, il ne lui donne aucun droit. Cela se règle une fois, dans les réglages du package,
  **Manage Actions access** → ajouter le dépôt en rôle **Write**.

**Deux images distinctes, deux charts** — `ghcr.io/agardenat/kdt-web` à côté de
`ghcr.io/agardenat/kdt-identity` :

- kdt-identity approuve des CSR `kubernetes.io/kube-apiserver-client` : il peut forger
  `O=system:masters`, et son image est `FROM scratch` sans shell ni `PATH` pour cette raison. Y
  ajouter un serveur web, ses assets et un jour un terminal websocket annulerait cette propriété.
- Les RBAC sont opposés : approbation de CSR d'un côté, aucun droit sur les ressources de l'autre.
  Une image commune, c'est un service account commun, et l'argument principal tombe.
- Le couplage réel est un crate, pas une image.
- kdt-identity met bien deux binaires dans une image, mais le plugin y est pour être **extrait**
  vers un poste, pas exécuté dans le cluster : ce n'est pas un précédent.
- Le chart de kdt-web ne déclare pas kdt-identity en dépendance Helm : il vérifie le prérequis, il
  ne l'embarque pas — même posture que `identity::install_command()`, qui affiche la commande sans
  jamais l'exécuter.

Du chart de kdt-identity, kdt-web reprend la NetworkPolicy deny-by-default (avec sa variante
Cilium), le `podSecurityContext` non-root et `readOnlyRootFilesystem`, et le refus de rendre un
ingress sans TLS — son cookie de session portera `Secure`. Il en diffère par son `rbac.yaml` : le
service account de kdt-web n'a **aucun droit sur les ressources**, et cela doit sauter aux yeux à
la lecture du chart. Si le chart engendre une clé de signature de cookie à la première
installation, le `lookup` Helm qui la relit ensuite fonctionne avec le helm-controller de Flux —
le piège qui déconnecte tout le monde à chaque synchronisation ne se pose donc pas ici.

**Version `2.0.0-beta.1`**, une seule pour tout le workspace (`[workspace.package] version`),
comme kdt-identity le fait pour ses trois crates : le dépôt n'a qu'un tag `v*` et qu'un CHANGELOG.
Le major marque la refonte du dépôt et l'arrivée d'un second binaire, **pas une rupture d'usage du
TUI** — à écrire explicitement dans le CHANGELOG. La pré-version dit l'état de kdt-web : dix vues
répondent et il se déploie, le reste n'existe pas.

`packaging/common.sh` sait épeler une pré-version : `2.0.0-beta.1` devient `2.0.0~beta.1` côté
dpkg (le `~` trie sous tout, y compris la chaîne vide) et `Version: 2.0.0` + `Release: 0.beta.1`
côté rpm. **Taguer** une pré-version demandait deux corrections, faites toutes deux avant le
premier tag :

- `softprops/action-gh-release` a `prerelease` à `false` par défaut, sans détection SemVer : la
  release aurait été publiée en « latest ». Les deux steps portent désormais
  `prerelease: ${{ contains(github.ref_name, '-') }}`.
- Le job `update-homebrew` n'avait aucune condition : il aurait écrit la pré-version dans la
  formule du tap, et tout `brew upgrade kdt` y aurait basculé. Il porte désormais
  `if: ${{ !contains(github.ref_name, '-') }}`.

L'autre voie reste ouverte, celle suivie pour `1.26.0-beta.1` : bumper `Cargo.toml` sans pousser de
tag et livrer par `packaging/build-all.sh` en local. Une pré-version jamais taguée se renomme en
finale le jour venu, section du CHANGELOG comprise ; une pré-version taguée, non.

## 9. Jalons

0. **Maquette d'interface** — faite, validée le 2026-09-06.
1. **App blanche** dans `web/` : React + Vite + TypeScript, le layout validé, le routage, des
   données factices. Aucun code métier, aucun backend.
2. **Workspace et `kdt-core`** : aucun changement fonctionnel, validé par un build release musl et
   les 461 tests existants. Unifier `Hint` / `Severity` et dériver `Serialize` dans le même
   mouvement. C'est là que la version est passée à `2.0.0-alpha.1`.
3. **Flow d'autorisation** dans kdt-identity, et le lien optionnel depuis la page du portail.
4. **kdt-web v0**, lecture seule : session, client kube par utilisateur, trois vues sans
   équivalent ailleurs — `diagnostic`, `flux`, `capacity` — branchées sur l'app blanche.
5. Vues restantes, puis les écritures, puis logs et exec.

La chaîne de livraison est en place : `Dockerfile` (musl, `FROM scratch`, avec le
`LABEL org.opencontainers.image.source`), job `image` dans `release.yml` sur le même tag `v*`, et
`deploy/helm/kdt-web`. Reste le geste qui ne se scripte pas : **passer le package GHCR en public**,
une fois, depuis les réglages du package. Sans lui, l'absence d'`imagePullSecrets` dans le chart
donne un `ImagePullBackOff` — et c'est bien le chart qui a raison, le binaire étant déjà distribué
en deb, rpm et Homebrew.

## 10. Ce qu'on ne fait pas

Viser la parité avec le TUI. Porter le port-forward. Laisser diverger deux interfaces — c'est la
raison d'être de `kdt-core`. Héberger l'interface dans kdt-identity. Donner à kdt-web un service
account puissant « en attendant ». Publier l'image en privé sans raison : le binaire est déjà
distribué en deb, rpm et Homebrew, l'image n'ajoute aucun secret à protéger.

Et une variante à écarter explicitement, parce qu'elle vient à l'esprit : **kdt-web lancé sur le
poste**, servant sur `127.0.0.1` avec le kubeconfig local. C'est le TUI avec une autre peau, et
kdt-identity n'y sert plus à rien. Le seul usage qui la justifierait — partager une session à
plusieurs — ne vaut pas un second mode à maintenir.
