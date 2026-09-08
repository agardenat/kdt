# Changelog

Toutes les versions publiées de kdt, la plus récente en premier. Chaque entrée reprend le
sujet du commit qui l'a apportée : type, portée, et ce qui change pour qui utilise l'outil.
Le versionnement suit [SemVer](https://semver.org/lang/fr/) et chaque version correspond au
tag `v<version>` qui a déclenché sa publication.

Les entrées jusqu'à la 1.24.0 incluse ont été reconstruites après coup depuis l'historique git :
elles disent ce que chaque version a apporté, pas ce qui en avait été annoncé à l'époque.

## [2.0.0-beta.6] — 2026-09-08

Trois défauts d'usage de kdt-web, et le même dans le TUI : des colonnes qui ne tombaient pas en
face de leur en-tête, des panneaux qui se refermaient sous les yeux à chaque rafraîchissement, et
un message d'erreur qui disait deux fois la même chose avant de disparaître trop vite.

- **fix(web)** — les colonnes de **toutes** les tables tombent en face de leur en-tête. Les
  gabarits sont écrits en `ch`, et un `ch` se mesure sur la police de la ligne : l'en-tête en
  10,5 px donnait des colonnes plus étroites que le corps en 12,5 px, et l'écart s'accumulait de
  colonne en colonne — jusqu'à vingt-huit pixels sur `CONTAINER`, qui passait à *gauche* de son
  titre. La typographie de l'en-tête se pose désormais sur les cellules, et la ligne d'en-tête
  porte le liseré de sévérité du corps, en transparent, pour partir des deux mêmes pixels.
- **fix(web)** — dans la table d'usage d'un node, la dernière colonne se mesurait sur son contenu :
  une ligne aux constats plus longs volait la largeur à la colonne souple d'avant elle, et les
  lignes se décalaient les unes par rapport aux autres.
- **fix(web, nodes)** — une seule colonne souple dans la table d'usage, et c'est la dernière.
  `POD` prenait toute la largeur d'un écran large, et le nom du pod restait seul à gauche d'un vide
  qui le séparait du container qu'il porte. Même correction dans la vue `u` du TUI, où `NS`, `POD`
  et `CONTAINER` se taillent maintenant sur ce qu'elles ont à montrer.
- **fix(web)** — `Related`, `Status` et `Logs` ne se vident plus à chaque passe de la vue. Une
  lecture reconstruit ses enregistrements, l'objet visé n'a pas bougé pour autant : le panneau se
  rafraîchit sans repasser par « Recherche… », et les sections dépliées de `Related` restent
  ouvertes.
- **fix(web)** — l'édition et la suppression ne rechargent plus par-dessus la saisie en cours. Le
  texte tapé dans `e` et le nom retapé pour confirmer un `Ctrl-D` étaient effacés toutes les vingt
  secondes par le rafraîchissement de la liste. Le YAML, lui, ne se redessine plus sous les yeux.
- **fix(web)** — un message d'**échec** ne s'efface plus tout seul au bout de huit secondes : il
  reste jusqu'au geste suivant, et un clic le referme. Un succès garde son minuteur, il n'y a rien
  à y relire. Le message tient sur une ligne et s'élide, texte entier dans l'infobulle.
- **fix(velero)** — l'inventaire d'un backup injoignable ne dit plus deux fois la même phrase.
  `publicUrl` était nommé par le téléchargement *et* par son appelant ; il ne l'est plus que par
  celui qui sait ce qu'il téléchargeait, et seulement quand c'est bien l'endpoint interne qui a
  fait échouer la lecture. L'URL signée y perd sa signature — cent caractères de query qui
  noyaient le seul nom d'hôte qui compte.

## [2.0.0-beta.5] — 2026-09-08

La vue **Nodes** arrive dans kdt-web, quatorzième vue et la première dont un geste **prend du
temps** : le drain d'un node se lit en flux plutôt que d'attendre une réponse deux minutes.

- **feat(web)** — vue **Nodes**, les deux écrans de `:nodes`. L'inventaire d'abord — `READY`, rôles,
  version, âge, et les alertes avec `Cordoned` en tête, parce que c'est la seule de la liste qui
  soit un geste et non un symptôme. Puis l'**usage par container** du node sélectionné, ce que `u`
  ouvre dans le TUI : les six quantités, les constats de dimensionnement (`noMemLim`, `cpuOver!!`,
  `OOMrisk`…), le tri qui garde les containers de la plateforme en dernier, et le cumul
  user / système / total dans le panneau du haut.
- **feat(web)** — **cordon et uncordon**, qui passent tout de suite comme dans kdt. Le menu n'offre
  que ce qui changerait quelque chose : un node cordonné propose `uncordon`. L'état courant est
  **relu côté serveur** avant d'écrire, pour qu'un node déjà dans l'état demandé soit répondu sans
  écriture — et non sur la foi de ce que la page affichait.
- **feat(web)** — le **drain**, avec les garde-fous de kdt : ce qui partirait, ce qui resterait, les
  budgets qui refuseront, et les pods que rien ne recréerait. Un constat grave exige de retaper le
  nom du node. La réponse est **en flux** (SSE) : un pod qu'un `PodDisruptionBudget` retient est
  réessayé pendant deux minutes, et le panneau montre pendant ce temps les évincés, les retenus et
  les échecs. Fermer l'overlay coupe le flux, jamais le drain.
- **security(web)** — les garde-fous sont **rejoués côté serveur juste avant d'évincer**, et la
  confirmation forte y est revérifiée : entre l'ouverture du panneau et le clic, le node a pu se
  vider, se remplir, ou perdre le budget qui le protégeait — et un garde-fou qui ne vit que dans la
  page se contourne en postant la requête à la main.
- **refactor(events, nodeops)** — les verdicts de la vue quittent `ui.rs` pour le métier : le ton
  d'une ligne de node et sa liste d'alertes, les onze constats de dimensionnement d'un container,
  les trois ordres de tri, le cumul user/système, et la rédaction des constats de drain. Les deux
  interfaces lisent désormais les mêmes règles au lieu d'en avoir chacune une copie.
- **fix(web)** — le ton `info` n'était défini dans aucun contenu du panneau du haut : une valeur au
  palier intermédiaire s'y peignait comme du texte ordinaire, donc comme une valeur calme.

## [2.0.0-beta.4] — 2026-09-08

L'analyse par une IA — le `i` de kdt — arrive dans kdt-web, en **cinquième geste générique** :
offerte dans les treize vues, sur la ligne sélectionnée, avec la configuration réglable depuis
l'application.

- **feat(web)** — bouton d'analyse dans la barre d'actions de toutes les vues, réponse **en flux**
  dans le panneau du haut (markdown rendu, blocs de commande copiables), et l'analyse qui survit au
  changement d'onglet ou de vue : y revenir relit ce qui a été écrit au lieu de rappeler le modèle.
- **feat(web)** — deux mondes de fournisseurs, qui coexistent. Ceux du déploiement viennent de
  `KDT_WEB_AI_PROVIDERS` — même forme que le tableau `providers` du fichier de configuration de kdt
  — et **leur clé ne sort jamais du pod** : le navigateur n'en apprend que le nom, le modèle et
  l'hôte joint. Ceux qu'une personne déclare depuis le réglage vivent **dans son navigateur** et
  accompagnent chaque requête ; le serveur ne les conserve pas.
- **feat(chart)** — `ai.providers` (posé dans un Secret) ou `ai.existingSecret`, et
  `ai.allowCustom`, qui décide si un navigateur peut nommer son propre endpoint. Une variable mal
  formée est refusée **au démarrage**, pas à la première analyse.
- **security(web)** — un endpoint nommé par un navigateur fait émettre une requête sortante au pod :
  `https` exigé, adresses de bouclage, privées et de lien-local refusées — ce qui écarte au passage
  le service de métadonnées du cloud. Un nom qui résout vers l'intérieur passerait : c'est le risque
  résiduel que `ai.allowCustom=false` retire.
- **refactor(ai)** — la construction du prompt quitte `ui.rs`, où la feature `tui` la rendait
  inatteignable pour kdt-web : les deux interfaces envoient désormais le même prompt, et la table de
  langue est passée en argument au lieu d'être lue dans un global de processus.

## [2.0.0-beta.3] — 2026-09-08

Trois vues de plus dans kdt-web — **capacité, stockage et network policies** — qui portent le
compte à treize. Elles ne font que constater : aucune n'écrit, et les quatre gestes génériques
(YAML, édition, touch, suppression) suffisent à agir sur l'objet d'une ligne.

- **feat(web)** — vue **capacité**, les trois mondes de `:capacity` : les nodes et ce que leur
  perte coûterait (simulation first-fit, avec les pods qui n'auraient nulle part où aller et
  pourquoi), le dimensionnement des workloads, et le `ResourceQuota` qui refusera le prochain
  déploiement. Sans metrics-server la colonne « consommé » reste vide au lieu d'afficher des zéros.
- **feat(web)** — vue **stockage**, les deux mondes de `:storage` : les claims et ce qui les
  empêche de se lier, puis les volumes rangés sous la classe qui les provisionne. Les octets qui
  dorment en `Released` et les constats du cluster — pas de classe par défaut, ou deux — sont dans
  une bande au-dessus de la table. Une liste de pods refusée ne se lit jamais comme « rien ne
  monte cette claim ».
- **feat(web)** — vue **network policies** : les `NetworkPolicy` natives avec leur verdict de
  posture par direction, et les CRD Cilium/Calico rendues factuellement — aucun verdict, parce que
  le défaut allow/deny de chaque moteur n'est pas celui du natif.
- **refactor** — les verdicts que le rendu du TUI portait encore descendent dans les modules
  métier : la tension d'un taux, le ton d'une phase, le mot d'une perte de node, l'effet d'une
  direction, et les enregistrements synthétiques des trois vues. Le TUI et kdt-web lisent
  désormais les mêmes fonctions ; deux implémentations auraient fini par peindre deux couleurs du
  même objet.

## [2.0.0-beta.2] — 2026-09-07

- **fix(ci)** — la `2.0.0-beta.1` n'a livré que son image : les deux jobs de binaires cherchaient
  `kdt-web` là où ils venaient de construire `kdt`, et se sont arrêtés avant de publier quoi que
  ce soit. Depuis que le dépôt est un workspace, `cargo metadata --no-deps` rend deux paquets, et
  `.packages[0]` n'est pas celui de la racine. Le nom est désormais désigné par son manifeste, et
  l'étape échoue franchement si elle ne le trouve pas plutôt que d'exporter une variable vide.

## [2.0.0-beta.1] — 2026-09-07

Le dépôt porte désormais deux binaires : `kdt`, le TUI, inchangé, et `kdt-web`, une interface web
qui parle au même métier. Le majeur marque cette refonte du dépôt, **pas une rupture d'usage** :
rien de ce que fait le TUI ne change, et une mise à jour depuis la 1.26 ne retire rien.

`beta.1` dit l'état réel de `kdt-web` : dix vues répondent, il se déploie par son image et son
chart, et il tourne. Le reste n'existe pas.

- **refactor** — kdt devient une bibliothèque en plus d'un binaire, sans qu'aucun fichier bouge.
  C'est ce qui permet à `kdt-web` de réutiliser les modules métier au lieu d'en copier les règles :
  les verdicts sont ce que kdt apporte, et deux implémentations divergeraient. Les trois modules
  qui dessinent dans un terminal — `ui`, `splash`, `glyphs` — passent derrière la feature `tui`,
  active par défaut, pour qu'un serveur ne compile pas `ratatui`.

- **feat(web)** — `kdt-web` s'authentifie par le flow d'autorisation de kdt-identity 1.0 : il
  n'a jamais accès au mot de passe ni au code TOTP, et obtient un droit de session que `revoke` et
  `spec.disabled` ferment comme celui d'un poste.

  Chaque requête est servie avec **le credential de la personne connectée** : l'apiserver voit
  `kdt:alice` et ses groupes, donc le RBAC du cluster s'applique tel quel. Le compte de service du
  pod n'a besoin d'aucun droit sur les ressources — c'est ce qui distingue kdt-web d'un tableau de
  bord classique, et ce qui fait qu'obtenir l'exécution de code dedans n'ouvre aucun accès.

  Le droit de session vit en mémoire, jamais sur disque ni dans un `Secret`. Un redémarrage le
  perd et chacun se reconnecte ; en échange, il n'existe aucun fichier contenant de quoi agir au
  nom de tout le monde. Corollaire assumé pour l'instant : **une seule réplique**.

- **feat(web)** — première vue : les évènements, dans la portée de namespaces demandée. Un refus
  de l'apiserver est rendu tel quel plutôt que traduit en liste vide, qui ferait croire à un
  cluster calme.

  Mêmes colonnes et même ordre que le TUI, et le même panneau d'inspection **au-dessus** de la
  table — `Logs`, `Status`, `Related`, les trois onglets de `DetailTab`. Repliable comme le `²`
  de kdt, et redimensionnable à la poignée, au double-clic ou au clavier : le web a une souris,
  le terminal n'en a pas.

- **feat(web)** — la vue Flux : l'arbre de dépendances GitOps, tel que le TUI le résout. Les
  arêtes — `dependsOn`, `status.helmChart`, `spec.sourceRef` — sont calculées par `kdt` et le
  navigateur n'en reçoit que le résultat : il n'a pas de quoi s'en rebâtir un qui différerait.
  Repliable, avec le décompte de ce qu'un pli cache (`✗3 ↻1`), et les branches qui mènent à un
  problème s'ouvrent d'elles-mêmes puis se referment une fois l'incident réglé.

  Le badge `no-prune` marque la Kustomization qui laisse survivre ce qui a disparu de git — c'est
  l'écart à la norme qui se signale, jamais la norme. `⊞` déplie ce qu'une Kustomization a
  appliqué, avec l'état vivant de chaque objet.

  Les leviers de kdt sont là : `reconcile`, `+source`, `sync racine`, et sur une HelmRelease
  `forcer l'upgrade` et `réarmer`. La bascule `suspend`/`resume` décide sa direction sur l'objet
  vivant et non sur le tableau affiché, qui a jusqu'à un rafraîchissement de retard. La phrase que
  kdt rédige est rendue telle quelle — un refus dit pourquoi, il ne devient pas une panne.

  L'arbre n'a pas de portée, comme dans kdt : le filtrer par namespace lui ferait perdre ses
  arêtes, la `GitRepository` de `flux-system` étant le parent de presque tout. La barre de portée
  le dit au lieu de filtrer en silence.

- **feat(web)** — la vue Workloads : les workloads du namespace, leurs pods, et les containers de
  chaque pod. Le rattachement d'un pod à son workload est celui de kdt — remontée des
  `ownerReferences` avec résolution ReplicaSet → Deployment — et le navigateur n'en reçoit que le
  résultat. Les pods orphelins ferment la marche plutôt que de disparaître.

  Chaque kind se compte comme il doit : répliques pour un Deployment, pods programmés pour un
  DaemonSet, complétions pour un Job — dont le verdict se lit sur les conditions, les compteurs ne
  distinguant pas un Job qui tourne d'un Job qui a renoncé. `spec.replicas` reste le seul témoin
  qu'un kind se scale, donc `scale` n'est pas proposé sur un DaemonSet ni sur un Job.

  `scale`, `restart` et `recycle` vivent sur la ligne qu'ils visent. `recycle` prévient de ce
  qu'il risque : une remontée en échec laisse le workload à zéro, et la réponse le dit.

- **feat(web)** — les vues Secrets et ConfigMaps, voisines et opposées sur un point. Une ConfigMap
  est du texte en clair : ses valeurs arrivent avec la ligne. Un Secret n'envoie **rien** — ni ses
  valeurs, ni son manifeste, qui les contient. Les révéler est une requête nommée, secret par
  secret, tracée côté serveur.

  C'est la règle du TUI — masqué par défaut, remis à masqué quand la sélection change — portée sur
  un média où « ne pas afficher » ne suffit plus : sur une page, il faut ne pas envoyer. Une liste
  qui porterait les valeurs les ferait traverser le réseau toutes les dix secondes, pour tous les
  secrets de la portée, et les laisserait dans l'onglet réseau des devtools.

  Les secrets TLS sont triés par urgence, l'échéance colorée par bande (expiré, moins de 15 jours,
  moins de 30), avec l'émetteur, les SAN, le `Certificate` cert-manager qui les produit et les
  Ingress qui les consomment. La clé privée n'est jamais lue.

- **feat(web)** — la vue certs : la chaîne cert-manager, du point d'ancrage jusqu'au Secret servi.
  Issuer → Certificate → CertificateRequest → Order → Challenge, puis le Secret produit et les
  Ingress qui le référencent. Un certificat qui expire ne dit pas pourquoi ; la chaîne, si.

  Les constats sont ceux de kdt et arrivent rédigés : un `dns-01` qui traîne au-delà du délai de
  propagation, un `http-01` que le solveur n'a pas publié, un Order invalide qui porte l'échec
  d'autorisation, un issuer cassé qui condamne tout ce qui pend dessous, un renouvellement échu
  sans rien en vol, un Secret absent derrière un Certificate `Ready`, un keystore demandé qui n'a
  jamais atterri. La chaîne d'un Certificate sain se replie d'elle-même, celle d'un Certificate en
  panne s'ouvre — et jamais contre un pli posé à la main.

  Les deux leviers suivent : `renouveler` force la ré-émission, `relancer ACME` supprime la
  demande en cours pour en faire repartir une neuve. La relance n'est offerte que s'il y a une
  demande vivante, et **jamais sous quota ACME** — y réessayer ne fait que brûler ce qui reste.

  Les Secrets sont relus dans la même portée pour la feuille de chaîne et pour ces constats. Une
  lecture refusée les laisse **muets** plutôt que d'affirmer une absence : un Secret illisible
  n'est pas un Secret manquant.

  Les deux vues se passent la main dans les deux sens, comme dans le TUI : d'une chaîne vers le
  Secret qu'elle produit, où le certificat est décodé et les valeurs se révèlent, et d'un Secret
  vers le Certificate qui l'émet — la chaîne visée s'ouvrant même si elle est saine, sans quoi le
  saut se poserait sur une ligne repliée.

- **feat(web)** — les trois gestes que kdt porte sur n'importe quel objet arrivent sur le web, dans
  toutes les vues : lire son YAML, l'éditer, l'horodater. Ils vivent dans la barre qui sépare les
  deux panneaux, et ce qu'ils ouvrent s'affiche dans le panneau du haut — c'est la disposition du
  web, là où le TUI n'a que `y`, `e` et `h`.

  L'édition garde les deux questions de kdt, posées avant d'écrire : *ce changement va-t-il
  survivre ?* — un objet appliqué par Flux, Argo ou Helm est remis en place à la réconciliation
  suivante — et *l'apiserver l'acceptera-t-il ?* Puis le tri des changements : ce que l'apiserver
  possède et ignorera, ce qu'il fige et refusera, ce qui ferait pointer le document vers un autre
  objet. Aucune de ces réponses ne bloque quoi que ce soit, et l'annulation reste la sortie par
  défaut. L'écriture est un PUT, comme `kubectl edit` : l'apiserver refuse si l'objet a bougé.

  L'horodatage inscrit **la personne connectée** comme auteur, pas le compte du pod : l'intérêt de
  l'annotation est de dire qui a demandé.

- **refactor** — la vue certs du TUI et celle du web lisent les mêmes règles : le libellé `READY`
  et son ton, le glyphe, ce qu'une ligne vise, les keystores qu'elle demande, le filtre à trois
  états — qui garde les ancêtres de ce qu'il retient — et les deux conversions en enregistrement
  d'évènement descendent de `ui.rs` dans `certmanager.rs`. La sonde qui déposait son inventaire
  dans un état partagé gagne une jumelle qui le rend, et les deux actions une forme qui répond au
  lieu de publier un toast. Les phrases des garde-fous d'édition quittent `ui.rs` pour `edit.rs`
  pour la même raison : un garde-fou qui se dirait autrement d'un côté et de l'autre serait un
  garde-fou de moins.

- **feat(web)** — le rail ne montre que les vues que ce cluster peut servir : sans Argo CD,
  pas d'onglet Argo CD. La sonde est un seul appel — la liste des groupes d'API — couvert par
  `system:discovery`, donc elle aboutit sans droit particulier.

  Un apiserver injoignable et un cluster sans add-on ne donnent **pas** la même réponse : sonde en
  échec, le rail n'écarte rien. Une vue qui disparaît est un message, et il serait faux.

- **refactor** — sept règles de la vue Workloads qui jugeaient le cluster depuis `ui.rs` — le ton
  d'un statut de pod, celui de la ligne, celui d'un container, l'étiquette et le ton du statut d'un
  workload, la lecture des redémarrages, le rattachement d'un pod à son workload — descendent dans
  `pods.rs`, avec les trois conversions en `EventRecord`. Deux verdicts jusque-là implicites y sont
  nommés : `is_scalable` et `is_restartable`.

- **refactor** — la vue Flux du TUI et celle du web lisent les mêmes règles : l'étiquette `READY`
  et son ton, le ton de la ligne — qui n'est pas le même, une ressource suspendue étant éteinte
  sur sa ligne et jaune sur son étiquette — la lecture de `no-prune`, et la conversion d'une
  ressource Flux en enregistrement d'évènement descendent de `ui.rs` dans `flux.rs`. Les trois
  sondes qui déposaient leur résultat dans un état partagé — inventaire Flux, inventaire d'une
  Kustomization, logs des controllers — gagnent une jumelle qui le rend, comme `pod_logs` avant
  elles : une requête HTTP veut une réponse, pas un état à redessiner.

- **refactor** — trois règles qui jugeaient le cluster vivaient dans `ui.rs`, donc derrière la
  feature `tui` et hors de portée de kdt-web : `is_critical_reason` — celle qui sépare un
  `CrashLoopBackOff` d'une sonde qui a hoqueté — descend dans `events.rs` avec le verdict à trois
  niveaux qu'elle produit, et `pod_logs`/`object_status` rendent désormais leur résultat au lieu
  de le déposer dans l'état que le TUI redessine. Une seule implémentation de chaque, appelée des
  deux côtés : deux interfaces qui jugent séparément finissent par ne plus dire la même chose du
  même évènement.

- **fix(tui)** — la colonne `CNT` des évènements tronquait : quatre caractères pour un compte qui
  s'écrit `x1232`, donc précisément l'évènement qui se répète — celui qu'on veut voir — perdait
  ses chiffres de droite. Six désormais.

- **change(tui)** — la colonne `TIME` des évènements devient `AGE` : `12:34:56` demandait de
  calculer soi-même la fraîcheur d'une ligne, `3m` la donne. Le panneau de détail suit, et la
  colonne se resserre de huit caractères à cinq.

- **feat(web)** — la vue identity : les comptes et les groups locaux de kdt-identity, avec les sept
  colonnes du TUI. La phase `Locked` est celle que kdt établit depuis le Secret de credentials — le
  contrôleur ne l'écrit jamais — et la colonne SESS dit si un compte tient un accès en ce moment,
  donc s'il y a quelque chose à révoquer.

  Les deux silences ne se lisent pas comme des zéros : un Secret de sessions illisible donne `?`,
  un compte sans session donne `—`, et les deux erreurs de lecture — credentials et sessions —
  voyagent séparément parce qu'elles taisent une colonne chacune.

  Le mode de délivrance est dit une fois, au niveau de la vue : c'est lui qui rend la colonne SESS
  lisible, en disant combien de temps un accès survit à sa révocation. Variable absente, rien
  n'est affirmé — l'amont défaute à `certificate`, mais l'absence décrit aussi un déploiement 0.1
  qui ne révoque rien. Le téléchargement de kubeconfig, seul accès que ni `revoke` ni
  `spec.disabled` n'atteignent, est signalé là et jamais comme un badge par ligne.

  Les sept écritures suivent : créer un compte ou un group depuis l'un ou l'autre monde, activer et
  désactiver, l'appartenance — toujours en JSON patch, jamais en merge, qui remplacerait
  `spec.members` en entier — inviter et fermer les sessions. Ces deux dernières sont des commandes
  lancées dans le pod contrôleur, que le serveur localise **lui-même** par les labels du chart : un
  nom de pod venu du navigateur ferait d'un `exec` une cible choisie par l'appelant. La sortie de
  `revoke` devient la réponse telle quelle, et le lien et le code d'une invitation n'existent que
  dans cette réponse-là.

- **feat(web)** — la vue Rancher : le couple *(identité Rancher `u-…`, identité réelle)* sans
  ouvrir Rancher, en quatre mondes — comptes, accès, projects, tokens — avec toutes les colonnes du
  TUI. Un compte `local` se signale parce qu'aucun départ de l'annuaire ne le révoque, un principal
  opaque est montré tel quel plutôt que déguisé en nom, et le rôle global que Rancher pose sur tout
  compte se lit comme de l'arrière-plan.

  Le monde des tokens montre d'abord les réglages de TTL qui les gouvernent : sur un cluster dont
  `kubeconfig-default-token-ttl-minutes` vaut `0`, c'est le titre et non une note de bas de page.
  Un token sans portée vaut sur tous les clusters gérés *et* sur l'API Rancher, un token sans
  expiration ne s'éteint jamais : les deux se signalent.

  Les quatre écritures — émettre un token, changer sa durée de vie, le révoquer, régler un
  setting — sont refusées sur un cluster downstream, où les objets d'identité sont des répliques.
  Le compte visé par une émission est **relu côté serveur** : le token porte le `userPrincipal`
  reconstruit depuis le principal réel, et un principal fourni par l'appelant ferait émettre un
  credential au nom de quelqu'un d'autre. Le credential rendu n'existe que dans cette réponse.

- **feat(web)** — la vue Kyverno : la jointure que Kyverno ne fait pas lui-même — une policy, ses
  règles et les ressources qui échouent dessus. Un `PolicyReport` ne nomme la policy et la règle
  que par des chaînes, et les rapports d'un Deployment ne citent que les règles `autogen-*` que
  Kyverno a dérivées : celles-ci sont dans l'arbre, marquées comme telles. La jointure se lit dans
  les deux sens — *que casse cette policy ?* et *qu'est-ce qui ne va pas dans ce namespace ?*

  Une policy saine referme ses règles, une policy en peine les ouvre, et un pli posé à la main
  gagne toujours : le verdict vient du serveur, le navigateur ne fait que le suivre.

  La bande de santé dit ce qu'aucune ligne ne dirait : Kyverno peut avoir tous ses controllers
  verts et **n'intercepter rien du tout** si aucun webhook n'est enregistré. La file des
  `UpdateRequest` y figure aussi — muette partout ailleurs, une file bloquée ne laissant ni
  PolicyReport ni refus d'admission — avec les policies qui la tiennent lorsqu'elle ne se draine
  plus, et le levier qui la vide.

  Les refus d'admission ont leur section, et ils n'existent nulle part ailleurs : la ressource
  refusée n'a jamais existé, donc aucun rapport ne la décrit — seul un Event en garde la trace.
  Les évènements illisibles laissent la section muette plutôt que d'affirmer qu'il n'y a eu aucun
  refus.

- **feat(web)** — la vue RBAC : non pas la liste des liaisons, que `kubectl get rolebindings -A`
  donne déjà, mais le **score** et le **graphe**. Un Role seul n'accorde rien tant qu'il n'est pas
  lié, et le même ClusterRole est anodin en RoleBinding namespacée et critique en
  ClusterRoleBinding : la sévérité se calcule par liaison, à partir des règles résolues, des sujets
  et du namespace — celle de kdt, pas une seconde règle écrite dans le navigateur.

  Les quatre lectures du TUI sont là : la liste d'audit, l'identité et tout ce qu'elle cumule, la
  liaison dépliée, et le rôle — la seule qui montre un ClusterRole re-accordé namespace par
  namespace comme **un** nœud, avec ce qu'il agrège et ce qu'il alimente. Un pli porte sur le nœud
  et non sur la ligne : un ClusterRole atteint par deux liaisons se replie d'un seul geste.

  L'attribution dit qui a posé l'objet, et ne range pas Kyverno, Rancher, les défauts du cluster ni
  les gestionnaires d'add-ons avec les grants orphelins : ils posent des objets sans passer par
  kubectl, ils sont attribués. Une liste de ServiceAccounts illisible n'autorise aucun « ce compte
  n'existe pas » — la vue le dit et se tait, plutôt que de montrer un graphe troué sans prévenir.

  La portée resserre ce qui est **montré**, jamais ce qui est **lu** : une arête d'agrégation ou un
  « personne ne lie ce rôle » calculés sur une liste partielle seraient faux. C'est la seule vue en
  graphe qui accepte une portée, et la règle de ce qu'un namespace contient — ses RoleBindings,
  plus les liaisons accordées à ses ServiceAccounts — est celle de kdt.

- **feat(web)** — la vue Velero, qui répond à la seule question qu'on pose à un système de
  sauvegarde : *si le cluster brûle maintenant, qu'est-ce qui revient ?* La réponse est éparpillée
  sur six kinds et deux silences, et c'est ce que la vue rassemble.

  Un backup `PartiallyFailed` n'est pas une nuance de succès : il est rouge, à côté de `Failed`,
  parce qu'il est allé au bout **sans** tout capturer. Un Schedule qui cesse de se déclencher ne
  laisse ni Event, ni condition, ni compteur de runs manqués — kdt réévalue le cron lui-même, et
  c'est ce calcul-là qui remplit la colonne EXPIRE. Un namespace qui porte un PVC qu'aucun schedule
  ne couvre est nommé au-dessus de la table : rien d'autre sur le cluster ne le dit.

  Le contenu d'un backup se déplie à la demande — namespaces, kinds, objets — et se télécharge
  depuis le stockage objet, jamais avec la liste. Il n'y a **pas de repli** : un bucket injoignable
  est rapporté comme tel, jamais rendu comme un backup qui n'aurait rien capturé. Chaque objet
  capturé porte son GVK réel, donc les gestes génériques ouvrent l'objet **vivant** — la question
  qu'on se pose devant un backup est justement s'il existe encore et s'il ressemble encore à ce qui
  a été pris.

  Le log d'un run est là, avec sa source : l'URL signée pointe l'adresse que *le cluster* utilise,
  et quand elle n'est pas joignable les lignes viennent du controller — partielles, et dites comme
  telles plutôt que lues comme un log complet.

  Les quatre écritures suivent : lancer un run depuis un schedule, mettre en pause ou reprendre,
  restaurer — tout, ou à la carte par namespaces, kinds, namespace cible et labels — et supprimer.
  La suppression passe par un `DeleteBackupRequest` et non par l'objet : supprimer le Backup ne
  supprime rien, le contrôleur de synchronisation le recrée depuis le bucket une minute plus tard.
  Le template d'un schedule et l'UID d'un backup sont **relus sur le cluster** : un spec ou un UID
  venu du navigateur ferait agir sur autre chose que ce que la ligne montre. Écraser les objets
  vivants demande de retaper le nom du backup, et une liste de namespaces vidée est refusée — elle
  restaurerait tout, l'inverse de ce qu'elle demande.

- **feat(web)** — le `Ctrl-D` de kdt arrive sur le web, dans toutes les vues : les garde-fous
  d'abord — déployé par un moteur GitOps, point d'entrée GitOps, cascade d'un Namespace ou d'une
  CRD, propriétaire qui recrée, namespace système, données persistantes, backup velero ou Medusa
  que supprimer l'objet ne supprime pas — puis la confirmation.

  Aucun constat ne bloque : ils décident **combien** la confirmation coûte. Un constat grave, ou
  une vérification qui n'a pas pu conclure, exige de retaper le nom de l'objet — et le serveur le
  revérifie, parce qu'un garde-fou qui ne vivrait que dans la page se contournerait en postant la
  requête à la main. Les garde-fous sont rejoués avant d'écrire plutôt que repris de la réponse
  précédente : entre les deux requêtes, l'objet a pu passer sous la main d'un moteur GitOps.

  La sortie par défaut ne supprime rien, comme dans kdt où `Entrée` annule : c'est le bouton
  d'annulation qui prend le focus, et celui qui supprime est une cible distincte, à distance.

- **feat(web)** — le bandeau du cluster arrive dans la barre du haut : le nom du cluster, la
  version de l'apiserver, ses nodes prêts et la pression CPU/mémoire. C'est ce que kdt affiche sur
  la deuxième ligne de son en-tête, avec les mêmes paliers d'occupation — descendus dans
  `events.rs` pour que les deux interfaces peignent la même couleur du même taux.

  Le nom vient de `KDT_WEB_CLUSTER`, sinon du contexte visé, sinon de l'hôte de l'apiserver, dont
  l'adresse complète accompagne le nom : c'est elle qui rend un mauvais cluster évident.

  Ce qui n'a pas été lu n'est pas affiché : sans le droit de lister les nodes, il n'y a ni compte
  de nodes ni allocation, et le bandeau le dit par un tiret au lieu d'un `0/0 ready` vert qui
  affirmerait un cluster sain que personne n'a regardé. Le TUI corrige la même affirmation.

- **fix(web)** — les listes déroulantes ne se refermaient qu'en recliquant sur le bouton qui les
  avait ouvertes : un clic à côté les laissait ouvertes, par-dessus ce qu'on voulait atteindre.
  Le clic hors du menu le referme désormais partout — sélecteur de portée et menus d'actions des
  cinq vues — et `Échap` aussi, sans replier le panneau derrière.

- **fix(web)** — le sélecteur de portée ne proposait rien : il fallait connaître le nom du
  namespace et le taper sans faute, une faute rendant une vue vide qu'on lit comme un cluster vide.
  Il liste désormais les namespaces et resserre la liste à la frappe, les choisis en tête avec de
  quoi les retirer.

  La saisie libre reste, et c'est la porte de sortie : lister les namespaces demande un droit
  cluster-scoped que beaucoup n'ont pas tout en travaillant dans un namespace qu'ils nomment très
  bien. Un refus laisse donc le champ utilisable et dit pourquoi il ne propose rien — il ne se
  rend pas comme une liste vide.

- **fix(web)** — le panneau du haut restait accroché à la sélection : il apparaissait au premier
  clic et repartait au suivant, décalant la table de 300 px sous le curseur. Il reste désormais en
  place tant qu'il est déplié — sans sélection il montre son cadre et l'invite — et c'est le pli,
  que la personne commande et que kdt retient, qui décide de sa présence. Sélectionner une ligne ne
  le déplie plus ; les commandes de la barre, celles qui révèlent un contenu, si.

- **fix(web)** — YAML, Éditer et Supprimer avaient chacun deux boutons : un dans la barre
  d'actions, un onglet permanent dans le panneau, sans que rien ne dise lequel faisait quoi. Ce
  sont des **overlays** dans kdt — on les ouvre et on les ferme — donc leur onglet n'existe plus
  que tant qu'on y est, porte sa croix, et `Échap` le referme avant de replier le panneau. Un
  overlay dont la cible disparaît retombe sur ce qui reste lisible.

- **refactor** — les vues identity et Rancher du TUI et celles du web lisent les mêmes règles : le
  ton d'une phase, celui d'une invitation périmée, celui de la colonne des sessions, le constat
  qu'un group ne donne aucun droit, le compte `local` qu'aucun annuaire ne révoque, le token
  éternel, la portée vide, le réglage à zéro minute, et les sept conversions en enregistrement
  d'évènement descendent de `ui.rs` dans `identity.rs` et `rancher.rs`. Les deux sondes qui
  déposaient leur inventaire dans un état partagé gagnent une jumelle qui le rend, et les phrases
  des garde-fous de suppression quittent `ui.rs` pour `delete.rs`.

- **fix(ci)** — un tag de pré-version ne publiait pas ce qu'il annonçait : `action-gh-release` a
  `prerelease` à `false` par défaut, sans détection SemVer, et le job Homebrew n'avait aucune
  condition — une `v2.0.0-beta.1` aurait été marquée « dernière version » et poussée dans la
  formule du tap, basculant tout le monde sur une alpha.

- **feat(web)** — kdt-web se déploie : une image `ghcr.io/agardenat/kdt-web` construite par le
  workflow de release sur le même tag `v*` que les binaires, et un chart `deploy/helm/kdt-web`.
  Jusqu'ici, ce qui tournait quelque part ne correspondait à rien de publié.

  L'image est `FROM scratch` — le binaire musl, le bundle du front, les racines TLS, rien d'autre.
  kdt-web détient les credentials des personnes connectées : un shell dans le conteneur suffirait
  à les lire, et il n'y en a pas.

  Le chart n'a **aucun `rbac.yaml`**, et c'est sa propriété principale : le compte de service
  n'est visé par aucun Role ni ClusterRole, parce que chaque requête part avec le credential de
  la personne connectée. Il refuse ce qui ne pourrait pas fonctionner — un `webUrl` en clair ou
  terminé par un `/`, que le portail rejetterait au retour, et une seconde réplique, qui
  servirait une requête sur deux depuis un processus qui ne connaît pas le visiteur.

- **docs** — le README, dans les deux langues, dit ce qu'est kdt-web : les dix vues, l'identité de
  la personne connectée à chaque requête, les deux prérequis côté kdt-identity, et la commande
  d'installation du chart. Le dépôt livrait un second binaire dont sa page d'accueil ne disait rien.

- **fix(web)** — un lien profond répondait « page manquante » : `/events` servait bien
  l'interface, mais avec un code 404. Le navigateur affichait la page, et la supervision, les
  caches et les journaux de l'ingress voyaient une page absente à chaque ouverture. Le repli de
  la SPA répond désormais 200.

## [1.26.0] — 2026-09-05

- **feat(identity)** — vue `:identity` : comptes et groups locaux de kdt-identity, avec la colonne
  RIGHTS qui dit ce que le système ne dit nulle part — un group que rien ne référence authentifie
  ses membres et ne leur accorde rien, alors que tous les objets réconcilient
- **feat(identity)** — `o` invite : `kdt-identity-server invite` exécuté nativement dans le pod
  contrôleur (localisé par ses labels, pas par le nom `<release>-controller` que `fullnameOverride`
  change), sortie capturée et jamais rendue au terminal. Le lien et le code s'affichent une seule
  fois et se copient **séparément** : ils sont faits pour voyager par deux canaux différents
- **feat(identity)** — création de user et de group, `spec.disabled`, et appartenance par sélecteur.
  L'appartenance est toujours un JSON patch, jamais un merge : un merge patch remplace
  `spec.members` en entier et efface les autres membres
- **feat(identity)** — les deux créations sont proposées depuis les deux mondes : un `KdtGroup` se
  crée en regardant le compte qu'il doit porter, sans passer par `g` et une sélection vide. La vue
  bascule sur le monde de l'objet créé et se pose sur sa ligne
- **feat(identity)** — la phase `Locked` est établie par kdt depuis le Secret de credentials, que le
  contrôleur ne renseigne jamais dans le status ; la colonne INVITE distingue un compte jamais
  invité d'une invitation en cours ou expirée
- **feat(identity)** — alignement sur kdt-identity 1.0 : colonne **SESS**, le nombre de sessions de
  renouvellement ouvertes lues dans le Secret `kdt-identity-oidc-<user>`. C'est la seule colonne qui
  dise si un compte tient un accès en ce moment, donc s'il y a quelque chose à révoquer — et `?`
  n'est pas `0`, un Secret illisible ne dit pas que personne n'est connecté
- **feat(identity)** — `o` **fermer les sessions** : `kdt-identity-server revoke` exécuté dans le pod
  contrôleur par le même chemin que l'invitation. Sa sortie devient le toast telle quelle — combien
  de sessions fermées, sous quel délai s'arrête le reste — plutôt qu'une reformulation par kdt
- **feat(identity)** — le **mode de délivrance** (`certificate` / `oidc`) est lu dans l'environnement
  du pod contrôleur et dit une fois dans le titre, avec la fenêtre de révocation qu'il implique.
  Variable absente ⇒ aucune affirmation : c'est aussi ce à quoi ressemble un déploiement antérieur à
  1.0. Le détail ajoute le droit de session et, en mode certificat, l'état de
  `portal.kubeconfigDownload` — le seul accès que ni `revoke` ni `spec.disabled` n'atteignent
- **change(identity)** — `spec.disabled` ne se décrit plus comme « les certificats déjà émis vivent
  jusqu'à leur expiration » : depuis 1.0 le contrôleur ferme les sessions et l'accès s'arrête au
  prochain renouvellement. Un compte désactivé qui garde des sessions est désormais un warning — le
  contrôleur ne réconcilie pas ce compte
- **feat(diagnostic)** — module kdt-identity : groups sans binding, members sans compte, comptes
  verrouillés. Absent du cluster ⇒ Info
- **feat(delete)** — supprimer un `KdtUser` annonce que son nom restera dans les `members` des
  groups qui le citent
- **change(palette)** — `users`, `user`, `identities`, `identites` ouvrent désormais `:identity` et
  non plus `:rancher`, qui garde `ranch` et `cattle` : chaque vue est nommée par sa source, et
  celle-ci est la seule que kdt peut écrire

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
