# Films de démonstration du README

Les GIFs affichés dans le `README.md` sont produits par [VHS](https://github.com/charmbracelet/vhs)
à partir des tapes de ce dossier. Ils sont versionnés : le README en a besoin.

## Régénérer

```bash
./demo/record.sh              # les cinq
./demo/record.sh demo/rbac.tape   # un seul
```

Prérequis : `vhs`, `ttyd` (≥ 1.7.4), `ffmpeg`, la police **JetBrains Mono**, et un binaire
construit dans `target/x86_64-unknown-linux-musl/release/`. Le script s'en assure avant de lancer
quoi que ce soit.

## Ce que ces tapes supposent

**Un cluster réel.** kdt n'a pas de mode hors-ligne : il abandonne au démarrage s'il ne peut pas
joindre d'API server. Les films tournent contre le cluster du kubeconfig courant, et son contenu
apparaît donc à l'image.

**Une interface en anglais**, via `KDT_CONFIG=demo/config.json`. Cette variable a priorité sur le
chemin XDG, donc la config personnelle de l'utilisateur n'est jamais lue ni écrite pendant un
enregistrement. Le fichier ne contient aucune clé d'API, ce qui garde le panneau IA hors du cadre.

**196 colonnes.** `Set FontSize 13` avec `Set Width 1560` y arrive tout juste. En dessous, le pied
de page de kdt se tronque : `balance_footer_rows` l'étale sur deux lignes mais ne dégrade pas
au-delà, et les derniers raccourcis se font couper. Le pied de page sert de témoin de largeur : s'il est entier, le reste l'est aussi.

## Pièges VHS

**VHS n'a pas de commande `Escape`**, et `Ctrl+[` ne la remplace pas. Un tape ne doit donc jamais
ouvrir un menu d'action : il ne saurait pas le refermer. Aucun scénario ici ne valide quoi que ce
soit — pas de reconcile, pas de suspend, pas de suppression, pas d'édition.

**`Wait` scrute le terminal tel qu'il était au dernier `Sleep`.** Placée juste après la frappe qui
change de vue, elle expire sur un tampon périmé au lieu de voir la vue arriver. Toujours amorcer :
`Sleep 1500ms` puis `Wait+Screen /jeton/`.

**Le parseur casse sur les chemins non quotés** contenant tirets et chiffres. Quand un chemin
n'est pas relatif et simple, l'entourer de guillemets.

## États par défaut à connaître

Deux vues s'ouvrent dans un état qui n'est pas celui qu'on croit : `flux_tree` vaut `true` par
défaut, donc `t` sur la vue Flux *sort* de l'arbre ; `rbac_orient` vaut `Flat`, donc il faut un `t`
pour entrer dans l'arbre. Les tapes en tiennent compte.
