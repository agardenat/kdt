# GIF de tête du README : le flux d'évènements, puis quatre vues d'analyse.
# Enregistrement : ./demo/record.sh (depuis la racine du dépôt).
#
# Trois contraintes à garder en tête avant de modifier ce fichier :
#   - VHS n'a pas de commande Escape (et Ctrl+[ ne la remplace pas) : n'ouvrir
#     aucun menu d'action, on ne saurait pas le refermer.
#   - en dessous de ~196 colonnes le pied de page de kdt se tronque.
#   - chaque vue interroge le cluster à l'entrée. La vue RBAC met ~3 s à
#     parcourir 101 bindings, et une pause trop courte filmait un écran vide.
#     D'où les `Wait` sur une chaîne qui ne paraît qu'une fois chargé — mais
#     toujours précédés d'un `Sleep` : `Wait` scrute l'état du terminal tel
#     qu'il était au dernier `Sleep`, et placée juste après la frappe elle
#     expire sur un tampon périmé au lieu de voir la vue arriver.

Require kdt

Output demo/hero.gif

Set FontFamily "JetBrains Mono"
Set FontSize 13
Set Width 1560
Set Height 840
Set Padding 14
Set Framerate 12
Set TypingSpeed 40ms
Set CursorBlink false

# Config dédiée : interface en anglais sans toucher à celle de l'utilisateur.
Env KDT_CONFIG "demo/config.json"
Env KDT_LOG "/tmp/kdt-demo.log"

Hide
Type "clear"
Enter
Sleep 500ms
Show

Type "kdt"
Sleep 300ms
Enter

# Le watcher liste avant de watcher : les évènements déjà présents arrivent d'un
# bloc, la table est pleine dès la première seconde.
Wait+Screen@200ms /lang=EN/
Sleep 3s

# Palette : toujours le nom canonique complet, la correspondance exacte
# l'emporte sur le classement par préfixe.
Type ":"
Sleep 250ms
Type "flux"
Enter
# L'arbre de dépendances est l'affichage par défaut : ne pas presser `t`, ce
# serait en sortir.
Sleep 1200ms
Wait+Screen@200ms /GitRepository/
Sleep 1200ms

Type ":"
Sleep 250ms
Type "capacity"
Enter
Sleep 1200ms
Wait+Screen@200ms /quotas/
Sleep 400ms
# Le monde « workloads » est autrement plus parlant que le monde « nodes » sur
# un cluster à un seul nœud.
Type "g"
Sleep 2200ms

Type ":"
Sleep 250ms
Type "kyverno"
Enter
Sleep 1400ms
Wait+Screen@200ms /enforce/
Sleep 1000ms

Type ":"
Sleep 250ms
Type "rbac"
Enter
# Seule attente masquée du film : ce balayage-là dure trois bonnes secondes et
# n'a rien à montrer. Les autres vues répondent assez vite pour rester à l'image.
Hide
Sleep 1500ms
Wait+Screen@200ms /bindings/
Show
Sleep 900ms
# L'orientation par défaut est `flat` : un `t` amène l'arbre par sujet.
Type "t"
Sleep 2300ms

Type "q"
Sleep 500ms
