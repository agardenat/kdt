# Vue RBAC : les quatre orientations de l'arbre des droits.
# Voir demo/hero.tape pour les contraintes VHS (pas d'Escape, 196 colonnes mini).

Require kdt

Output demo/rbac.gif

Set FontFamily "JetBrains Mono"
Set FontSize 13
Set Width 1560
Set Height 840
Set Padding 14
Set Framerate 12
Set TypingSpeed 40ms
Set CursorBlink false

Env KDT_CONFIG "demo/config.json"
Env KDT_LOG "/tmp/kdt-demo.log"

Hide
Type "clear"
Enter
Type "kdt"
Enter
Wait+Screen@200ms /lang=EN/
Sleep 2s
Type ":"
Sleep 250ms
Type "rbac"
Enter
# Ce balayage-là dure trois bonnes secondes : l'attendre plutôt que la deviner.
Sleep 1500ms
Wait+Screen@200ms /bindings/
Show

# `flat` est l'orientation par défaut : la liste des bindings classée par sévérité.
Sleep 2200ms
# `t` fait tourner flat → by subject → by binding → by role.
Type "t"
Sleep 2500ms
Space
Sleep 1500ms
Type "t"
Sleep 2200ms
Type "t"
Sleep 2200ms

Hide
Type "q"
Sleep 300ms
