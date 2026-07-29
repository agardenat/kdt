# Vue Kyverno : les policies, leurs règles et ce qu'elles bloquent réellement.
# Voir demo/hero.tape pour les contraintes VHS (pas d'Escape, 196 colonnes mini).

Require kdt

Output demo/kyverno.gif

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
Type "kyverno"
Enter
Sleep 1500ms
Wait+Screen@200ms /enforce/
Show

# La bande de santé du haut : contrôleurs, webhooks, rapports.
Sleep 2500ms
Down
Sleep 1500ms
Down
Sleep 1500ms
# Bascule sur l'axe « par ressource » : ce que chaque objet enfreint.
Type "t"
Sleep 2500ms

Hide
Type "q"
Sleep 300ms
