# Vue FluxCD : l'arbre de dépendances cluster-wide.
# Voir demo/hero.tape pour les contraintes VHS (pas d'Escape, 196 colonnes mini).

Require kdt

Output demo/flux.gif

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

# Démarrage masqué : on entre directement dans la vue.
Hide
Type "clear"
Enter
Type "kdt"
Enter
Wait+Screen@200ms /lang=EN/
Sleep 2s
Type ":"
Sleep 250ms
Type "flux"
Enter
Sleep 1500ms
Wait+Screen@200ms /GitRepository/
Show

Sleep 2500ms
# Plier puis déplier la branche sélectionnée.
Space
Sleep 1800ms
Space
Sleep 1500ms
# Descendre dans l'arbre, chaque ligne rechargeant le panneau de statut.
Down
Sleep 900ms
Down
Sleep 900ms
Down
Sleep 1800ms

Hide
Type "q"
Sleep 300ms
