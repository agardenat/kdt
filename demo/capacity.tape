# Vue Capacité : la marge réelle, nœud par nœud puis workload par workload.
# Voir demo/hero.tape pour les contraintes VHS (pas d'Escape, 196 colonnes mini).

Require kdt

Output demo/capacity.gif

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
Type "capacity"
Enter
Sleep 1500ms
Wait+Screen@200ms /quotas/
Show

# Monde « nodes » : le verdict sur le nœud et sur le cluster.
Sleep 2500ms
# Monde « workloads » : ce que chaque charge réserve face à ce qu'elle consomme.
Type "g"
Sleep 2500ms
Down
Sleep 900ms
Down
Sleep 900ms
Down
Sleep 1800ms
# Monde « quotas ».
Type "g"
Sleep 2000ms

Hide
Type "q"
Sleep 300ms
