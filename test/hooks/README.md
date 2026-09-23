# Jeu de test pour la vue `:hooks`

Manifestes jetables qui produisent, sur n'importe quel cluster, chacun des cas que la vue doit
savoir rendre : les trois mondes, les verdicts de chaque niveau, et les deux témoins négatifs.

Tout ce qui peut l'être est cantonné au namespace `kdt-hooks-test`, par un `namespaceSelector` qui
nomme ce namespace. Les objets eux-mêmes sont cluster-scoped — c'est la nature de ces quatre kinds —
donc ils apparaîtront dans la vue de tout le monde tant qu'ils sont posés.

| Fichier | Ce qu'il exerce |
|---|---|
| `01-ns.yaml` | le namespace de test |
| `02-vwc-orphan-fail.yaml` | `failurePolicy: Fail` vers un service inexistant → **Danger** : les écritures qui matchent sont refusées |
| `03-vwc-orphan-ignore.yaml` | la même en `Ignore`, timeout 25 s → **Warn** : rien n'est bloqué, chaque requête paie l'attente |
| `04-vwc-catchall.yaml` | règle `*/*/*` sans exclusion système → **Warn** attrape-tout, `sideEffects: Unknown` |
| `05-mwc-mixed.yaml` | trois webhooks, trois `failurePolicy` (dont une absente) dans **une** configuration |
| `06-vwc-empty.yaml` | `webhooks: []` → **Info** : le vestige d'un opérateur désinstallé |
| `07-vwc-ca.sh` | un caBundle qui expire dans 7 jours → **Warn** (script, pas manifeste : voir plus bas) |
| `08-crd-conversion.yaml` | CRD en `strategy: Webhook` vers un service mort → **Danger** : `kubectl get widgets` échoue |
| `09-crd-none.yaml` | CRD en `strategy: None` → **ne doit pas apparaître** dans le monde conversion |
| `10-apiservice.yaml` | APIService agrégée vers un service mort → **Danger** : `Available=False`, découverte incomplète |

`05` est celui qui compte le plus : il prouve qu'une ligne doit être un **webhook nommé** et non une
configuration. Replié sur l'objet, la colonne POLICY n'aurait que « mixte » à écrire, et le
`mixed-default.kdt.test` — qui n'écrit pas `failurePolicy` du tout — doit se lire `Fail` en grisé,
parce que c'est le défaut de l'apiserver et non ce que l'objet dit.

## Avertissements

**`04-vwc-catchall.yaml` est en `Ignore`, et doit le rester.** Un `*/*/*` en `Fail` vers un service
qui ne répond pas bloque **toutes** les écritures du cluster, `kube-system` compris — et le
désinstaller demande précisément d'écrire. Ne pas le basculer en `Fail`, y compris depuis la vue
avec `P`, sur un cluster qu'on ne peut pas jeter.

**`10-apiservice.yaml` dégrade la découverte tant qu'il est posé.** `kubectl api-resources` se
plaindra du groupe `kdt.test`, et certains clients mettront quelques secondes de plus à démarrer.
C'est précisément ce que la vue sert à rendre visible ; c'est aussi pourquoi il se retire à la fin.

## Application

L'ordre est libre, sauf le namespace en premier.

```sh
kubectl --context <ctx> apply -f test/hooks/01-ns.yaml
kubectl --context <ctx> apply -f test/hooks/02-vwc-orphan-fail.yaml
kubectl --context <ctx> apply -f test/hooks/03-vwc-orphan-ignore.yaml
kubectl --context <ctx> apply -f test/hooks/04-vwc-catchall.yaml
kubectl --context <ctx> apply -f test/hooks/05-mwc-mixed.yaml
kubectl --context <ctx> apply -f test/hooks/06-vwc-empty.yaml
sh test/hooks/07-vwc-ca.sh --context <ctx>
kubectl --context <ctx> apply -f test/hooks/08-crd-conversion.yaml
kubectl --context <ctx> apply -f test/hooks/09-crd-none.yaml
kubectl --context <ctx> apply -f test/hooks/10-apiservice.yaml
```

`07-vwc-ca.sh` est un script parce qu'un certificat écrit dans un YAML versionné serait périmé
quelques jours plus tard : la fixture testerait alors « expiré » sans qu'on l'ait demandé. Il prend
les mêmes arguments que `kubectl` et les lui passe, d'où le `--context` à la fin.

## Retrait

```sh
kubectl --context <ctx> delete validatingwebhookconfiguration \
  kdt-hooks-orphan-fail kdt-hooks-orphan-ignore kdt-hooks-catchall kdt-hooks-empty \
  kdt-hooks-ca-expiring
kubectl --context <ctx> delete mutatingwebhookconfiguration kdt-hooks-mixed
kubectl --context <ctx> delete apiservice v1alpha1.kdt.test
kubectl --context <ctx> delete crd widgets.kdt.test gadgets.kdt.test
kubectl --context <ctx> delete namespace kdt-hooks-test
```

Retirer l'APIService **avant** la CRD : tant qu'elle est là, la découverte du groupe `kdt.test` est
en échec, et la suppression de la CRD passe par cette même découverte.
