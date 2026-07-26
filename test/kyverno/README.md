# Jeu de test Kyverno pour la vue `:kyverno`

Manifestes jetables qui produisent, sur un cluster où Kyverno tourne, chacun des cas que la vue
doit savoir rendre. Tout est cantonné au namespace `kdt-kyverno-test` : les deux ClusterPolicy
matchent explicitement ce namespace, parce qu'une `ClusterPolicy` en `Enforce` non scopée bloquerait
des créations réelles ailleurs sur le cluster.

| Fichier | Ce qu'il exerce |
|---|---|
| `01-ns.yaml` | le namespace de test |
| `02-workloads.yaml` | quatre Deployments : sans limits, en `:latest`, conforme, et couvert par l'exception |
| `03-cpol-require-limits.yaml` | `ClusterPolicy` **Enforce** + autogen → résultats `fail` |
| `04-cpol-audit-latest.yaml` | `ClusterPolicy` **Audit**, deux règles → résultats `fail` non bloquants |
| `05-vpol-broken.yaml` | `ValidatingPolicy` CEL (moteur `policies.kyverno.io/v1`) qui explose à l'évaluation → résultats **`error`** |
| `06-polex.yaml` | `PolicyException` rattachée à une règle autogen |
| `07-cleanuppolicy.yaml` | `CleanupPolicy` : ni règles ni rapport, seulement une crontab |

## Application

**L'ordre compte.** Les charges de travail passent en premier, avant la policy `Enforce` : une
ressource refusée à l'admission n'existe pas, donc n'apparaît dans aucun `PolicyReport`. En
appliquant les workloads d'abord, ils existent et c'est le scan de fond qui les rapporte — le cas
que la vue montre dans son arbre.

```sh
kubectl apply -f test/kyverno/01-ns.yaml
kubectl apply -f test/kyverno/02-workloads.yaml
kubectl apply -f test/kyverno/03-cpol-require-limits.yaml
kubectl apply -f test/kyverno/04-cpol-audit-latest.yaml
kubectl apply -f test/kyverno/05-vpol-broken.yaml
kubectl apply -f test/kyverno/06-polex.yaml     # voir le prérequis ci-dessous
kubectl apply -f test/kyverno/07-cleanuppolicy.yaml
```

Le scan de fond (`--resyncPeriod=15m` par défaut) peut mettre un moment ; les rapports d'admission
sont eux immédiats. Pour forcer une réévaluation d'un objet précis : la touche `h` de kdt, ou
`kubectl annotate --overwrite`.

### Prérequis pour `06-polex.yaml`

Les `PolicyException` ne sont prises en compte que si les contrôleurs tournent avec
`--enablePolicyException=true`. Par défaut le chart les démarre à `false` : l'objet est créé, la vue
le liste et le rattache à sa policy, mais l'exception n'a aucun effet et le `fail` de
`legacy-excepted` reste. Pour l'activer sur un cluster de test :

```sh
for d in kyverno-admission-controller kyverno-background-controller kyverno-reports-controller; do
  kubectl -n kyverno patch deploy "$d" --type=json \
    -p='[{"op":"replace","path":"/spec/template/spec/containers/0/args","value":["--enablePolicyException=true"]}]' \
    2>/dev/null || true
done
```

(La forme exacte dépend des args déjà posés par le chart : relire `kubectl -n kyverno get deploy
kyverno-admission-controller -o jsonpath='{.spec.template.spec.containers[0].args}'` avant de
patcher, et ne remplacer que la valeur du flag.)

## Cas à provoquer à la main

Le **refus d'admission** n'est dans aucun `PolicyReport` — c'est tout l'intérêt du bandeau
« refus d'admission récents » du panneau détail. Pour en produire un, appliquer une ressource
violante *après* la policy `Enforce` :

```sh
kubectl -n kdt-kyverno-test run refused --image=registry.k8s.io/pause:3.9
# Error from server: admission webhook "validate.kyverno.svc-fail" denied the request
```

## Nettoyage

```sh
kubectl delete -f test/kyverno/06-polex.yaml -f test/kyverno/05-vpol-broken.yaml \
               -f test/kyverno/04-cpol-audit-latest.yaml -f test/kyverno/03-cpol-require-limits.yaml \
               --ignore-not-found
kubectl delete ns kdt-kyverno-test --ignore-not-found
```
