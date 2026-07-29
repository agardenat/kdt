#!/usr/bin/env bash
# Régénère les GIFs du README à partir des tapes VHS.
#
# Prérequis : vhs, ttyd (>= 1.7.4), ffmpeg, la police JetBrains Mono, et un
# cluster joignable — kdt n'a pas de mode hors-ligne, le film tourne contre le
# cluster du kubeconfig courant.
#
# Les tapes utilisent des chemins relatifs à la racine du dépôt : on s'y place.

set -euo pipefail

cd "$(dirname "$0")/.."

BIN_DIR="target/x86_64-unknown-linux-musl/release"

if [[ ! -x "$BIN_DIR/kdt" ]]; then
	echo "binaire absent : $BIN_DIR/kdt" >&2
	echo "construire d'abord : cargo build --release" >&2
	exit 1
fi

for tool in vhs ttyd ffmpeg; do
	command -v "$tool" >/dev/null || { echo "$tool introuvable" >&2; exit 1; }
done

# `Require kdt` dans les tapes vérifie cette entrée de PATH.
export PATH="$PWD/$BIN_DIR:$PATH"

tapes=("${@:-}")
if [[ -z "${tapes[0]}" ]]; then
	tapes=(demo/hero.tape demo/flux.tape demo/capacity.tape demo/kyverno.tape demo/rbac.tape)
fi

for tape in "${tapes[@]}"; do
	echo "==> $tape"
	vhs "$tape"
done

echo
echo "Poids des GIFs :"
du -h demo/*.gif | sort -k2
