#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"

NAME="$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -n1)"
VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -n1)"
SUMMARY="kdt — Kubernetes Diagnostic Tools"
MAINTAINER="Antoine Gardenat <agardenat@leisambro.net>"
LICENSE="proprietary"

TARGET_TRIPLE="x86_64-unknown-linux-musl"

build_binary() {
    echo ">> cargo build --release ($TARGET_TRIPLE)"
    ( cd "$ROOT" && cargo build --release )
    BIN="$ROOT/target/$TARGET_TRIPLE/release/$NAME"
    if [[ ! -x "$BIN" ]]; then
        BIN="$(find "$ROOT/target" -type f -name "$NAME" -path '*release*' ! -name '*.d' 2>/dev/null | head -n1)"
    fi
    [[ -x "$BIN" ]] || { echo "binaire introuvable" >&2; exit 1; }
    echo ">> binaire: $BIN"
}
