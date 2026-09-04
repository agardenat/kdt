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

# A SemVer pre-release (`1.26.0-beta.1`) is spelled the same way by nobody: Cargo writes it with a
# dash, `rpm` refuses a dash in `Version` outright, and `dpkg` would read it as an upstream version
# followed by a revision. Both have to sort **below** the final release, which is the whole point of
# cutting a beta:
#   dpkg — `~` sorts lower than anything, the empty string included, so `1.26.0~beta.1 < 1.26.0`.
#   rpm  — the pre-release moves into `Release`, prefixed `0.` so that `0.beta.1` sorts below the
#          `1` the final build uses.
if [[ "$VERSION" == *-* ]]; then
    UPSTREAM="${VERSION%%-*}"
    PRERELEASE="${VERSION#*-}"
    DEB_VERSION="${UPSTREAM}~${PRERELEASE}"
    RPM_VERSION="$UPSTREAM"
    RPM_RELEASE="0.${PRERELEASE}"
else
    DEB_VERSION="$VERSION"
    RPM_VERSION="$VERSION"
    RPM_RELEASE="1"
fi

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
