#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

ARCH="amd64"
build_binary

STAGE="$DIST/deb/${NAME}_${VERSION}_${ARCH}"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin"

install -Dm755 "$BIN" "$STAGE/usr/bin/$NAME"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Maintainer: $MAINTAINER
Description: $SUMMARY
 TUI Rust pour surveiller les évènements Kubernetes, inspecter les nœuds,
 lancer un diagnostic cluster et exporter des rapports.
EOF

OUT="$DIST/${NAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT"
echo ">> $OUT"
