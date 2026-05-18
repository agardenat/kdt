#!/usr/bin/env bash
set -euo pipefail
HERE="$(dirname "${BASH_SOURCE[0]}")"
bash "$HERE/build-deb.sh"
bash "$HERE/build-rpm.sh"
