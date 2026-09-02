#!/usr/bin/env bash
# Print the CHANGELOG section of one version, for the release notes of its tag.
#
# Takes the tag (`v1.25.0`) or the bare version, and writes the entries of that section without its
# heading. A version with no section is not an error: the release is still published, with a line
# pointing at the file, rather than failing a whole workflow over its notes.
#
# `awk` only, no `sed` address ranges: this runs on the macOS runner too, and the blank lines a
# plain extraction leaves at either end are invisible in the rendered notes.
set -euo pipefail

version="${1#v}"
changelog="${2:-CHANGELOG.md}"

# `index(...) == 1` anchors on the heading, and the trailing space keeps `1.2.0` from matching
# `1.2.0-rc1`.
section=$(awk -v v="$version" '
  index($0, "## [" v "] ") == 1 { found = 1; next }
  found && /^## \[/ { exit }
  found { print }
' "$changelog")

if printf '%s' "$section" | grep -q '[^[:space:]]'; then
  printf '%s\n' "$section"
else
  printf 'Notes de version absentes du CHANGELOG pour %s — voir CHANGELOG.md.\n' "$version"
fi
