#!/bin/sh
# Prints one version's section of a plugin folder's CHANGELOG.md: the lines under "## <version>" up to the
# next "## " heading, without leading blank lines. Nothing when the file or the section is missing.
#
#   sh tools/changes.sh switch-updates 1.1.1
[ -f "$1/CHANGELOG.md" ] || exit 0
awk -v version="$2" '/^## / { on = ($2 == version); next } on' "$1/CHANGELOG.md" | sed '/./,$!d'
