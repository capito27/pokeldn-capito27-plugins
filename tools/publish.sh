#!/bin/sh
# Releases one plugin folder's version and lists it in pokeldn-source.json. A version already released as
# <id>-<version> is only listed, from its release; a new one is packed, signed with KEY and released first.
# .github/workflows/release.yml runs it for every plugin folder. By hand it needs a pokeldn checkout (POKELDN,
# default ../pokeldn), the signing key (KEY, a PEM file, never made here: packages signed by another key are
# refused as updates) and gh signed in. PUBLISH=0 packs and lists without looking at GitHub. The release notes
# are the version's "## <version>" section of the folder's CHANGELOG.md, which a new version must have.
#
#   KEY=signing.pem sh tools/publish.sh switch-updates
set -e
folder="$1"
[ -f "$folder/plugin.toml" ] || { echo "usage: sh tools/publish.sh <plugin folder>" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
pokeldn=${POKELDN:-$root/../pokeldn}
repo=${REPO:-capito27/pokeldn-capito27-plugins}
python=${PYTHON:-$pokeldn/.venv/bin/python}
[ -x "$python" ] || [ -n "$PYTHON" ] || python=$pokeldn/.venv/Scripts/python.exe
[ -x "$python" ] || [ -n "$PYTHON" ] || python=python3
version=$("$python" -c "import sys, tomllib; print(tomllib.load(open(sys.argv[1], 'rb'))['version'])" "$folder/plugin.toml")
id=$("$python" -c "import sys, tomllib; print(tomllib.load(open(sys.argv[1], 'rb'))['id'])" "$folder/plugin.toml")
tag=$id-$version
file=$tag.pokeplugin
mkdir -p "$root/dist"
if [ "${PUBLISH:-1}" = 1 ] && gh release view "$tag" -R "$repo" >/dev/null 2>&1; then
    echo "$tag is released: listing it"
    gh release download "$tag" -R "$repo" -p "$file" -D "$root/dist" --clobber
else
    notes=$(sh "$root/tools/changes.sh" "$folder" "$version")
    [ -n "$notes" ] || { echo "$folder/CHANGELOG.md has no '## $version' section" >&2; exit 1; }
    [ -n "$KEY" ] && [ -f "$KEY" ] || { echo "KEY must name the signing key's PEM file" >&2; exit 1; }
    (cd "$root/dist" && "$python" "$pokeldn/scripts/pack_plugin.py" "$root/$folder" --key "$KEY")
    if [ "${PUBLISH:-1}" = 1 ]; then
        gh release create "$tag" "$root/dist/$file" --title "$tag" --notes "$notes" -R "$repo" \
            ${TARGET:+--target "$TARGET"}
    fi
fi
cd "$root"
"$python" "$pokeldn/scripts/plugin_source.py" "dist/$file" -o pokeldn-source.json --name "Capito27's plugins" \
    --homepage "https://github.com/$repo" \
    --download "https://github.com/$repo/releases/download/{id}-{version}/{file}" \
    --icon "https://raw.githubusercontent.com/$repo/main/$folder/icon.png"
