# Capito27's plugins

Plugins for [pokeldn](https://github.com/Decryptu/pokeldn), each in its own folder, and the source listing
`pokeldn-source.json` that names their released packages.

| folder | plugin | what it adds |
|---|---|---|
| `switch-updates` | Switch Updates | backs up a Switch game's update or system update, and sends a saved update to another console, through Match Version With Local Users |

## Installing

Open **Plugins**, then **Sources**, and add

    capito27/pokeldn-capito27-plugins

then press **Install** on the plugin under **Browse**. A `.pokeplugin` from
[Releases](https://github.com/capito27/pokeldn-capito27-plugins/releases) can also be dropped on the Plugins page.
Every package is signed; the install screen shows the key's fingerprint, the same for every version.

## Publishing a version

Raise `version` in the plugin's `plugin.toml`, add a `## <version>` section with the changes to the plugin's
`CHANGELOG.md`, and push to `main`. The [Release](.github/workflows/release.yml) workflow refuses a version
without that section, then tests every plugin folder against pokeldn on Linux and Windows. Then, for each folder
whose version has no release yet, it:

- packs the folder, signed with the `PLUGIN_SIGNING_KEY` secret
- creates the `<id>-<version>` release holding the package, with the version's changelog section as its notes
- commits the new entry and its SHA-256 to `pokeldn-source.json`

Players see the new version once that commit is on `main`. A push that leaves the versions alone only runs the
tests. **Run workflow** under Actions does the same for one folder or for all of them. `exclude` in
`plugin.toml` keeps the tests, tools and docs out of the package.

The key is made once, straight into the secret, so it is never written to disk. It needs a Python with
pycryptodome, such as pokeldn's own: without one, the secret is stored empty, and the release stops at
"Signing key".

    python -c "from Crypto.PublicKey import ECC; print(ECC.generate(curve='ed25519').export_key(format='PEM'))" | gh secret set PLUGIN_SIGNING_KEY -R capito27/pokeldn-capito27-plugins

GitHub never shows a secret again. So there is no copy to lose, but also none to restore: a new key signs
packages that installed copies refuse as an update, and players would have to remove the plugin and install it
again. Each run's summary names the key's fingerprint. `tools/publish.sh` is what the workflow runs; by hand it
takes the key as a PEM file in `KEY`.

## License

AGPL-3.0, like pokeldn: see [LICENSE](LICENSE).
