# Switch Updates

A pokeldn plugin that backs up a Nintendo Switch game's update or system update, and sends a saved update to
another console, through the console's own **Match Version With Local Users** (`nn::lcs`). pokeldn joins the
console's group over the ESP32 board as one more console: no homebrew, and nothing changes on the console unless
it takes an update. It needs pokeldn 0.29.0 or newer (plugin API 1.8), the board, and `prod.keys` chosen in
Settings; from 0.29.1 an upload runs at the board's full speed, about 0.5 MB/s.

## The tools

They appear under **Switch Updates** on the Games page. Each run leaves a card at the top of its tool's page, and
a note with the game's icon on each library file it touched.

| tool | what it does |
|---|---|
| Match Version | On the console: HOME, highlight the game, +, **Software Update → Match Version With Local Users → Next → Create Group**, then Start. The card shows the game, its group and its installed version; a pop-up offers to back up its update, send it a newer one from the library, back up its system update, or leave. The card then says how the share ended and at what speed. |
| Check saved updates | Hashes every file in the library against its content meta and verifies Nintendo's signatures; a file that passed is read again only once it changes. |
| Import an update | Adds an NSP, a system update's NCAs or an archive of them (zip, 7z, rar, tar) once it passes the same checks. |

**An older update.** A console registers the newest version of a game it has run as that game's minimum version
and refuses any update below it, even after deleting the update. The only way to reset that minimum and send an
older update is to factory reset the console, then play the game from a release-day cartridge, without updating
it, before the share. Match Version says so when the console refuses.

## The library

`Documents/pokeldn/Switch`, one file per update, sorted by name until the player picks another order:

    Pokémon Brilliant Diamond [0100000011D90800][v196608](1.3.0).nsp
    System update 20.5.0.zip

A system update is a stored ZIP of its NCAs. Unfinished transfers keep hidden names until whole. A library in the
older layout (`Updates/`, `System/<version>/`) is converted on the first run. The data folder
(`plugin-data/switch-updates`) keeps the checks' results, the system version pokeldn claims and the games' icons,
each with a small copy for the library's rows.

## Sources

The protocol is documented in [`docs/lcs.md`](docs/lcs.md): captures of pokeldn sharing with consoles, our own
reading of firmware 20.5.0's qlaunch, `ns` and `nim`, and switchbrew. The plugin holds no Nintendo code, keys or
content: it reads the player's `prod.keys` and serves only updates a console sent or the player imported, which
the receiving console checks against Nintendo's signatures.

## Development

    POKELDN_SOURCE=../../pokeldn ../../pokeldn/.venv/Scripts/python -m pytest -q -W error

The tests need a pokeldn checkout of plugin API 1.8 (`POKELDN_SOURCE`, else a `pokeldn` folder next to this
repository). `tools/lcs_host.py` hosts a group as a console would, `tools/lcs_simulate.py pull|offer|system` runs
a whole share against it over loopback or two simulated boards, `tools/lcs_ns_check.py` and
`tools/lcs_qlaunch_check.py` check the protocol constants against firmware dumps, and `tools/make_icons.py` draws
the icons. The thumbnail tests compare against Pillow and are skipped without it.

## License

AGPL-3.0, like pokeldn: see [LICENSE](https://github.com/capito27/pokeldn-capito27-plugins/blob/main/LICENSE).
