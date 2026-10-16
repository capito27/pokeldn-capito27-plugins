"""What the tools leave on their pages (switchlcs.cards over pokeldn.panel): Match Version's card for the console
it met and how the share ended, a note with the game's icon on each library file a check, an import or a backup
touched, and the check's and the import's cards. Read back as the app reads the `[panel]` lines."""

import os
import shutil
from pathlib import Path

from pokeldn import panel

import lcs_check
import lcs_import
from switchlcs import cards, library
from tests.test_lcs_content import KEYS
from tests.test_lcs_simulate import game, match_run, plugin_data, trusting  # noqa: F401 -- fixtures
from tests.test_lcs_verify import signers, system_folder  # noqa: F401 -- a fixture
from tests.test_library import NAME, SYSTEM, keys_file, signed_nsp


def panels(printed):
    """The cards and notes a run printed, in order, as the app reads them."""
    return [panel.read(line) for line in printed.splitlines() if line.startswith(panel.PREFIX)]


def card(printed, id):
    """The last card shown under `id`."""
    return [p for p in panels(printed) if p and p.get("id") == id][-1]


def notes(printed):
    """{file: its last note}."""
    return {p["file"]: p for p in panels(printed) if p and "file" in p}


def rows(shown):
    return {label: value for label, value in (x for x in shown["lines"] if isinstance(x, list))}


def test_a_backup_shows_the_console_and_marks_the_saved_update(game, tmp_path, capsys, plugin_data):  # noqa: F811
    _base, update, _keys, icon = game
    code, printed, out = match_run(game, tmp_path, capsys, ["--pull"], ["--console", str(update)])
    assert code == 0, printed
    assert None not in panels(printed)
    shown = card(printed, "console")
    assert shown["title"] == "Game" and shown["tone"] == "ok"
    assert shown["lines"][0] == "Backed up its update 1.0.2"
    assert shown["chips"] == [["Installed", "1.0.2"]]
    assert rows(shown)["Game ID"] == "0100187003A36000" and rows(shown)["Publisher"] == "Maker"
    assert Path(shown["image"]).read_bytes() == icon
    assert shown["image"] == str(plugin_data / "icons" / "0100187003A36000.jpg")
    [saved] = os.listdir(out)
    assert rows(shown)["Saved"] == saved
    note = notes(printed)[saved]
    assert note["state"] == "ok" and note["text"].startswith("Backed up from ") and note["image"] == shown["image"]


def test_a_run_that_leaves_says_so_on_the_card(game, tmp_path, capsys, monkeypatch):  # noqa: F811
    """An upload the console already has: the card names the console's version and why pokeldn left."""
    trusting(monkeypatch)
    _base, update, _keys, _icon = game
    code, printed, _out = match_run(game, tmp_path, capsys, ["--offer", str(update)], ["--console", str(update)])
    assert code == 1
    shown = card(printed, "console")
    assert shown["tone"] == "warning" and "already has version v131072" in shown["lines"][0]
    assert rows(shown)["Internal version"] == "131072"


def test_a_check_marks_every_file_and_sums_it_up(signers, tmp_path, capsys, monkeypatch, plugin_data):  # noqa: F811
    from switchlcs import verify
    update, system = verify.check_update, verify.check_system
    monkeypatch.setattr(verify, "check_update", lambda *a, trust=None, **k: update(*a, trust=signers[1], **k))
    monkeypatch.setattr(verify, "check_system", lambda *a, trust=None, **k: system(*a, trust=signers[1], **k))
    root = tmp_path / "Switch"
    root.mkdir()
    signed_nsp(signers, root / NAME)
    folder, _names = system_folder(signers, tmp_path)
    library.zip_system(folder, root / SYSTEM)
    (root / "Broken.nsp").write_bytes(b"PFS0")
    argv = ["--keys", str(keys_file(tmp_path)), "--out", str(root), "--checks", str(tmp_path / "checks")]
    assert lcs_check.main(argv) == 1
    printed = capsys.readouterr().out
    assert None not in panels(printed)
    marked = notes(printed)
    assert {name: n["state"] for name, n in marked.items()} == {NAME: "ok", SYSTEM: "ok", "Broken.nsp": "bad"}
    assert marked[NAME]["text"].startswith("Complete") and marked[SYSTEM]["image"] is None
    checking = next(p for p in panels(printed) if p.get("file") == NAME)
    assert checking["state"] == "checking"
    shown = card(printed, "check")
    assert shown["tone"] == "error" and rows(shown) == {"Complete": "2", "Damaged or not Nintendo's": "1",
                                                        "Not checked": "0"}
    (root / "Broken.nsp").unlink()
    assert lcs_check.main(argv) == 0
    printed = capsys.readouterr().out
    assert card(printed, "check")["tone"] == "ok" and notes(printed)[NAME]["state"] == "ok"


def test_an_import_marks_the_file_it_added(signers, tmp_path, capsys, monkeypatch):  # noqa: F811
    from switchlcs import verify
    update = verify.check_update
    monkeypatch.setattr(verify, "check_update", lambda *a, trust=None, **k: update(*a, trust=signers[1], **k))
    root = tmp_path / "Switch"
    source = signed_nsp(signers, tmp_path / "copy.nsp")
    keys = keys_file(tmp_path)
    assert lcs_import.main(["--keys", str(keys), "--out", str(root), "--file", source]) == 0
    printed = capsys.readouterr().out
    assert notes(printed)[NAME]["state"] == "ok"
    shown = card(printed, "import")
    assert shown["tone"] == "ok" and shown["lines"] == [f"Imported {NAME}"]
    assert lcs_import.main(["--keys", str(keys), "--out", str(root), "--file", source]) == 1
    shown = card(capsys.readouterr().out, "import")
    assert shown["tone"] == "error" and shown["lines"][0].startswith("Not imported: copy.nsp: already saved")


def test_an_icon_comes_from_the_nsp_once_and_is_kept(game, plugin_data, tmp_path):  # noqa: F811
    base, _update, _keys, icon = game
    shutil.copy(base, tmp_path / "Game.nsp")
    entry = library.Saved("update", str(tmp_path / "Game.nsp"), "Game")
    path = cards.icon_of(entry, KEYS)
    assert path.read_bytes() == icon and path.parent == plugin_data / "icons"
    (tmp_path / "Game.nsp").write_bytes(b"")            # the kept icon is found by the update's ID
    assert cards.icon_of(library.Saved("update", entry.path, "Game", "0100187003A36800"), KEYS) == path
    named = tmp_path / "Game [0100187003A36800][v131072](1.0.2).nsp"    # or the one in its name, without keys
    named.write_bytes(b"")
    assert cards.icon_of(library.Saved("update", str(named), ""), None) == path
    assert cards.icon_of(library.Saved("system", entry.path, "System update 20.5.0"), KEYS) is None


def test_a_game_keeps_the_first_icon_found_for_it(plugin_data):  # noqa: F811
    first = cards.save_icon(0x0100187003A36000, b"\xff\xd8 the first")
    assert first.read_bytes() == b"\xff\xd8 the first"
    assert cards.save_icon(0x0100187003A36800, b"\xff\xd8 a later update's") == first   # its update's ID
    assert first.read_bytes() == b"\xff\xd8 the first"
    assert cards.save_icon(0x0100187003A36000, b"not a JPEG") == first
    assert cards.save_icon(0x01008F6008C5E000, b"not a JPEG") is None


def test_long_names_fit_the_card(capsys):
    advert = type("Advertisement", (), {"name": "N" * 300, "node_count": 1, "max_nodes": 8})()
    control = type("Control", (), {"name": "T" * 300, "publisher": "P" * 300})()
    app = type("App", (), {"application_id": 1 << 56, "display_version": b"9" * 16, "update_size": 1})()
    console = cards.Console()
    console.found(advert, app, control)
    console.end("error", "E" * 500, Saved="S" * 500)
    shown = card(capsys.readouterr().out, "console")
    assert len(shown["title"]) == panel.TITLE and shown["lines"][0].endswith("…")


def test_the_cards_speed_adds_up_each_transfer(monkeypatch):
    """A system update can arrive in more than one transfer, each counting from 0 again."""
    import lcs_match
    clock = iter([10.0, 11.0, 12.0, 13.0, 14.0])
    monkeypatch.setattr(lcs_match.time, "monotonic", lambda: next(clock))
    flow = lcs_match.Flow()
    for done in (0, 1_000_000, 2_000_000, 500_000, 1_000_000):
        flow.moved(done)
    assert flow.speed() == "0.75 MB/s"
    assert lcs_match.Flow().speed() == ""
