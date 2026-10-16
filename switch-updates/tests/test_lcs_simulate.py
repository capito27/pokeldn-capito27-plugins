"""lcs_match.py, the plugin's Match Version tool, against tools/lcs_host.py --console over loopback, with small built
NSPs: a base game whose Control NCA holds a RomFS (control.nacp and an icon), and an update with a rights-id Program
NCA and its ticket. tools/lcs_simulate.py runs both and compares every file the receiver wrote with the source's;
the library it saves into holds one NSP per update and one ZIP per system update."""

import os
import shutil
import struct
from types import SimpleNamespace

import pytest

from switchlcs import content, loopback, nca
from tests.test_lcs_content import KEYS, build_cnmt, build_nca, build_romfs, info_for
from tests.test_lcs_control import nacp

APP = 0x0100187003A36000
PATCH = APP | 0x800
REQUIRED_SYSTEM = 0x20100000            # 8.1.0


def write_nsp(path, files):
    """A PFS0 of `files` ({name: bytes})."""
    names = b"".join(n.encode() + b"\0" for n in files)
    names += bytes(-(16 + 24 * len(files) + len(names)) % 0x20)
    table, at, name_at = b"", 0, 0
    for n, data in files.items():
        table += struct.pack("<QQII", at, len(data), name_at, 0)
        at += len(data)
        name_at += len(n) + 1
    with open(path, "wb") as fh:
        fh.write(b"PFS0" + struct.pack("<III", len(files), len(names), 0) + table + names
                 + b"".join(files.values()))


def meta_files(key, contents, extended=bytes(0x10)):
    """{name: bytes} of the Meta NCA for `key` listing `contents` ((raw, type) pairs) and the contents."""
    infos = [info_for(raw, ctype) for raw, ctype in contents]
    meta = build_nca(nca.NCA_META, key.id, pfs_files=[("x.cnmt", build_cnmt(key, infos, extended=extended))])
    files = {info_for(meta, nca.META).content_id.hex() + ".cnmt.nca": meta}
    files.update({i.content_id.hex() + ".nca": raw for i, (raw, _t) in zip(infos, contents)})
    return files


@pytest.fixture
def game(tmp_path):
    icon = b"\xff\xd8\xff\xe0" + os.urandom(3000)
    control = build_nca(2, APP, romfs=build_romfs({"control.nacp": nacp("Game", "Maker", "1.0.0"),
                                                   "icon_AmericanEnglish.dat": icon}))
    base = tmp_path / "base.nsp"
    write_nsp(base, meta_files(nca.ContentMetaKey(APP, 0, nca.APPLICATION),
                               [(control, nca.CONTROL), (build_nca(0, APP, body=os.urandom(5000)), nca.PROGRAM)]))
    rights = struct.pack(">Q", PATCH) + bytes(7) + b"\x07"
    program = build_nca(0, APP, body=os.urandom(300_000), rights_id=rights)
    update = tmp_path / "update.nsp"
    update_control = build_nca(2, APP, romfs=build_romfs({"control.nacp": nacp("Game", "Maker", "1.0.2")}))
    files = meta_files(nca.ContentMetaKey(PATCH, 0x20000, nca.PATCH),
                       [(program, nca.PROGRAM), (update_control, nca.CONTROL)],
                       extended=struct.pack("<QII", APP, REQUIRED_SYSTEM, 0))       # Let's Go 1.0.2's: 8.1.0
    files.update({rights.hex() + ".tik": os.urandom(0x2C0), rights.hex() + ".cert": os.urandom(0x700)})
    write_nsp(update, files)
    keys = tmp_path / "prod.keys"
    keys.write_text("".join(f"{k} = {v.hex()}\n" for k, v in KEYS.items()))
    return base, update, keys, icon


def test_control_data_from_an_nsp(game):
    base, _update, _keys, icon = game
    app_id, data = content.nsp_control_data(str(base), KEYS)
    assert app_id == APP and data == nacp("Game", "Maker", "1.0.0") + icon


@pytest.fixture(autouse=True)
def plugin_data(tmp_path_factory, monkeypatch):
    """The plugin's data folder (the claimed system version, the checks), one per test."""
    from switchlcs import library
    folder = tmp_path_factory.mktemp("plugin-data")
    monkeypatch.setattr(library, "data_folder", lambda: folder)
    return folder


def trusting(monkeypatch):
    """The built update carries no Nintendo signatures; switchlcs.verify has its own tests. -> the stand-in
    check_update, which reports the fixture's update: v0x20000, display version 1.0.2."""
    import lcs_match
    from switchlcs import control, verify

    def check_update(path, *a, **k):
        return verify.UpdateInfo(str(path), APP, PATCH, 0x20000, 0, os.path.getsize(path),
                                 control.ApplicationControl.parse(nacp("Game", "Maker", "1.0.2")))
    monkeypatch.setattr(lcs_match.verify, "check_update", check_update)
    return check_update


@pytest.mark.parametrize("scenario", ["pull", "offer"])
def test_loopback_scenarios(game, tmp_path, capsys, monkeypatch, scenario):
    import lcs_simulate
    trusting(monkeypatch)
    base, update, keys, icon = game
    out = tmp_path / "out"
    assert lcs_simulate.main([scenario, "--base", str(base), "--update", str(update), "--out", str(out),
                              "--keys", str(keys), "--timeout", "20"]) == 0
    printed = capsys.readouterr().out
    assert "5 received file(s) identical to the source's" in printed
    assert "Game (Maker)" in printed and (out / "icon.jpg").read_bytes() == icon
    if scenario == "pull":          # one NSP at the library's top, named with its Control NCA's display version
        assert os.listdir(out / "pokeldn") == [f"Game [{PATCH:016X}][v{0x20000}](1.0.2).nsp"]
    else:
        assert len(os.listdir(out / "console")) == 5 and os.listdir(out / "pokeldn") == []


def test_boards_refuse_a_large_update(game, tmp_path, monkeypatch, capsys):
    import lcs_simulate
    base, update, keys, _icon = game
    monkeypatch.setattr(lcs_simulate, "BOARD_LIMIT", 1000)
    assert lcs_simulate.main(["pull", "--transport", "boards", "--base", str(base), "--update", str(update),
                              "--out", str(tmp_path / "out"), "--keys", str(keys)]) == 2
    assert "--transport loopback" in capsys.readouterr().err


def test_loopback_advertisement():
    host = loopback.LoopbackHost(b"x" * 0x100)
    host.start()
    try:
        guest = loopback.LoopbackGuest()
        guest.start(timeout=5)
        assert guest.app_data == b"x" * 0x100
        host.set_app_data_later(b"y" * 0x100)
        guest.start(timeout=5)
        assert guest.app_data == b"y" * 0x100
    finally:
        host.stop()


def test_a_stopped_loopback_host_no_longer_advertises():
    host = loopback.LoopbackHost(b"x" * 0x100)
    host.start()
    loopback.LoopbackGuest().start(timeout=5)       # the advertise thread is back in accept
    host.stop()
    with pytest.raises(TimeoutError):
        loopback.LoopbackGuest().start(timeout=0.5)
    host = loopback.LoopbackHost(b"y" * 0x100)
    host.start()
    try:
        guest = loopback.LoopbackGuest()
        guest.start(timeout=5)
        assert guest.app_data == b"y" * 0x100
    finally:
        host.stop()


def match_run(game, tmp_path, capsys, args, host_args):
    """lcs_match.py `args` against a stand-in console run with `host_args`. -> (exit code, what it printed, the
    library)."""
    import lcs_host
    import lcs_match
    import lcs_simulate
    base, _update, keys, _icon = game
    common = ["--keys", str(keys), "--timeout", "20", "--loopback"]
    host = lcs_simulate.Run("console", lcs_host.main, ["--name", "Console", "--out", str(tmp_path / "console"),
                                                       "--control-from", str(base), *host_args, *common])
    host.start()
    out = tmp_path / "Switch"
    try:
        code = lcs_match.main(["--out", str(out), "--icon", str(tmp_path / "icon.jpg"), *args, *common])
    finally:
        host.join(30)
    return code, capsys.readouterr().out, out


@pytest.mark.parametrize("pick", ["Back up its update 1.0.2", "Send update 1.0.2 (131072)", "Leave the group"])
def test_the_tool_lists_what_the_console_can_take(game, tmp_path, capsys, monkeypatch, pick):
    """Run as the app runs it, with no option: it shows the console's game and asks. A console with the update
    can give it or its system update; one with the base game only can take a newer update from the library."""
    import lcs_match
    trusting(monkeypatch)
    base, update, _keys, icon = game
    asked = []

    def ask(title, text, labels):
        asked.append((title, labels))
        return labels.index(pick) if pick in labels else None
    monkeypatch.setattr(lcs_match, "ask", ask)
    out = tmp_path / "Switch"
    sending = pick.startswith("Send")
    if sending:                     # the library holds the update; the console has the base game
        out.mkdir()
        shutil.copy(update, out / "Game.nsp")
    code, printed, out = match_run(game, tmp_path, capsys, [], ["--console", str(base if sending else update)])
    assert code == 0, printed
    [(title, labels)] = asked
    assert title == "Found Game" and (tmp_path / "icon.jpg").read_bytes() == icon
    if sending:
        assert "Game (Maker), " + f"{APP:016X}: no update installed" in printed
        assert labels == ["Send update 1.0.2 (131072)", "Leave the group"]
        assert "[progress] " in printed and "Sent 0 MB to the console." in printed
        assert len(os.listdir(tmp_path / "console")) == 5
        return
    assert f"Game (Maker), {APP:016X}: version 1.0.2, an update of 0 MB" in printed
    assert labels == ["Back up its update 1.0.2", "Back up its system update", "Leave the group"]
    if pick == "Leave the group":
        assert printed.splitlines()[-1] == "Left the group." and os.listdir(out) == []
        return
    name = f"Game [{PATCH:016X}][v{0x20000}](1.0.2).nsp"
    assert os.listdir(out) == [name] and f"Saved {name}" in printed       # the parts folder is gone
    ours, theirs = dict(content._pfs0_entries(str(out / name))), dict(content._pfs0_entries(str(update)))
    assert set(ours) == set(theirs)
    for entry, at in ours.items():
        assert content._read(str(out / name), *at) == content._read(str(update), *theirs[entry])


def test_a_saved_copy_and_the_newest_offers_are_listed(monkeypatch):
    """At most MAX_OFFERS newer updates, newest first: with pull, system and leave, the pop-up's 8 buttons."""
    import lcs_match
    from switchlcs import library
    saved = [library.Saved("update", f"{v}.nsp", "Game", f"{PATCH:016X}", v << 16, f"1.0.{v}") for v in range(1, 10)]
    monkeypatch.setattr(library, "saved", lambda out: saved)
    monkeypatch.setattr(library, "read", lambda entry, keys: entry)
    app = SimpleNamespace(application_id=APP, update_size=1, display_version=b"1.0.2\0\0")
    options = lcs_match.choices(app, None, "library", {})
    assert [label for _a, _n, label in options] == [
        "Back up its update 1.0.2 (already saved)",
        *(f"Send update 1.0.{v} ({v << 16})" for v in (9, 8, 7, 6, 5)),
        "Back up its system update", "Leave the group"]
    assert options[1][:2] == ("offer", "9.nsp") and options[-1][0] is None
    assert [label for _a, _n, label in lcs_match.choices(None, None, "library", {})] == \
        ["Back up its system update", "Leave the group"]


def test_the_choice_is_a_pop_up_in_the_app_and_a_numbered_list_in_a_terminal(monkeypatch, capsys):
    import builtins
    import lcs_match
    monkeypatch.setattr(lcs_match.popup, "available", lambda: True)
    shown = []

    def choose(title, text, options, *, id=None, on_choice=None, on_dismiss=None, tone="info"):
        shown.append((title, options, id))
        (on_choice(2) if options[0] == "a" else on_dismiss())
    monkeypatch.setattr(lcs_match.popup, "choose", choose)
    assert lcs_match.ask("Found Game", "Choose.", ["a", "b", "c"]) == 2
    assert lcs_match.ask("Found Game", "Choose.", ["x", "y"]) is None
    assert shown[0] == ("Found Game", ["a", "b", "c"], "lcs-choice")
    monkeypatch.setattr(lcs_match.popup, "available", lambda: False)
    typed = iter(["9", "", "2"])
    monkeypatch.setattr(builtins, "input", lambda prompt: next(typed))
    assert lcs_match.ask("Found Game", "Choose.", ["a", "b"]) == 1
    assert "  1. a\n  2. b" in capsys.readouterr().out

    def closed(prompt):
        raise EOFError
    monkeypatch.setattr(builtins, "input", closed)
    assert lcs_match.ask("Found Game", "Choose.", ["a", "b"]) is None


def test_the_console_sends_its_system_update(game, tmp_path, capsys, plugin_data):
    """The system scenario: pokeldn claims 0.0.0, and the stand-in console sends the system update installed in a
    folder, which pokeldn packs into its ZIP and remembers the version of. Both sides record their lcs messages."""
    import json
    import zipfile

    import lcs_simulate
    from switchlcs import library
    from tests.test_lcs_session import guest_source, install
    base, update, keys, _icon = game
    firmware = tmp_path / "registered"
    firmware.mkdir()
    install(guest_source()[0], firmware)
    out = tmp_path / "out"
    assert lcs_simulate.main(["system", "--base", str(base), "--update", str(update), "--system", str(firmware),
                              "--out", str(out), "--keys", str(keys), "--timeout", "20", "--capture"]) == 0
    assert "3 received file(s) identical to the source's" in capsys.readouterr().out
    assert os.listdir(out / "pokeldn") == ["System update 20.5.0.zip"]
    with zipfile.ZipFile(out / "pokeldn" / "System update 20.5.0.zip") as z:
        assert {i.compress_type for i in z.infolist()} == {zipfile.ZIP_STORED}
    assert library.system_version(plugin_data) == "20.5.0"
    for side, sent in (("console", "RECEIVE_SYSTEM_UPDATE"), ("pokeldn", "RECEIVE_SYSTEM_UPDATE_REPLY")):
        records = [json.loads(line) for line in (out / f"{side}.jsonl").read_text().splitlines()]
        assert any(r.get("name") == sent and r["dir"] == "out" for r in records)
    # then a refresh in sync with the console, which completes the share without its game update
    names = [r.get("name") for r in records if r.get("dir") == "out"]
    assert names[names.index("RECEIVE_SYSTEM_UPDATE_REPLY"):][-1] == "JOIN_REFRESH"
    console = [r.get("name") for r in map(json.loads, (out / "console.jsonl").read_text().splitlines())]
    assert "RECEIVE_APPLICATION" not in console and console[-1] in ("SHARE_COMPLETED", None)


class Breaks:
    """A content source that fails after `reads` reads: the console stops mid-transfer."""

    def __init__(self, source, reads=1):
        self.source, self.reads = source, reads

    def read_content(self, *a):
        self.reads -= 1
        if self.reads < 0:
            raise OSError("the console left")
        return self.source.read_content(*a)

    def __getattr__(self, name):
        return getattr(self.source, name)


def breaking(monkeypatch):
    from switchlcs import session
    serve = content.serve
    monkeypatch.setattr(session.content, "serve", lambda sock, source, progress=None:
                        serve(sock, Breaks(source), progress))


def test_a_refused_join_is_reported_with_the_consoles_code(game, tmp_path, capsys, monkeypatch):
    from switchlcs import session
    monkeypatch.setattr(session.Host, "_validate", staticmethod(lambda join: session.REJECT_INCOMPATIBLE))
    _base, update, _keys, _icon = game
    code, printed, out = match_run(game, tmp_path, capsys, ["--pull"], ["--console", str(update)])
    assert code == 1 and printed.splitlines()[-1] == "The console refused to let pokeldn join (error 2211-0256)."
    assert os.listdir(out) == []


def test_a_download_cut_short_keeps_nothing(game, tmp_path, capsys, monkeypatch):
    breaking(monkeypatch)
    _base, update, _keys, _icon = game
    code, printed, out = match_run(game, tmp_path, capsys, ["--pull"], ["--console", str(update)])
    said = printed.splitlines()[-1]
    assert code == 1 and said.startswith("The share stopped: ") and said.endswith("Nothing incomplete was kept.")
    assert os.listdir(out) == []                            # no NSP, no hidden parts folder


def test_an_upload_leaves_a_console_that_already_has_that_version(game, tmp_path, capsys, monkeypatch):
    """The console's own record stands in the 0x09 while pokeldn's is not newer: it names the console's
    version, and pokeldn leaves before the share and says why."""
    trusting(monkeypatch)
    _base, update, _keys, _icon = game
    code, printed, _out = match_run(game, tmp_path, capsys, ["--offer", str(update)], ["--console", str(update)])
    assert code == 1 and printed.splitlines()[-1].startswith(f"The console already has version v{0x20000} of the game")
    assert "[progress] " not in printed


def test_an_upload_the_console_does_not_pull_is_reported(game, tmp_path, capsys, monkeypatch):
    """A console that has run a newer version than the one offered takes nothing older, even with that update
    deleted. Its installed game is older than pokeldn's, so pokeldn's record replaces its own in the 0x09 and
    hides that version: the console completes the share without pulling, and the run says so."""
    import lcs_match
    trusting(monkeypatch)
    base, update, _keys, _icon = game
    code, printed, _out = match_run(game, tmp_path, capsys, ["--offer", str(update)],
                                    ["--console", str(base), "--required-version", "0x30000"])
    assert code == 1 and printed.splitlines()[-1] == lcs_match.NOT_TAKEN


def test_an_offer_is_checked_before_the_scan(game, tmp_path, capsys):
    """The real check: the built update is not signed by Nintendo, so nothing is joined."""
    import lcs_match
    _base, update, keys, _icon = game
    assert lcs_match.main(["--offer", str(update), "--out", str(tmp_path / "Switch"), "--keys", str(keys),
                           "--loopback", "--timeout", "0.5"]) == 1
    printed = capsys.readouterr().out
    assert "Looking for the console's group" not in printed and printed.strip()


def test_a_system_update_cut_short_is_not_saved(game, tmp_path, capsys, monkeypatch, plugin_data):
    from switchlcs import library
    from tests.test_lcs_session import guest_source, install
    firmware = tmp_path / "registered"
    firmware.mkdir()
    install(guest_source()[0], firmware)
    breaking(monkeypatch)
    _base, update, _keys, _icon = game
    code, printed, out = match_run(game, tmp_path, capsys, ["--system"],
                                   ["--console", str(update), "--system", str(firmware)])
    assert code == 1 and "The console sends its system update 20.5.0." in printed
    assert printed.splitlines()[-1].startswith("The share stopped: ")
    assert os.listdir(out) == [] and library.system_version(plugin_data) == library.DEFAULT_SYSTEM


def test_only_a_whole_system_update_is_kept(tmp_path, plugin_data):
    import lcs_match
    from switchlcs import library
    whole, cut = tmp_path / ".1-20.5.0-system-parts", tmp_path / ".1-21.0.0-system-parts"
    for folder in (whole, cut):
        folder.mkdir()
        (folder / "a.nca").write_bytes(b"a")
    old = tmp_path / "System update 20.5.0.zip"
    old.write_bytes(b"an older copy")
    received = lcs_match._settle([str(whole / "a.nca"), "elsewhere.nca"],
                                 {str(whole): (str(old), "20.5.0"),
                                  str(cut): (str(tmp_path / "System update 21.0.0.zip"), "21.0.0")})
    assert received == ["elsewhere.nca", str(old)]
    assert os.listdir(tmp_path) == [old.name] and zipfile_names(old) == ["a.nca"]
    assert library.system_version(plugin_data) == "20.5.0"


def zipfile_names(path):
    import zipfile
    with zipfile.ZipFile(path) as z:
        return z.namelist()


def test_no_keys_and_no_group_say_what_to_do(game, tmp_path, capsys):
    import lcs_match
    from switchlcs import session
    _base, _update, keys, _icon = game
    assert lcs_match.main(["--out", str(tmp_path)]) == 1
    assert "Choose prod.keys in Settings first" in capsys.readouterr().out
    assert lcs_match.main(["--pull", "--out", str(tmp_path), "--keys", str(keys), "--timeout", "0.5",
                           "--loopback"]) == 1
    assert capsys.readouterr().out.splitlines()[-1] == lcs_match.NOT_FOUND

    class Live:
        def __init__(self, error):
            self.error = error

        def start(self, timeout):
            raise self.error
    with pytest.raises(session.SessionError, match="No Match Version"):     # pokeldn.ldn.network.join's
        lcs_match.find_group(Live(RuntimeError("no joinable Match Version With Local Users group (saw 0)")), 1)
    with pytest.raises(RuntimeError, match="board"):            # anything else is not hidden
        lcs_match.find_group(Live(RuntimeError("the board did not answer")), 1)


def test_a_lost_board_ends_the_run_as_an_error_not_a_stop(game, monkeypatch, tmp_path, capsys):
    import pokeldn.ldn
    import lcs_match
    from pokeldn.ldn import esp32_wlan
    _base, _update, keys, _icon = game

    def interrupted(*args):
        raise KeyboardInterrupt
    monkeypatch.setattr(lcs_match, "run", interrupted)
    monkeypatch.setattr(pokeldn.ldn, "_radio_lost", "")
    argv = ["--pull", "--out", str(tmp_path), "--keys", str(keys)]
    assert lcs_match.main(argv) == 0                                # the app's Stop
    assert capsys.readouterr().out == "Stopped.\n"
    monkeypatch.setattr(esp32_wlan._thread, "interrupt_main", lambda: None)
    esp32_wlan.board_lost(log=lambda line: None, error="write timeout")
    assert lcs_match.main(argv) == 1
    assert capsys.readouterr().out == "The board's USB connection failed (write timeout).\n"


def test_a_console_that_goes_quiet_is_named_with_the_wait():
    import socket
    import lcs_match
    quiet = lcs_match._plainly(socket.timeout("timed out"), "pull", timeout=600)
    assert str(quiet) == "The share stopped: the console sent nothing for 10 minutes. Nothing incomplete was kept."
    assert "for 30 seconds" in str(lcs_match._plainly(TimeoutError("timed out"), "pull", timeout=30))
    assert "the peer stopped acknowledging" in str(lcs_match._plainly(TimeoutError("the peer stopped acknowledging"),
                                                                      "pull", timeout=600))


def test_a_reject_after_the_upload_is_not_called_a_refused_join():
    """Seen live: the console pulled the whole update, installed it, and 25 s later sent 0x08 reason 4."""
    import lcs_match
    rejected = lcs_match.session.Rejected(4)
    before = lcs_match._plainly(rejected, "offer")
    after = lcs_match._plainly(rejected, "offer", served=True)
    assert "refused to let pokeldn join" in str(before)
    assert "received the whole update, then ended the share (error 2211-0256)" in str(after)


@pytest.mark.parametrize("installed, required, said", [
    (0x30000, 0x30000, f"The console has version v{0x30000} of the game"),
    (0x10000, 0x30000, f"The console has run version v{0x30000} of the game"),
    (0x20000, 0x30000, f"The console has run version v{0x30000} of the game"),
])
def test_an_older_update_names_the_factory_reset_in_a_pop_up(installed, required, said, monkeypatch):
    """A console never installs an update older than the newest version it has run: only a factory reset clears
    that, and the player is told so in a pop-up as well as the run's error."""
    import lcs_match
    shown = []
    monkeypatch.setattr(lcs_match.popup, "available", lambda: True)
    monkeypatch.setattr(lcs_match.popup, "acknowledge", lambda title, text, **kw: shown.append((title, text, kw)))
    info = SimpleNamespace(application_version=installed, required_application_version=required)
    with pytest.raises(lcs_match.session.Leaving) as left:
        lcs_match.refuse_older(info, 0x20000)
    assert str(left.value) == f"{said}, newer than this update (v{0x20000}). {lcs_match.OLDER}"
    assert "factory reset" in lcs_match.OLDER and "release-day cartridge" in lcs_match.OLDER
    assert shown == [("The console won't take an older update", str(left.value),
                      {"id": "lcs-older-update", "tone": "warning"})]


def test_the_same_version_or_an_older_console_opens_no_pop_up(monkeypatch):
    import lcs_match
    shown = []
    monkeypatch.setattr(lcs_match.popup, "available", lambda: True)
    monkeypatch.setattr(lcs_match.popup, "acknowledge", lambda *a, **kw: shown.append(a))
    same = SimpleNamespace(application_version=0x20000, required_application_version=0x20000)
    with pytest.raises(lcs_match.session.Leaving, match="the same as this update"):
        lcs_match.refuse_older(same, 0x20000)
    lcs_match.refuse_older(SimpleNamespace(application_version=0x10000, required_application_version=0x10000),
                           0x20000)
    assert shown == [] and lcs_match.older_update(lcs_match.NOT_TAKEN) == lcs_match.NOT_TAKEN and len(shown) == 1
