"""The plugin's library (switchlcs.library): one file per update, a system update as its ZIP, the Switch page's
folders brought over, the checks kept; lcs_check.py over it; and the plugin as pokeldn loads and guards it."""
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import lcs_check
from conftest import ROOT, SOURCE
from switchlcs import library, verify
from tests.test_lcs_content import KEYS
from tests.test_lcs_simulate import write_nsp
from tests.test_lcs_verify import PATCH, VERSION, signers, system_folder, update_files  # noqa: F401 -- a fixture

NAME = f"Game [{PATCH:016X}][v{VERSION}](1.0.2).nsp"
SYSTEM = "System update 23.0.1.zip"
APP = PATCH & ~0x800


def signed_nsp(signers, path):
    files, _infos = update_files(signers)
    write_nsp(path, files)
    return str(path)


def keys_file(tmp_path):
    path = tmp_path / "prod.keys"
    path.write_text("".join(f"{name} = {value.hex()}\n" for name, value in KEYS.items()))
    return path


def test_the_library_lists_updates_and_system_updates_by_their_names(tmp_path):
    for name in (NAME, "Other.nsp", SYSTEM, "notes.txt", ".hidden.nsp", "Half.nsp.part", "System update 1.zip"):
        (tmp_path / name).write_bytes(b"")
    (tmp_path / ".20261016-120000-parts").mkdir()
    found = {os.path.basename(e.path): e for e in library.saved(tmp_path)}
    assert sorted(found) == sorted([NAME, "Other.nsp", SYSTEM])
    assert (found[NAME].title, found[NAME].title_id, found[NAME].version, found[NAME].version_line) == \
        ("Game", f"{PATCH:016X}", VERSION, f"1.0.2 ({VERSION})")
    assert (found[SYSTEM].kind, found[SYSTEM].title, found[SYSTEM].version_line) == \
        ("system", "System update 23.0.1", "23.0.1")
    assert found["Other.nsp"].title_id == ""


def test_an_update_reads_its_id_version_and_name_from_the_nsp(signers, tmp_path):
    entry = library.saved(Path(signed_nsp(signers, tmp_path / "Anything.nsp")).parent)[0]
    read = library.read(entry, KEYS)
    assert (read.title, read.title_id, read.version, read.display_version, read.read) == \
        ("Game", f"{PATCH:016X}", VERSION, "1.0.2", True)
    assert library.read(entry, None) == entry


def test_newer_lists_what_the_console_would_take():
    def update(version, display):
        return library.Saved("update", f"{version}.nsp", "Game", f"{PATCH:016X}", version, display)
    old, mid, new = update(0x10000, "1.0.1"), update(0x20000, "1.0.2"), update(0x30000, "1.0.3")
    other = library.Saved("update", "x.nsp", "Other", "0100000000010800", 0x90000, "9.0.0")
    saved = [old, other, new, mid]
    assert library.of_game(saved, APP) == [new, mid, old]
    assert library.newer(saved, APP, 0x20000) == [new]
    assert library.newer(saved, APP, None, "1.0.2") == [new, old]       # its version unknown: all but its own
    assert library.same_as_console(saved, APP, "1.0.2") == mid
    assert library.same_as_console(saved, APP, "") is None


def test_a_system_update_folder_packs_into_a_stored_zip_that_checks(signers, tmp_path):
    folder, names = system_folder(signers, tmp_path)
    target = library.zip_system(folder, tmp_path / SYSTEM)
    with zipfile.ZipFile(target) as z:
        assert {i.filename for i in z.infolist()} == set(names.values())
        assert {i.compress_type for i in z.infolist()} == {zipfile.ZIP_STORED}
    assert [p.name for p in tmp_path.iterdir() if library.hidden(p.name)] == []
    seen = []
    info = verify.check_system(target, KEYS, progress=lambda d, t: seen.append((d, t)), trust=signers[1])
    assert (info.version, info.metas, info.contents) == (0x5C010014, 2, 1) and seen[-1] == (info.size, info.size)
    damaged = tmp_path / "damaged.zip"
    with zipfile.ZipFile(target) as src, zipfile.ZipFile(damaged, "w") as out:
        for item in src.infolist():
            data = src.read(item)
            out.writestr(item.filename, data[:-1] + bytes([data[-1] ^ 1]) if item.filename == names["data"] else data)
    with pytest.raises(verify.InvalidUpdate, match="does not match the hash Nintendo listed"):
        verify.check_system(damaged, KEYS, trust=signers[1])
    with pytest.raises(verify.InvalidUpdate, match="cannot be read"):
        verify.check_system(tmp_path / "missing.zip", KEYS, trust=signers[1])


def test_the_switch_pages_folders_become_one_file_each(signers, tmp_path):
    root = tmp_path / "Switch"
    (root / "Updates").mkdir(parents=True)
    signed_nsp(signers, root / "Updates" / NAME)
    signed_nsp(signers, root / "Updates" / "Taken.nsp")
    (root / "Taken.nsp").write_bytes(b"already at the top")
    folder, names = system_folder(signers, tmp_path)
    shutil.copytree(folder, root / "System" / "23.0.1")
    (root / "System" / ".20261016-120000-23.0.1-parts").mkdir()
    lines = []
    library.migrate(root, lines.append)
    assert sorted(os.listdir(root)) == sorted([NAME, "Taken.nsp", SYSTEM, "Updates", "System"])
    assert os.listdir(root / "Updates") == ["Taken.nsp"]                 # its name was taken: left where it was
    assert os.listdir(root / "System") == [".20261016-120000-23.0.1-parts"]
    with zipfile.ZipFile(root / SYSTEM) as z:
        assert {i.filename for i in z.infolist()} == set(names.values())
    assert lines == [f"Moved {NAME} to the library's top", f"Packed system update 23.0.1 into {SYSTEM}"]
    library.sweep(root / "System")
    (root / "Updates" / "Taken.nsp").unlink()
    library.migrate(root, lines.append)
    assert sorted(os.listdir(root)) == sorted([NAME, "Taken.nsp", SYSTEM])


def test_a_cut_short_run_is_swept(tmp_path):
    (tmp_path / ".20261016-120000-parts").mkdir()
    (tmp_path / ".20261016-120000-parts" / "x.nca").write_bytes(b"")
    (tmp_path / "Game.nsp.part").write_bytes(b"")
    (tmp_path / f".{SYSTEM}.part").write_bytes(b"")
    (tmp_path / NAME).write_bytes(b"")
    library.sweep(tmp_path)
    assert os.listdir(tmp_path) == [NAME]


def test_the_claimed_system_version_and_the_checks_are_kept(tmp_path):
    assert library.system_version(tmp_path) == library.DEFAULT_SYSTEM
    library.remember_system_version("23.0.1", tmp_path)
    library.remember_system_version("not a version", tmp_path)
    assert library.system_version(tmp_path) == "23.0.1"
    library.save_checks({"a.nsp": {"state": "valid"}}, tmp_path)
    assert library.load_checks(tmp_path) == {"a.nsp": {"state": "valid"}}
    (tmp_path / "checks.json").write_text("{broken")
    assert library.load_checks(tmp_path) == {}


def test_the_check_tool_hashes_each_file_once_until_it_changes(signers, tmp_path, monkeypatch, capsys):
    update, system = verify.check_update, verify.check_system
    monkeypatch.setattr(verify, "check_update", lambda *a, trust=None, **k: update(*a, trust=signers[1], **k))
    monkeypatch.setattr(verify, "check_system", lambda *a, trust=None, **k: system(*a, trust=signers[1], **k))
    root, data = tmp_path / "Switch", tmp_path / "data"
    root.mkdir()
    signed_nsp(signers, root / NAME)
    folder, _names = system_folder(signers, tmp_path)
    library.zip_system(folder, root / SYSTEM)
    (root / "Broken.nsp").write_bytes(b"not an nsp")
    argv = ["--keys", str(keys_file(tmp_path)), "--out", str(root), "--checks", str(data)]
    assert lcs_check.main(argv) == 1
    out = capsys.readouterr().out
    assert "[BAD] Broken.nsp: not an NSP" in out
    assert f"[OK] {NAME}: Complete" in out and f"[OK] {SYSTEM}: Complete · 2 content metas" in out
    assert "1 damaged or not Nintendo's" in out and "[progress] " in out
    (root / "Broken.nsp").unlink()
    assert lcs_check.main(argv) == 0
    out = capsys.readouterr().out
    assert "[progress] " not in out and out.count("(checked before)") == 2
    assert set(library.load_checks(data)) == {str(root / NAME), str(root / SYSTEM)}
    assert lcs_check.main([*argv, "--again"]) == 0 and "(checked before)" not in capsys.readouterr().out


def pokeldn(*args, data, cwd):
    env = dict(os.environ, POKELDN_PLUGINS=ROOT, POKELDN_DATA=str(data), PYTHONPATH=SOURCE)
    for name in ("POKELDN_RADIO", "POKELDN_MANAGED_RUN", "POKELDN_POPUPS"):
        env.pop(name, None)
    return subprocess.run([sys.executable, "-m", "pokeldn", *args], cwd=cwd, env=env, capture_output=True,
                          text=True, timeout=120)


def test_pokeldn_loads_the_plugin_and_its_tools(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    listed = pokeldn("--plugins", data=data, cwd=tmp_path)
    assert "switch-updates       Switch Updates, API 1.8: loaded" in listed.stdout, listed.stdout + listed.stderr
    tools = pokeldn("--list", data=data, cwd=tmp_path).stdout
    for key, name in (("lcs-match", "Match Version"), ("lcs-check", "Check saved updates"),
                      ("lcs-import", "Import an update")):
        assert f"Switch Updates: {name}" in tools and key in tools


def test_a_check_run_from_pokeldn_brings_the_old_library_over_under_the_guardrails(signers, tmp_path):
    """The tool runs as the app runs it, with the plugin guard on: moving the Switch page's NSPs up, packing its
    system update folder and removing the folder are allowed in the plugin's library."""
    data = tmp_path / "data"
    root = data / "Switch"
    (root / "Updates").mkdir(parents=True)
    signed_nsp(signers, root / "Updates" / NAME)
    folder, _names = system_folder(signers, tmp_path)
    shutil.copytree(folder, root / "System" / "23.0.1")
    (data / "settings.json").write_text(json.dumps({"keys": str(keys_file(tmp_path))}))
    run = pokeldn("lcs-check", data=data, cwd=tmp_path)
    assert "PermissionError" not in run.stdout + run.stderr, run.stdout + run.stderr
    assert f"Moved {NAME} to the library's top" in run.stdout
    assert f"Packed system update 23.0.1 into {SYSTEM}" in run.stdout
    assert sorted(os.listdir(root)) == sorted([NAME, SYSTEM])
    # The test signers are not Nintendo's: both are refused, which shows each was read whole.
    assert run.returncode == 1 and "2 damaged or not Nintendo's" in run.stdout
