"""Updates brought into the library from files (switchlcs.importer, lcs_import.py): one NSP or one system update ZIP
each, checked before they show, nothing half done left in sight."""
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

import lcs_import
from switchlcs import importer, library, verify
from tests.test_lcs_content import KEYS
from tests.test_lcs_simulate import write_nsp
from tests.test_lcs_verify import PATCH, VERSION, signers, system_folder, update_files  # noqa: F401 -- a fixture

NAME = f"Game [{PATCH:016X}][v{VERSION}](1.0.2).nsp"
SYSTEM = "System update 23.0.1.zip"


def signed_nsp(signers, path):
    files, _infos = update_files(signers)
    write_nsp(path, files)
    return str(path)


def library_folder(tmp_path):
    root = tmp_path / "Switch"
    root.mkdir()
    return root


def leftovers(root):
    """Anything an import left beside what the library lists."""
    return [name for name in os.listdir(root) if library.hidden(name)]


def zip_names(path):
    with zipfile.ZipFile(path) as z:
        return {i.filename for i in z.infolist()}


def test_dropped_paths_make_one_import_per_nsp_and_one_per_system_update(tmp_path):
    folder = tmp_path / "Mixed"
    (folder / "deep").mkdir(parents=True)
    for name in ("a.nsp", "deep/b.NSP", "c.nca", "deep/d.nca", "notes.txt", "deep/fw.zip"):
        (folder / name).write_bytes(b"")
    for name in ("x.nca", "y.nca", "z.nsp", "fw.tar.gz", "fw.7z", "readme.md"):
        (tmp_path / name).write_bytes(b"")
    (tmp_path / "Empty").mkdir()
    paths = [str(folder), *(str(tmp_path / n) for n in ("x.nca", "y.nca", "z.nsp", "fw.tar.gz", "fw.7z",
                                                         "readme.md")), str(tmp_path / "Empty")]
    found, refused = importer.jobs(paths)
    assert [(j.kind, j.label, [os.path.basename(s) for s in j.sources]) for j in found] == [
        ("update", "a.nsp", ["a.nsp"]), ("update", "b.NSP", ["b.NSP"]), ("system", "Mixed", ["c.nca", "d.nca"]),
        ("system", "fw.zip", ["fw.zip"]), ("update", "z.nsp", ["z.nsp"]), ("system", "fw.tar.gz", ["fw.tar.gz"]),
        ("system", "fw.7z", ["fw.7z"]), ("system", "2 NCAs", ["x.nca", "y.nca"])]
    assert [(os.path.basename(p), why) for p, why in refused] == [
        ("readme.md", "is not an NSP, an NCA, a folder or an archive"),
        ("Empty", "holds no NSP, no NCA and no archive")]


def test_an_nsp_is_checked_copied_under_its_standard_name_and_not_imported_twice(signers, tmp_path):
    root = library_folder(tmp_path)
    source = signed_nsp(signers, tmp_path / "whatever.nsp")
    stages = []
    done = importer.run(importer.Job("update", (source,), "whatever.nsp"), root, KEYS,
                        progress=lambda stage, d, t: stages.append(stage), trust=signers[1])
    assert done == importer.Imported("update", str(root / NAME), done.message)
    assert done.message.startswith("Complete") and done.message.endswith("Nintendo's signatures verify")
    assert Path(done.path).read_bytes() == Path(source).read_bytes()
    assert stages[0] == "copying" and stages[-1] == "checking"
    with pytest.raises(importer.Refused, match=re.escape(f"already saved, as {NAME}")):
        importer.run(importer.Job("update", (source,), ""), root, KEYS, trust=signers[1])
    # Under another name too: the saved NSP's own content meta gives its update ID and version.
    os.rename(done.path, root / "Mine.nsp")
    with pytest.raises(importer.Refused, match="already saved, as Mine.nsp"):
        importer.run(importer.Job("update", (source,), ""), root, KEYS, trust=signers[1])
    assert leftovers(root) == []


def test_the_saved_updates_come_from_their_content_meta_else_their_name(signers, tmp_path):
    signed_nsp(signers, tmp_path / "Anything.nsp")
    (tmp_path / f"Named [{PATCH:016X}][v65536].nsp").write_bytes(b"not an nsp")
    (tmp_path / "junk.nsp").write_bytes(b"not an nsp")
    (tmp_path / "notes.txt").write_bytes(b"")
    assert [(i, v, os.path.basename(p)) for i, v, p in importer.saved_updates(tmp_path, KEYS)] == [
        (f"{PATCH:016X}", VERSION, "Anything.nsp"), (f"{PATCH:016X}", 65536, f"Named [{PATCH:016X}][v65536].nsp")]


@pytest.mark.parametrize("stage", ["copying", "checking"])
def test_a_cancelled_import_leaves_nothing(signers, tmp_path, stage):
    root = library_folder(tmp_path)
    source = signed_nsp(signers, tmp_path / "whatever.nsp")

    def progress(now, done, total):
        if now == stage:
            raise importer.Cancelled
    with pytest.raises(importer.Cancelled, match="cancelled"):
        importer.run(importer.Job("update", (source,), ""), root, KEYS, progress, trust=signers[1])
    assert os.listdir(root) == []


def test_an_error_on_the_way_is_the_reason_and_leaves_nothing(signers, tmp_path, monkeypatch):
    root = library_folder(tmp_path)
    source = signed_nsp(signers, tmp_path / "whatever.nsp")

    def full(*args, **kwargs):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(importer, "_copy", full)
    with pytest.raises(importer.Refused, match=r"^stopped: \[Errno 28\] No space left on device$"):
        importer.run(importer.Job("update", (source,), ""), root, KEYS, trust=signers[1])
    folder, _names = system_folder(signers, tmp_path)
    with pytest.raises(importer.Refused, match="No space left"):
        importer.run(importer.jobs([str(folder)])[0][0], root, KEYS, trust=signers[1])
    assert os.listdir(root) == []


def test_an_nsp_that_fails_its_check_is_refused_and_leaves_nothing(signers, tmp_path):
    root = library_folder(tmp_path)
    junk = tmp_path / "junk.nsp"
    junk.write_bytes(b"not an nsp")
    with pytest.raises(importer.Refused, match="not an NSP"):
        importer.run(importer.Job("update", (str(junk),), ""), root, KEYS, trust=signers[1])
    files, infos = update_files(signers)
    program = infos[0].content_id.hex() + ".nca"
    files[program] = files[program][:-1] + bytes([files[program][-1] ^ 1])    # only the copy's hashing sees it
    source = str(tmp_path / "changed.nsp")
    write_nsp(source, files)
    with pytest.raises(importer.Refused, match="does not match the hash Nintendo listed"):
        importer.run(importer.Job("update", (source,), ""), root, KEYS, trust=signers[1])
    with pytest.raises(importer.Refused, match="Add prod.keys"):
        importer.run(importer.Job("update", (source,), ""), root, None)
    assert os.listdir(root) == []


def odd_names(signers, tmp_path):
    """A system update whose files are named as no tool names them, with a file it does not list beside them.
    -> (the folder, the names pokeldn gives them)."""
    folder, names = system_folder(signers, tmp_path)
    odd = tmp_path / "Odd"
    odd.mkdir()
    for i, name in enumerate(sorted(names.values())):
        shutil.copy(folder / name, odd / f"part{i}.nca")
    (odd / "extra.nca").write_bytes(os.urandom(0x1000))
    return odd, set(names.values())


def test_a_system_update_is_gathered_from_any_names_into_its_zip(signers, tmp_path):
    root = library_folder(tmp_path)
    odd, names = odd_names(signers, tmp_path)
    found, _refused = importer.jobs([str(odd)])
    stages = []
    done = importer.run(found[0], root, KEYS, lambda stage, d, t: stages.append(stage), trust=signers[1])
    assert done.path == str(root / SYSTEM) and done.message.startswith("Complete · 2 content metas")
    assert stages.index("reading") < stages.index("copying") < stages.index("checking")    # found by its hash
    assert zip_names(done.path) == names
    with zipfile.ZipFile(done.path) as z:
        assert {i.compress_type for i in z.infolist()} == {zipfile.ZIP_STORED}
    assert os.path.exists(odd / "part0.nca")             # copied, not moved
    with pytest.raises(importer.Refused, match="system update 23.0.1 is already saved"):
        importer.run(found[0], root, KEYS, trust=signers[1])
    assert leftovers(root) == [] and os.listdir(root) == [SYSTEM]
    assert library.short_version(verify.check_system(done.path, KEYS).version) == "23.0.1"     # read from the ZIP


def test_a_system_update_with_a_content_missing_is_refused(signers, tmp_path):
    root = library_folder(tmp_path)
    folder, names = system_folder(signers, tmp_path)
    (folder / names["data"]).unlink()
    with pytest.raises(importer.Refused, match="1 of the 1 contents the system update lists are missing"):
        importer.run(importer.jobs([str(folder)])[0][0], root, KEYS, trust=signers[1])
    (folder / names["top"]).unlink()
    with pytest.raises(importer.Refused, match="holds no system update"):
        importer.run(importer.jobs([str(folder)])[0][0], root, KEYS, trust=signers[1])
    assert os.listdir(root) == []


def archive(kind, source, path):
    if kind == "zip":
        with zipfile.ZipFile(path, "w") as z:
            for name in os.listdir(source):
                z.write(source / name, f"Firmware 23.0.1/{name}")
    elif kind == "tar.gz":
        with tarfile.open(path, "w:gz") as tar:
            tar.add(source, "Firmware")
    else:
        tool = importer.extractor()
        if tool is None or tool[1] == "x":
            pytest.skip("no bsdtar to write a 7z with")
        subprocess.run([tool[0], "--format", "7zip", "-cf", str(path), "-C", str(source), "."], check=True)


@pytest.mark.parametrize("kind", ["zip", "tar.gz", "7z"])
def test_a_system_update_comes_out_of_an_archive(signers, tmp_path, kind):
    root = library_folder(tmp_path)
    odd, names = odd_names(signers, tmp_path)
    path = tmp_path / f"firmware.{kind}"
    archive(kind, odd, path)
    stages = []
    done = importer.run(importer.jobs([str(path)])[0][0], root, KEYS,
                        progress=lambda stage, d, t: stages.append(stage), trust=signers[1])
    assert zip_names(done.path) == names and "extracting" in stages and stages[-1] == "packing"
    assert "copying" not in stages                       # extracted beside the library: moved into place
    assert leftovers(root) == []


def test_an_archive_python_cannot_open_goes_to_the_systems_extractor(signers, tmp_path, monkeypatch):
    root = library_folder(tmp_path)
    path = tmp_path / "firmware.7z"
    path.write_bytes(b"7z")
    monkeypatch.setattr(importer, "extractor", lambda: None)
    with pytest.raises(importer.Refused, match="needs 7-Zip or bsdtar to open .7z archives"):
        importer.run(importer.jobs([str(path)])[0][0], root, KEYS, trust=signers[1])
    assert leftovers(root) == []


def test_a_cancel_stops_the_systems_extractor_too(signers, tmp_path, monkeypatch):
    root = library_folder(tmp_path)
    path = tmp_path / "firmware.7z"
    path.write_bytes(b"7z")
    # An extractor that would take a minute; the archive and destination arguments follow the script, unread.
    monkeypatch.setattr(importer, "extractor", lambda: [sys.executable, "-c", "import time; time.sleep(60)"])
    calls = []

    def progress(stage, done, total):
        calls.append(stage)
        if len(calls) == 3:
            raise importer.Cancelled
    started = time.monotonic()
    with pytest.raises(importer.Cancelled):
        importer.run(importer.jobs([str(path)])[0][0], root, KEYS, progress, trust=signers[1])
    assert time.monotonic() - started < 10 and os.listdir(root) == []


def test_a_cut_short_import_is_swept(tmp_path):
    root = library_folder(tmp_path)
    (root / ".import-abc").mkdir()
    (root / f".Game.nsp{importer.PART}").write_bytes(b"")
    (root / "Game.nsp").write_bytes(b"")
    (root / SYSTEM).write_bytes(b"")
    importer.sweep(root)
    assert sorted(os.listdir(root)) == ["Game.nsp", SYSTEM]


def test_the_import_tool_adds_a_file_and_says_why_another_is_not(signers, tmp_path, capsys):
    root = library_folder(tmp_path)
    keys = tmp_path / "prod.keys"
    keys.write_text("".join(f"{name} = {value.hex()}\n" for name, value in KEYS.items()))
    source = signed_nsp(signers, tmp_path / "copy.nsp")
    junk = tmp_path / "notes.txt"
    junk.write_text("")
    assert lcs_import.main(["--keys", str(keys), "--out", str(root), "--file", source, "--file", str(junk)]) == 1
    out = capsys.readouterr().out
    assert "Not imported: notes.txt is not an NSP, an NCA, a folder or an archive." in out
    assert f"Imported {NAME}: Complete" in out
    assert "[progress] " in out and os.listdir(root) == [NAME]
    assert lcs_import.main(["--keys", str(keys), "--out", str(root), "--file", source]) == 1
    assert f"Not imported: copy.nsp: already saved, as {NAME}." in capsys.readouterr().out
    assert lcs_import.main(["--out", str(root), "--file", source]) == 1
    assert "Choose prod.keys in Settings" in capsys.readouterr().out


@pytest.fixture(autouse=True)
def _test_signers(signers, monkeypatch):
    """The import's checks trust the test signers."""
    update, system = verify.check_update, verify.check_system
    monkeypatch.setattr(verify, "check_update", lambda *a, trust=None, **k: update(*a, trust=signers[1], **k))
    monkeypatch.setattr(verify, "check_system", lambda *a, trust=None, **k: system(*a, trust=signers[1], **k))
