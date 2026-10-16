"""Updates brought into the library from files (lcs_import.py): an NSP, or a system update as loose NCAs, a folder
of them or an archive of them. Each is checked as lcs_check.py checks the library, refused when the library already
has it, and saved under the name a download gets: `content.update_name` for an NSP, `System update <version>.zip`
for a system update. Nothing half done shows in the library: an import is written there under a hidden name
(switchlcs.library.hidden), and takes its name once it passes."""

import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass

from switchlcs import content, library, nca, verify

ARCHIVES = (".zip", ".7z", ".rar", ".tar", ".tgz", ".tbz", ".tbz2", ".txz", ".tzst", ".tar.gz", ".tar.bz2",
            ".tar.xz", ".tar.zst")
PICKED = ["nsp", "nca", "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz", "tbz2", "xz", "txz", "zst", "tzst"]
PART = ".importing.part"    # an NSP being imported: .<name>.importing.part
STAGE = ".import-"          # a system update being imported: .import-<random>
CHUNK = 8 << 20
CONTENT_NAME = re.compile(r"[0-9a-f]{32}(\.cnmt)?\.nca")
MAX_META = 16 << 20         # a Meta NCA is a few KB: a file claiming to be one past this is not read whole


class Refused(Exception):
    """Why an item was not imported."""


class Cancelled(Refused):
    """The page asked to stop the import (its progress callback raises this)."""

    def __init__(self):
        super().__init__("cancelled")


@dataclass(frozen=True)
class Job:
    kind: str                       # update or system
    sources: tuple[str, ...]        # update: one NSP; system: NCAs and archives of them
    label: str                      # what the page calls it


@dataclass(frozen=True)
class Imported:
    kind: str
    path: str                       # the NSP or the system update's ZIP
    message: str                    # its check's result, as the Saved list shows it


def is_archive(path: str) -> bool:
    return path.lower().endswith(ARCHIVES)


def _is(path: str, ext: str) -> bool:
    return path.lower().endswith(ext)


def jobs(paths: list[str]) -> tuple[list[Job], list[tuple[str, str]]]:
    """Dropped or picked paths -> the imports they make, and (path, reason) for each taken for none. Each NSP is
    an import of its own; the loose NCAs among `paths` make one system update; a folder makes one of its NCAs, one
    import for each NSP in it and one for each archive in it; an archive makes one system update."""
    found, refused, loose = [], [], []
    for path in paths:
        name = os.path.basename(path.rstrip("/\\")) or path
        if os.path.isdir(path):
            nsps, ncas, archives = [], [], []
            for folder, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for file in sorted(files):
                    full = os.path.join(folder, file)
                    (nsps if _is(file, ".nsp") else ncas if _is(file, ".nca") else
                     archives if is_archive(file) else []).append(full)
            found += [Job("update", (p,), os.path.basename(p)) for p in nsps]
            if ncas:
                found.append(Job("system", tuple(ncas), name))
            found += [Job("system", (p,), os.path.basename(p)) for p in archives]
            if not nsps and not ncas and not archives:
                refused.append((path, "holds no NSP, no NCA and no archive"))
        elif _is(path, ".nsp"):
            found.append(Job("update", (path,), name))
        elif _is(path, ".nca"):
            loose.append(path)
        elif is_archive(path):
            found.append(Job("system", (path,), name))
        else:
            refused.append((path, "is not an NSP, an NCA, a folder or an archive"))
    if loose:
        found.append(Job("system", tuple(loose), os.path.basename(loose[0]) if len(loose) == 1 else
                         f"{len(loose)} NCAs"))
    return found, refused


def sweep(root) -> None:
    """Remove what an import cut short left: the app closed during it."""
    library.sweep(root)


def _listing(folder: str) -> list[str]:
    try:
        return [os.path.join(folder, name) for name in os.listdir(folder)]
    except OSError:
        return []


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _copy(source: str, target: str, progress, done: int = 0, total: int = 0) -> int:
    with open(source, "rb") as src, open(target, "wb") as out:
        while chunk := src.read(CHUNK):
            out.write(chunk)
            done += len(chunk)
            progress("copying", done, total)
    return done


def _quiet(stage, done, total) -> None:
    pass


def run(job: Job, root, keys: dict | None, progress=None, trust: verify.Trust | None = None) -> Imported:
    """Import `job` into the library at `root`: Refused says why not. `progress(stage, done, total)` follows the
    reading, copying, extracting and checking (total 0 when unknown); raising Cancelled from it stops the import.
    Whatever stops it, nothing of it is left in the library."""
    if not keys:
        raise Refused("Add prod.keys in Settings to check it")
    try:
        if job.kind == "update":
            return import_update(job.sources[0], root, keys, progress, trust)
        return import_system(list(job.sources), root, keys, progress, trust)
    except OSError as error:        # a source gone, a disk full: said as the reason
        raise Refused(f"stopped: {error}") from None


def saved_updates(folder, keys: dict) -> list[tuple[str, int, str]]:
    """(update ID, internal version, path) of each NSP in `folder`: from its content meta, else from its name."""
    found = []
    for path in sorted(_listing(str(folder))):
        if not path.lower().endswith(".nsp"):
            continue
        try:
            entries = dict(content._pfs0_entries(path))
            metas = [n for n in entries if n.endswith(".cnmt.nca") and entries[n][1] <= MAX_META]
            cnmt = nca.read_cnmt(content._read(path, *entries[metas[0]]), keys)
            found.append((f"{cnmt.id:016X}", cnmt.version, path))
        except Exception:       # noqa: BLE001 -- any file can sit in the folder: its name says what it is, if anything
            if match := library.NSP_NAME.match(os.path.basename(path)):
                found.append((match["id"].upper(), int(match["version"]), path))
    return found


def import_update(source: str, root, keys: dict, progress=None, trust: verify.Trust | None = None) -> Imported:
    """Copy an NSP into the library under content.update_name, once its signatures pass and no saved update has its
    update ID and internal version, and hash every content of the copy before it shows."""
    progress = progress or _quiet
    try:
        info = verify.check_update(source, keys, hash_contents=False, trust=trust)
    except verify.InvalidUpdate as error:
        raise Refused(str(error)) from None
    except KeyError as error:
        raise Refused(f"prod.keys lacks {error.args[0]}") from None
    except OSError as error:
        raise Refused(f"cannot be read: {error}") from None
    folder = str(root)
    patch = f"{info.patch_id:016X}"
    same = next((path for title_id, version, path in saved_updates(folder, keys)
                 if title_id == patch and version == info.version), None)
    if same:
        raise Refused(f"already saved, as {os.path.basename(same)}")
    name = content.update_name(info.control.name or "update", info.patch_id, info.version, info.display_version)
    target = os.path.join(folder, name)
    if os.path.exists(target):
        raise Refused(f"already saved, as {name}")
    os.makedirs(folder, exist_ok=True)
    part = os.path.join(folder, f".{name}{PART}")
    try:
        _copy(source, part, progress, total=os.path.getsize(source))
        try:
            whole = verify.check_update(part, keys, trust=trust,
                                        progress=lambda done, total: progress("checking", done, total))
        except verify.InvalidUpdate as error:
            raise Refused(str(error)) from None
        if os.path.exists(target):
            raise Refused(f"already saved, as {name}")
        os.replace(part, target)
    finally:
        _remove(part)
    return Imported("update", target, library.update_verdict(whole))


def import_system(sources: list[str], root, keys: dict, progress=None,
                  trust: verify.Trust | None = None) -> Imported:
    """Gather a system update from NCAs and archives of them into its ZIP, each content named by its content ID, once
    every content its SystemUpdate content meta lists is there and matches Nintendo's hash."""
    progress = progress or _quiet
    folder = str(root)
    os.makedirs(folder, exist_ok=True)
    stage = tempfile.mkdtemp(prefix=STAGE, dir=folder)
    try:
        ncas = []
        for i, source in enumerate(sources):
            ncas += _extract(source, os.path.join(stage, f"archive-{i}"), progress) if is_archive(source) \
                else [source]
        plan, version = _plan(ncas, keys, progress)
        text = library.short_version(version)
        target = os.path.join(folder, library.system_name(text))
        if os.path.exists(target):
            raise Refused(f"system update {text} is already saved")
        out = os.path.join(stage, "out")
        os.mkdir(out)
        mine = os.path.join(os.path.realpath(stage), "")
        copied = {name: path for name, path in plan.items() if not os.path.realpath(path).startswith(mine)}
        done, total = 0, sum(os.path.getsize(path) for path in copied.values())
        for name, path in plan.items():
            if name in copied:
                done = _copy(path, os.path.join(out, name), progress, done, total)
            else:                   # extracted here: moved, not copied again
                os.replace(path, os.path.join(out, name))
        try:
            info = verify.check_system(out, keys, trust=trust,
                                       progress=lambda done, total: progress("checking", done, total))
        except verify.InvalidUpdate as error:
            raise Refused(str(error)) from None
        if os.path.exists(target):
            raise Refused(f"system update {text} is already saved")
        progress("packing", 0, 0)
        library.zip_system(out, target)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return Imported("system", target, library.system_verdict(info))


def _plan(ncas: list[str], keys: dict, progress=_quiet) -> tuple[dict[str, str], int]:
    """-> ({the name in the system update's ZIP: the NCA to put there}, the SystemUpdate's version). A Meta NCA is
    found by its header and named by its content ID, the first half of its SHA-256; another content by its file name
    when that is its content ID, else by its SHA-256 among the contents listed. Files that are no NCA, or that the
    system update does not list, are left out."""
    if "header_key" not in keys:
        raise Refused("prod.keys lacks header_key")
    metas, others = {}, []
    for path in ncas:
        try:
            with open(path, "rb") as fh:
                head = fh.read(nca.HEADER_SIZE)
            header = nca.NcaHeader.parse(head, keys["header_key"])
        except Exception:       # noqa: BLE001 -- any file can be named .nca: one that is not is left out
            continue
        if header.content_type != nca.NCA_META:
            others.append(path)
            continue
        if os.path.getsize(path) > MAX_META:
            continue
        with open(path, "rb") as fh:
            raw = fh.read()
        try:
            cnmt = nca.read_cnmt(raw, keys)
        except KeyError as error:
            raise Refused(f"prod.keys lacks {error.args[0]}") from None
        except Exception:       # noqa: BLE001 -- a Meta NCA cut short or changed: check_system names it if needed
            continue
        metas.setdefault(cnmt.key, (path, hashlib.sha256(raw).digest()[:16], cnmt))
    tops = sorted({key.version for key in metas if key.type == nca.SYSTEM_UPDATE})
    if not tops:
        raise Refused(f"holds no system update: none of its {len(ncas)} NCAs is a SystemUpdate content meta")
    if len(tops) > 1:
        raise Refused(f"holds {len(tops)} system updates, {', '.join(library.short_version(v) for v in tops)}: "
                      "import one at a time")
    top_key = next(key for key in metas if key.type == nca.SYSTEM_UPDATE)
    top = metas[top_key][2]
    listed = [nca.ContentMetaKey(k.id, k.version, k.type) for k in top.metas]
    missing = [k for k in listed if k not in metas]
    if missing:
        raise Refused(f"{len(missing)} of the {len(listed)} content metas the system update lists are missing, "
                      f"{missing[0].id:016x} first")
    plan = {metas[k][1].hex() + ".cnmt.nca": metas[k][0] for k in [top_key, *listed]}
    needed = {info.content_id: info for k in listed for info in metas[k][2].contents
              if info.type != nca.DELTA_FRAGMENT}
    by_name = {}
    for path in others:
        name = os.path.basename(path).lower()
        if CONTENT_NAME.fullmatch(name):
            by_name.setdefault(bytes.fromhex(name[:32]), path)
    left = {}
    for content_id, info in needed.items():
        path = by_name.get(content_id)
        if path and os.path.getsize(path) == info.size:
            plan[content_id.hex() + ".nca"] = path
        else:
            left[content_id] = info
    if left:                    # named otherwise: found by their hash, read only when their size is one listed
        sizes = {info.size for info in left.values()}
        by_hash = {info.hash: content_id for content_id, info in left.items()}
        placed = set(plan.values())
        unknown = [path for path in others if path not in placed and os.path.getsize(path) in sizes]
        done, total = 0, sum(os.path.getsize(path) for path in unknown)
        for path in unknown:
            digest = hashlib.sha256()
            with open(path, "rb") as fh:
                while chunk := fh.read(CHUNK):
                    digest.update(chunk)
                    done += len(chunk)
                    progress("reading", done, total)
            if (content_id := by_hash.get(digest.digest())) in left:
                plan[content_id.hex() + ".nca"] = path
                del left[content_id]
    if left:
        first = next(iter(left))
        raise Refused(f"{len(left)} of the {len(needed)} contents the system update lists are missing, "
                      f"{first.hex()}.nca first")
    return plan, top_key.version


def _extract(archive: str, dest: str, progress) -> list[str]:
    """The NCAs in an archive, extracted under `dest`: zip and tar (gzip, bzip2, xz) by Python itself, 7z, rar and
    anything Python cannot open by the system's bsdtar or 7-Zip."""
    os.makedirs(dest)
    name = archive.lower()
    try:
        if name.endswith(".zip"):
            return _unzip(archive, dest, progress)
        if name.endswith((".tar", ".tgz", ".tbz", ".tbz2", ".txz", ".tar.gz", ".tar.bz2", ".tar.xz")):
            return _untar(archive, dest, progress)
    except (NotImplementedError, zipfile.BadZipFile, tarfile.TarError, EOFError):
        shutil.rmtree(dest, ignore_errors=True)     # a method Python lacks: the system's extractor tries
        os.makedirs(dest)
    return _external(archive, dest, progress)


def _member(dest: str, name: str, index: int) -> str:
    """Where an archive's NCA goes: by its own name, in a folder of its own when another has that name."""
    base = os.path.basename(name.replace("\\", "/"))
    path = os.path.join(dest, base)
    if os.path.exists(path):
        os.makedirs(os.path.join(dest, str(index)), exist_ok=True)
        path = os.path.join(dest, str(index), base)
    return path


def _stream(src, path: str, progress, done: int, total: int) -> int:
    with open(path, "wb") as out:
        while chunk := src.read(CHUNK):
            out.write(chunk)
            done += len(chunk)
            progress("extracting", done, total)
    return done


def _unzip(archive: str, dest: str, progress) -> list[str]:
    with zipfile.ZipFile(archive) as z:
        members = [m for m in z.infolist() if not m.is_dir() and _is(m.filename, ".nca")]
        done, total, found = 0, sum(m.file_size for m in members), []
        for i, member in enumerate(members):
            path = _member(dest, member.filename, i)
            with z.open(member) as src:
                done = _stream(src, path, progress, done, total)
            found.append(path)
    return found


def _untar(archive: str, dest: str, progress) -> list[str]:
    with tarfile.open(archive, "r:*") as tar:
        members = [m for m in tar.getmembers() if m.isfile() and _is(m.name, ".nca")]
        done, total, found = 0, sum(m.size for m in members), []
        for i, member in enumerate(members):
            path = _member(dest, member.name, i)
            with tar.extractfile(member) as src:
                done = _stream(src, path, progress, done, total)
            found.append(path)
    return found


def extractor() -> list[str] | None:
    """The system's archive extractor: bsdtar (Windows' own tar.exe, macOS's tar) or 7-Zip; None without one."""
    windows = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "tar.exe")
    found = [shutil.which("bsdtar"), windows if os.name == "nt" and os.path.isfile(windows) else None]
    tar = shutil.which("tar")
    if tar and os.name != "nt":
        try:
            if "bsdtar" in subprocess.run([tar, "--version"], capture_output=True, text=True, timeout=10).stdout:
                found.append(tar)
        except (OSError, subprocess.SubprocessError):
            pass
    if tool := next((t for t in found if t), None):
        return [tool, "-x", "-f"]
    for name in ("7z", "7zz", "7za"):
        if tool := shutil.which(name):
            return [tool, "x", "-y", "-bd"]
    return None


def _external(archive: str, dest: str, progress) -> list[str]:
    command = extractor()
    if command is None:
        raise Refused(f"needs 7-Zip or bsdtar to open {os.path.splitext(archive)[1]} archives")
    progress("extracting", 0, 0)
    if command[1] == "x":                   # 7-Zip
        command = [*command, f"-o{dest}", "--", archive]
    else:
        command = [*command, archive, "-C", dest]
    with tempfile.TemporaryFile() as said, subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=said, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)) as tool:
        while True:
            try:
                code = tool.wait(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                pass
            try:
                progress("extracting", 0, 0)
            except BaseException:   # cancelled: the extractor stops with it
                tool.kill()
                raise
        if code:
            said.seek(0)
            lines = said.read().decode(errors="replace").strip().splitlines()
            raise Refused(f"could not be extracted: {lines[-1] if lines else f'exit {code}'}")
    found = []
    for folder, _dirs, files in os.walk(dest):
        found += [os.path.join(folder, f) for f in sorted(files)
                  if _is(f, ".nca") and not os.path.islink(os.path.join(folder, f))]
    return found
