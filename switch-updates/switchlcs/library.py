"""The plugin's library (plugin.toml's `library`, Documents/pokeldn/Switch): the updates it saved, one file each, as
the Games page lists them. A game update is an NSP named by content.update_name; a system update is a ZIP of its
NCAs, `System update 20.5.0.zip`, stored uncompressed (NCAs are encrypted and do not compress). Work in progress
sits under names the Games page leaves out: a leading dot, or a `.part` ending.

The plugin's own state, the checks' results and the system version pokeldn claims, is in its data folder."""

import json
import os
import re
import shutil
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path

from switchlcs import content, nca, verify
from switchlcs.control import ApplicationControl

PLUGIN_ID = "switch-updates"
DEFAULT_SYSTEM = "20.5.0"
SYSTEM_VERSION = re.compile(r"\d{1,2}\.\d{1,2}\.\d{1,2}")
# content.update_name's form; the display version is absent from names before it and from an unknown one.
NSP_NAME = re.compile(r"^(?P<title>.*?) \[(?P<id>[0-9A-Fa-f]{16})\]\[v(?P<version>\d+)\](?:\((?P<display>[^)]*)\))?"
                      r"\.nsp$", re.IGNORECASE)
SYSTEM_NAME = re.compile(r"^System update (?P<version>\d+\.\d+\.\d+)\.zip$", re.IGNORECASE)
CHUNK = 8 << 20


def short_version(value: int) -> str:
    """A packed system version (ns, cnmt) as the console's System Settings shows it: 0x50500064 -> 20.5.0."""
    return f"{value >> 26}.{(value >> 20) & 0x3F}.{(value >> 16) & 0xF}"


def system_name(version: str) -> str:
    return f"System update {version}.zip"


def hidden(name: str) -> bool:
    """Whether the Games page leaves a name out: the plugin's work in progress."""
    return name.startswith(".") or name.endswith(".part")


def folder(out=None) -> Path:
    """The library: `out` when a script was given one, else the plugin's."""
    if out:
        return Path(out)
    from pokeldn import plugins
    return plugins.library_folder(PLUGIN_ID)


def data_folder() -> Path:
    from pokeldn import plugins
    return Path(plugins.data_folder(PLUGIN_ID))


# ---- what is saved ----

@dataclass(frozen=True)
class Saved:
    kind: str                       # update or system
    path: str
    title: str                      # the game's name, or "System update 20.5.0"
    title_id: str = ""              # an update's ID: 16 hex digits
    version: int = 0                # an update's internal version
    display_version: str = ""       # "1.2.0": an update's own, a system update's
    read: bool = False              # the ID and version came from the NSP itself, not its name

    @property
    def version_line(self) -> str:
        if self.kind == "system":
            return self.display_version
        if not self.display_version:
            return f"internal version {self.version}"
        return f"{self.display_version} ({self.version})"


def saved(root) -> list[Saved]:
    """The library's updates and system updates, by their file names, newest file first."""
    found = []
    for path in Path(root).iterdir() if Path(root).is_dir() else ():
        if not path.is_file() or hidden(path.name):
            continue
        if match := NSP_NAME.match(path.name):
            entry = Saved("update", str(path), match["title"], match["id"].upper(), int(match["version"]),
                          match["display"] or "")
        elif path.suffix.lower() == ".nsp":
            entry = Saved("update", str(path), path.stem)
        elif match := SYSTEM_NAME.match(path.name):
            entry = Saved("system", str(path), f"System update {match['version']}",
                          display_version=match["version"])
        else:
            continue
        found.append((path.stat().st_mtime, entry))
    return [entry for _mtime, entry in sorted(found, key=lambda pair: pair[0], reverse=True)]


def read(entry: Saved, keys: dict | None) -> Saved:
    """An update as the NSP itself names it: its ID and version from its content meta, its name and display
    version from its Control NCA. Whatever the keys do not open keeps what the file name says."""
    if entry.kind != "update" or not keys:
        return entry
    try:
        patches = [k for k in content.NspSource([entry.path], keys).metas if k.type == nca.PATCH]
        if len(patches) == 1:
            entry = replace(entry, title_id=f"{patches[0].id:016X}", version=patches[0].version, read=True)
    except Exception:   # noqa: BLE001 -- any file can sit in the library: one pokeldn cannot read keeps its name
        pass
    try:
        control = ApplicationControl.parse(content.nsp_control_data(entry.path, keys)[1])
        entry = replace(entry, title=control.name or entry.title,
                        display_version=control.display_version or entry.display_version)
    except Exception:   # noqa: BLE001 -- no Control NCA, or one the keys do not open
        pass
    return entry


def update_id(application_id: int) -> str:
    """The update's ID of a game, as names show it: 01008F6008C5E000 -> 01008F6008C5E800."""
    return f"{application_id | verify.PATCH_ID_BIT:016X}"


def of_game(updates: list[Saved], application_id: int) -> list[Saved]:
    """The saved updates of this game, newest version first."""
    wanted = update_id(application_id)
    return sorted((u for u in updates if u.kind == "update" and u.title_id.upper() == wanted),
                  key=lambda u: u.version, reverse=True)


def newer(updates: list[Saved], application_id: int, installed: int | None, display_version: str = "") -> list[Saved]:
    """The saved updates the console would take: its game's, above its installed version. With that version
    unknown, every one but those with the console's display version; the run leaves before an upload the console
    would refuse."""
    mine = of_game(updates, application_id)
    if installed is None:
        return [u for u in mine if not (display_version and u.display_version == display_version)]
    return [u for u in mine if u.version > installed]


def same_as_console(updates: list[Saved], application_id: int, display_version: str) -> Saved | None:
    """A saved update with the console's display version: backing up its update would only fetch it again."""
    if not display_version:
        return None
    return next((u for u in of_game(updates, application_id) if u.display_version == display_version), None)


# ---- system updates as ZIPs ----

def zip_system(source, target) -> str:
    """Pack a system update folder (<content id>.nca files) into `target`, stored: written under a hidden name and
    moved into place whole. -> target."""
    target = str(target)
    names = sorted(n for n in os.listdir(source) if n.lower().endswith(".nca"))
    part = os.path.join(os.path.dirname(target), f".{os.path.basename(target)}.part")
    try:
        with zipfile.ZipFile(part, "w", zipfile.ZIP_STORED, allowZip64=True) as z:
            for name in names:
                z.write(os.path.join(source, name), name)
        os.replace(part, target)
    finally:
        if os.path.exists(part):
            os.remove(part)
    return target


def _zip_matches(path, source) -> bool:
    """Whether a ZIP holds every NCA of `source` at its size."""
    want = {n: os.path.getsize(os.path.join(source, n)) for n in os.listdir(source) if n.lower().endswith(".nca")}
    with zipfile.ZipFile(path) as z:
        have = {i.filename: i.file_size for i in z.infolist()}
    return all(have.get(n) == size for n, size in want.items())


def migrate(root, log=print) -> None:
    """Bring a library the Switch page kept (Updates/<name>.nsp, System/<version>/) to one file per update: each NSP
    moves up, each system update folder becomes its ZIP, and an emptied folder goes. A name already taken leaves
    that item where it is."""
    root = Path(root)
    updates, systems = root / "Updates", root / "System"
    for path in sorted(updates.glob("*.nsp")) if updates.is_dir() else ():
        target = root / path.name
        if not target.exists():
            os.replace(path, target)
            log(f"Moved {path.name} to the library's top")
    for path in sorted(systems.iterdir()) if systems.is_dir() else ():
        if not path.is_dir() or hidden(path.name) or not SYSTEM_VERSION.fullmatch(path.name):
            continue
        target = root / system_name(path.name)
        if target.exists():
            continue
        zip_system(path, target)
        if _zip_matches(target, path):
            shutil.rmtree(path)
            log(f"Packed system update {path.name} into {target.name}")
    for path in (updates, systems):
        try:
            path.rmdir()            # only when empty
        except OSError:
            pass


def sweep(root) -> None:
    """Remove what a run cut short left in the library (the app closed mid-transfer): hidden folders and
    unfinished files. One run at a time uses the library, so none is in use."""
    for path in Path(root).iterdir() if Path(root).is_dir() else ():
        if not hidden(path.name):
            continue
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            try:
                path.unlink()
            except OSError:         # held open elsewhere: the next run tries again
                pass


# ---- checks ----

def update_verdict(info: verify.UpdateInfo) -> str:
    return f"Complete · {info.size / 1e6:,.0f} MB · Nintendo's signatures verify"


def system_verdict(info: verify.SystemInfo) -> str:
    return f"Complete · {info.metas} content metas, {info.contents} contents · Nintendo's signatures verify"


def check(entry: Saved, keys: dict, progress=None) -> tuple[str, str]:
    """-> (state, message): valid, invalid or unchecked, after hashing every content and verifying every
    signature of a saved update or system update."""
    try:
        if entry.kind == "update":
            return "valid", update_verdict(verify.check_update(entry.path, keys, progress=progress))
        return "valid", system_verdict(verify.check_system(entry.path, keys, progress=progress))
    except verify.MissingKey as error:
        return "unchecked", f"Not checked: {error}."
    except KeyError as error:
        return "unchecked", f"Not checked: prod.keys lacks {error.args[0]}."
    except verify.InvalidUpdate as error:
        return "invalid", str(error)
    except Exception as error:      # noqa: BLE001 -- any file can sit in the library
        return "invalid", f"cannot be read: {error}"


def fingerprint(path: str, keys_path: str) -> list:
    """What a check's result depends on: the file's name, size and times, and the keys file's."""
    s = os.stat(path)
    try:
        k = os.stat(os.path.expanduser(keys_path))
        keys = [keys_path, k.st_size, k.st_mtime_ns]
    except (OSError, ValueError):
        keys = [keys_path]
    return [keys, [os.path.basename(path), s.st_size, s.st_mtime_ns]]


def _load(name: str, folder=None) -> dict:
    try:
        with open(Path(folder or data_folder()) / name, encoding="utf-8") as fh:
            found = json.load(fh)
        return found if isinstance(found, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(name: str, value: dict, folder=None) -> None:
    path = Path(folder or data_folder()) / name
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        part = path.with_name(path.name + ".part")
        part.write_text(json.dumps(value, indent=1), encoding="utf-8")
        os.replace(part, path)
    except OSError:
        pass


def load_checks(folder=None) -> dict:
    """{path: {"fingerprint": [...], "state": ..., "message": ...}} from earlier checks."""
    return _load("checks.json", folder)


def save_checks(checks: dict, folder=None) -> None:
    _save("checks.json", checks, folder)


def system_version(folder=None) -> str:
    """The system version pokeldn tells the console it runs: the last one a console sent, else DEFAULT_SYSTEM."""
    value = _load("state.json", folder).get("system_version", "")
    return value if isinstance(value, str) and SYSTEM_VERSION.fullmatch(value) else DEFAULT_SYSTEM


def remember_system_version(version: str, folder=None) -> None:
    if SYSTEM_VERSION.fullmatch(version):
        _save("state.json", {**_load("state.json", folder), "system_version": version}, folder)
