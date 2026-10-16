"""What the tools leave on their pages (pokeldn.panel, plugin API 1.8): a card for the console Match Version met and
how its share ended, a card for the last check and the last import, and a note on each library file they read,
with the game's icon. Outside the app pokeldn.panel prints its `[panel]` line and nothing else.

The icons are the games' own JPEGs, one per game, kept in the plugin's data folder (`icons/<application ID>.jpg`)
where the app draws images from. A game's updates all share it, so the first one found stays: the one Match Version
receives from a console, or the one in the Control NCA of the first of the game's updates a tool reads. An update
finds it by its title ID, from its file name when the list did not read the NSP. The console card shows the JPEG;
the notes show a 64 x 64 PNG made from it once, beside it (`<ID>.png`): the app reads and sends every note's image
when it opens the page, and a few dozen whole icons kept it from opening for seconds."""

import os
from pathlib import Path

from pokeldn import panel

from switchlcs import content, library, thumbnail
from switchlcs.control import ApplicationControl

MB = 1_000_000


def _fit(text, limit: int) -> str:
    """`text` cut to what a card holds (pokeldn.panel's limits): a game's or a group's name can be longer."""
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _row(label: str, value) -> str:
    return f"{_fit(label, panel.CHIP)}\t{_fit(value, panel.TEXT)}"


# ---- the games' icons ----

def _icons() -> Path | None:
    try:
        return library.data_folder() / "icons"
    except Exception:       # noqa: BLE001 -- run outside pokeldn's plugins: no data folder, no image
        return None


def _kept(folder: Path, title_id: int) -> Path:
    """Where a game's icon is kept: by its application ID, which its updates' IDs share but for the last 12 bits."""
    return folder / f"{title_id & ~0xFFF:016X}.jpg"


def save_icon(application_id: int, jpeg: bytes) -> Path | None:
    """The game's icon in the data folder, written when it has none yet. -> its path, or None when there is none to
    draw."""
    folder = _icons()
    if folder is None:
        return None
    path = _kept(folder, application_id)
    if path.is_file():
        return path
    if not jpeg.startswith(b"\xff\xd8") or len(jpeg) > panel.IMAGE_BYTES:
        return None
    try:
        folder.mkdir(parents=True, exist_ok=True)
        part = path.with_name(path.name + ".part")
        part.write_bytes(jpeg)
        os.replace(part, path)
    except OSError:
        return None
    return path


def icon_of(entry: library.Saved, keys: dict | None) -> Path | None:
    """A saved update's game icon: the one kept for its game, else read from the NSP's Control NCA and kept."""
    if entry.kind != "update" or (folder := _icons()) is None:
        return None
    title_id = entry.title_id or ((match := library.NSP_NAME.match(os.path.basename(entry.path))) and match["id"])
    if title_id and (kept := _kept(folder, int(title_id, 16))).is_file():
        return kept
    if not keys:
        return None
    try:
        application_id, data = content.nsp_control_data(entry.path, keys)
        return save_icon(application_id, ApplicationControl.parse(data).icon)
    except Exception:       # noqa: BLE001 -- no Control NCA, one the keys do not open, or no icon in it
        return None


def small(icon) -> Path | None:
    """A kept icon's thumbnail, made beside it once; the icon itself when it cannot be made."""
    if not icon:
        return None
    icon = Path(icon)
    path = icon.with_suffix(".png")
    try:
        if path.is_file():
            return path
        png = thumbnail.from_jpeg(icon.read_bytes())
        if png is None:
            return icon
        part = path.with_name(path.name + ".part")
        part.write_bytes(png)
        os.replace(part, path)
    except OSError:
        return icon
    return path


# ---- library notes ----

def checking(name: str, image=None) -> None:
    panel.annotate(name, state="checking", text="Checking…", image=small(image))


def checked(name: str, state: str, message: str, image=None) -> None:
    """A check's result on its file: valid and invalid as ok and bad; unchecked (keys missing) leaves no note."""
    if state == "unchecked":
        panel.unannotate(name)
        return
    panel.annotate(name, state="ok" if state == "valid" else "bad", text=_fit(message, panel.TEXT),
                   image=small(image))


def backed_up(name: str, group: str, image=None) -> None:
    """A file Match Version saved: every content arrived hashed against its content meta."""
    panel.annotate(name, text=_fit(f"Backed up from {group}", panel.TEXT), image=small(image))


# ---- Match Version's console ----

class Console:
    """The card of the console a Match Version run met: the game, its icon and versions, then how the share ended.
    Each change shows it again under the same id, replacing the last."""

    ID = "console"

    def __init__(self):
        self.title, self.group, self.image, self.rows, self.chips = "", "", None, {}, {}

    def found(self, advertisement, app, control, icon=None):
        self.title = (control.name if control and control.name else "Unknown game") if app else "System update"
        self.group, self.image = advertisement.name, icon
        self.rows = {"Group": f"{self.group} · {advertisement.node_count} of {advertisement.max_nodes} consoles"}
        if app:
            if control and control.publisher:
                self.rows["Publisher"] = control.publisher
            self.rows["Game ID"] = f"{app.application_id:016X}"
            shown = app.display_version.rstrip(bytes(1)).decode(errors="replace")
            if app.update_size:
                self.chips["Installed"] = shown
                self.rows["Update size"] = f"{app.update_size / MB:,.0f} MB"
            else:
                self.chips["Installed"] = "No update"
        self.show()

    def set(self, label: str, value) -> None:
        self.rows[label] = value
        self.show()

    def end(self, tone: str, outcome: str, **rows) -> None:
        """How the run ended, as the card's tone, a line and any rows it adds. Nothing when no console was met."""
        if not self.title:
            return
        self.rows.update(rows)
        self.show(tone, outcome)

    def show(self, tone: str = "info", outcome: str = "") -> None:
        if not self.title:
            return
        lines = [_row(label, value) for label, value in self.rows.items()]
        if outcome:
            lines = [_fit(outcome, panel.TEXT), *lines]
        chips = [(_fit(k, panel.CHIP), _fit(v, panel.CHIP)) for k, v in self.chips.items()][:panel.CHIPS]
        panel.show(self.ID, _fit(self.title, panel.TITLE), lines[:panel.LINES], image=self.image, chips=chips,
                   tone=tone)


def summary(id: str, title: str, rows: dict, tone: str, lines=()) -> None:
    """A tool's last result as a card: `lines` first, then `rows` as two columns."""
    body = [_fit(line, panel.TEXT) for line in lines] + [_row(k, v) for k, v in rows.items()]
    panel.show(id, _fit(title, panel.TITLE), body[:panel.LINES], tone=tone)
