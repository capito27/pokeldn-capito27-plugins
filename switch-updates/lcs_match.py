"""Join a console's "Match Version With Local Users" group, show its game, then back up its update, send it a newer
one from the library, or back up its system update (docs/lcs.md "pokeldn joining a console's group").

    (them) HOME -> the game -> + -> Software Update -> Match Version With Local Users -> Next -> Create Group

From the app (the Switch Updates tool "Match Version"), the choice is a pop-up listing what the console can take;
from a terminal, a numbered list. --pull, --offer NSP and --system choose ahead. Updates go to the plugin's library,
one NSP each; a system update to its ZIP, `System update 20.5.0.zip`.

    POKELDN_PLUGINS=. python -m pokeldn lcs-match                    # as the app runs it
    python lcs_match.py --keys prod.keys --out DIR --pull            # development, without the app
    python lcs_match.py --loopback --out DIR --pull                  # against tools/lcs_host.py --loopback

The console decides who sends from the versions in pokeldn's join: to pull, pokeldn declares the base game (version
0); to offer, the update's version; for the system update, the base game and system 0.0.0.
"""
import argparse
import os
import queue
import shutil
import sys
import time
import traceback

from pokeldn import popup, progress
from pokeldn.ldn import radio_lost

from switchlcs import advertise as adv
from switchlcs import (
    cards,
    content,
    delivery,
    library,
    loopback,
    nca,
    net,
    session,
    verify,
)
from switchlcs import control as c
from switchlcs.record import recording

BASE_VERSION = 0
LOWEST_SYSTEM = "0.0.0"      # below any console's: the console sends its system update
MAX_OFFERS = 5               # newer saved updates the choice lists; with pull, system and leave, the pop-up's 8
MB = 1_000_000

NOT_FOUND = ("No Match Version With Local Users group was found nearby. On the console, choose Create Group for the "
             "game and leave it on the group's screen, then start the tool again.")
# CanDeliverApplication: the console's required version is only ever raised, and only a factory reset clears it
# (docs/lcs.md). Run from a release-day cartridge, the game sets it no higher than its first version.
OLDER = ("A Switch registers the newest version of a game it has run as that game's minimum version, and never "
         "installs an update below it, even after that update is deleted. The only way to reset the minimum and send "
         "this update is to factory reset the console (System Settings, System, Formatting Options, Initialize "
         "Console), which erases everything on it, then play the game from a release-day cartridge, without updating "
         "it, before sending the update again.")
NOT_TAKEN = f"The console finished without taking the update. {OLDER}"
WAITING = "Joined the group. On the console, start matching the version; the transfer begins once it does."


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--pull", action="store_true", help="back up the console's update of its game")
    mode.add_argument("--offer", metavar="NSP", help="send this newer update")
    mode.add_argument("--system", action="store_true", help="back up the console's system update")
    p.add_argument("--keys", default=None, help="prod.keys (the app passes the file Settings names)")
    p.add_argument("--out", metavar="DIR", help="the library; default the plugin's (Documents/pokeldn/Switch)")
    p.add_argument("--system-version", default="",
                   help="the system version pokeldn claims, major.minor.micro[-relstep]; default the last one a "
                        f"console sent, else {library.DEFAULT_SYSTEM}")
    p.add_argument("--name", default="pokeldn", help="the name the console shows for pokeldn")
    p.add_argument("--icon", metavar="FILE", help="write the game's icon (a JPEG) here")
    p.add_argument("--timeout", type=float, default=600, help="seconds to wait for the console")
    p.add_argument("--capture", metavar="FILE",
                   help="record every 55555 message and 55556 header, both directions, as JSON lines")
    p.add_argument("--loopback", action="store_true",
                   help=f"development: join tools/lcs_host.py --loopback on {loopback.HOST_IP}, no LDN")
    return p


def system_version(text):
    head, _, relstep = text.partition("-")
    major, minor, micro = (int(x) for x in head.split("."))
    return delivery.system_version(major, minor, micro, int(relstep or 0))


def claimed_system(args) -> str:
    if args.system_version:
        return args.system_version
    try:
        return library.system_version()
    except Exception:       # noqa: BLE001 -- run outside pokeldn's plugins: no data folder to read
        return library.DEFAULT_SYSTEM


def offering(paths, keys, app_id):
    """-> (source, the Patch keys of `app_id`, their highest version)."""
    source = content.NspSource(paths, keys)
    patches = session.patch_keys(list(source.metas), app_id)
    if not patches:
        raise session.SessionError(f"{os.path.basename(paths[0])} holds no update of this game ({app_id:016x})")
    if len(patches) > c.MAX_KEYS:
        raise session.SessionError(f"{len(patches)} content metas; a transfer carries at most {c.MAX_KEYS}")
    return source, patches, max(k.version for k in patches)


def app_record(app_id, version):
    return c.AppRecord(adv.application_info(app_id),
                       [delivery.ApplicationDeliveryInfo(application_id=app_id, application_version=version).pack()])


def join_message(args, app, version, claimed):
    sdi = delivery.SystemDeliveryInfo(system_update_version=system_version(claimed)).pack()
    return c.Join(sdi, args.name, [app_record(app.application_id, version)] if app else [])


def display_version(app):
    return app.display_version.rstrip(bytes(1)).decode(errors="replace")


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.keys:
        print("Choose prod.keys in Settings first: the tool needs them to read the console's updates.")
        return 1
    keys_path = os.path.expanduser(args.keys)
    card = cards.Console()
    try:
        out = library.folder(args.out)
        return run(args, keys_path, str(out), card)
    except KeyboardInterrupt:           # the player's Stop, or the board left USB
        if lost := radio_lost():
            card.end("error", lost)         # the card first: the run's output ends with what happened
            print(lost)
            return 1
        card.end("warning", "Stopped.")
        print("Stopped.")
        return 0
    except (session.SessionError, session.Leaving, verify.InvalidUpdate) as error:
        card.end("warning" if isinstance(error, session.Leaving) else "error", str(error))
        print(error)
        return 1
    except Exception as error:          # noqa: BLE001 -- the session's output carries the trace
        traceback.print_exc()
        card.end("error", f"The run failed: {type(error).__name__}. The session's output has the details.")
        return 1


def run(args, keys_path, out, card):
    keys = nca.load_keys(keys_path)
    os.makedirs(out, exist_ok=True)
    library.migrate(out)
    library.sweep(out)
    offer = None
    if args.offer:                      # chosen ahead: checked before the scan
        offer = check_offer(args.offer, keys)
    live = loopback.LoopbackGuest() if args.loopback else net.Guest(keys_path)
    print("Looking for the console's group. Keep the Switch on the group's screen, near the board.")
    find_group(live, args.timeout)
    recorder = None
    try:
        advertisement = adv.Advertisement.parse(live.app_data)
        app = advertisement.apps[0] if advertisement.apps else None
        network, recorder = recording(net.tcp_for(live), args.capture)
        sock = network.connect((live.host_ip, c.PORT), args.timeout)
        control = session.query_control(sock, app.application_id, args.timeout) if app else None
        if control and control.icon and args.icon:
            with open(args.icon, "wb") as fh:
                fh.write(control.icon)
        show(advertisement, app, control)
        icon = cards.save_icon(app.application_id, control.icon) if control and control.icon else None
        card.found(advertisement, app, control, icon)
        action, nsp = decide(args, app, control, out, keys)
        if action is None:
            sock.close()
            card.end("info", "Left the group.")
            print("Left the group.")
            return 0
        if action == "offer" and offer is None:
            offer = check_offer(nsp, keys, app.application_id)
        return share(args, keys, live, network, sock, app, control, action, offer, out, card)
    finally:
        if recorder:
            recorder.close()
        live.stop()


def find_group(live, timeout):
    """live.start, with a scan that finds no group reported in the console's terms."""
    try:
        live.start(timeout=timeout)
    except TimeoutError as error:           # the loopback host is not up
        raise session.SessionError(NOT_FOUND) from error
    except RuntimeError as error:           # pokeldn.ldn.network.join: every scan saw no joinable lcs group
        if "no joinable" not in str(error):
            raise
        raise session.SessionError(NOT_FOUND) from error


def show(advertisement, app, control):
    print(f"Found the group {advertisement.name!r}, {advertisement.node_count} of {advertisement.max_nodes} "
          "consoles.")
    if not app:
        print("  No game in this group: it shares the console's system update only.")
        return
    name = control.name if control else "Unknown game"
    publisher = f" ({control.publisher})" if control and control.publisher else ""
    installed = (f"version {display_version(app)}, an update of {app.update_size / MB:,.0f} MB"
                 if app.update_size else "no update installed")
    print(f"  {name}{publisher}, {app.application_id:016X}: {installed}")


def decide(args, app, control, out, keys):
    """-> (action, NSP for an offer): system, pull, offer or None to leave; asked unless an option chose."""
    if args.pull:
        return "pull", None
    if args.offer:
        return "offer", args.offer
    if args.system:
        return "system", None
    options = choices(app, control, out, keys)
    labels = [label for _action, _nsp, label in options]
    name = control.name if control else "the console's game"
    index = ask(f"Found {name}", "Choose what to do. pokeldn joins the group only then.", labels)
    action, nsp, label = options[index] if index is not None else (None, None, "Leave")
    print(f"Chosen: {label}")
    return action, nsp


def choices(app, control, out, keys) -> list[tuple]:
    """(action, NSP, label) for each thing the console can do with pokeldn, Leave last."""
    options = []
    if app and app.update_size:
        shown = display_version(app)
        saved = [library.read(entry, keys) for entry in library.saved(out) if entry.kind == "update"]
        copy = library.same_as_console(saved, app.application_id, shown)
        options.append(("pull", None, f"Back up its update {shown}" + (" (already saved)" if copy else "")))
        for entry in library.newer(saved, app.application_id, None, shown)[:MAX_OFFERS]:
            options.append(("offer", entry.path, f"Send update {entry.version_line}"))
        options.append(("system", None, "Back up its system update"))
    elif app:
        saved = [library.read(entry, keys) for entry in library.saved(out) if entry.kind == "update"]
        for entry in library.newer(saved, app.application_id, 0)[:MAX_OFFERS]:
            options.append(("offer", entry.path, f"Send update {entry.version_line}"))
    else:
        options.append(("system", None, "Back up its system update"))
    options.append((None, None, "Leave the group"))
    return options


def ask(title, text, labels) -> int | None:
    """The index of the option the player picks: a pop-up in the app, a numbered list in a terminal. None when the
    pop-up is dismissed."""
    if popup.available():
        answers = queue.Queue()
        popup.choose(title, text, labels, id="lcs-choice", on_choice=answers.put,
                     on_dismiss=lambda: answers.put(None))
        while True:             # a short wait, so the player's Stop interrupts it
            try:
                return answers.get(timeout=0.5)
            except queue.Empty:
                continue
    print(text)
    for i, label in enumerate(labels, 1):
        print(f"  {i}. {label}")
    while True:
        try:
            picked = input(f"Choose 1 to {len(labels)}: ").strip()
        except EOFError:
            return None
        if picked.isdigit() and 1 <= int(picked) <= len(labels):
            return int(picked) - 1


def check_offer(nsp, keys, application_id=None):
    """The update to send, checked whole before the console is asked to take it: every content hashed, every
    signature verified."""
    title = f"Checking {os.path.basename(nsp)}"
    info = verify.check_update(nsp, keys, application_id,
                               progress=lambda done, total: progress.show(done, total, title))
    print(f"{info.control.name or 'Update'} {info.display_version} (internal version {info.version}), "
          f"{info.size / MB:,.0f} MB: Nintendo's signatures verify.")
    return info


def share(args, keys, live, network, sock, app, control, action, offer, out, card):
    """Join for the chosen action and answer the console until it completes the share."""
    title = control.name if control else "update"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    parts = os.path.join(out, f".{stamp}-parts")
    source, offers, version = None, [], BASE_VERSION
    claimed = claimed_system(args)
    if action == "system":
        claimed = LOWEST_SYSTEM
    elif not app:
        raise session.SessionError("the group's advertisement names no game")
    elif action == "pull":
        if not app.update_size:
            raise session.SessionError("the console has the game without an update: nothing to back up")
    else:
        source, offers, version = offering([offer.path], keys, app.application_id)
        if version != offer.version:
            raise session.SessionError("the NSP's update changed since it was checked")
    work = {"pull": f"Backing up {title} {display_version(app) if app else ''}".strip(),
            "offer": f"Sending {title} {offer.display_version if offer else ''}".strip(),
            "system": "Backing up the system update"}[action]
    flow = Flow()

    def moved(done, total):
        """The receiver announces the total after the Meta NCA, so `total` can still be None."""
        flow.moved(done)
        if total:
            progress.show(done, total, work)

    guest = session.Guest(network, live.our_ip, join_message(args, app, version, claimed), source=source,
                          offers=offers, outdir=parts, keys=keys, timeout=args.timeout, progress=moved)
    systems = {}        # the hidden folder a system update arrives in -> its ZIP

    def system(info):
        text = library.short_version(info.system_update_version)
        guest.system_outdir = os.path.join(out, f".{stamp}-{text}-system-parts")
        systems[guest.system_outdir] = (os.path.join(out, library.system_name(text)), text)
        print(f"The console sends its system update {text}.")
        card.set("System update", text)

    guest.on_system = system
    guest.listing = lambda done, total: progress.show(done, total, "Reading the list of contents", "items")
    first, consoles = [True], []

    def in_sync(join):
        """After the system update, the refresh names the console's game version too: the console has nothing
        left to send and completes the share, without sending its game update."""
        if action != "system" or not consoles:
            return join
        return session.with_version(join, app.application_id, consoles[0].application_version)

    guest.after_system = in_sync

    def snapshot(snap):
        """The console's own delivery info arrives in the first 0x09 after the join (docs/lcs.md): report its
        installed version, and leave an upload it would refuse. Later 0x09s follow the share and are not the
        console's state before it. A system download joins with the game at the base version: a console sends its
        system update only to a member that is to receive a game update needing a newer system than the
        member's (seen live)."""
        info = consoles_info(snap, app.application_id, guest.join) if app and first[0] else None
        if app and first[0] and info is None:
            print("The group shows pokeldn's own delivery info: the console's game is older, or archived. Its "
                  "version is known only to the console, which decides whether it takes the update.")
        first[0] = False
        if info is None:
            return
        consoles.append(info)
        print(f"The console has internal version {info.application_version} of the game.")
        card.set("Internal version", info.application_version)
        if action == "offer":
            refuse_older(info, version)

    guest.on_snapshot = snapshot
    print(WAITING)
    try:
        guest.run(live.host_ip, sock)
    except BaseException as error:
        _settle(guest.received, systems)
        _remove_tree(parts)
        plain = _plainly(error, action, served=bool(guest.served), timeout=args.timeout)
        if plain is error:
            raise
        raise plain from error
    received = _settle(guest.received, systems)
    if action == "offer" and not guest.served:
        raise session.SessionError(older_update(NOT_TAKEN))
    files = [p for p in received if not p.startswith(parts + os.sep)]
    taken = [p for p in received if p.startswith(parts + os.sep)]
    if taken:       # the game's update: one NSP, which the tool can send to another console
        got = _update_version(taken, keys)
        patch_id = app.application_id | verify.PATCH_ID_BIT
        written = content.write_nsp(os.path.join(out, content.update_name(title, patch_id, got)), taken)
        files.append(_named_with_display_version(written, title, patch_id, got, keys))
        _remove_tree(parts)
    for path in files:
        print(f"Saved {os.path.basename(path)}")
        cards.backed_up(os.path.basename(path), card.group, image=card.image if path.endswith(".nsp") else None)
    sent = sum(s.bytes_sent for s in guest.served)
    if sent:
        print(f"Sent {sent / MB:,.0f} MB to the console.")
    rows = {"Saved": ", ".join(os.path.basename(p) for p in files)} if files else {}
    if speed := flow.speed():
        rows["Speed"] = speed
    outcome = {"pull": f"Backed up its update {display_version(app) if app else ''}".strip(),
               "offer": f"Sent update {offer.display_version if offer else ''}".strip() + f", {sent / MB:,.0f} MB",
               "system": "Backed up its system update"}[action]
    card.end("ok", outcome, **rows)
    return 0


class Flow:
    """The share's speed for the card, from its progress: the bytes moved between the first progress and the last.
    Each transfer counts from 0 again, so a count that drops starts the next one."""

    def __init__(self):
        self.started = self.last_at = None
        self.moved_bytes = self.last = 0

    def moved(self, done: int) -> None:
        now = time.monotonic()
        if self.started is None:
            self.started, self.last = now, done
        self.moved_bytes += done - self.last if done >= self.last else done
        self.last, self.last_at = done, now

    def speed(self) -> str:
        """"0.52 MB/s", or empty when the share moved data for under a second."""
        if self.started is None or self.last_at - self.started < 1:
            return ""
        return f"{self.moved_bytes / (self.last_at - self.started) / MB:.2f} MB/s"


def _remove_tree(path):
    shutil.rmtree(path, ignore_errors=True)


def older_update(message: str) -> str:
    """`message`, also shown as a pop-up: the console refuses an update older than one it has run."""
    if popup.available():
        popup.acknowledge("The console won't take an older update", message, id="lcs-older-update", tone="warning")
    return message


def consoles_info(snapshot, application_id, join=None):
    """The newest ApplicationDeliveryInfo of `application_id` in a 0x09, or None. While the console's own record
    stands there (docs/lcs.md), it is the console's: installed and required versions. A member's record replaces it
    when it ranks newer, so delivery infos that are `join`'s own are not the console's (seen live with the game
    archived)."""
    ours = {raw for r in (join.apps if join else ()) for raw in r.delivery_infos}
    infos = [delivery.ApplicationDeliveryInfo.parse(raw, verify=False)
             for r in snapshot.apps if r.application_id == application_id for raw in r.delivery_infos
             if raw not in ours]
    return max(infos, key=lambda i: i.application_version, default=None)


def refuse_older(info, version):
    """Leave before the share when the console's delivery info shows it would not take `version`: it has that
    version or a newer one, or it has run a newer one (CanDeliverApplication)."""
    if info is None:
        return
    if info.application_version > version:
        said = f"The console has version v{info.application_version} of the game"
    elif info.required_application_version > version:
        said = f"The console has run version v{info.required_application_version} of the game"
    elif info.application_version == version:
        raise session.Leaving(f"The console already has version v{version} of the game, the same as this update.")
    else:
        return
    raise session.Leaving(older_update(f"{said}, newer than this update (v{version}). {OLDER}"))


def _settle(received, systems):
    """Pack each system update received whole (its files are in `received`, which a transfer extends only once it
    completes) into its ZIP, replacing an older copy, and drop the rest. -> `received` with each system update's
    files replaced by its ZIP."""
    received = list(received)
    for hidden, (target, text) in systems.items():
        mine = [p for p in received if p.startswith(hidden + os.sep)]
        if mine:
            library.zip_system(hidden, target)
            try:
                library.remember_system_version(text)
            except Exception:   # noqa: BLE001 -- run outside pokeldn's plugins: no data folder
                pass
            received = [p for p in received if p not in mine] + [target]
        _remove_tree(hidden)
    return received


def _plainly(error, action, served=False, timeout=None):
    """Say what happened in the console's terms. A stop (KeyboardInterrupt) and anything unforeseen pass unchanged.
    `served`: the console pulled the whole update before the error; `timeout`: the seconds a read waited."""
    if isinstance(error, session.Leaving):
        return error
    if isinstance(error, session.Rejected) and served:
        return session.SessionError(
            f"The console received the whole update, then ended the share (error "
            f"{session.REJECT_CODES.get(error.reason, error.reason)}). Its Data Management shows whether "
            f"it kept the update.")
    if isinstance(error, session.Rejected):
        return session.SessionError(f"The console refused to let pokeldn join (error "
                                    f"{session.REJECT_CODES.get(error.reason, error.reason)}).")
    if isinstance(error, (OSError, content.ProtocolError, c.ProtocolError, session.SessionError)):
        after = ("The console did not receive the whole update." if action == "offer" else
                 "Nothing incomplete was kept.")
        why = str(error).rstrip(".") or type(error).__name__
        if isinstance(error, TimeoutError) and why == "timed out" and timeout:
            why = f"the console sent nothing for {timeout / 60:g} minutes" if timeout >= 120 else \
                f"the console sent nothing for {timeout:g} seconds"
        return session.SessionError(f"The share stopped: {why}. {after}")
    return error


def _named_with_display_version(path, title, patch_id, version, keys):
    """The NSP renamed with its own display version (content.update_name), once its Control NCA reads."""
    try:
        display = c.ApplicationControl.parse(content.nsp_control_data(path, keys)[1]).display_version
    except Exception:       # noqa: BLE001 -- the NSP is whole either way; it keeps the name without it
        return path
    named = os.path.join(os.path.dirname(path), content.update_name(title, patch_id, version, display))
    if display and named != path:
        os.replace(path, named)
        return named
    return path


def _update_version(paths, keys):
    for path in paths:
        if path.endswith(".cnmt.nca"):
            with open(path, "rb") as fh:
                return nca.read_cnmt(fh.read(), keys).version
    return 0


if __name__ == "__main__":
    sys.exit(main())
