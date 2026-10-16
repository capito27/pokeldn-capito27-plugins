#!/usr/bin/env python3
"""Run the lcs "pokeldn joins a console" workflow end to end: tools/lcs_host.py --console stands in for the
console, lcs_match.py is pokeldn.

    python tools/lcs_simulate.py pull   --base BASE.nsp --update UPDATE.nsp --keys prod.keys --out DIR
    python tools/lcs_simulate.py offer  --base BASE.nsp --update UPDATE.nsp --keys prod.keys --out DIR
    python tools/lcs_simulate.py system --base BASE.nsp --update UPDATE.nsp --system FIRMWARE --keys prod.keys --out DIR
    python tools/lcs_simulate.py pull --transport boards ...    # small updates only

pull:   the console has the update and answers 0x03 from the base game's Control NCA; pokeldn finds the group,
        queries the game, joins as the base version and receives the update over 55556 into OUT/pokeldn, its
        library, as one NSP.
offer:  the console has only the base game; pokeldn offers the update, and the console pulls it.
system: the console has the update and the system update installed in FIRMWARE (a folder of NCAs, Ryujinx's
        bis/system/Contents/registered, or a library ZIP); pokeldn joins claiming 0.0.0 and the base game, so the
        console suspends it and sends the system update the game update requires, which pokeldn packs into its
        ZIP. pokeldn's refresh then names the console's system and game versions, and the console completes the
        share.

--capture records both sides' lcs messages (switchlcs.record) in OUT/console.jsonl and OUT/pokeldn.jsonl.

--transport loopback (the default) runs 55555 and 55556 over the OS's TCP between 127.0.0.1 and 127.0.0.2
(switchlcs.loopback), at disk speed: for developing the protocols with large updates. --transport boards runs them
over the plugin's TCP through two simulated ESP32 boards and pokeldn's plugin network surface, LDN included, as
over a real board. Python moves about 1.6 MB/s that way, so it takes transfers up to BOARD_LIMIT; --allow-large
lifts the limit for a deliberate long run, and --loss PERCENT loses that share of the data frames between the
boards. docs/lcs.md "pokeldn joining a console's group".
"""
import argparse
import contextlib
import os
import sys
import threading
import time
import traceback
import zipfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["POKELDN_RADIO"] = "esp32:simulated"      # read only by --transport boards

import lcs_host                                                          # noqa: E402
import lcs_match                                                         # noqa: E402
from ldn import wlan                                                     # noqa: E402

from switchlcs import content, library, nca                              # noqa: E402
from pokeldn.ldn import esp32, esp32_sim, esp32_wlan, userspace_ip       # noqa: E402

CHANNEL = 6
BOARD_LIMIT = 256 << 20         # bytes to move; about 3 minutes through the simulated boards


def boards(loss=0.0):
    """Two simulated boards on one air that loses `loss` of the data frames. The first thread to open a
    radio (the host's) gets the first."""
    air = esp32_sim.Air()
    air.loss = loss
    radios = [esp32.Radio(esp32_sim.SimulatedBoard(air).host_stream()) for _ in range(2)]
    owners, lock = {}, threading.Lock()

    @contextlib.asynccontextmanager
    async def factory():
        with lock:
            if threading.get_ident() not in owners:
                owners[threading.get_ident()] = radios[min(len(owners), 1)]
            radio = owners[threading.get_ident()]
        esp = esp32_wlan.EspFactory(radio, port_factory=userspace_ip.userspace_port, join_timeout=5)
        try:
            yield esp
        finally:
            esp.router.close()
    return radios, factory


class Run(threading.Thread):
    def __init__(self, name, fn, argv):
        super().__init__(name=name, daemon=True)
        self.fn, self.argv, self.code, self.error = fn, argv, None, None

    def run(self):
        try:
            self.code = self.fn(self.argv)
        except BaseException as e:                       # noqa: BLE001
            self.error = e
            traceback.print_exc()


def files_of(path):
    """{name: (size, read(offset, size))} of a folder's files, a ZIP's members or an NSP's entries."""
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            sizes = {i.filename: i.file_size for i in z.infolist()}

        def member(name, at, n):
            with zipfile.ZipFile(path) as z, z.open(name) as fh:
                fh.seek(at)
                return fh.read(n)
        return {n: (size, lambda at, n_, name=n: member(name, at, n_)) for n, size in sorted(sizes.items())}
    if os.path.isdir(path):
        found = {n: (os.path.join(path, n), 0, os.path.getsize(os.path.join(path, n)))
                 for n in sorted(os.listdir(path))}
    else:
        found = {n: (path, *at) for n, at in content._pfs0_entries(path)}
    return {n: (size, lambda at, n_, f=f, base=base: content._read(f, base + at, n_))
            for n, (f, base, size) in found.items()}


def installed_files(root, keys):
    """{name as received: (size, read(offset, size))} of a system update's installed contents."""
    source = content.DirSource(root, keys)
    metas = {m.content_id for m in source.metas.values()}
    return {cid.hex() + (".cnmt.nca" if cid in metas else ".nca"):
            (source.content_size(cid, check=False), lambda at, n, cid=cid: source.read_content(cid, at, n))
            for cid in source.parts}


def verify(received, expected):
    """Compare every file the receiving side wrote (a folder, or the NSP pokeldn packed) with the
    same-named one of `expected` (files_of / installed_files). -> a list of problems, empty when all are
    identical."""
    got = files_of(received)
    problems = [] if got else [f"nothing in {received}"]
    for name, (size, ours) in got.items():
        if name not in expected:
            problems.append(f"{name}: not in the source")
            continue
        total, theirs = expected[name]
        if size != total:
            problems.append(f"{name}: {size} bytes, the source has {total}")
            continue
        for at in range(0, size, 8 << 20):
            if ours(at, min(8 << 20, size - at)) != theirs(at, min(8 << 20, size - at)):
                problems.append(f"{name}: differs from the source")
                break
    return problems


def received_and_expected(args, console_out, pokeldn_out, keys):
    """-> (what the receiver wrote: the console's folder, or pokeldn's NSP or system update ZIP, or None; the files
    it should match)."""
    if args.scenario == "offer":
        return console_out, files_of(args.update)
    found = [e.path for e in library.saved(pokeldn_out) if e.kind == ("system" if args.scenario == "system" else
                                                                       "update")]
    if args.scenario == "system":
        system = args.system
        if system.lower().endswith(".zip"):
            return (found[0] if found else None), files_of(system)
        return (found[0] if found else None), installed_files(system, nca.load_keys(keys))
    return (found[0] if found else None), files_of(args.update)


def folder_size(root):
    return sum(os.path.getsize(os.path.join(d, f)) for d, _s, files in os.walk(root) for f in files)


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("scenario", choices=("pull", "offer", "system"))
    p.add_argument("--base", required=True, help="the base game NSP")
    p.add_argument("--update", help="pull, offer: the update NSP")
    p.add_argument("--system", metavar="DIR", help="system: the console's installed system update, or its ZIP")
    p.add_argument("--out", required=True, help="a directory for what each side receives")
    p.add_argument("--transport", choices=("loopback", "boards"), default="loopback")
    p.add_argument("--loss", type=float, default=0.0, metavar="PERCENT",
                   help="--transport boards: lose this share of the data frames, at random")
    p.add_argument("--capture", action="store_true", help="record both sides' lcs messages in OUT")
    p.add_argument("--allow-large", action="store_true",
                   help=f"--transport boards: allow a transfer over {BOARD_LIMIT >> 20} MiB")
    p.add_argument("--keys", required=True, help="prod.keys")
    p.add_argument("--timeout", type=float, default=120)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.scenario == "system") != bool(args.system) or not args.update:
        parser.error("every scenario takes --update NSP; system also takes --system DIR")
    boarded = args.transport == "boards"
    if not args.system:
        moved = os.path.getsize(args.update)
    else:
        moved = folder_size(args.system) if os.path.isdir(args.system) else os.path.getsize(args.system)
    if boarded and moved > BOARD_LIMIT and not args.allow_large:
        print(f"{moved >> 20} MiB to move: the simulated boards move about 1.6 MB/s, so they take "
              f"transfers up to {BOARD_LIMIT >> 20} MiB. Use --transport loopback, or --allow-large for a "
              "deliberate long run.", file=sys.stderr)
        return 2
    keys = os.path.expanduser(args.keys)
    common = ["--keys", keys, "--timeout", str(args.timeout)]
    loop = [] if boarded else ["--loopback"]
    console_out, pokeldn_out = os.path.join(args.out, "console"), os.path.join(args.out, "pokeldn")
    os.makedirs(console_out, exist_ok=True)
    os.makedirs(pokeldn_out, exist_ok=True)
    installed = [args.update] if args.scenario in ("pull", "system") else [args.base]
    host_argv = ["--name", "Console", "--out", console_out, "--control-from", args.base, *common, *loop]
    host_argv += ["--channel", str(CHANNEL)] if boarded else []
    host_argv += [x for path in installed for x in ("--console", path)]
    host_argv += ["--system", args.system] if args.system else []
    join_argv = ["--icon", os.path.join(args.out, "icon.jpg"), "--out", pokeldn_out, *common, *loop]
    if args.capture:
        host_argv += ["--capture", os.path.join(args.out, "console.jsonl")]
        join_argv += ["--capture", os.path.join(args.out, "pokeldn.jsonl")]
    join_argv += {"pull": ["--pull"], "offer": ["--offer", args.update], "system": ["--system"]}[args.scenario]

    radios = []
    if boarded:
        radios, factory = boards(args.loss / 100)
        wlan.set_factory(factory)
    host, joiner = Run("console", lcs_host.main, host_argv), Run("pokeldn", lcs_match.main, join_argv)
    started = time.monotonic()
    try:
        host.start()
        if boarded:
            time.sleep(3)                               # the group is up before the scan
        joiner.start()                                  # over loopback it waits for the host itself
        for t in (joiner, host):
            while t.is_alive():
                t.join(1)
    finally:
        if boarded:
            wlan.set_factory(None)
        for r in radios:
            r.close()
    elapsed = time.monotonic() - started
    print(f"\n[simulate] {args.scenario} over {args.transport}: console exit {host.code}, pokeldn exit "
          f"{joiner.code}, {elapsed:.0f} s, {moved / max(elapsed, 1e-3) / 1e6:.1f} MB/s")
    for t in (host, joiner):
        if t.error:
            print(f"[simulate] {t.name} failed: {t.error!r}")
    ok = host.code == joiner.code == 0 and not (host.error or joiner.error)
    if ok:
        received, expected = received_and_expected(args, console_out, pokeldn_out, keys)
        problems = verify(received, expected) if received else ["pokeldn saved nothing"]
        for problem in problems:
            print(f"[simulate] {problem}")
        count = len(files_of(received)) if received else 0
        print(f"[simulate] {count} received file(s) {'differ from' if problems else 'identical to'} the source's")
        ok = not problems
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
