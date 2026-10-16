#!/usr/bin/env python3
"""Host a "Match Version With Local Users" group that a console joins (docs/lcs.md).

    python tools/lcs_host.py --log-join join.bin            # record a console's join, then stop
    python tools/lcs_host.py --backup-system out/su         # pull the console's system update
    python tools/lcs_host.py --backup-app 0100F2C0115B6000 --out out/app
    python tools/lcs_host.py --serve backup/update.nsp      # give the console this game update
    python tools/lcs_host.py --console update.nsp --out DIR  # share like a console: newest wins
    python tools/lcs_host.py --console base.nsp --out DIR --system FIRMWARE   # and send an older member
                                                                            # this system update

    (them) HOME -> the game -> + -> Software Update -> Match Version With Local Users -> Next -> Join Group

    python tools/lcs_host.py --loopback --console update.nsp --out DIR   # development: no LDN, no radio

It hosts through pokeldn's plugin surface (switchlcs.net), so it needs the ESP32 board (POKELDN_RADIO) or
--loopback. --system takes a folder of NCAs or a system update ZIP from the library.
Untested against a console: the first run should be --log-join, which only reads the 0x05.
"""
import argparse
import os
import shutil
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from switchlcs import advertise as adv, content, control as c, delivery, loopback, nca, net, session  # noqa: E402
from switchlcs.record import recording                                     # noqa: E402

LDN_PROTOCOL = 1        # qlaunch never calls SetProtocol, so a Switch 1 group is Protocol NX (switchbrew)


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--log-join", metavar="FILE", help="write the first console's 0x05 here and stop")
    mode.add_argument("--backup-system", metavar="DIR", help="pull the console's system update into DIR")
    mode.add_argument("--backup-app", metavar="APP_ID", type=lambda s: int(s, 16),
                      help="pull the console's update of this application (with --out)")
    mode.add_argument("--serve", metavar="NSP", action="append", help="send this update; repeatable")
    mode.add_argument("--console", metavar="NSP", action="append",
                      help="act as a console with this game installed (base and/or update NSPs; "
                           "repeatable): answer 0x03, and send or take the update by version")
    p.add_argument("--control-from", metavar="NSP",
                   help="--console: the NSP whose Control NCA answers 0x03; default the newest given")
    p.add_argument("--out", help="where --backup-app, and --console when the member's is newer, write")
    p.add_argument("--system", metavar="DIR",
                   help="act as a console on this system update: a folder of its installed NCAs (Ryujinx's "
                        "bis/system/Contents/registered) or a library ZIP. The group claims its version, and a "
                        "member on an older one is sent it before anything else")
    p.add_argument("--required-version", type=lambda v: int(v, 0), default=0,
                   help="--console: the newest version of the game this console has run (ns's required "
                        "version); it takes no update older than that")
    p.add_argument("--name", default="pokeldn", help="the group's name on the console")
    p.add_argument("--system-version", default="20.5.0",
                   help="the firmware pokeldn claims, as major.minor.micro[-relstep]")
    p.add_argument("--keys", required=True, help="prod.keys")
    p.add_argument("--loopback", action="store_true",
                   help=f"development: host on {loopback.HOST_IP} for lcs_match.py --loopback, no LDN")
    p.add_argument("--channel", type=int, default=None)
    p.add_argument("--timeout", type=float, default=600, help="seconds to wait for the console")
    p.add_argument("--capture", metavar="FILE",
                   help="record every 55555 message and 55556 header, both directions, as JSON lines")
    return p


def system_version(text):
    head, _, relstep = text.partition("-")
    major, minor, micro = (int(x) for x in head.split("."))
    return delivery.system_version(major, minor, micro, int(relstep or 0))


def serving(paths, keys):
    """-> (source, application ID, the Patch keys offered, the highest version)."""
    source = content.NspSource(paths, keys)
    patches = [k for k in source.metas if k.type == nca.PATCH]
    if not patches:
        raise SystemExit("no game update (Patch content meta) in " + ", ".join(paths))
    app_id = patches[0].id & ~0xFFF
    if any(k.id & ~0xFFF != app_id for k in patches):
        raise SystemExit("the NSPs hold updates of more than one game")
    if len(patches) > c.MAX_KEYS:
        raise SystemExit(f"{len(patches)} content metas; a transfer carries at most {c.MAX_KEYS}")
    return source, app_id, patches, max(k.version for k in patches)


def installed(paths, keys, control_from):
    """--console: -> (source, application ID, its Patch keys, the installed version, its display
    version, control data). The version is the highest Patch among `paths`, 0 for a base game alone;
    the display version is the newest NSP's, as a console advertises its installed game's."""
    source = content.NspSource(paths, keys)
    app_ids = {k.id & ~0xFFF for k in source.metas if k.type in (nca.APPLICATION, nca.PATCH)}
    if len(app_ids) != 1:
        raise SystemExit(f"--console needs one game, found {len(app_ids)} in " + ", ".join(paths))
    app_id = app_ids.pop()
    patches = session.patch_keys(list(source.metas), app_id)
    newest = max(paths, key=lambda p: max((k.version for k in content.NspSource([p], keys).metas), default=0))
    control_id, data = content.nsp_control_data(control_from or newest, keys)
    if control_id != app_id:
        raise SystemExit(f"--control-from is {control_id:016x}, not {app_id:016x}")
    try:
        newest_data = content.nsp_control_data(newest, keys)[1]
    except ValueError:                  # no Control NCA in it
        newest_data = data
    display = c.ApplicationControl.parse(newest_data).display_version
    return source, app_id, patches, max((k.version for k in patches), default=0), display.encode(), data


def required_system(paths, keys, key):
    """The system version the Patch `key`'s content meta requires (its extended header +0x8), which a
    console's delivery info carries as its required system version; 0 when no NSP holds it."""
    for path in paths:
        for name, at in content._pfs0_entries(path):
            if name.endswith(".cnmt.nca"):
                cnmt = nca.read_cnmt(content._read(path, *at), keys)
                if cnmt.key == key and len(cnmt.extended_header) >= 0xC:
                    return struct.unpack_from("<I", cnmt.extended_header, 8)[0]
    return 0


def advertised_app(app_id, version, display=b"", required=0, source=None, patches=(), required_system=0):
    """The record a console's 0x09 shows and the advertisement's entry. A console advertises its update's
    size (ns's EstimateRequiredSize), not its version: here the size of the update's contents."""
    size = sum(source.content_size(i) for k in patches for i in source.allowed[k]) \
        if source is not None and version else 0
    info = adv.application_info(app_id, display, update_size=size)
    record = c.AppRecord(info, [delivery.ApplicationDeliveryInfo(application_id=app_id, application_version=version,
                                                                 required_application_version=required,
                                                                 required_system_version=required_system).pack()])
    return record, adv.App.from_info(info)


def make_host(args, advertisement, keys_path):
    return net.Host(keys_path, advertisement.pack(), LDN_PROTOCOL, channel=args.channel)


def system_folder(path, keep):
    """A system update's folder: `path` itself, or a library ZIP extracted into a folder `keep` removes."""
    if os.path.isdir(path):
        return path
    folder = tempfile.mkdtemp(prefix="lcs-system-")
    keep.append(folder)
    with zipfile.ZipFile(path) as z:
        z.extractall(folder)
    return folder


def describe(join):
    info = delivery.SystemDeliveryInfo.parse(join.system_info, verify=False)
    gate = delivery.verify_system(join.system_info)
    print(f"  name {join.name!r}, join version {join.version:#04x}, system "
          f"{delivery.version_string(info.system_update_version)}, join gate "
          f"{delivery.error_code(gate) if gate else 'passes'}")
    for app in join.apps:
        for raw in app.delivery_infos:
            a = delivery.ApplicationDeliveryInfo.parse(raw, verify=False)
            print(f"  application {a.application_id:016x} version {a.application_version:#x}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    if (args.backup_app is not None or args.console) and not args.out:
        print("--backup-app and --console need --out", file=sys.stderr)
        return 2
    keys_path = os.path.expanduser(args.keys)
    keys = nca.load_keys(keys_path)
    extracted = []
    try:
        return serve(args, keys_path, keys, extracted)
    finally:
        for folder in extracted:
            shutil.rmtree(folder, ignore_errors=True)


def serve(args, keys_path, keys, extracted):
    records, apps, source, control, system = [], [], None, {}, None
    if args.system:
        system = content.DirSource(system_folder(args.system, extracted), keys)
        if system.system_update() is None:
            raise SystemExit(f"no SystemUpdate content meta in {args.system}")
        print(f"system update {delivery.version_string(system.system_update().version)}: "
              f"{len(system.metas)} content metas")
    if args.console:
        source, app_id, offered, version, display, data = installed(args.console, keys, args.control_from)
        newest = max(offered, default=None)
        record, app = advertised_app(app_id, version, display, args.required_version, source, offered,
                                     required_system(args.console, keys, newest) if newest else 0)
        records, apps, control = [record], [app], {app_id: data}
        print(f"console with {app_id:016x} v{version:#x} ({c.ApplicationControl.parse(data).name})")
    elif args.serve:
        source, app_id, offered, version = serving(args.serve, keys)
        record, app = advertised_app(app_id, version, source=source, patches=offered)
        records, apps = [record], [app]
        print(f"serving {app_id:016x} v{version:#x}: {len(offered)} content meta(s)")
    advertisement = adv.Advertisement(args.name, apps)
    if args.loopback:
        ldn_host = loopback.LoopbackHost(advertisement.pack())
    else:
        ldn_host = make_host(args, advertisement, keys_path)
    ldn_host.start()
    recorder = sock = None
    try:
        network, recorder = recording(net.tcp_for(ldn_host), args.capture)
        listener = network.listen(c.PORT)
        listener.settimeout(args.timeout)
        print(f"group {args.name!r} up at {ldn_host.our_ip}; waiting for a console to join")
        sock, addr = listener.accept()
        listener.close()
        if args.log_join:
            sock.settimeout(30)
            mtype, payload = c.read(sock)
            with open(args.log_join, "wb") as fh:
                fh.write(c.pack(mtype, payload))
            print(f"{addr[0]} sent {mtype:#04x} of {len(payload)} bytes -> {args.log_join}")
            if mtype in (c.JOIN, c.JOIN_REFRESH):
                describe(c.Join.parse(payload))
            return 0
        ours = system.system_update().version if system else system_version(args.system_version)
        sdi = delivery.SystemDeliveryInfo(system_update_version=ours).pack()
        # --timeout also bounds the wait for a guest's join after its query: a person choosing in lcs_match.py
        host = session.Host(network, ldn_host.our_ip, args.name, sdi, records, control=control, timeout=args.timeout)
        member = host.admit(sock, addr[0])
        print(f"{member.name!r} joined from {member.ip} as node {member.node_id}")
        describe(member.join)
        advertisement.node_count = 1 + len(host.members)
        ldn_host.set_app_data_later(advertisement.pack())
        host.start_share()
        theirs = delivery.SystemDeliveryInfo.parse(member.join.system_info, verify=False).system_update_version
        # a console sends its system update only to a member that is to receive its game update and is
        # below the system version that update requires (seen live on 2026-10-13)
        mine = session._app_info(records, app_id) if args.console else None
        member_app = session._app_info(member.join.apps, app_id) if args.console else None
        needs = bool(mine and member_app and mine.application_version > member_app.application_version
                     and theirs < mine.required_system_version)
        if system and theirs < ours and needs:
            print(f"the member is on {delivery.version_string(theirs)}: sending the system update")
            stats = host.push_system_update(member, system, progress=_progress)
            print(f"\nsystem update: {stats.bytes_sent} bytes sent" if stats else "the member declined it")
        if args.console:
            outcome, result = host.match_application(member, app_id, source, offered, args.out, keys,
                                                     progress=_progress)
            paths = ([f"{result.bytes_sent} bytes sent"] if outcome == "sent" else result or [])
            print(f"\n{outcome}")
        elif args.backup_system:
            paths = host.pull_system_update(member, args.backup_system, keys, progress=_progress)
        elif args.backup_app is not None:
            paths = host.pull_application(member, args.backup_app, args.out, keys, progress=_progress)
        else:
            stats = host.push_application(member, app_id, offered, source, progress=_progress)
            paths = [f"{stats.bytes_sent} bytes sent"]
        print(f"\n{len(paths)} file(s): " + ", ".join(os.path.basename(p) for p in paths))
        host.finish()
        return 0
    finally:
        if sock:
            sock.close()
        if recorder:
            recorder.close()
        ldn_host.stop()


def _progress(done, total):
    """The receiver announces the total after the Meta NCA, so `total` can still be None."""
    if total:
        print(f"\r{done / total:6.1%} of {total} bytes", end="", flush=True)


if __name__ == "__main__":
    sys.exit(main())
