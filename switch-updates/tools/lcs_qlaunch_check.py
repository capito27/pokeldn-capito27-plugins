#!/usr/bin/env python3
"""Check switchlcs.control and switchlcs.advertise against qlaunch's own 55555 message builders,
advertise-data builder and guest-side advertise parser, run under unicorn.

    python ../pokeldn/tools/switch/nso_read.py <qlaunch exefs>/main qlaunch.bin
    python tools/lcs_qlaunch_check.py qlaunch.bin                 # POKELDN_SOURCE: a pokeldn checkout, else ../pokeldn

Firmware 20.5.0 addresses. Each qlaunch sender is called with chosen arguments; `send` (0x1f0220) is
replaced to capture the bytes, the session mutex (0x1e9a40 / 0x1e9b00) and the "own delivery info"
fetch (0x432490) are stubbed, and the captured message is compared with the module's. The advertise
builder (0x432fd0) has its ns application-info fetch (0x432ad0) stubbed, as the answer to 0x01 / 0x03
(0x433330) has its control-data fetch (0x432c80); the guest's parser (0x4331f0)
reads pokeldn's advertise data and its output is compared with advertise.Advertisement.parse.
docs/lcs.md "The control channel — TCP 55555" and "The LDN layer".
"""
import os
import struct
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SOURCE = os.environ.get("POKELDN_SOURCE") or os.path.join(ROOT, "..", "pokeldn")
sys.path.insert(0, os.path.join(SOURCE, "tools", "switch"))         # nso_run: pokeldn's unicorn harness
sys.path.insert(0, ROOT)
from nso_run import RETURN, SCRATCH, STACK, Runner                          # noqa: E402
from unicorn import UcError                                                 # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0  # noqa: E402

from switchlcs import advertise as adv, control as c, nca               # noqa: E402

SEND, ERRNO, POLL, LOCK, UNLOCK, OWN_SYSTEM_INFO = 0x1f0220, 0x1f0520, 0x1f0370, 0x1e9a40, 0x1e9b00, 0x432490
APP_INFO, BUILD_ADVERTISEMENT, PARSE_ADVERTISEMENT = 0x432ad0, 0x432fd0, 0x4331f0
ANSWER_QUERY, CONTROL_DATA = 0x433330, 0x432c80
HEAP = SCRATCH + 0x100000
SIGNATURE = (0x434d70, bytes.fromhex("ff8301d1fd7b02a9"))      # the 0x07 builder's prologue at 20.5.0


class Qlaunch(Runner):
    def __init__(self, path):
        super().__init__(path)
        self.sent, self.own_info, self.app_info, self.next = [], bytes(0x100), bytes(0x80), HEAP
        self.control = b""
        self.hooks = {SEND: self._send, ERRNO: lambda: 0, POLL: lambda: 1, LOCK: lambda: 0,
                      UNLOCK: lambda: 0, OWN_SYSTEM_INFO: self._own_info, APP_INFO: self._app_info,
                      CONTROL_DATA: self._control}

    def x(self, n):
        return self.uc.reg_read(UC_ARM64_REG_X0 + n)

    def _send(self):
        self.sent.append(bytes(self.uc.mem_read(self.x(1), self.x(2))))
        return self.x(2)

    def _own_info(self):
        self.uc.mem_write(self.x(0), self.own_info)
        return 0

    def _app_info(self):
        """(out 0x80-byte info, work buffer, its size, application ID)."""
        self.uc.mem_write(self.x(0), self.app_info)
        return 0

    def _control(self):
        """(out u64 size, buffer, its size, application ID): ns's GetApplicationControlData."""
        self.uc.mem_write(self.x(1), self.control)
        self.uc.mem_write(self.x(0), struct.pack("<Q", len(self.control)))
        return 0

    def read(self, addr, size):
        return bytes(self.uc.mem_read(addr, size))

    def _code(self, uc, addr, size, _):
        hook = self.hooks.get(addr)
        if hook is not None:
            uc.reg_write(UC_ARM64_REG_X0, hook() & 0xFFFFFFFFFFFFFFFF)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def put(self, data):
        at = self.next
        self.write(at, data)
        self.next += (len(data) + 0xFFF) & ~0xFFF
        return at

    def run(self, addr, *args):
        """-> the bytes qlaunch sent, joined. The function's x0 is left in self.result."""
        self.sent = []
        self.uc.reg_write(UC_ARM64_REG_SP, STACK)
        self.uc.reg_write(UC_ARM64_REG_LR, RETURN)
        for i, v in enumerate(args):
            self.uc.reg_write(UC_ARM64_REG_X0 + i, v)
        try:
            self.uc.emu_start(addr, RETURN, count=2_000_000)
        except UcError as e:
            raise RuntimeError(f"{addr:#x}: {e} at {self.uc.reg_read(UC_ARM64_REG_PC):#x}") from None
        self.result = self.x(0)
        return b"".join(self.sent)


def cases(q):
    """(name, qlaunch's bytes, pokeldn's bytes)."""
    fd, ip, node, app_id = 7, 0xA9FE0102, 0xA9FE0103, 0x01008F6008C5E000
    sdi = bytes(range(256))
    q.own_info = sdi
    name = "Player"
    info = struct.pack("<Q", app_id) + bytes(range(0x80, 0xF8))
    adis = [bytes([0xD0 + i]) * 0x100 for i in range(2)]
    record = c.AppRecord(info, adis)
    keys = [nca.ContentMetaKey(0x01008F6008C5E800, 0x10000 * (i + 1), nca.PATCH) for i in range(3)]

    join = c.Join(sdi, name, [record])
    yield ("0x05 join, head", q.run(0x4349a0, fd, q.put(c._name(name)), q.put(bytes((c.JOIN_VERSION,))), 1,
                                     len(record.pack())), join.pack()[:0x190])
    refresh = c.Join(sdi, name, [record], flag=1)
    yield ("0x18 refresh, head", q.run(0x434b30, fd, q.put(c._name(name)), q.put(bytes((c.JOIN_VERSION,))),
                                        q.put(sdi), 1, 1, len(record.pack())),
           refresh.pack(c.JOIN_REFRESH)[:0x190])
    app_src = info + struct.pack("<I", len(adis))
    yield ("application record + infos", q.run(0x435040, fd, q.put(app_src))
           + b"".join(q.run(0x435170, fd, q.put(a)) for a in adis), record.pack())
    snap = c.Snapshot([record], [c.Node(ip, name), c.Node(node, "Other")])
    head = q.run(0x434f50, fd, 1, 2, len(snap.payload()) - 8)
    nodes = b"".join(q.run(0x435250, fd, q.put(struct.pack("<I4x", n.node_id) + c._name(n.name)))
                     for n in snap.nodes)
    yield ("0x09 snapshot", head + q.run(0x435040, fd, q.put(app_src))
           + b"".join(q.run(0x435170, fd, q.put(a)) for a in adis) + nodes, snap.pack())
    for mtype, sender in ((c.LEAVE, 0x4334d0), (c.REJECT, 0x433470), (c.SUSPEND, 0x433c30)):
        yield (f"{mtype:#04x}", q.run(sender, fd, 9), c.byte_message(mtype, 9))
    yield ("0x07 accept", q.run(0x433410, fd, 0x12345678), c.accept(0x12345678))
    yield ("0x0a start share", q.run(0x433530, fd), c.pack(c.START_SHARE))
    yield ("0x0b node info", q.run(0x433630, fd, q.put(bytes(range(256)) * 5 + bytes(0x80))),
           c.pack(c.NODE_INFO, bytes(range(256)) * 5 + bytes(0x80)))
    yield ("0x1a", q.run(0x433690, fd), c.pack(c.UNKNOWN_1A))
    yield ("0x1c completed", q.run(0x433580, fd), c.share_completed())
    # The sender copies the block from +0x98 of its session record.
    yield ("0x1c completed + info", q.run(0x4335d0, fd, q.put(bytes(0x98) + bytes(range(0x40)))),
           c.share_completed(bytes(range(0x40))))
    yield ("0x0e send system update", q.run(0x433d50, fd, 1, ip, node, 1),
           c.SystemTransfer(1, ip, node, flag=1).pack(c.SEND_SYSTEM_UPDATE))
    yield ("0x10 receive system update", q.run(0x433e90, fd, 2, ip, node, q.put(sdi), 1),
           c.SystemTransfer(2, ip, node, sdi, flag=1).pack(c.RECEIVE_SYSTEM_UPDATE))
    yield ("0x0d", q.run(0x433c90, fd, 3), c.TransferReply(3).pack(c.SUSPEND_REPLY))
    yield ("0x0f", q.run(0x433e30, fd, q.put(sdi)), c.TransferReply(2, sdi).pack(c.SEND_SYSTEM_UPDATE_REPLY))
    yield ("0x11", q.run(0x433f20, fd, 5), c.TransferReply(5).pack(c.RECEIVE_SYSTEM_UPDATE_REPLY))
    yield ("0x12 application setup", q.run(0x433fe0, fd, 0, app_id), c.application_setup(app_id))
    yield ("0x13", q.run(0x434050, fd, 6), c.result(c.APPLICATION_SETUP_RESULT, 6))
    yield ("0x17", q.run(0x434300, fd, 7), c.result(c.RECEIVE_APPLICATION_RESULT, 7))
    yield ("0x14 send application", q.run(0x4340c0, fd, 1, ip, node, app_id, 1),
           c.ApplicationTransfer(1, ip, node, app_id, flag=1).pack(c.SEND_APPLICATION))
    raw_keys = b"".join(k.pack() for k in keys)
    yield ("0x15 application keys", q.run(0x434160, fd, q.put(raw_keys), len(keys)), c.application_keys(keys))
    yield ("0x16 receive application", q.run(0x434210, fd, 2, ip, node, app_id, q.put(raw_keys), len(keys), 1),
           c.ApplicationTransfer(2, ip, node, app_id, keys, flag=1).pack(c.RECEIVE_APPLICATION))

    # The 0x01 / 0x03 answer: (fd, &application ID, buffer, its size, 1 for 0x01's size-only reply).
    q.control = bytes(range(256)) * 0x40 + bytes.fromhex("ffd8") + b" icon" * 0x300
    for flag, mtype in ((0, c.CONTROL_DATA), (1, c.CONTROL_SIZE)):
        theirs = q.run(ANSWER_QUERY, fd, q.put(struct.pack("<Q", app_id)), q.put(bytes(c.CONTROL_DATA_SIZE)),
                       c.CONTROL_DATA_SIZE, flag)
        yield (f"{mtype:#04x} control reply", theirs if q.result == 0 else b"failed",
               c.ControlReply(app_id, len(q.control), q.control).pack(mtype))

    # The advertisement: settings {u64 application IDs, u8 count at +8, u8 max nodes at +9}.
    q.app_info = (struct.pack("<QI", app_id, 0x30000).ljust(0x18, b"\xee") + b"1.2.0".ljust(16, b"\0")
                  + bytes(range(0x28, 0x80)))
    for apps in ([app_id], []):
        out = q.put(b"\xcc" * adv.SIZE)
        settings = q.put(struct.pack("<QBB", apps[0] if apps else 0, len(apps), 6))
        q.run(BUILD_ADVERTISEMENT, out, settings, q.put(bytes((c.JOIN_VERSION,))), q.put(c._name("pokeldn")),
              q.put(bytes(0x1D000)), 0x1D000)
        ours = adv.Advertisement("pokeldn", [adv.App.from_info(q.app_info)] if apps else [], max_nodes=6)
        yield (f"advertisement, {len(apps)} app", q.read(out, adv.SIZE) if q.result == 0 else b"failed",
               ours.pack())

    def guest_view(raw):
        out = q.put(bytes(0x100))
        q.run(PARSE_ADVERTISEMENT, out, q.put(raw))
        if not q.result & 1:
            return b"refused"
        o = q.read(out, 0x100)
        apps = [(struct.unpack_from("<II", o, 0x88 + i * 0x20), o[0x90 + i * 0x20:0xA0 + i * 0x20],
                 struct.unpack_from("<Q", o, 0xA0 + i * 0x20)[0]) for i in range(o[0xA8])]
        return repr((c._unname(o[:0x81]), apps, o[0xA9], o[0xAA])).encode()

    def pokeldn_view(raw):
        try:
            a = adv.Advertisement.parse(raw)
        except ValueError:
            return b"refused"
        return repr((a.name, [((x.flags & 7, x.attributes), x.display_version, x.application_id) for x in a.apps],
                     a.max_nodes, a.node_count)).encode()

    good = adv.Advertisement("Player's Switch", [adv.App(app_id, 0x50000, b"2.0.1".ljust(16, b"\0"), 7)],
                             node_count=3, max_nodes=8).pack()
    for what, raw in (("valid", good), ("no nodes", good[:2] + b"\0" + good[3:]),
                      ("more nodes than the maximum", good[:2] + b"\x09\x08" + good[4:]),
                      ("two applications", good[:4] + b"\x02" + good[5:])):
        yield (f"guest parse, {what}", guest_view(raw), pokeldn_view(raw))


def main(argv=None):
    path = (argv or sys.argv[1:])[0]
    q = Qlaunch(path)
    if bytes(q.img[SIGNATURE[0]:SIGNATURE[0] + 8]) != SIGNATURE[1]:
        sys.exit(f"{path}: not qlaunch 20.5.0's main; this tool is pinned to 20.5.0's addresses")
    failures = 0
    for name, theirs, ours in cases(q):
        same = theirs == ours
        failures += not same
        print(f"{name:30s} {len(theirs):#7x} bytes  {'same' if same else 'DIFFERENT'}")
        if not same:
            at = next((i for i, (a, b) in enumerate(zip(theirs, ours)) if a != b), min(len(theirs), len(ours)))
            print(f"    first difference at {at:#x}: qlaunch {theirs[at:at + 16].hex(' ')}"
                  f" / pokeldn {ours[at:at + 16].hex(' ')}")
    print("all agree" if not failures else f"{failures} DISAGREE")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
