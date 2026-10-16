"""lcs sessions: the order in which the host and a guest exchange 55555 messages, and the 55556
transfers they start. docs/lcs.md "Session flow".

`Host` is pokeldn hosting a group that consoles join; its three jobs are the user-facing goals: pull a
member's system update, pull a member's game update, and serve a game update from a backup. `Guest`
answers the way qlaunch 20.5.0's guest does; it stands in for a console in tests and is the start of
pokeldn joining a console's group.

Both run over any network with `connect((ip, port), timeout)` and `listen(port)` -> a listener with
`accept()`, `settimeout()` and `close()`: a switchlcs.tcp.TcpLayer or `SocketNetwork` (switchlcs.net.tcp_for).
The 55556 sender is the server and the receiver the client, and the transfer commands name the peer
by IPv4 address only: the port is always 55556.
"""

import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field, replace

from switchlcs import content, control as c, delivery, nca

log = logging.getLogger(__name__)

# 0x08 reasons index the table at 0xf23884; the guest shows the 2211-xxxx code. The host sends the
# reason whose code its join validator returned.
REJECT_CODES = {1: "2211-0232", 2: "2211-0260", **{r: "2211-0256" for r in range(3, 9)},
                9: "2211-0233", 10: "2211-0234"}
REJECT_CLOSED = 2                # the group is not taking members (0x42d354)
REJECT_INCOMPATIBLE = 3          # a delivery info the host's validator refuses

READY = 2                        # 0x13 / 0x17: the guest can take part now (0x425c04, 0x4236ec)
NOT_READY_SETUP = 0              # 0x13: the application is in use; the guest sends 0x1a once it is not
TRANSFER_KIND_SEND, TRANSFER_KIND_RECEIVE = 1, 2
PEER_IS_HOST, PEER_IS_MEMBER = 0, 1   # a transfer command's flag: the peer it names is the host itself,
                                      # or another member (0x10 at 0x42b994 / 0x42bb00, 0x14 at 0x42c40c /
                                      # 0x42c4cc, 0x16 at 0x42c7b0 / 0x42c670)
SUSPEND_FOR_SYSTEM = 1           # 0x0c kind before a share's first system update (0x42a080); the guest
                                 # answers 0x0d 0 and enters state 6. Later passes send 2 (0x42a2b0)
NOT_SUSPENDED = 2                # 0x0c kind 2, and the guest's 0x0d to it: the host's 0x0d handler
                                 # (0x42d580) leaves the node's state as it is
REPLY_KIND = 2                   # byte 0 of 0x0f / 0x11 / 0x15 from a 20.5.0 guest
LEAVE_DROP = 0                   # 0x06 kind: the host drops the node (1 would keep it for a reboot)
COMPLETED_INFO = bytes(c.COMPLETED_INFO_SIZE)
FIRST_NODE_ID = 1                # the stand-in's node IDs; a console handed out 0x4016b8e8, 0x4016b8e9
TIMEOUT = 30.0
REFRESH_EVERY = 1.0              # after sending an update, the guest's 0x18 answers a 0x09 at most this often
LISTEN_GRACE = 10.0              # how long a refused 55556 connect is retried: the sender's nim task
                                 # starts listening only after its 0x0f / 0x15 reply


class SessionError(Exception):
    pass


class Leaving(SessionError):
    """The guest chose to leave: Guest.run sends a 0x06 before closing."""


class Rejected(SessionError):
    def __init__(self, reason):
        super().__init__(f"rejected with reason {reason} ({REJECT_CODES.get(reason, 'unknown')})")
        self.reason = reason


def ip_to_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


class SocketNetwork:
    """The OS's TCP, bound to one local address (switchlcs.loopback). Each lcs port is moved down by PORT_SHIFT:
    Windows reserves blocks of its dynamic range (49152 and up) for Hyper-V and WSL, at times 55555 and 55556
    among them, and no program may bind a reserved port."""

    PORT_SHIFT = 10000

    def __init__(self, ip: str):
        self.ip = ip

    def connect(self, address, timeout=None):
        host, port = address
        return socket.create_connection((host, port - self.PORT_SHIFT), timeout, source_address=(self.ip, 0))

    def listen(self, port: int):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.ip, port - self.PORT_SHIFT))
        sock.listen(1)
        return sock


def system_update_key(system_info: bytes) -> nca.ContentMetaKey:
    """The content meta a member's SystemDeliveryInfo offers."""
    info = delivery.SystemDeliveryInfo.parse(system_info, verify=False)
    return nca.ContentMetaKey(info.effective_system_update_id, info.system_update_version, nca.SYSTEM_UPDATE)


def with_version(join: c.Join, application_id: int, version: int) -> c.Join:
    """`join` with its delivery infos for `application_id` at `version`, as a member's 0x18 after it
    installs an update: a console host sends the update again to a member whose refresh is still older."""
    def moved(raw):
        info = delivery.ApplicationDeliveryInfo.parse(raw, verify=False)
        info.application_version = max(info.application_version, version)
        return info.pack()
    apps = [c.AppRecord(r.info, [moved(raw) for raw in r.delivery_infos]) if r.application_id == application_id else r
            for r in join.apps]
    return replace(join, apps=apps)


def patch_keys(keys, application_id: int) -> list:
    """The Patch content metas among `keys` that belong to `application_id`."""
    return [k for k in keys if k.type == nca.PATCH and (k.id ^ application_id) & ~0xFFF == 0]


def _expect(sock, wanted, on_other=None, timeout=TIMEOUT):
    """Read messages until one whose type is in `wanted`: -> (type, payload). Others go to
    `on_other(type, payload)`; a 0x06 (leave) or 0x08 (reject) ends the wait."""
    sock.settimeout(timeout)
    while True:
        mtype, payload = c.read(sock)
        if mtype in wanted:
            return mtype, payload
        if mtype == c.REJECT:
            raise Rejected(payload[0] if payload else 0)
        if mtype == c.LEAVE:
            raise SessionError(f"the peer left (kind {payload[0] if payload else 0})")
        if on_other is None:
            log.debug("ignored lcs message %#04x of %d bytes", mtype, len(payload))
        else:
            on_other(mtype, payload)


# ---- pokeldn as the host ----

@dataclass
class Member:
    sock: object
    ip: str
    node_id: int
    join: c.Join
    ready: bool = True             # cleared by a 0x13 of 0, set again by its 0x1a

    @property
    def name(self) -> str:
        return self.join.name


@dataclass
class Host:
    network: object
    ip: str
    name: str
    system_info: bytes
    apps: list = field(default_factory=list)      # AppRecord, shown in the snapshot
    node_id: int = FIRST_NODE_ID
    timeout: float = TIMEOUT
    members: list = field(default_factory=list)
    closed: bool = False
    control: dict = field(default_factory=dict)   # application ID -> control data, for 0x01 / 0x03

    def __post_init__(self):
        self._next_id = self.node_id + 1

    def snapshot(self) -> c.Snapshot:
        """Each game's record is the host's own, unless a member's ranks newer (0x4307b0): a console whose
        game is older than pokeldn's, or archived, shows pokeldn's own record back (seen live)."""
        def newest(record):
            info = _app_info([record], record.application_id)
            return info.application_version if info else -1
        apps = []
        for record in self.apps:
            theirs = [r for m in self.members for r in m.join.apps if r.application_id == record.application_id]
            apps.append(max([record, *theirs], key=newest))
        return c.Snapshot(apps, [c.Node(self.node_id, self.name)] + [c.Node(m.node_id, m.name) for m in self.members])

    def broadcast_snapshot(self) -> None:
        raw = self.snapshot().pack()
        for m in self.members:
            m.sock.sendall(raw)

    def admit(self, sock, ip: str) -> Member:
        """Take the 0x05 from a connected guest: validate it as the host's join handler does
        (0x42d2e8), answer 0x07 with the member's node ID and send everyone the new snapshot. A
        0x01 / 0x03 before it is answered, as qlaunch's dispatch does."""
        _mtype, payload = _expect(sock, (c.JOIN,), self._answer_query(sock), self.timeout)
        join = c.Join.parse(payload)
        reason = REJECT_CLOSED if self.closed else self._validate(join)
        if reason:
            sock.sendall(c.byte_message(c.REJECT, reason))
            raise Rejected(reason)
        member = Member(sock, ip, self._next_id, join)
        self._next_id += 1
        sock.sendall(c.accept(member.node_id))
        self.members.append(member)
        self.broadcast_snapshot()
        return member

    def _answer_query(self, sock):
        def handle(mtype, payload):
            if mtype not in (c.CONTROL_QUERY, c.CONTROL_SIZE_QUERY):
                log.debug("ignored lcs message %#04x before the join", mtype)
                return
            app_id = c.parse_control_query(payload)
            data = self.control.get(app_id)
            if data is None:                # qlaunch aborts on the ns error (0x433404)
                raise SessionError(f"control data of {app_id:016x} asked for; a console would crash")
            reply = c.ControlReply(app_id, len(data), data)
            sock.sendall(reply.pack(c.CONTROL_DATA if mtype == c.CONTROL_QUERY else c.CONTROL_SIZE))
        return handle

    @staticmethod
    def _validate(join: c.Join) -> int:
        if delivery.verify_system(join.system_info):
            return REJECT_INCOMPATIBLE
        if len(join.apps) > 1 or any(delivery.verify_application(i)
                                     for a in join.apps for i in a.delivery_infos):
            return REJECT_INCOMPATIBLE
        return 0

    def _on_other(self, member):
        def handle(mtype, payload):
            if mtype == c.JOIN_REFRESH:
                member.join = c.Join.parse(payload)
            elif mtype == c.UNKNOWN_1A:
                member.ready = True
            else:
                log.debug("ignored lcs message %#04x from %s", mtype, member.ip)
        return handle

    def _expect(self, member, *wanted):
        return _expect(member.sock, wanted, self._on_other(member), self.timeout)

    def start_share(self) -> None:
        """0x0a to every member; each answers with a 0x18 refresh and only then acts on transfer
        commands (its worker waits for lcs state 4)."""
        self.closed = True
        for m in self.members:
            m.sock.sendall(c.pack(c.START_SHARE))
        for m in self.members:
            _t, payload = self._expect(m, c.JOIN_REFRESH)
            m.join = c.Join.parse(payload)

    def pull_system_update(self, member, outdir, keys, progress=None) -> list:
        """Goal 1: 0x0e asks `member` to send its system update to pokeldn; it answers 0x0f with its
        SystemDeliveryInfo and listens on 55556, and pokeldn pulls. -> the written paths. qlaunch's own
        host never receives a system update (it aborts at 0x42bbc0), so this exchange is pokeldn's: the
        0x0e and its flag follow qlaunch's member-to-member form with the host as the named peer."""
        member.sock.sendall(c.SystemTransfer(TRANSFER_KIND_SEND, ip_to_int(self.ip), self.node_id,
                                             flag=PEER_IS_HOST).pack(c.SEND_SYSTEM_UPDATE))
        _t, payload = self._expect(member, c.SEND_SYSTEM_UPDATE_REPLY)
        info = c.TransferReply.parse(payload).system_info
        return self._pull(member, system_update_key(info), outdir, keys, progress)

    def prepare_application(self, member, application_id: int) -> None:
        """0x12: the member answers 0x13 2 when the application can be touched now, or 0 and later 0x1a
        once the user has closed it."""
        member.sock.sendall(c.application_setup(application_id))
        _t, payload = self._expect(member, c.APPLICATION_SETUP_RESULT)
        if payload[0] == READY:
            return
        if payload[0] != NOT_READY_SETUP:
            raise SessionError(f"application setup answered {payload[0]}")
        member.ready = False
        while not member.ready:
            self._expect(member, c.UNKNOWN_1A)
            member.ready = True

    def pull_application(self, member, application_id: int, outdir, keys, progress=None) -> list:
        """Goal 2: 0x14 asks `member` to send its update of `application_id`; it answers 0x15 with the
        content metas it offers and listens on 55556. -> the written paths. A host that receives sends
        no 0x12 first (0x42c3e0): the sender's game need not be closed."""
        member.sock.sendall(c.ApplicationTransfer(TRANSFER_KIND_SEND, ip_to_int(self.ip), self.node_id,
                                                  application_id, flag=PEER_IS_HOST).pack(c.SEND_APPLICATION))
        _t, payload = self._expect(member, c.SEND_APPLICATION_KEYS)
        offered = c.parse_application_keys(payload)
        if payload[0] != REPLY_KIND or not offered:
            raise SessionError(f"{member.ip} offers nothing for {application_id:016x}")
        paths = self._pull(member, offered, outdir, keys, progress)
        # A console host marks the sender as still transferring (0x4303b0, state 3) and waits on it
        # (0x42c138) until the sender's 0x18 moves it on; the sender sends it on the next 0x09.
        self.broadcast_snapshot()
        try:
            _t, payload = self._expect(member, c.JOIN_REFRESH)
        except TimeoutError:
            raise SessionError("the member sent no 0x18 after sending its update; a console would wait for it "
                               "without end") from None
        member.join = c.Join.parse(payload)
        return paths

    def push_system_update(self, member, source, progress=None):
        """A console host sending its own system update, the one `system_info` names, as qlaunch's does
        (0x42b87c): 0x0c suspends `member` until its 0x0d, then, with the host listening on 55556, 0x10
        names the host and its SystemDeliveryInfo; the member answers 0x11 and connects. A 0x11 of kind
        0 declines (it needs no update). Once served, the host waits for the member's 0x18 (0x42b760),
        which must name a system version no older than the one sent, or the host would send it again.
        -> content.ServeStats, or None when declined."""
        member.sock.sendall(c.byte_message(c.SUSPEND, SUSPEND_FOR_SYSTEM))
        _t, payload = self._expect(member, c.SUSPEND_REPLY)
        if payload[0]:
            raise SessionError(f"{member.ip} answered the suspend with {payload[0]}")
        listener = self.network.listen(c.CONTENT_PORT)
        try:
            listener.settimeout(self.timeout)
            member.sock.sendall(c.SystemTransfer(TRANSFER_KIND_RECEIVE, ip_to_int(self.ip), self.node_id,
                                                 self.system_info, flag=PEER_IS_HOST)
                                .pack(c.RECEIVE_SYSTEM_UPDATE))
            _t, payload = self._expect(member, c.RECEIVE_SYSTEM_UPDATE_REPLY)
            if c.TransferReply.parse(payload).kind == 0:
                return None
            conn, addr = listener.accept()
        finally:
            listener.close()
        stats = self._serve(member, conn, addr, source, progress)
        try:
            _t, payload = self._expect(member, c.JOIN_REFRESH)
        except TimeoutError:
            raise SessionError("the member sent no 0x18 after the system update; a console would wait for it "
                               "without end") from None
        member.join = c.Join.parse(payload)
        sent = delivery.SystemDeliveryInfo.parse(self.system_info, verify=False).system_update_version
        now = delivery.SystemDeliveryInfo.parse(member.join.system_info, verify=False).system_update_version
        if now < sent:
            raise SessionError(f"after the system update, the member's refresh names {now:#x}, older than "
                               f"{sent:#x}; a console would send it again")
        return stats

    def push_application(self, member, application_id: int, offered: list, source, progress=None):
        """Goal 3: listen on 55556, 0x12, then 0x16 tells `member` to pull `offered` (Patch content
        metas, at most 0x12) from pokeldn; it answers 0x17 and connects. The member sends a 0x18
        refresh with its new delivery infos once installed. -> content.ServeStats."""
        listener = self.network.listen(c.CONTENT_PORT)
        try:
            listener.settimeout(self.timeout)
            self.prepare_application(member, application_id)
            member.sock.sendall(c.ApplicationTransfer(TRANSFER_KIND_RECEIVE, ip_to_int(self.ip), self.node_id,
                                                      application_id, offered, flag=PEER_IS_HOST)
                                .pack(c.RECEIVE_APPLICATION))
            _t, payload = self._expect(member, c.RECEIVE_APPLICATION_RESULT)
            if payload[0] != READY:
                raise SessionError(f"{member.ip} answered 0x17 with {payload[0]}")
            conn, addr = listener.accept()
        finally:
            listener.close()
        stats = self._serve(member, conn, addr, source, progress)
        _t, payload = self._expect(member, c.JOIN_REFRESH)
        member.join = c.Join.parse(payload)
        return stats

    def _serve(self, member, conn, addr, source, progress):
        try:
            if addr[0] != member.ip:
                raise SessionError(f"55556 connection from {addr[0]}, expected {member.ip}")
            conn.settimeout(self.timeout)
            return content.serve(conn, source, progress)
        finally:
            conn.close()

    def match_application(self, member, application_id: int, source=None, offered=(), outdir="",
                          keys=None, progress=None):
        """A console host's game-update share, reduced to two nodes: the newer of the host's
        advertised version and the member's (from its 0x18) sends, if ns's CanDeliverApplication allows
        it: a receiver whose required version (the newest it has run) is above the sender's version
        takes nothing. The host's newer: 0x16, pokeldn serves `offered` from `source`. The member's
        newer: 0x14, pokeldn pulls into `outdir`.
        -> ("sent", ServeStats), ("received", paths) or ("none", None)."""
        ours, theirs = _app_info(self.apps, application_id), _app_info(member.join.apps, application_id)
        if ours is None or theirs is None or ours.application_version == theirs.application_version:
            return "none", None
        if ours.application_version > theirs.application_version:
            if not delivery.can_deliver_application(theirs, ours):
                return "none", None
            stats = self.push_application(member, application_id, list(offered), source, progress)
            after = _app_info(member.join.apps, application_id)
            if after is None or delivery.can_deliver_application(after, ours):
                # a console sends the update again, without end: seen live on 2026-10-13
                raise SessionError(f"after installing {ours.application_version}, the member's refresh "
                                   f"({after.application_version if after else None}, attributes "
                                   f"{after.attributes if after else 0:#x}) still takes it; a console would "
                                   "send it again")
            return "sent", stats
        if not delivery.can_deliver_application(ours, theirs):
            return "none", None
        return "received", self.pull_application(member, application_id, outdir, keys or {}, progress)

    def _pull(self, member, key, outdir, keys, progress):
        """One 55556 connection to `member` pulling `key` (a ContentMetaKey or a list of them)."""
        sock = _connect_when_listening(self.network, member.ip, self.timeout)
        try:
            sock.settimeout(self.timeout)
            return content.receive(sock, key, outdir, keys, progress)
        finally:
            sock.close()

    def finish(self, info: bytes = COMPLETED_INFO) -> None:
        """0x1c to everyone. A 20.5.0 guest needs the 0x40-byte block (it drops the session on an
        empty 0x1c); qlaunch sends the empty form only to members whose join version is 0x10 or 0x11."""
        for m in self.members:
            m.sock.sendall(c.share_completed(None if m.join.version & 0xFE == 0x10 else info))


def _app_info(records, application_id):
    """The ApplicationDeliveryInfo with the highest version for `application_id` in AppRecords, or None."""
    infos = [delivery.ApplicationDeliveryInfo.parse(raw, verify=False)
             for r in records if r.application_id == application_id for raw in r.delivery_infos]
    return max(infos, key=lambda i: i.application_version, default=None)


def _connect_when_listening(network, ip, timeout):
    deadline = time.monotonic() + LISTEN_GRACE
    while True:
        try:
            return network.connect((ip, c.CONTENT_PORT), timeout)
        except ConnectionRefusedError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.25)


# ---- pokeldn as a guest ----

def query_control(sock, application_id: int, timeout: float = TIMEOUT) -> c.ApplicationControl:
    """Ask a console host for a game's NACP and icon (0x03 -> 0x04). Its dispatch has no join-state
    check, so this works on the 55555 connection before the 0x05. Ask only for the application the
    group advertises: qlaunch aborts on any ns error fetching the control data (0x433404), which a
    game that is not installed would be."""
    sock.sendall(c.control_query(application_id))
    sock.settimeout(timeout)
    while True:
        mtype, payload = c.read(sock, limit=0xC + c.CONTROL_DATA_SIZE)
        if mtype == c.CONTROL_DATA:
            break
        log.debug("ignored lcs message %#04x while querying", mtype)
    reply = c.ControlReply.parse(payload)
    if reply.application_id != application_id or len(reply.data) != reply.size:
        raise SessionError(f"control data for {reply.application_id:016x}, "
                           f"{len(reply.data):#x} of {reply.size:#x} bytes")
    return c.ApplicationControl.parse(reply.data)


@dataclass
class Guest:
    """Answers a host as qlaunch 20.5.0's guest does. `source` (a content.Source) serves what the host
    asks it to send; `outdir` and `keys` receive what the host sends it; `offers` lists the
    ContentMetaKeys it holds (for 0x15)."""
    network: object
    ip: str
    join: c.Join
    source: object = None
    offers: list = field(default_factory=list)
    outdir: str = ""
    keys: dict = field(default_factory=dict)
    timeout: float = TIMEOUT
    node_id: int = 0
    snapshot: c.Snapshot | None = None
    completed: bytes | None = None
    received: list = field(default_factory=list)
    served: list = field(default_factory=list)
    progress: object = None        # progress(done, total) during a 55556 transfer
    listing: object = None         # listing(done, total) while its content metas are read, before any content
    on_system: object = None       # on_system(SystemDeliveryInfo) when the host sends its system update
    after_system: object = None    # after_system(join) -> the join its 0x18 names once that update is in
    on_snapshot: object = None     # on_snapshot(Snapshot) on each 0x09; raising Leaving leaves the group
    system_outdir: str = ""        # where a system update goes; `outdir` when empty
    _refresh_pending: bool = field(default=False, repr=False)
    _refreshed_at: float = field(default=0.0, repr=False)

    def connect(self, host_ip: str):
        """The 55555 connection, for query_control before run."""
        return self.network.connect((host_ip, c.PORT), self.timeout)

    def run(self, host_ip: str, sock=None) -> None:
        """Join `host_ip` (on `sock` when given) and answer until the host's 0x1c."""
        sock = sock or self.connect(host_ip)
        try:
            sock.sendall(self.join.pack())
            mtype, payload = _expect(sock, (c.ACCEPT,), timeout=self.timeout)
            self.node_id = int.from_bytes(payload[:4], "big")
            while self.completed is None:
                mtype, payload = c.read(sock)
                self._handle(sock, mtype, payload)
        except Leaving:
            try:
                sock.sendall(c.byte_message(c.LEAVE, LEAVE_DROP))
            except OSError:
                pass
            raise
        finally:
            sock.close()

    def _handle(self, sock, mtype, payload):
        if mtype == c.REJECT:
            raise Rejected(payload[0])
        if mtype == c.SNAPSHOT:
            self.snapshot = c.Snapshot.parse(payload)
            if self.on_snapshot:
                self.on_snapshot(self.snapshot)
            # qlaunch's guest, once its send task is done, keeps a refresh pending (+0x210) and sends
            # the 0x18 on the next 0x09 (0x425138); the host waits for it (0x42c138). A refresh that
            # reached the host before it marked the transfer done would be lost, so later 0x09s
            # repeat it, at most once a REFRESH_EVERY, until the host moves on.
            now = time.monotonic()
            if self._refresh_pending and now - self._refreshed_at >= REFRESH_EVERY:
                self._refreshed_at = now
                sock.sendall(self.join.pack(c.JOIN_REFRESH))
            return
        self._refresh_pending = False
        if mtype == c.START_SHARE:
            sock.sendall(self.join.pack(c.JOIN_REFRESH))
        elif mtype == c.SUSPEND:            # as qlaunch's guest (0x42568c): kind 1 suspends, 2 does not
            kind = payload[0] if payload else 0
            if kind in (SUSPEND_FOR_SYSTEM, NOT_SUSPENDED):
                sock.sendall(c.TransferReply(0 if kind == SUSPEND_FOR_SYSTEM else NOT_SUSPENDED)
                             .pack(c.SUSPEND_REPLY))
        elif mtype == c.SEND_SYSTEM_UPDATE:
            cmd = c.SystemTransfer.parse(payload)
            if self.source is None:
                raise SessionError("the host asked for this guest's system update, which it does not hold: "
                                   "it claimed a newer system version than the host's")
            listener = self.network.listen(c.CONTENT_PORT)
            sock.sendall(c.TransferReply(REPLY_KIND, self.join.system_info).pack(c.SEND_SYSTEM_UPDATE_REPLY))
            self._serve(listener, cmd.peer_ip)
        elif mtype == c.RECEIVE_SYSTEM_UPDATE:
            cmd = c.SystemTransfer.parse(payload)
            if self.on_system:
                self.on_system(delivery.SystemDeliveryInfo.parse(cmd.system_info, verify=False))
            sock.sendall(c.TransferReply(REPLY_KIND).pack(c.RECEIVE_SYSTEM_UPDATE_REPLY))
            self._receive(cmd.peer_ip, [system_update_key(cmd.system_info)], self.system_outdir or self.outdir)
            # The host waits while this node is still transferring (0x42b760) and only a refresh, a
            # 0x19, a 0x1a or a leave moves it on: say the system update is now the sender's own.
            self.join = replace(self.join, system_info=cmd.system_info)
            if self.after_system:
                self.join = self.after_system(self.join)
            sock.sendall(self.join.pack(c.JOIN_REFRESH))
        elif mtype == c.APPLICATION_SETUP:
            sock.sendall(c.result(c.APPLICATION_SETUP_RESULT, READY))
        elif mtype == c.SEND_APPLICATION:
            cmd = c.ApplicationTransfer.parse(payload)
            listener = self.network.listen(c.CONTENT_PORT)
            sock.sendall(c.application_keys(patch_keys(self.offers, cmd.application_id), REPLY_KIND))
            self._serve(listener, cmd.peer_ip)
            self._refresh_pending = True
        elif mtype == c.RECEIVE_APPLICATION:
            cmd = c.ApplicationTransfer.parse(payload)
            sock.sendall(c.result(c.RECEIVE_APPLICATION_RESULT, READY))
            self._receive(cmd.peer_ip, cmd.keys)
            installed = max((k.version for k in patch_keys(cmd.keys, cmd.application_id)), default=None)
            if installed is not None:       # the refresh names what was installed, or the host sends it again
                self.join = with_version(self.join, cmd.application_id, installed)
            sock.sendall(self.join.pack(c.JOIN_REFRESH))
        elif mtype == c.SHARE_COMPLETED:
            if len(payload) < c.COMPLETED_INFO_SIZE:
                raise SessionError("0x1c without its 0x40-byte block")
            self.completed = payload[:c.COMPLETED_INFO_SIZE]
        else:
            log.debug("guest ignored lcs message %#04x", mtype)

    def _serve(self, listener, peer_ip):
        try:
            listener.settimeout(self.timeout)
            conn, addr = listener.accept()
        finally:
            listener.close()
        try:
            if addr[0] != int_to_ip(peer_ip):
                raise SessionError(f"55556 connection from {addr[0]}, expected {int_to_ip(peer_ip)}")
            conn.settimeout(self.timeout)
            self.served.append(content.serve(conn, self.source, self.progress))
        finally:
            conn.close()

    def _receive(self, peer_ip, keys, outdir=None):
        sock = _connect_when_listening(self.network, int_to_ip(peer_ip), self.timeout)
        try:
            sock.settimeout(self.timeout)
            self.received += content.receive(sock, keys, outdir or self.outdir, self.keys, self.progress,
                                             self.listing)
        finally:
            sock.close()
