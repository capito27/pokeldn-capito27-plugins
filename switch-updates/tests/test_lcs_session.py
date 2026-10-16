"""lcs sessions: pokeldn's Host against its Guest (which answers as qlaunch 20.5.0's guest does), over
pokeldn's userspace TCP between two simulated LDN stations, with the 55556 transfers they start."""

import os
import socket
import struct
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from switchlcs import content, control as c, delivery, nca, session
from tests.test_lcs_content import KEYS, DictSource, build_nca
from tests.test_tcp import A_IP, B_IP, link  # noqa: F401  (the fixture)

APP = 0x0100000000001000
PATCH = APP | 0x800
SU = nca.ContentMetaKey(0x0100000000000816, delivery.system_version(20, 5, 0, 100), nca.SYSTEM_UPDATE)


def system_info(version=SU.version):
    return delivery.SystemDeliveryInfo(system_update_version=version).pack()


def app_record(version):
    info = delivery.ApplicationDeliveryInfo(application_id=APP, application_version=version).pack()
    return c.AppRecord(struct.pack("<Q", APP).ljust(c.APP_INFO_SIZE, b"\0"), [info])


def add_patch(src, version, size=50_000):
    rights = struct.pack(">Q", PATCH) + bytes(7) + bytes((version >> 16,))
    program = build_nca(0, APP, body=os.urandom(size), rights_id=rights)
    key = nca.ContentMetaKey(PATCH, version, nca.PATCH)
    info = src.add_content(program, nca.PROGRAM)
    src.add_meta(key, [info])
    src.tickets[rights] = (b"ticket %d" % version, b"cert")
    return key, info


def guest_source():
    """A console on 20.5.0 with v1 of the game's update."""
    src = DictSource()
    sub = nca.ContentMetaKey(0x0100000000000809, SU.version, 0x02)
    data = src.add_content(build_nca(4, sub.id, body=os.urandom(20_000)), nca.DATA)
    src.add_meta(sub, [data])
    src.add_meta(SU, [], [sub])
    key, _info = add_patch(src, 0x10000)
    return src, [key], data


class Thread(threading.Thread):
    def __init__(self, target):
        super().__init__(target=self._run, daemon=True)
        self._target_fn, self.error, self.result = target, None, None

    def _run(self):
        try:
            self.result = self._target_fn()
        except BaseException as e:                       # noqa: BLE001
            self.error = e

    def finish(self, timeout=60):
        self.join(timeout)
        assert not self.is_alive(), "still running"
        if self.error:
            raise self.error
        return self.result


def test_host_and_guest(link, tmp_path):                 # noqa: F811
    lk = link(delay=0.001)
    gsrc, offers, sys_data = guest_source()
    hsrc = DictSource()
    v2, v2_info = add_patch(hsrc, 0x20000)
    guest = session.Guest(lk.b.tcp, B_IP, c.Join(system_info(), "Switch", [app_record(0x10000)]),
                          source=gsrc, offers=offers, outdir=str(tmp_path / "guest"), keys=KEYS)
    host = session.Host(lk.a.tcp, A_IP, "pokeldn", system_info(), [app_record(0x20000)])
    listener = lk.a.tcp.listen(c.PORT)
    listener.settimeout(10)
    g = Thread(lambda: guest.run(A_IP))
    g.start()

    conn, addr = listener.accept()
    listener.close()
    member = host.admit(conn, addr[0])
    assert (member.ip, member.node_id, member.name) == (B_IP, 2, "Switch")
    host.start_share()
    pulled = host.pull_system_update(member, str(tmp_path / "su"), KEYS)
    assert len(pulled) == 3
    assert (tmp_path / "su" / (sys_data.content_id.hex() + ".nca")).read_bytes() == gsrc.blobs[sys_data.content_id]
    pulled = host.pull_application(member, APP, str(tmp_path / "app"), KEYS)
    assert sorted(os.path.splitext(p)[1] for p in pulled) == [".cert", ".nca", ".nca", ".tik"]
    stats = host.push_application(member, APP, [v2], hsrc)
    assert stats.requests[-1] == (content.EXIT, None) and stats.total_size == v2_info.size
    host.finish()
    g.finish()

    assert guest.node_id == member.node_id
    assert [(n.node_id, n.name) for n in guest.snapshot.nodes] == [(1, "pokeldn"), (2, "Switch")]
    assert guest.snapshot.apps[0].application_id == APP
    assert guest.completed == session.COMPLETED_INFO
    assert (tmp_path / "guest" / (v2_info.content_id.hex() + ".nca")).read_bytes() == hsrc.blobs[v2_info.content_id]
    assert len(guest.served) == 2 and all(s.requests[-1] == (content.EXIT, None) for s in guest.served)


@pytest.mark.parametrize("host_version,guest_version", [(0x20000, 0), (0, 0x10000)])
def test_console_like_host_matches_versions(link, tmp_path, host_version, guest_version):  # noqa: F811
    """pokeldn joins a console: it queries the game before the 0x05, then the newer side sends."""
    from tests.test_lcs_control import nacp
    lk = link(delay=0.001)
    data = nacp("Game", "Maker", "2.0.0") + b"icon"
    hsrc, gsrc = DictSource(), DictSource()
    host_keys = [add_patch(hsrc, host_version)[0]] if host_version else []
    guest_keys = [add_patch(gsrc, guest_version)[0]] if guest_version else []
    host = session.Host(lk.a.tcp, A_IP, "Console", system_info(), [app_record(host_version)], control={APP: data})
    guest = session.Guest(lk.b.tcp, B_IP, c.Join(system_info(), "pokeldn", [app_record(guest_version)]),
                          source=gsrc, offers=guest_keys, outdir=str(tmp_path / "guest"), keys=KEYS)
    listener = lk.a.tcp.listen(c.PORT)
    listener.settimeout(10)

    def join():
        sock = guest.connect(A_IP)
        guest.control = session.query_control(sock, APP)
        guest.run(A_IP, sock)
    g = Thread(join)
    g.start()
    conn, addr = listener.accept()
    listener.close()
    member = host.admit(conn, addr[0])
    host.start_share()
    outcome, result = host.match_application(member, APP, hsrc, host_keys, str(tmp_path / "host"), KEYS)
    host.finish()
    g.finish()

    assert guest.control.name == "Game" and guest.control.icon == b"icon"
    if host_version > guest_version:
        assert outcome == "sent" and result.requests[-1] == (content.EXIT, None)
        assert sorted(os.path.splitext(p)[1] for p in guest.received) == [".cert", ".nca", ".nca", ".tik"]
    else:
        assert outcome == "received" and len(guest.served) == 1
        assert sorted(os.path.splitext(p)[1] for p in result) == [".cert", ".nca", ".nca", ".tik"]


def install(src, root):
    """`src`'s contents as installed: Meta NCAs as <id>.nca files, the others as Ryujinx's <id>.nca
    folders, in two parts."""
    metas = {m.content_id for m in src.metas.values()}
    for content_id, raw in src.blobs.items():
        path = root / (content_id.hex() + ".nca")
        if content_id in metas:
            path.write_bytes(raw)
        else:
            path.mkdir()
            (path / "00").write_bytes(raw[:1000])
            (path / "01").write_bytes(raw[1000:])


def test_a_console_host_sends_its_installed_system_update(link, tmp_path):    # noqa: F811
    """The host suspends the older member, then 0x10 names itself; the member pulls every content
    meta the SystemUpdate lists, from installed contents."""
    lk = link(delay=0.001)
    gsrc, _offers, _data = guest_source()
    root = tmp_path / "registered"
    root.mkdir()
    install(gsrc, root)
    system = content.DirSource(str(root), KEYS)
    assert system.system_update() == SU and set(system.metas) == set(gsrc.metas)
    guest = session.Guest(lk.b.tcp, B_IP, c.Join(system_info(delivery.system_version(19, 0, 1)), "pokeldn"),
                          outdir=str(tmp_path / "guest"), keys=KEYS)
    seen = []
    guest.on_system = seen.append
    host = session.Host(lk.a.tcp, A_IP, "Console", system_info())
    listener = lk.a.tcp.listen(c.PORT)
    listener.settimeout(10)
    g = Thread(lambda: guest.run(A_IP))
    g.start()
    conn, addr = listener.accept()
    listener.close()
    member = host.admit(conn, addr[0])
    host.start_share()
    stats = host.push_system_update(member, system)
    host.finish()
    g.finish()

    assert seen[0].system_update_version == SU.version
    assert stats.requests[-1] == (content.EXIT, None)
    assert len(guest.received) == 3          # the SystemUpdate meta, the meta it lists, its content
    for path in guest.received:
        assert Path(path).read_bytes() == gsrc.blobs[bytes.fromhex(os.path.basename(path)[:32])]
    assert member.join.system_info == system_info()      # its 0x18 names the host's own system update


def test_a_refresh_that_still_names_the_old_system_is_caught(link, tmp_path):    # noqa: F811
    """A console host waits for the member's 0x18 after its system update and sends the update again
    while that refresh is older: the stand-in says so instead."""
    lk = link(delay=0.001)
    gsrc, _offers, _data = guest_source()
    root = tmp_path / "registered"
    root.mkdir()
    install(gsrc, root)
    old = system_info(delivery.system_version(19, 0, 1))
    guest = session.Guest(lk.b.tcp, B_IP, c.Join(old, "pokeldn"), outdir=str(tmp_path / "guest"), keys=KEYS,
                          after_system=lambda join: replace(join, system_info=old))
    host = session.Host(lk.a.tcp, A_IP, "Console", system_info(), timeout=5)
    listener = lk.a.tcp.listen(c.PORT)
    listener.settimeout(10)
    g = Thread(lambda: guest.run(A_IP))
    g.start()
    conn, addr = listener.accept()
    listener.close()
    member = host.admit(conn, addr[0])
    host.start_share()
    with pytest.raises(session.SessionError, match="send it again"):
        host.push_system_update(member, content.DirSource(str(root), KEYS))
    host.finish()
    g.finish()


@pytest.mark.parametrize("kind,answer", [(1, 0), (2, 2), (3, None)])
def test_the_guest_answers_a_suspend_as_qlaunchs_does(kind, answer):
    a, b = socket.socketpair()
    a.settimeout(1)
    guest = session.Guest(None, B_IP, c.Join(system_info(), "pokeldn"))
    guest._handle(b, c.SUSPEND, bytes((kind, 0, 0, 0)))
    if answer is None:
        with pytest.raises(socket.timeout):
            a.recv(1)
    else:
        assert c.read(a) == (c.SUSPEND_REPLY, c.TransferReply(answer).pack(c.SUSPEND_REPLY)[8:])
    a.close()
    b.close()


def test_a_guest_that_leaves_on_the_snapshot_sends_a_leave():
    a, b = socket.socketpair()
    a.settimeout(5)
    seen = []

    def leave(snapshot):
        seen.append(snapshot)
        raise session.Leaving("too old")
    guest = session.Guest(None, B_IP, c.Join(system_info(), "pokeldn"), on_snapshot=leave)
    a.sendall(c.accept(2) + c.Snapshot([app_record(0x20000)]).pack())
    with pytest.raises(session.Leaving):
        guest.run(A_IP, b)
    assert c.read(a)[0] == c.JOIN
    assert c.read(a) == (c.LEAVE, bytes((session.LEAVE_DROP, 0, 0, 0)))
    assert seen[0].apps[0].application_id == APP
    a.close()


def test_a_member_that_needs_no_system_update_declines_it():
    def guest(sock):
        assert c.read(sock)[0] == c.SUSPEND
        sock.sendall(c.TransferReply(0).pack(c.SUSPEND_REPLY))
        assert c.read(sock)[0] == c.RECEIVE_SYSTEM_UPDATE
        sock.sendall(c.TransferReply(0).pack(c.RECEIVE_SYSTEM_UPDATE_REPLY))

    class Network:
        def listen(self, port):
            return socket.socket()
    a, t = scripted(guest)
    host = session.Host(Network(), A_IP, "Console", system_info())
    member = session.Member(a, B_IP, 2, c.Join(system_info(), "Switch"))
    assert host.push_system_update(member, None) is None
    t.finish()


def test_query_for_another_game_is_refused():
    def guest(sock):
        sock.sendall(c.control_query(APP + 0x1000))
    a, t = scripted(guest)
    host = session.Host(None, A_IP, "Console", system_info(), control={APP: b""})
    with pytest.raises(session.SessionError, match="would crash"):
        host.admit(a, B_IP)
    t.finish()


def test_bad_delivery_info_is_rejected(link):            # noqa: F811
    lk = link()
    forged = bytearray(system_info())
    forged[0xC] ^= 1                                     # the version, under the HMAC
    guest = session.Guest(lk.b.tcp, B_IP, c.Join(bytes(forged), "Switch"))
    host = session.Host(lk.a.tcp, A_IP, "pokeldn", system_info())
    listener = lk.a.tcp.listen(c.PORT)
    listener.settimeout(10)
    g = Thread(lambda: guest.run(A_IP))
    g.start()
    conn, addr = listener.accept()
    listener.close()
    with pytest.raises(session.Rejected) as host_side:
        host.admit(conn, addr[0])
    assert host_side.value.reason == session.REJECT_INCOMPATIBLE
    with pytest.raises(session.Rejected, match="2211-0256"):
        g.finish()
    assert not host.members


PAIRS = []      # scripted()'s sockets, closed after each test


@pytest.fixture(autouse=True)
def _close_pairs():
    yield
    while PAIRS:
        PAIRS.pop().close()


def scripted(script):
    """A socket pair; the far end runs script(sock) in a thread."""
    a, b = socket.socketpair()
    PAIRS.extend((a, b))
    a.settimeout(10)
    b.settimeout(10)
    t = Thread(lambda: script(b))
    t.start()
    return a, t


def test_application_in_use_waits_for_1a():
    def guest(sock):
        assert c.read(sock) == (c.APPLICATION_SETUP, c.application_setup(APP)[8:])
        sock.sendall(c.result(c.APPLICATION_SETUP_RESULT, session.NOT_READY_SETUP))
        sock.sendall(c.Join(system_info(), "Switch").pack(c.JOIN_REFRESH))    # interleaved
        sock.sendall(c.pack(c.UNKNOWN_1A))
    a, t = scripted(guest)
    host = session.Host(None, A_IP, "pokeldn", system_info())
    member = session.Member(a, B_IP, 2, c.Join(system_info(), "old"))
    host.prepare_application(member, APP)
    t.finish()
    assert member.ready and member.name == "Switch"


@pytest.mark.parametrize("icon", [b"icon", bytes(0x31D75)], ids=["switch", "switch 2"])
def test_guest_queries_the_game_before_joining(icon):
    """A Switch 2 host's icon outgrows a Switch's whole control data buffer (seen: 0x31D75 bytes)."""
    from tests.test_lcs_control import nacp
    data = nacp("Game", "Maker", "1.0.2") + icon

    def console(sock):
        mtype, payload = c.read(sock)
        assert (mtype, c.parse_control_query(payload)) == (c.CONTROL_QUERY, APP)
        sock.sendall(c.ControlReply(APP, len(data), data).pack())
        mtype, payload = c.read(sock)
        assert mtype == c.JOIN and c.Join.parse(payload).name == "pokeldn"
        sock.sendall(c.accept(2) + c.share_completed(bytes(range(0x40))))
    a, t = scripted(console)
    control = session.query_control(a, APP)
    assert (control.name, control.publisher, control.display_version) == ("Game", "Maker", "1.0.2")
    assert control.icon == icon
    guest = session.Guest(None, B_IP, c.Join(system_info(), "pokeldn", [app_record(0x10000)]))
    guest.run(A_IP, a)
    t.finish()
    assert guest.node_id == 2 and guest.completed == bytes(range(0x40))


def test_finish_matches_join_version():
    a, t = scripted(c.read)
    b, t2 = scripted(c.read)
    host = session.Host(None, A_IP, "pokeldn", system_info())
    host.members = [session.Member(a, B_IP, 2, c.Join(system_info())),
                    session.Member(b, "169.254.1.3", 3, c.Join(system_info(), version=0x11))]
    host.finish(bytes(range(0x40)))
    assert t.finish() == (c.SHARE_COMPLETED, bytes(range(0x40)))
    assert t2.finish() == (c.SHARE_COMPLETED, b"")


def test_closed_group_rejects():
    a, t = scripted(lambda sock: (sock.sendall(c.Join(system_info()).pack()), c.read(sock))[1])
    host = session.Host(None, A_IP, "pokeldn", system_info(), closed=True)
    with pytest.raises(session.Rejected):
        host.admit(a, B_IP)
    assert t.finish() == (c.REJECT, bytes((session.REJECT_CLOSED, 0, 0, 0)))


def test_keys_and_addresses():
    keys = [nca.ContentMetaKey(PATCH, 1, nca.PATCH), nca.ContentMetaKey(APP, 1, nca.APPLICATION),
            nca.ContentMetaKey(0x0100000000002800, 1, nca.PATCH)]
    assert session.patch_keys(keys, APP) == keys[:1]
    assert session.system_update_key(system_info()) == SU
    assert session.int_to_ip(session.ip_to_int(B_IP)) == B_IP == "169.254.1.2"


def test_lcs_host_backs_up_a_system_update_on_simulated_boards(tmp_path, monkeypatch):
    """tools/lcs_host.py --backup-system on one simulated ESP32 board; a guest scans for the lcs group, joins it
    through a second board and pokeldn's plugin network surface (switchlcs.net), and answers as a console."""
    import contextlib

    import lcs_host
    from ldn import wlan
    from switchlcs import advertise as adv
    from pokeldn.ldn import esp32, esp32_sim, esp32_wlan, userspace_ip
    from switchlcs import net

    monkeypatch.setenv("POKELDN_RADIO", "esp32:simulated")
    keys_file = tmp_path / "prod.keys"
    ldn_keys = {name: os.urandom(16) for name in ("aes_kek_generation_source", "aes_key_generation_source",
                                                  "master_key_00", "master_key_12")}
    keys_file.write_text("".join(f"{k} = {v.hex()}\n" for k, v in {**ldn_keys, **KEYS}.items()))
    air = esp32_sim.Air()
    radios = [esp32.Radio(esp32_sim.SimulatedBoard(air).host_stream()) for _ in range(2)]
    owners, lock = {}, threading.Lock()

    @contextlib.asynccontextmanager
    async def factory():
        with lock:                                     # the host's LDN thread asks first
            if threading.get_ident() not in owners:
                owners[threading.get_ident()] = radios[min(len(owners), 1)]
            radio = owners[threading.get_ident()]
        esp = esp32_wlan.EspFactory(radio, port_factory=userspace_ip.userspace_port, join_timeout=5)
        try:
            yield esp
        finally:
            esp.router.close()

    gsrc, offers, sys_data = guest_source()
    out = tmp_path / "su"

    def console():
        live = net.Guest(str(keys_file))
        live.start(timeout=20)
        try:
            assert adv.Advertisement.parse(live.app_data).name == "pokeldn"
            guest = session.Guest(net.tcp_for(live), live.our_ip,
                                  c.Join(system_info(), "Switch"), source=gsrc, offers=offers)
            guest.run(live.host_ip)
            return guest
        finally:
            live.stop()

    wlan.set_factory(factory)
    host = Thread(lambda: lcs_host.main(["--keys", str(keys_file), "--channel", "6", "--timeout", "30",
                                         "--backup-system", str(out)]))
    joiner = Thread(console)
    try:
        host.start()
        time.sleep(3)
        joiner.start()
        guest = joiner.finish(90)
        assert host.finish(30) == 0
    finally:
        wlan.set_factory(None)
        for r in radios:
            r.close()
    assert guest.completed == session.COMPLETED_INFO and len(guest.served) == 1
    assert (out / (sys_data.content_id.hex() + ".nca")).read_bytes() == gsrc.blobs[sys_data.content_id]


def test_a_refused_content_connect_is_retried(monkeypatch):
    """The sender's nim task listens only after its 0x0f / 0x15, so the first connect can be refused."""
    monkeypatch.setattr(session.time, "sleep", lambda s: None)
    calls = []

    class Network:
        def connect(self, address, timeout):
            calls.append(address)
            if len(calls) < 3:
                raise ConnectionRefusedError
            return "socket"
    assert session._connect_when_listening(Network(), B_IP, 5) == "socket"
    assert calls == [(B_IP, c.CONTENT_PORT)] * 3
    monkeypatch.setattr(session, "LISTEN_GRACE", -1)
    calls.clear()
    with pytest.raises(ConnectionRefusedError):
        session._connect_when_listening(Network(), B_IP, 5)


def test_after_sending_its_update_the_guest_refreshes_on_the_next_snapshots(monkeypatch):
    """Seen live: after pulling an update from pokeldn, a console sent two 0x09s and waited. qlaunch's
    guest answers the first 0x09 after its send task with a 0x18 (0x425138); pokeldn repeats it on
    later 0x09s, at most once a second, until the host moves on."""
    a, b = socket.socketpair()
    a.settimeout(0.3)

    class Network:
        def listen(self, port):
            return None
    guest = session.Guest(Network(), B_IP, c.Join(system_info(), "pokeldn"))
    monkeypatch.setattr(guest, "_serve", lambda listener, peer_ip: None)
    snapshot = c.Snapshot([], [c.Node(1, "Console"), c.Node(2, "pokeldn")]).payload()

    def refreshed():
        try:
            return c.read(a)[0] == c.JOIN_REFRESH
        except socket.timeout:
            return False
    guest._handle(b, c.SNAPSHOT, snapshot)
    assert not refreshed()
    guest._handle(b, c.SEND_APPLICATION, c.ApplicationTransfer(session.TRANSFER_KIND_SEND, 0xA9FE6101, 1, APP,
                                                               flag=session.PEER_IS_HOST).payload())
    assert c.read(a)[0] == c.SEND_APPLICATION_KEYS
    guest._handle(b, c.SNAPSHOT, snapshot)
    assert refreshed()
    guest._handle(b, c.SNAPSHOT, snapshot)
    assert not refreshed()                          # within the second
    guest._refreshed_at -= session.REFRESH_EVERY
    guest._handle(b, c.SNAPSHOT, snapshot)
    assert refreshed()
    guest._handle(b, c.APPLICATION_SETUP, c.application_setup(APP)[8:])
    assert c.read(a)[0] == c.APPLICATION_SETUP_RESULT
    guest._refreshed_at -= session.REFRESH_EVERY
    guest._handle(b, c.SNAPSHOT, snapshot)
    assert not refreshed()                          # the host moved on
    a.close()
    b.close()
