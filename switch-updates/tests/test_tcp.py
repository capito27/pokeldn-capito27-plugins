"""The plugin's TCP (switchlcs.tcp) on pokeldn's userspace stack, through the stack's IP protocol hook as
switchlcs.net puts it on a network: two Stacks joined by a simulated link that can drop, delay, reorder and
duplicate frames, and lcs's 55556 content transfer carried over it."""

import hashlib
import heapq
import os
import random
import socket
import struct
import threading
import time

import pytest

from pokeldn.ldn import userspace_ip

from switchlcs import tcp

A_IP, B_IP = "169.254.1.1", "169.254.1.2"
A_MAC, B_MAC = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"


class TcpStack(userspace_ip.Stack):
    """A userspace stack whose TCP is the plugin's, made on first use; until then TCP segments are ignored."""
    _layer = None

    @property
    def tcp(self) -> tcp.TcpLayer:
        if self._layer is None:
            self._layer = tcp.TcpLayer(self)
            self.add_protocol(tcp.PROTO_TCP, self._layer.handle)
        return self._layer


class Link:
    """Frames are delivered from a thread after `delay` (plus up to `jitter`, which reorders them);
    `loss` and `dup` are per-frame probabilities. `drop(frame)` may also pick frames to lose."""

    def __init__(self, loss=0.0, dup=0.0, delay=0.001, jitter=0.0, seed=1, drop=None):
        self.loss, self.dup, self.delay, self.jitter, self.drop = loss, dup, delay, jitter, drop
        self.rng = random.Random(seed)
        self.heap, self.n = [], 0
        self.cond = threading.Condition()
        self.closed = False
        self.a = TcpStack("a", A_MAC, lambda f: self.put(self.b, f))
        self.b = TcpStack("b", B_MAC, lambda f: self.put(self.a, f))
        self.a.set_address(A_IP, "169.254.1.255")
        self.b.set_address(B_IP, "169.254.1.255")
        self.a.add_neighbor(B_IP, B_MAC)
        self.b.add_neighbor(A_IP, A_MAC)
        self.sent = self.lost = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def put(self, stack, frame):
        with self.cond:
            self.sent += 1
            if (self.drop and self.drop(frame)) or self.rng.random() < self.loss:
                self.lost += 1
                return
            for _ in range(2 if self.rng.random() < self.dup else 1):
                when = time.monotonic() + self.delay + self.rng.random() * self.jitter
                self.n += 1
                heapq.heappush(self.heap, (when, self.n, stack, frame))
            self.cond.notify()

    def run(self):
        while True:
            with self.cond:
                while not self.closed and (not self.heap or self.heap[0][0] > time.monotonic()):
                    self.cond.wait(None if not self.heap else self.heap[0][0] - time.monotonic())
                if self.closed:
                    return
                _when, _n, stack, frame = heapq.heappop(self.heap)
            stack.deliver(frame)

    def close(self):
        with self.cond:
            self.closed = True
            self.cond.notify()


@pytest.fixture
def link(request):
    made = []

    def make(**kw):
        made.append(Link(**kw))
        return made[-1]
    yield make
    for lk in made:
        lk.close()


def pair(lk, port=55556):
    listener = lk.b.tcp.listen(port)
    listener.settimeout(10)
    client = lk.a.tcp.connect((B_IP, port), timeout=10)
    server, addr = listener.accept()
    listener.close()
    for s in (client, server):
        s.settimeout(30)
    assert addr == (A_IP, client.getsockname()[1])
    assert client.getpeername() == (B_IP, port)
    return client, server


def recv_all(sock, n):
    out = bytearray()
    while len(out) < n:
        part = sock.recv(n - len(out))
        assert part, f"EOF after {len(out)} of {n}"
        out += part
    return bytes(out)


def transfer(sender, receiver, data):
    t = threading.Thread(target=sender.sendall, args=(data,))
    t.start()
    got = recv_all(receiver, len(data))
    t.join(30)
    return got


def test_segment_codec():
    seg = tcp.Segment(55556, 49152, 0xFFFFFFF0, 7, tcp.SYN | tcp.ACK, 0xFFFF, b"", tcp.MSS)
    raw = tcp.build_segment(A_IP, B_IP, seg)
    assert len(raw) == 24 and raw[12] == 6 << 4
    assert tcp.parse_segment(A_IP, B_IP, raw) == seg
    assert tcp.parse_segment(A_IP, "169.254.1.3", raw) is None             # the pseudo header counts
    bad = bytearray(tcp.build_segment(A_IP, B_IP, tcp.Segment(1, 2, 3, 4, tcp.ACK, 5, b"data")))
    bad[-1] ^= 1
    assert tcp.parse_segment(A_IP, B_IP, bytes(bad)) is None
    assert tcp._diff(5, 0xFFFFFFFE) == 7 and tcp._diff(0xFFFFFFFE, 5) == -7
    syn = tcp.Segment(49152, 55556, 1, 0, tcp.SYN, 4096, b"", tcp.MSS, 6, (0x3FCCD2E2, 0))
    raw = tcp.build_segment(A_IP, B_IP, syn)
    assert len(raw) == 40 and tcp.parse_segment(A_IP, B_IP, raw) == syn


def _raw_segment(sport, dport, seq, ack, flags, window, options=b"", payload=b""):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (20 + len(options)) // 4 << 4, flags,
                         window, 0, 0) + options
    total = tcp.checksum(tcp._pseudo(A_IP, B_IP, len(header) + len(payload)) + header + payload)
    return header[:16] + struct.pack("!H", total) + header[18:] + payload


class _Peer:
    """Stack B's TCP, fed segments by hand as from A; `sent()` returns what B answered."""

    def __init__(self):
        self.frames = []
        self.stack = TcpStack("b", B_MAC, self.frames.append)
        self.stack.set_address(B_IP, "169.254.1.255")
        self.stack.add_neighbor(A_IP, A_MAC)

    def feed(self, raw):
        self.stack.tcp.handle(A_IP, B_IP, raw)

    def sent(self):
        out = [tcp.parse_segment(B_IP, A_IP, f[34:]) for f in self.frames
               if f[12:14] == b"\x08\x00" and f[23] == tcp.PROTO_TCP]
        self.frames.clear()
        return out


def test_the_options_a_console_offers_are_taken():
    """A console's 55556 SYN (live): MSS 1460, window scale 6, SACK permitted and timestamps, window
    4096. Its BSD stack grows its 4 KiB receive buffer only with timestamps, so both are taken, and
    the window it advertises later is scaled."""
    peer = _Peer()
    listener = peer.stack.tcp.listen(55556)
    listener.settimeout(5)
    peer.feed(_raw_segment(25404, 55556, 1000, 0, tcp.SYN, 4096,
                           bytes.fromhex("020405b4010303060402080a3fccd2e200000000")))
    syn_ack, = peer.sent()
    assert syn_ack.flags == tcp.SYN | tcp.ACK and syn_ack.mss == tcp.MSS and syn_ack.wscale == 0
    assert syn_ack.ts[1] == 0x3FCCD2E2
    peer.feed(tcp.build_segment(A_IP, B_IP, tcp.Segment(25404, 55556, 1001, syn_ack.seq + 1, tcp.ACK, 64,
                                                         ts=(0x3FCCD2E3, syn_ack.ts[0]))))
    server, _ = listener.accept()
    assert server.snd_wnd == 64 << 6 and server.mss == tcp.MSS - tcp.TS_SPACE
    server.settimeout(5)
    server.send(bytes(10_000))
    data = peer.sent()
    # The 4096-byte window holds 2.8 segments, and the sender fills it: the console grows its buffer only once
    # more than 7/8 of it arrives within a round trip. Kept for whole ones, an upload stayed at 150 KB/s (live).
    assert [len(s.payload) for s in data] == [1448, 1448, 1200]
    assert all(s.ts[1] == 0x3FCCD2E3 and s.wscale is None for s in data)
    peer.feed(tcp.build_segment(A_IP, B_IP, tcp.Segment(25404, 55556, 1001, data[-1].seq + 1200, tcp.ACK,
                                                         1000, ts=(0x3FCCD2F0, data[-1].ts[0]))))
    assert server.snd_wnd == 64_000
    more = peer.sent()
    assert sum(len(s.payload) for s in more) == 10_000 - 4096
    assert all(s.ts[1] == 0x3FCCD2F0 for s in more)
    server.abort()


def test_a_peer_without_options_gets_none():
    peer = _Peer()
    listener = peer.stack.tcp.listen(55556)
    listener.settimeout(5)
    peer.feed(tcp.build_segment(A_IP, B_IP, tcp.Segment(25404, 55556, 1000, 0, tcp.SYN, 4096, mss=tcp.MSS)))
    syn_ack, = peer.sent()
    assert syn_ack.wscale is None and syn_ack.ts is None
    peer.feed(tcp.build_segment(A_IP, B_IP, tcp.Segment(25404, 55556, 1001, syn_ack.seq + 1, tcp.ACK, 64)))
    server, _ = listener.accept()
    assert server.snd_wnd == 64 and server.mss == tcp.MSS
    server.abort()


def test_echo_and_close(link):
    lk = link()
    client, server = pair(lk)
    for s in (client, server):                     # each side offers both options, so both hold
        assert s.ts_ok and s.snd_scale == 0 and s.mss == tcp.MSS - tcp.TS_SPACE
    client.sendall(b"hello")
    assert recv_all(server, 5) == b"hello"
    server.sendall(b"world")
    assert recv_all(client, 5) == b"world"
    client.close()
    assert server.recv(10) == b""                 # FIN
    with pytest.raises(BrokenPipeError):
        client.sendall(b"late")
    server.close()
    deadline = time.monotonic() + tcp.TIME_WAIT + 2
    while (lk.a.tcp.connections() or lk.b.tcp.connections()) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not lk.a.tcp.connections() and not lk.b.tcp.connections()


def test_refused(link):
    lk = link()
    lk.b.tcp                                      # B answers TCP once its layer exists
    with pytest.raises(ConnectionRefusedError):
        lk.a.tcp.connect((B_IP, 55555), timeout=5)
    assert lk.b.tcp.counters["resets_sent"] == 1


def test_lost_syn_is_retried(link):
    first = []

    def drop_first_syn(frame):
        is_syn = frame[23] == 6 and frame[14 + 20 + 13] == tcp.SYN
        if is_syn and not first:
            first.append(frame)
            return True
        return False
    lk = link(drop=drop_first_syn)
    started = time.monotonic()
    client, server = pair(lk)
    assert first and time.monotonic() - started >= tcp.RTO_INITIAL * 0.9


def test_bulk_both_ways(link):
    lk = link(delay=0.002)
    client, server = pair(lk)
    data = os.urandom(1 << 20)
    started = time.monotonic()
    assert transfer(client, server, data) == data
    assert transfer(server, client, data[::-1]) == data[::-1]
    assert time.monotonic() - started < 30
    assert client.retransmits == 0 and server.retransmits == 0


def _payload_sizes(frames, port):
    """TCP payload sizes of the frames sent from `port`."""
    sizes = []
    for frame in frames:
        if frame[12:14] != b"\x08\x00" or frame[23] != 6:
            continue
        ihl = (frame[14] & 0xF) * 4
        total = int.from_bytes(frame[16:18], "big")
        tcp_at = 14 + ihl
        if int.from_bytes(frame[tcp_at:tcp_at + 2], "big") == port:
            sizes.append(total - ihl - (frame[tcp_at + 12] >> 4) * 4)
    return [n for n in sizes if n]


def test_a_bulk_sender_sends_whole_segments():
    """Seen live: room under MAX_FLIGHT or cwnd short of a segment went out at once, and 45% of an
    upload's segments were partial. With more data waiting, the sender waits for room instead."""
    frames = []
    lk = Link(delay=0.002, drop=lambda frame: frames.append(bytes(frame)) and False)
    try:
        client, server = pair(lk)
        data = os.urandom(1 << 20)
        assert transfer(client, server, data) == data
        sizes = _payload_sizes(frames, client.getsockname()[1])
        partial = [n for n in sizes[:-1] if n != client.mss]
        assert sum(sizes) >= len(data) and partial == []
    finally:
        lk.close()


@pytest.mark.parametrize("seed,delay,jitter", [(1, 0.002, 0.004), (2, 0.002, 0.004), (3, 0.002, 0.004),
                                               (1, 0.0, 0.0), (4, 0.0, 0.0)])
def test_bulk_over_a_bad_link(link, seed, delay, jitter):
    # With no delay, ACKs race the sender's small segments; a fast retransmit once sent bytes past
    # snd_max, and the peer's ACK of them was then dropped as acknowledging unsent data: a stall.
    lk = link(loss=0.03, dup=0.02, delay=delay, jitter=jitter, seed=seed)
    client, server = pair(lk)
    data = os.urandom(1 << 20 if not delay else 256 << 10)
    assert transfer(client, server, data) == data
    assert lk.lost > 0 and client.retransmits > 0
    reply = os.urandom(300_000)
    assert transfer(server, client, reply) == reply


def test_sequence_numbers_wrap(link, monkeypatch):
    """Both ISNs just below 2**32, with loss: a multi-GB lcs transfer always wraps them."""
    monkeypatch.setattr(tcp.random, "getrandbits", lambda bits: (1 << 32) - 20_000)
    lk = link(loss=0.03, delay=0.001, seed=5)
    client, server = pair(lk)
    data = os.urandom(200_000)
    assert transfer(client, server, data) == data
    assert transfer(server, client, data[::-1]) == data[::-1]


def test_zero_window(link):
    lk = link()
    client, server = pair(lk)
    data = os.urandom(tcp.RCVBUF + tcp.SNDBUF + 50_000)
    t = threading.Thread(target=client.sendall, args=(data,))
    t.start()
    time.sleep(0.5)                             # the receiver reads nothing: its window closes
    assert server._window() == 0
    assert t.is_alive()                          # the sender is blocked on a full send buffer
    assert recv_all(server, len(data)) == data
    t.join(10)


def test_reset(link):
    lk = link()
    client, server = pair(lk)
    server.abort()
    with pytest.raises(ConnectionResetError):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            client.recv(10)


def test_peer_gone_times_out(link, monkeypatch):
    monkeypatch.setattr(tcp, "DATA_RETRIES", 3)
    gone = []
    lk = link(drop=lambda frame: bool(gone))
    client, server = pair(lk)
    gone.append(True)
    client.sendall(b"into the void")
    client.settimeout(20)
    with pytest.raises(socket.timeout):
        client.recv(10)


def test_lcs_content_over_tcp(link, tmp_path):
    """A Patch content meta pulled with switchlcs.content over the userspace TCP of a lossy link."""
    from switchlcs import content, nca
    from tests.test_lcs_content import KEYS, DictSource, build_nca

    lk = link(loss=0.01, delay=0.002, jitter=0.002)
    src = DictSource()
    rights = struct.pack(">Q", 0x0100000000001800) + bytes(8)
    program = build_nca(0, 0x0100000000001000, body=os.urandom(600_000), rights_id=rights)
    info = src.add_content(program, nca.PROGRAM)
    key = nca.ContentMetaKey(0x0100000000001800, 0x10000, nca.PATCH)
    src.add_meta(key, [info])
    src.tickets[rights] = (b"tik", b"cert")
    listener = lk.b.tcp.listen(content.PORT)
    listener.settimeout(10)
    stats = {}

    def sender():
        conn, addr = listener.accept()
        assert addr[0] == A_IP                   # nim's sender accepts only the expected receiver
        conn.settimeout(30)
        stats["s"] = content.serve(conn, src)
        conn.close()
    t = threading.Thread(target=sender)
    t.start()
    sock = lk.a.tcp.connect((B_IP, content.PORT), timeout=10)
    sock.settimeout(30)
    paths = content.receive(sock, key, str(tmp_path), KEYS)
    sock.close()
    t.join(30)
    listener.close()
    assert len(paths) == 4
    got = (tmp_path / (info.content_id.hex() + ".nca")).read_bytes()
    assert hashlib.sha256(got).digest() == info.hash
    assert stats["s"].requests[-1] == (content.EXIT, None)
