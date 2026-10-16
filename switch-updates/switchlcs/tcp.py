"""TCP on pokeldn's userspace stack, through the IP protocol hook a plugin's network has
(pokeldn.ldn.network.Network.add_protocol; switchlcs.net), enough to carry lcs's TCP 55555 and 55556
sessions over the ESP32 board, which has no kernel interface. Active and passive open, cumulative ACKs,
out-of-order segments held until the hole fills, Reno congestion control with fast retransmit and
NewReno partial ACKs (RFC 5681, 6582), the RFC 6298 retransmit timer, zero-window probes, FIN and RST.

Window scaling and timestamps (RFC 7323) are taken when the peer offers them, for the peer's sake: a
console's receive buffer starts at 4 KiB and its BSD stack grows it only on a connection with
timestamps, then past 64 KiB only with scaling. Our own window stays 64 KiB (shift 0), and the
timestamps serve only as echoes: RTT samples and PAWS are left out. Not implemented: SACK and urgent
data. The retransmit timeout is capped at RTO_MAX rather than a minute, since a stalled radio link
should recover quickly.

Sockets block (settimeout is honoured) and offer sendall/recv like socket.socket. Frames leave through
the stack after the layer's lock is released, so a `transmit` may hand them straight to another layer.
"""

import itertools
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass

PROTO_TCP = 6
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
MSS = 1460                       # a 1500-byte MTU less the IPv4 and TCP headers
TS_SPACE = 12                    # NOP, NOP and the timestamps option, in every segment once agreed
RCVBUF = 0xFFFF                  # our window: we offer scaling with shift 0, for the peer's window
MAX_SCALE = 14
SNDBUF = 256 * 1024
# What the sender keeps unacknowledged, whatever the windows allow. The board's USB link drains at
# about 0.7 MB/s with a 10 ms round trip, a 7 KB bandwidth-delay product: more only waits in the
# board's send queue, where a fast retransmit then queues behind it (100 ms behind 50 KB, seen live).
MAX_FLIGHT = 32 * 1024
RTO_INITIAL, RTO_MIN, RTO_MAX = 1.0, 0.2, 2.0
SYN_RETRIES = 6
DATA_RETRIES = 15
TIME_WAIT = 1.0
TICK = 0.01
EPHEMERAL_FIRST, EPHEMERAL_LAST = 49152, 65535

SYN_SENT, SYN_RCVD, ESTABLISHED, TIME_WAIT_STATE, CLOSED = \
    "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "TIME_WAIT", "CLOSED"


def checksum(data: bytes) -> int:
    """The Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += bytes(1)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _diff(a: int, b: int) -> int:
    """a - b in sequence space, signed."""
    d = (a - b) & 0xFFFFFFFF
    return d - (1 << 32) if d & 0x80000000 else d


def _seq(n: int) -> int:
    return n & 0xFFFFFFFF


@dataclass
class Segment:
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes = b""
    mss: int | None = None
    wscale: int | None = None
    ts: tuple[int, int] | None = None   # (TSval, TSecr)

    @property
    def length(self) -> int:
        """The sequence space it takes: data, plus one each for SYN and FIN."""
        return len(self.payload) + bool(self.flags & SYN) + bool(self.flags & FIN)


def _pseudo(src_ip: str, dst_ip: str, length: int) -> bytes:
    return socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, PROTO_TCP, length)


def build_segment(src_ip: str, dst_ip: str, seg: Segment) -> bytes:
    options = struct.pack("!BBH", 2, 4, seg.mss) if seg.mss else b""
    if seg.wscale is not None:
        options += struct.pack("!BBBB", 1, 3, 3, seg.wscale)
    if seg.ts is not None:
        options += struct.pack("!BBBBII", 1, 1, 8, 10, *seg.ts)
    header = struct.pack("!HHIIBBHHH", seg.sport, seg.dport, seg.seq, seg.ack,
                         (20 + len(options)) // 4 << 4, seg.flags, seg.window, 0, 0) + options
    total = checksum(_pseudo(src_ip, dst_ip, len(header) + len(seg.payload)) + header + seg.payload)
    return header[:16] + struct.pack("!H", total) + header[18:] + seg.payload


def parse_segment(src_ip: str, dst_ip: str, data: bytes) -> Segment | None:
    """-> the segment, or None if it is short or its checksum is wrong."""
    if len(data) < 20 or checksum(_pseudo(src_ip, dst_ip, len(data)) + data):
        return None
    sport, dport, seq, ack, offset, flags, window = struct.unpack_from("!HHIIBBH", data)
    offset = (offset >> 4) * 4
    if offset < 20 or offset > len(data):
        return None
    mss = wscale = ts = None
    at = 20
    while at < offset:
        kind = data[at]
        if kind == 0:
            break
        if kind == 1:
            at += 1
            continue
        if at + 1 >= offset or data[at + 1] < 2:
            break
        if at + data[at + 1] > offset:
            break
        if kind == 2 and data[at + 1] == 4:
            mss = struct.unpack_from("!H", data, at + 2)[0]
        elif kind == 3 and data[at + 1] == 3:
            wscale = data[at + 2]
        elif kind == 8 and data[at + 1] == 10:
            ts = struct.unpack_from("!II", data, at + 2)
        at += data[at + 1]
    return Segment(sport, dport, seq, ack, flags & 0x3F, window, bytes(data[offset:]), mss, wscale, ts)


class TcpSocket:
    """One connection. Made by TcpLayer.connect or TcpListener.accept."""

    def __init__(self, layer: "TcpLayer", local, remote, iss: int):
        self._layer = layer
        self.local, self.remote = local, remote
        self.state = CLOSED
        self._cond = threading.Condition(layer._lock)
        self._timeout = None
        self.error: BaseException | None = None
        # Send side: _sndbuf[0] is the byte at snd_una once the SYN is acknowledged.
        self.iss = iss
        self.snd_una = self.snd_nxt = self.snd_max = iss
        self.snd_wnd = 0
        self.mss = MSS                 # payload per segment, less TS_SPACE once timestamps are agreed
        self.snd_scale: int | None = None   # the peer's window shift, once both SYNs carried one
        self.ts_ok = False
        self.ts_recent = 0
        self._ts_base = random.getrandbits(32)
        self._sndbuf = bytearray()
        self.fin_queued = self.fin_acked = False
        # Receive side.
        self.rcv_nxt = 0
        self._rcvbuf = bytearray()
        self._ooo: dict[int, tuple[bytes, bool]] = {}
        self.peer_fin = False
        self._read_closed = False
        self._adv_wnd = RCVBUF
        # Timers and congestion control.
        self.rto = RTO_INITIAL
        self._srtt: float | None = None
        self._rttvar = 0.0
        self._rto_deadline: float | None = None
        self._persist_deadline: float | None = None
        self._time_wait_until = 0.0
        self._retries = 0
        self._timed: tuple[int, float] | None = None
        self.cwnd = 10 * MSS
        self.ssthresh = 1 << 30
        self._dupacks = 0
        self._recover: int | None = None
        self.retransmits = 0
        self._listener: "TcpListener | None" = None

    # ---- the application side ----

    def settimeout(self, value) -> None:
        self._timeout = value

    def gettimeout(self):
        return self._timeout

    def setblocking(self, flag: bool) -> None:
        self._timeout = None if flag else 0.0

    def getsockname(self):
        return self.local

    def getpeername(self):
        return self.remote

    def setsockopt(self, *args) -> None:
        pass

    def _wait(self, ready, deadline) -> None:
        """Wait on the layer lock (held) until `ready()`; raises the connection's error or a timeout."""
        while not ready():
            if self.error is not None:
                raise self.error
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise socket.timeout("timed out")
            self._cond.wait(remaining)

    def _deadline(self):
        return None if self._timeout is None else time.monotonic() + self._timeout

    def send(self, data) -> int:
        data = memoryview(data).cast("B")
        deadline = self._deadline()
        with self._layer._lock:
            if self.fin_queued:
                raise BrokenPipeError("the connection is shut down for writing")
            self._wait(lambda: self.error is not None or len(self._sndbuf) < SNDBUF, deadline)
            if self.error is not None:
                raise self.error
            n = min(len(data), SNDBUF - len(self._sndbuf))
            self._sndbuf += data[:n]
            self._output()
        self._layer._flush()
        return n

    def sendall(self, data) -> None:
        view = memoryview(data).cast("B")
        while view:
            view = view[self.send(view):]

    def recv(self, bufsize: int = 65536) -> bytes:
        deadline = self._deadline()
        with self._layer._lock:
            self._wait(lambda: bool(self._rcvbuf) or self.peer_fin or self._read_closed
                       or self.error is not None, deadline)
            if not self._rcvbuf and self.error is not None and not self.peer_fin:
                raise self.error
            out = bytes(self._rcvbuf[:bufsize])
            del self._rcvbuf[:bufsize]
            # Window update once the window has opened by two segments (RFC 1122 4.2.3.3).
            if self.state == ESTABLISHED and self._window() - self._adv_wnd >= min(2 * self.mss, RCVBUF // 2):
                self._send(ACK)
        self._layer._flush()
        return out

    def shutdown(self, how: int) -> None:
        with self._layer._lock:
            if how in (socket.SHUT_RD, socket.SHUT_RDWR):
                self._read_closed = True
                self._rcvbuf.clear()
                self._cond.notify_all()
            if how in (socket.SHUT_WR, socket.SHUT_RDWR) and not self.fin_queued \
                    and self.state in (ESTABLISHED, SYN_RCVD):
                self.fin_queued = True
                self._output()
        self._layer._flush()

    def close(self) -> None:
        """Send FIN once the queued data is out; the connection finishes in the background."""
        with self._layer._lock:
            if self.state == SYN_SENT:
                self._layer._remove(self)
                return
        self.shutdown(socket.SHUT_RDWR)

    def abort(self) -> None:
        """Reset the connection (RST) and drop anything queued."""
        with self._layer._lock:
            if self.state in (ESTABLISHED, SYN_RCVD):
                self._emit(RST | ACK, self.snd_nxt)
            self._fail(ConnectionAbortedError("aborted"))
        self._layer._flush()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---- the segment side; everything below runs under the layer lock ----

    def _window(self) -> int:
        return max(0, RCVBUF - len(self._rcvbuf))

    def _emit(self, flags, seq, payload=b"") -> None:
        window = self._window()
        self._adv_wnd = window
        mss = wscale = ts = None
        offering = self.state == SYN_SENT
        if flags & SYN:
            mss = MSS
            if offering or self.snd_scale is not None:
                wscale = 0
        if self.ts_ok or (offering and flags & SYN):
            ts = (_seq(int(time.monotonic() * 1000) + self._ts_base), self.ts_recent)
        seg = Segment(self.local[1], self.remote[1], _seq(seq), _seq(self.rcv_nxt) if flags & ACK else 0,
                      flags, window, bytes(payload), mss, wscale, ts)
        self._layer._out.append((self.local[0], self.remote[0], seg))

    def _peer_window(self, seg: Segment) -> int:
        """A SYN's window is never scaled (RFC 7323 2.2)."""
        return seg.window if seg.flags & SYN else seg.window << (self.snd_scale or 0)

    def _agree(self, seg: Segment) -> None:
        """Take the options of the peer's SYN: each holds only when both SYNs carry it."""
        if seg.wscale is not None:
            self.snd_scale = min(seg.wscale, MAX_SCALE)
        if seg.ts is not None:
            self.ts_ok = True
            self.ts_recent = seg.ts[0]
        self.mss = min(MSS, seg.mss or 536) - (TS_SPACE if self.ts_ok else 0)

    def _send(self, flags) -> None:
        self._emit(flags, self.snd_nxt)

    def _arm(self, now=None) -> None:
        if self._rto_deadline is None:
            self._rto_deadline = (now or time.monotonic()) + self.rto

    def _fail(self, error: BaseException) -> None:
        if self.error is None:
            self.error = error
        self.state = CLOSED
        self._layer._remove(self)

    def _finish_if_done(self) -> None:
        if self.fin_acked and self.peer_fin and self.state == ESTABLISHED:
            self.state = TIME_WAIT_STATE
            self._time_wait_until = time.monotonic() + TIME_WAIT
            self._rto_deadline = self._persist_deadline = None
            self._cond.notify_all()

    def _on_segment(self, seg: Segment) -> None:
        if self.state == SYN_SENT:
            self._on_syn_sent(seg)
            return
        if seg.flags & RST:
            # Accept a reset only in the receive window (RFC 5961 3.2, without the challenge ACK).
            if 0 <= _diff(seg.seq, self.rcv_nxt) <= max(self._adv_wnd, 1):
                self._fail(ConnectionResetError("reset by peer"))
            return
        if self.ts_ok and seg.ts is not None and _diff(seg.seq, self.rcv_nxt) <= 0:
            self.ts_recent = seg.ts[0]                 # the newest in-order TSval (RFC 7323 4.3)
        if seg.flags & SYN:
            if self.state == SYN_RCVD and _seq(seg.seq + 1) == self.rcv_nxt:
                self._emit(SYN | ACK, self.iss)                   # our SYN-ACK was lost
            else:
                self._send(ACK)
            return
        if not seg.flags & ACK:
            return
        if self.state == SYN_RCVD:
            if seg.ack != _seq(self.iss + 1):
                self._layer._reset_for(self.local[0], self.remote[0], seg)
                return
            self._established(seg)
            self._layer._accepted(self)
        self._on_ack(seg)
        self._on_data(seg)
        self._output()
        self._finish_if_done()

    def _on_syn_sent(self, seg: Segment) -> None:
        if seg.flags & ACK and seg.ack != _seq(self.iss + 1):
            if not seg.flags & RST:
                self._layer._reset_for(self.local[0], self.remote[0], seg)
            return
        if seg.flags & RST:
            if seg.flags & ACK:
                self._fail(ConnectionRefusedError(f"{self.remote[0]}:{self.remote[1]} refused"))
            return
        if seg.flags & SYN and seg.flags & ACK:
            self.rcv_nxt = _seq(seg.seq + 1)
            self._agree(seg)
            self._established(seg)
            self._send(ACK)

    def _established(self, seg: Segment) -> None:
        now = time.monotonic()
        if self._timed is not None and self._retries == 0:
            self._sample(now - self._timed[1])
        self._timed = None
        self.snd_una = self.snd_nxt = self.snd_max = _seq(self.iss + 1)
        self.snd_wnd = self._peer_window(seg)
        self.cwnd = 10 * self.mss
        self._retries = 0
        self._rto_deadline = None
        self.state = ESTABLISHED
        self._cond.notify_all()

    def _sample(self, rtt: float) -> None:
        """RFC 6298 2.2-2.3."""
        if self._srtt is None:
            self._srtt, self._rttvar = rtt, rtt / 2
        else:
            self._rttvar = 0.75 * self._rttvar + 0.25 * abs(self._srtt - rtt)
            self._srtt = 0.875 * self._srtt + 0.125 * rtt
        self.rto = min(RTO_MAX, max(RTO_MIN, self._srtt + max(TICK, 4 * self._rttvar)))

    def _on_ack(self, seg: Segment) -> None:
        acked = _diff(seg.ack, self.snd_una)
        if acked < 0 or _diff(seg.ack, self.snd_max) > 0:
            return                                    # old, or for data never sent
        if acked == 0:
            window = self._peer_window(seg)
            outstanding = self.snd_max != self.snd_una
            if outstanding and not seg.payload and not seg.flags & FIN and window == self.snd_wnd:
                self._dupacks += 1
                if self._dupacks == 3 and self._recover is None:
                    flight = _diff(self.snd_max, self.snd_una)
                    self.ssthresh = max(flight // 2, 2 * self.mss)
                    self._recover = self.snd_max
                    self._retransmit_first()
                    self.cwnd = self.ssthresh + 3 * self.mss
                elif self._dupacks > 3:
                    self.cwnd += self.mss
            if window == 0:
                self._retries = 0                      # alive, just full: keep probing
            if window != self.snd_wnd:
                self.snd_wnd = window
                self._cond.notify_all()
            return
        end_of_data = _seq(self.snd_una + len(self._sndbuf))
        if self.fin_queued and seg.ack == _seq(end_of_data + 1):
            self.fin_acked = True
        del self._sndbuf[:min(acked, len(self._sndbuf))]
        self.snd_una = seg.ack
        if _diff(self.snd_nxt, self.snd_una) < 0:
            self.snd_nxt = self.snd_una               # the peer held segments past a go-back point
        self.snd_wnd = self._peer_window(seg)
        now = time.monotonic()
        if self._timed is not None and _diff(seg.ack, self._timed[0]) >= 0:
            self._sample(now - self._timed[1])
            self._timed = None
        self._retries = 0
        self._dupacks = 0
        if self._recover is not None:
            if _diff(seg.ack, self._recover) >= 0:
                self.cwnd = self.ssthresh
                self._recover = None
            else:                                     # a partial ACK: the next hole (RFC 6582 3.2)
                self._retransmit_first()
                self.cwnd = max(self.cwnd - acked + self.mss, self.mss)
        elif self.cwnd < self.ssthresh:
            self.cwnd += min(acked, self.mss)
        else:
            self.cwnd += max(1, self.mss * self.mss // self.cwnd)
        self._rto_deadline = None
        if self.snd_max != self.snd_una:
            self._arm(now)
        self._persist_deadline = None
        self._cond.notify_all()

    def _retransmit_first(self) -> None:
        self.retransmits += 1
        self._timed = None
        # Only what was sent: past snd_max the peer's ACK would be for data we never sent, and dropped.
        n = min(self.mss, len(self._sndbuf), _diff(self.snd_max, self.snd_una))
        if n > 0:
            self._emit(ACK | PSH, self.snd_una, self._sndbuf[:n])
        elif self.fin_queued:
            self._emit(FIN | ACK, self.snd_una)

    def _on_data(self, seg: Segment) -> None:
        fin = bool(seg.flags & FIN)
        if not seg.payload and not fin:
            return
        if self.peer_fin:
            self._send(ACK)                            # a retransmission of what we have
            return
        offset = _diff(seg.seq, self.rcv_nxt)
        if offset > 0:
            if offset < 4 * RCVBUF:
                self._ooo[seg.seq] = (seg.payload, fin)
            self._send(ACK)                            # a duplicate ACK, for the sender's fast retransmit
            return
        self._take(seg.payload[-offset:] if offset else seg.payload, fin, len(seg.payload) + offset)
        while self._ooo and not self.peer_fin:
            ready = [s for s in self._ooo if _diff(s, self.rcv_nxt) <= 0]
            if not ready:
                break
            for s in ready:
                payload, held_fin = self._ooo.pop(s)
                off = _diff(s, self.rcv_nxt)
                if len(payload) + off > 0 or (held_fin and len(payload) + off == 0):
                    self._take(payload[-off:] if off else payload, held_fin, len(payload) + off)
        if self.peer_fin:
            self._ooo.clear()
        self._send(ACK)
        self._cond.notify_all()

    def _take(self, data: bytes, fin: bool, new: int) -> None:
        if new < 0 or (new == 0 and not fin):
            return
        if not self._read_closed:
            self._rcvbuf += data
        self.rcv_nxt = _seq(self.rcv_nxt + len(data))
        if fin:
            self.rcv_nxt = _seq(self.rcv_nxt + 1)
            self.peer_fin = True

    def _output(self, probe: bool = False) -> None:
        if self.state != ESTABLISHED:
            return
        now = time.monotonic()
        while True:
            inflight = _diff(self.snd_nxt, self.snd_una)
            pending = len(self._sndbuf) - inflight
            if pending > 0:
                room = min(self.snd_wnd, self.cwnd, MAX_FLIGHT) - inflight
                if room <= 0 and probe and inflight == 0:
                    room = 1                           # a zero-window probe
                if room <= 0:
                    if self.snd_wnd == 0 and inflight == 0 and self._persist_deadline is None:
                        self._persist_deadline = now + self.rto
                    return
                n = min(self.mss, pending, room)
                ours = self.snd_wnd > min(self.cwnd, MAX_FLIGHT)
                if n < self.mss and n < pending and inflight and not probe and ours:
                    # Sender silly-window avoidance (RFC 9293 3.8.6.2.1): with more data waiting, room
                    # short of a segment under cwnd or MAX_FLIGHT waits for the next ACK. Sent at once, it
                    # made 45% of an upload's segments partial, at 1078 bytes on average. The peer's own
                    # window is filled: a console's starts at 4288 bytes and grows only once more than 7/8
                    # of it arrives within a round trip, so two whole segments a trip kept it there and an
                    # upload at 150 KB/s (seen live).
                    return
                self._emit(ACK | PSH, self.snd_nxt, self._sndbuf[inflight:inflight + n])
                self.snd_nxt = _seq(self.snd_nxt + n)
                if _diff(self.snd_nxt, self.snd_max) > 0:
                    if self._timed is None:
                        self._timed = (self.snd_nxt, now)
                    self.snd_max = self.snd_nxt
                self._arm(now)
                probe = False
            elif pending == 0 and self.fin_queued and not self.fin_acked:
                self._emit(FIN | ACK, self.snd_nxt)
                self.snd_nxt = _seq(self.snd_nxt + 1)
                if _diff(self.snd_nxt, self.snd_max) > 0:
                    self.snd_max = self.snd_nxt
                self._arm(now)
                return
            else:
                return

    def _on_tick(self, now: float) -> None:
        if self.state == TIME_WAIT_STATE:
            if now >= self._time_wait_until:
                self.state = CLOSED
                self._layer._remove(self)
            return
        if self._rto_deadline is not None and now >= self._rto_deadline:
            self._on_rto(now)
        if self._persist_deadline is not None and now >= self._persist_deadline:
            self._persist_deadline = None
            self._output(probe=True)

    def _on_rto(self, now: float) -> None:
        self._retries += 1
        self.rto = min(RTO_MAX, self.rto * 2)
        self._rto_deadline = now + self.rto
        self._timed = None
        if self.state in (SYN_SENT, SYN_RCVD):
            if self._retries > SYN_RETRIES:
                self._fail(socket.timeout("no SYN-ACK" if self.state == SYN_SENT else "no ACK"))
                return
            self._emit(SYN if self.state == SYN_SENT else SYN | ACK, self.iss)
            return
        if self._retries > DATA_RETRIES:
            self._fail(socket.timeout("the peer stopped acknowledging"))
            return
        # Go back to the first unacknowledged byte with a one-segment window (RFC 5681 3.1).
        self.ssthresh = max(_diff(self.snd_max, self.snd_una) // 2, 2 * self.mss)
        self.cwnd = self.mss
        self._recover = None
        self._dupacks = 0
        self.snd_nxt = self.snd_una
        self.retransmits += 1
        self._rto_deadline = None
        self._output(probe=True)
        self._arm(now)


class TcpListener:
    def __init__(self, layer: "TcpLayer", port: int, backlog: int):
        self._layer = layer
        self.port = port
        self.backlog = backlog
        self._queue: list[TcpSocket] = []
        self._pending = 0
        self._cond = threading.Condition(layer._lock)
        self._timeout = None
        self.closed = False

    def settimeout(self, value) -> None:
        self._timeout = value

    def getsockname(self):
        return (self._layer.stack.ip, self.port)

    def accept(self):
        """-> (TcpSocket, (ip, port)) of the next established connection."""
        deadline = None if self._timeout is None else time.monotonic() + self._timeout
        with self._layer._lock:
            while not self._queue:
                if self.closed:
                    raise OSError("the listener is closed")
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise socket.timeout("timed out")
                self._cond.wait(remaining)
            conn = self._queue.pop(0)
            return conn, conn.remote

    def close(self) -> None:
        with self._layer._lock:
            self.closed = True
            if self._layer._listeners.get(self.port) is self:
                del self._layer._listeners[self.port]
            self._cond.notify_all()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class TcpLayer:
    """The TCP of one stack: anything with `ip`, `name` and `send_ip(proto, dst, payload)`, whose protocol 6
    packets reach `handle`."""

    def __init__(self, stack):
        self.stack = stack
        self._lock = threading.Lock()
        self._tx_lock = threading.Lock()
        self._conns: dict[tuple, TcpSocket] = {}        # (local port, remote ip, remote port)
        self._listeners: dict[int, TcpListener] = {}
        self._out: list[tuple[str, str, Segment]] = []
        self._timer: threading.Thread | None = None
        self._ports = itertools.cycle(range(EPHEMERAL_FIRST + random.randrange(1000), EPHEMERAL_LAST + 1))
        self.counters = {"in": 0, "out": 0, "bad": 0, "resets_sent": 0}

    # ---- the application side ----

    def listen(self, port: int, backlog: int = 8) -> TcpListener:
        with self._lock:
            if port in self._listeners:
                raise OSError(f"TCP port {port} is already listening")
            listener = TcpListener(self, port, backlog)
            self._listeners[port] = listener
            return listener

    def connect(self, address, timeout: float | None = None, port: int = 0) -> TcpSocket:
        if self.stack.ip is None:
            raise OSError("the interface has no address yet")
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._lock:
            remote = (address[0], int(address[1]))
            if not port:
                port = next(p for p in self._ports if (p, *remote) not in self._conns)
            conn = TcpSocket(self, (self.stack.ip, port), remote, random.getrandbits(32))
            conn.state = SYN_SENT
            self._add(conn)
            conn._timed = (_seq(conn.iss + 1), time.monotonic())
            conn._emit(SYN, conn.iss)
            conn.snd_nxt = conn.snd_max = _seq(conn.iss + 1)
            conn._arm()
        self._flush()
        with self._lock:
            try:
                conn._wait(lambda: conn.state != SYN_SENT, deadline)
            except socket.timeout:
                self._remove(conn)
                raise
            if conn.error is not None:
                raise conn.error
        return conn

    # ---- the stack side ----

    def handle(self, src_ip: str, dst_ip: str, data: bytes) -> None:
        """An IP payload of protocol 6 from the stack."""
        if dst_ip != self.stack.ip:
            return
        seg = parse_segment(src_ip, dst_ip, data)
        if seg is None:
            self.counters["bad"] += 1
            return
        self.counters["in"] += 1
        with self._lock:
            conn = self._conns.get((seg.dport, src_ip, seg.sport))
            if conn is not None:
                conn._on_segment(seg)
            elif seg.flags & RST:
                pass
            elif seg.flags & SYN and not seg.flags & ACK and seg.dport in self._listeners:
                self._on_syn(self._listeners[seg.dport], src_ip, dst_ip, seg)
            else:
                self._reset_for(dst_ip, src_ip, seg)
        self._flush()

    def _on_syn(self, listener: TcpListener, src_ip: str, dst_ip: str, seg: Segment) -> None:
        if len(listener._queue) + listener._pending >= listener.backlog:
            return                                     # the peer retries its SYN
        conn = TcpSocket(self, (dst_ip, seg.dport), (src_ip, seg.sport), random.getrandbits(32))
        conn.state = SYN_RCVD
        conn._listener = listener
        conn.rcv_nxt = _seq(seg.seq + 1)
        conn.snd_wnd = seg.window
        conn._agree(seg)
        listener._pending += 1
        self._add(conn)
        conn._timed = (_seq(conn.iss + 1), time.monotonic())
        conn._emit(SYN | ACK, conn.iss)
        conn.snd_nxt = conn.snd_max = _seq(conn.iss + 1)
        conn._arm()

    def _accepted(self, conn: TcpSocket) -> None:
        listener = conn._listener
        if listener is None:
            return
        conn._listener = None
        listener._pending -= 1
        if listener.closed:
            conn._emit(RST | ACK, conn.snd_nxt)
            conn._fail(ConnectionAbortedError("the listener closed"))
            return
        listener._queue.append(conn)
        listener._cond.notify_all()

    def _reset_for(self, local_ip: str, remote_ip: str, seg: Segment) -> None:
        """RFC 793 "Reset Generation" for a segment that belongs to no connection."""
        if seg.flags & RST:
            return
        if seg.flags & ACK:
            reply = Segment(seg.dport, seg.sport, seg.ack, 0, RST, 0)
        else:
            reply = Segment(seg.dport, seg.sport, 0, _seq(seg.seq + seg.length), RST | ACK, 0)
        self.counters["resets_sent"] += 1
        self._out.append((local_ip, remote_ip, reply))

    def _add(self, conn: TcpSocket) -> None:
        self._conns[(conn.local[1], *conn.remote)] = conn
        if self._timer is None:
            self._timer = threading.Thread(target=self._run_timer, name=f"tcp-{self.stack.name}",
                                           daemon=True)
            self._timer.start()

    def _remove(self, conn: TcpSocket) -> None:
        key = (conn.local[1], *conn.remote)
        if self._conns.get(key) is conn:
            del self._conns[key]
        listener = conn._listener
        if listener is not None:
            listener._pending -= 1
            conn._listener = None
        conn._cond.notify_all()

    def connections(self) -> list[TcpSocket]:
        with self._lock:
            return list(self._conns.values())

    def _run_timer(self) -> None:
        while True:
            time.sleep(TICK)
            with self._lock:
                if not self._conns:
                    self._timer = None
                    return
                now = time.monotonic()
                for conn in list(self._conns.values()):
                    conn._on_tick(now)
            self._flush()

    def _flush(self) -> None:
        """Send queued segments in order, outside the layer lock. One thread drains at a time; a
        flush that finds another draining (on any thread, or this one re-entered through a
        synchronous `transmit`) leaves its segments to it."""
        while True:
            if not self._tx_lock.acquire(blocking=False):
                return
            try:
                while True:
                    with self._lock:
                        if not self._out:
                            break
                        out, self._out = self._out, []
                    for src_ip, dst_ip, seg in out:
                        self.counters["out"] += 1
                        try:
                            self.stack.send_ip(PROTO_TCP, dst_ip, build_segment(src_ip, dst_ip, seg))
                        except OSError:
                            pass
            finally:
                self._tx_lock.release()
            with self._lock:
                if not self._out:
                    return
