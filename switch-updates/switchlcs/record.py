"""Record an lcs session's messages: every 55555 control message whole, and every 55556 header with
the start of its data, both directions, one JSON line each (lcs_match.py and tools/lcs_host.py
--capture). docs/lcs.md "Recording a session".

`RecordingNetwork` wraps a session network (switchlcs.session); the sockets it hands out pass every
byte through unchanged and feed a parser per direction, so a transfer's content streams past
without being kept.
"""

import json
import os
import threading
import time

from switchlcs import content, control as c

CONTROL_NAMES = {getattr(c, name): name for name in (
    "CONTROL_SIZE_QUERY", "CONTROL_SIZE", "CONTROL_QUERY", "CONTROL_DATA", "JOIN", "LEAVE", "ACCEPT", "REJECT",
    "SNAPSHOT", "START_SHARE", "NODE_INFO", "SUSPEND", "SUSPEND_REPLY", "SEND_SYSTEM_UPDATE",
    "SEND_SYSTEM_UPDATE_REPLY", "RECEIVE_SYSTEM_UPDATE", "RECEIVE_SYSTEM_UPDATE_REPLY", "APPLICATION_SETUP",
    "APPLICATION_SETUP_RESULT", "SEND_APPLICATION", "SEND_APPLICATION_KEYS", "RECEIVE_APPLICATION",
    "RECEIVE_APPLICATION_RESULT", "JOIN_REFRESH", "UNKNOWN_19", "UNKNOWN_1A", "UNKNOWN_1B", "SHARE_COMPLETED")}
CONTENT_NAMES = {content.EXIT: "EXIT", content.META_INFO: "META_INFO", content.CONTENT: "CONTENT",
                 content.TICKET: "TICKET", content.TOTAL_SIZE: "TOTAL_SIZE"}
CONTROL_KEEP = c.MAX_PAYLOAD      # every control message whole, but a 0x04's icon
CONTENT_KEEP = 0x40               # a request's body, a meta info reply; not the contents


class Recorder:
    """Writes the JSON lines to `path`; shared by every socket of a run."""

    def __init__(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.out = open(path, "w", encoding="utf-8")
        self.start = time.monotonic()
        self.lock = threading.Lock()

    def write(self, **record):
        record = {"t": round(time.monotonic() - self.start, 4), **record}
        with self.lock:
            if self.out.closed:             # a connection closed after the run's end
                return
            self.out.write(json.dumps(record) + "\n")
            self.out.flush()

    def close(self):
        with self.lock:
            self.out.close()


class _Stream:
    """Splits one direction's bytes into messages: a header of `head` bytes, then `body(header)`
    bytes of which the first `keep` are recorded."""

    def __init__(self, emit, head, body, describe, keep):
        self.emit, self.head, self.body, self.describe, self.keep = emit, head, body, describe, keep
        self.header, self.data, self.left, self.size = b"", b"", 0, 0

    def feed(self, chunk):
        chunk = memoryview(chunk)
        while chunk:
            if self.left:
                take = min(self.left, len(chunk))
                room = self.keep - len(self.data)
                if room > 0:
                    self.data += bytes(chunk[:min(room, take)])
                self.left -= take
                chunk = chunk[take:]
                if not self.left:
                    self._done()
                continue
            take = min(self.head - len(self.header), len(chunk))
            self.header += bytes(chunk[:take])
            chunk = chunk[take:]
            if len(self.header) == self.head:
                try:
                    self.size = self.left = self.body(self.header)
                except Exception as error:      # not this protocol: say so and record no more
                    self.emit(error=f"{type(error).__name__}: {error}", raw=self.header.hex())
                    self.feed = lambda chunk: None
                    return
                if not self.left:
                    self._done()

    def _done(self):
        self.emit(**self.describe(self.header), size=self.size, hex=self.data.hex(),
                  **({"kept": len(self.data)} if len(self.data) < self.size else {}))
        self.header, self.data = b"", b""


def _control_body(header):
    magic, _mtype, zero, size = c.HEADER.unpack(header)
    if magic != c.MAGIC or zero:
        raise c.ProtocolError(f"bad header {header.hex()}")
    return size


def _control_describe(header):
    mtype = header[1]
    return {"type": mtype, "name": CONTROL_NAMES.get(mtype, f"UNKNOWN_{mtype:02X}")}


def _content_body(header):
    magic, _mid, meta_size, data_size = content.HEADER.unpack(header)
    if magic not in (content.MAGIC_REQUEST, content.MAGIC_REPLY) or data_size < 0:
        raise content.ProtocolError(f"bad header {header.hex()}")
    return meta_size + data_size


def _content_describe(header):
    magic, mid, meta_size, _data_size = content.HEADER.unpack(header)
    return {"magic": "LDRq" if magic == content.MAGIC_REQUEST else "LDRs", "type": mid,
            "name": CONTENT_NAMES.get(mid, f"UNKNOWN_{mid:02X}"), **({"meta": meta_size} if meta_size else {})}


class RecordingSocket:
    """A connection whose traffic is recorded; everything else passes to the wrapped one."""

    def __init__(self, sock, recorder, port, peer):
        self._sock, self._recorder, self._port, self._peer = sock, recorder, port, peer
        self._streams = {d: self._stream(d) for d in ("out", "in")}

    def _stream(self, direction):
        def emit(**record):
            self._recorder.write(port=self._port, peer=self._peer, dir=direction, **record)
        if self._port == c.PORT:
            return _Stream(emit, c.HEADER.size, _control_body, _control_describe, CONTROL_KEEP)
        return _Stream(emit, content.HEADER.size, _content_body, _content_describe, CONTENT_KEEP)

    def sendall(self, data):
        self._sock.sendall(data)
        self._streams["out"].feed(data)

    def recv(self, n, *flags):
        data = self._sock.recv(n, *flags)
        if data:
            self._streams["in"].feed(data)
        return data

    def close(self):
        self._recorder.write(port=self._port, peer=self._peer, event="close")
        self._sock.close()

    def __getattr__(self, name):
        return getattr(self._sock, name)


class RecordingListener:
    def __init__(self, listener, recorder, port):
        self._listener, self._recorder, self._port = listener, recorder, port

    def accept(self):
        sock, addr = self._listener.accept()
        self._recorder.write(port=self._port, peer=addr[0], event="accept")
        return RecordingSocket(sock, self._recorder, self._port, addr[0]), addr

    def __getattr__(self, name):
        return getattr(self._listener, name)


class RecordingNetwork:
    """A session network (connect / listen) whose connections are recorded."""

    def __init__(self, network, recorder):
        self.network, self.recorder = network, recorder

    def connect(self, address, timeout=None):
        sock = self.network.connect(address, timeout)
        self.recorder.write(port=address[1], peer=address[0], event="connect")
        return RecordingSocket(sock, self.recorder, address[1], address[0])

    def listen(self, port):
        return RecordingListener(self.network.listen(port), self.recorder, port)

    def __getattr__(self, name):
        return getattr(self.network, name)


def recording(network, path):
    """-> (network, None) when `path` is empty, else (a RecordingNetwork, its Recorder)."""
    if not path:
        return network, None
    recorder = Recorder(path)
    return RecordingNetwork(network, recorder), recorder
