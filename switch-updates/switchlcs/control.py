"""The lcs TCP 55555 control channel: framing and every message qlaunch 20.5.0 builds.
docs/lcs.md "The control channel — TCP 55555".

Every message is an 8-byte header {u8 0x10, u8 type, u16 0, BE u32 payload length} and the payload.
Integers qlaunch writes itself are big-endian; `ns` structures (delivery infos, the application info
block, content-meta keys) travel as their raw little-endian bytes. The layouts are the output of
qlaunch's own builders run under unicorn (tools/lcs_qlaunch_check.py compares them byte for
byte).
"""

import struct
from dataclasses import dataclass, field

from switchlcs import nca

PORT = 55555
CONTENT_PORT = 55556             # fixed: the transfer commands carry only the peer's IP
MAGIC = 0x10
HEADER = struct.Struct(">BBHI")
MAX_PAYLOAD = 0x10000            # a snapshot of 8 nodes with every delivery info is under 0x9000

(CONTROL_SIZE_QUERY, CONTROL_SIZE, CONTROL_QUERY, CONTROL_DATA, JOIN, LEAVE, ACCEPT, REJECT, SNAPSHOT,
 START_SHARE, NODE_INFO, SUSPEND, SUSPEND_REPLY, SEND_SYSTEM_UPDATE, SEND_SYSTEM_UPDATE_REPLY,
 RECEIVE_SYSTEM_UPDATE, RECEIVE_SYSTEM_UPDATE_REPLY, APPLICATION_SETUP, APPLICATION_SETUP_RESULT,
 SEND_APPLICATION, SEND_APPLICATION_KEYS, RECEIVE_APPLICATION, RECEIVE_APPLICATION_RESULT,
 JOIN_REFRESH, UNKNOWN_19, UNKNOWN_1A, UNKNOWN_1B, SHARE_COMPLETED) = range(1, 0x1D)

JOIN_VERSION = 0x13
NAME_SIZE = 0x81
DELIVERY_INFO_SIZE = 0x100
APP_INFO_SIZE = 0x80
NODE_INFO_SIZE = 0x580
COMPLETED_INFO_SIZE = 0x40
MAX_DELIVERY_INFOS = 0x10        # the host refuses an application record with more (0x42dc20)
CONTROL_DATA_SIZE = 0x1D000      # the host's GetApplicationControlData buffer (0x429d68)
MAX_CONTROL_DATA = 0x100000      # what a guest takes: a Switch 2 host's icon is larger (0x35D75 seen in all)
NACP_SIZE = 0x4000
MAX_KEYS = 0x12                  # ns's limit for an application transfer
TRANSFER_MARK = 0x14             # byte 1 of a system transfer command, bytes 1-2 (04 14) of an
                                 # application one: constants in every qlaunch 20.5.0 message


class ProtocolError(Exception):
    pass


def recv_exactly(sock, n):
    out = bytearray()
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part:
            raise ConnectionError(f"peer closed with {n - len(out)} of {n} bytes outstanding")
        out += part
    return bytes(out)


def pack(mtype: int, payload: bytes = b"") -> bytes:
    return HEADER.pack(MAGIC, mtype, 0, len(payload)) + payload


def send(sock, mtype: int, payload: bytes = b"") -> None:
    sock.sendall(pack(mtype, payload))


def read(sock, limit: int = MAX_PAYLOAD) -> tuple[int, bytes]:
    """-> (type, payload) of the next message."""
    magic, mtype, zero, size = HEADER.unpack(recv_exactly(sock, HEADER.size))
    if magic != MAGIC or zero:
        raise ProtocolError(f"bad header {magic:#04x} {mtype:#04x} {zero:#06x}")
    if size > limit:
        raise ProtocolError(f"message {mtype:#04x} of {size:#x} bytes")
    return mtype, recv_exactly(sock, size)


def _need(payload: bytes, size: int, what: str) -> None:
    if len(payload) < size:
        raise ProtocolError(f"{what} of {len(payload):#x} bytes, expected at least {size:#x}")


# ---- one-field messages ----

def byte_message(mtype: int, value: int) -> bytes:
    """0x06 leave, 0x08 reject (reason 1-10, mapped to 2211-xxxx by the table at 0xf23884) and
    0x0c suspend: {u8, 3 zero}."""
    return pack(mtype, bytes((value, 0, 0, 0)))


def accept(value: int) -> bytes:
    """0x07, {BE u32}."""
    return pack(ACCEPT, struct.pack(">I", value))


def result(mtype: int, value: int) -> bytes:
    """0x13 and 0x17: {u8 result, 7 zero}."""
    return pack(mtype, bytes((value,)) + bytes(7))


def application_setup(application_id: int) -> bytes:
    """0x12: {u8 4, 3 zero, BE u64 application ID}."""
    return pack(APPLICATION_SETUP, struct.pack(">B3xQ", 4, application_id))


def parse_application_setup(payload: bytes) -> int:
    _need(payload, 0xC, "application setup")
    return struct.unpack_from(">B3xQ", payload)[1]


def share_completed(info: bytes | None = None) -> bytes:
    """0x1c, empty or with a 0x40-byte block."""
    return pack(SHARE_COMPLETED, b"" if info is None else info.ljust(COMPLETED_INFO_SIZE, b"\0"))


# ---- the control-data query ----

def control_query(application_id: int, data: bool = True) -> bytes:
    """0x03 (or 0x01 when `data` is false), guest to host: {BE u64 application ID}. The host reads
    the 0x10 bytes at 0x429c78 / 0x429cf8 and answers through 0x433330."""
    return pack(CONTROL_QUERY if data else CONTROL_SIZE_QUERY, struct.pack(">Q", application_id))


def parse_control_query(payload: bytes) -> int:
    _need(payload, 8, "control query")
    return struct.unpack_from(">Q", payload)[0]


@dataclass
class ControlReply:
    """0x04 (to 0x03) and 0x02 (to 0x01), host to guest (builder 0x434730, data by 0x434870):
    {BE u64 application ID, BE u32 size}, followed in a 0x04 by `size` bytes of ns's
    GetApplicationControlData: the 0x4000-byte NACP, then the icon (a JPEG)."""
    application_id: int
    size: int
    data: bytes = b""

    def pack(self, mtype: int = CONTROL_DATA) -> bytes:
        return pack(mtype, struct.pack(">QI", self.application_id, self.size)
                    + (self.data if mtype == CONTROL_DATA else b""))

    @classmethod
    def parse(cls, payload: bytes) -> "ControlReply":
        _need(payload, 0xC, "control reply")
        app_id, size = struct.unpack_from(">QI", payload)
        return cls(app_id, size, payload[0xC:0xC + size])


NACP_LANGUAGES = ("AmericanEnglish", "BritishEnglish", "Japanese", "French", "German", "LatinAmericanSpanish",
                  "Spanish", "Italian", "Dutch", "CanadianFrench", "Portuguese", "Russian", "Korean",
                  "TraditionalChinese", "SimplifiedChinese", "BrazilianPortuguese")


@dataclass
class ApplicationControl:
    """What a 0x04 tells about the game (switchbrew NACP): 16 title entries of {0x200 name, 0x100
    publisher} at 0, the display version at 0x3060, and the icon after the NACP."""
    titles: dict
    display_version: str
    icon: bytes

    @property
    def name(self) -> str:
        return next(iter(self.titles.values()), ("", ""))[0]

    @property
    def publisher(self) -> str:
        return next(iter(self.titles.values()), ("", ""))[1]

    @classmethod
    def parse(cls, data: bytes) -> "ApplicationControl":
        _need(data, NACP_SIZE, "control data")
        titles = {}
        for i, language in enumerate(NACP_LANGUAGES):
            entry = data[i * 0x300:(i + 1) * 0x300]
            name, publisher = _unname(entry[:0x200]), _unname(entry[0x200:])
            if name:
                titles[language] = (name, publisher)
        return cls(titles, _unname(data[0x3060:0x3070]), data[NACP_SIZE:])


# ---- the join and the snapshot ----

@dataclass
class AppRecord:
    """One application: `ns`'s 0x80-byte application info (its first u64 is the application ID,
    little-endian) and the ApplicationDeliveryInfos for it. Serialised as {u8 N, 7 zero, info, N x
    0x100 delivery infos} in the join, its refresh and the snapshot."""
    info: bytes
    delivery_infos: list = field(default_factory=list)

    @property
    def application_id(self) -> int:
        return struct.unpack_from("<Q", self.info)[0]

    def pack(self) -> bytes:
        if len(self.delivery_infos) > MAX_DELIVERY_INFOS:
            raise ValueError(f"{len(self.delivery_infos)} delivery infos, at most {MAX_DELIVERY_INFOS}")
        return (bytes((len(self.delivery_infos),)) + bytes(7) + self.info.ljust(APP_INFO_SIZE, b"\0")
                + b"".join(self.delivery_infos))

    @classmethod
    def parse_from(cls, payload: bytes, at: int) -> tuple["AppRecord", int]:
        if at + 0x88 > len(payload):
            raise ProtocolError("cut inside an application record")
        n = payload[at]
        if n > MAX_DELIVERY_INFOS:
            raise ProtocolError(f"application record with {n} delivery infos")
        info = payload[at + 8:at + 0x88]
        at += 0x88
        end = at + n * DELIVERY_INFO_SIZE
        if end > len(payload):
            raise ProtocolError("cut inside the delivery infos")
        return cls(info, [payload[i:i + DELIVERY_INFO_SIZE] for i in range(at, end, DELIVERY_INFO_SIZE)]), end


def _name(name: str) -> bytes:
    return name.encode()[:NAME_SIZE - 1].ljust(NAME_SIZE, b"\0")


def _unname(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


@dataclass
class Join:
    """0x05 (join) and 0x18 (join refresh), guest to host: builders 0x4349a0 / 0x434b30, host parser
    0x42da40, which accepts at most one application record."""
    system_info: bytes
    name: str = ""
    apps: list = field(default_factory=list)
    version: int = JOIN_VERSION
    flag: int = 0                   # byte 2: 0 in a join; the refresh passes its caller's value

    def payload(self) -> bytes:
        head = bytes((self.version, len(self.apps), self.flag)) + _name(self.name) + bytes(4) \
            + self.system_info
        return head + b"".join(app.pack() for app in self.apps)

    def pack(self, mtype: int = JOIN) -> bytes:
        return pack(mtype, self.payload())

    @classmethod
    def parse(cls, payload: bytes) -> "Join":
        _need(payload, 0x188, "join")
        join = cls(system_info=payload[0x88:0x188], name=_unname(payload[3:3 + NAME_SIZE]),
                   version=payload[0], flag=payload[2])
        at = 0x188
        for _ in range(payload[1]):
            app, at = AppRecord.parse_from(payload, at)
            join.apps.append(app)
        return join


@dataclass
class Node:
    """A member in a snapshot: {BE u32 id, 7 zero, 0x81-byte name} (builder 0x435250)."""
    node_id: int
    name: str = ""

    SIZE = 0x8C

    def pack(self) -> bytes:
        return struct.pack(">I", self.node_id) + bytes(7) + _name(self.name)


@dataclass
class Snapshot:
    """0x09, host to guest: {u8 application count, u8 node count (at most 8), 6 zero}, the
    application records, then the node records (sender 0x433a40)."""
    apps: list = field(default_factory=list)
    nodes: list = field(default_factory=list)

    def payload(self) -> bytes:
        return (bytes((len(self.apps), len(self.nodes))) + bytes(6) + b"".join(a.pack() for a in self.apps)
                + b"".join(n.pack() for n in self.nodes))

    def pack(self) -> bytes:
        return pack(SNAPSHOT, self.payload())

    @classmethod
    def parse(cls, payload: bytes) -> "Snapshot":
        _need(payload, 8, "snapshot")
        snap, at = cls(), 8
        for _ in range(payload[0]):
            app, at = AppRecord.parse_from(payload, at)
            snap.apps.append(app)
        for _ in range(payload[1]):
            if at + Node.SIZE > len(payload):
                raise ProtocolError("snapshot cut inside a node record")
            snap.nodes.append(Node(struct.unpack_from(">I", payload, at)[0],
                                   _unname(payload[at + 0xB:at + Node.SIZE])))
            at += Node.SIZE
        return snap


# ---- transfers ----

@dataclass
class SystemTransfer:
    """0x0e "send your system update to `peer_ip`" (kind 1, delivery info all zero) and 0x10
    "receive the system update from `peer_ip`" (kind 2, the sender's SystemDeliveryInfo), host to
    guest (builder 0x435620; guest parsers 0x4257a4 / 0x42595c). The guest hands `peer_ip` and port
    55556 to ns's RequestSendSystemUpdate / RequestReceiveSystemUpdate."""
    kind: int
    peer_ip: int
    node_id: int
    system_info: bytes = bytes(DELIVERY_INFO_SIZE)
    flag: int = 0

    def payload(self) -> bytes:
        return (struct.pack(">BBBxII4x", self.kind, TRANSFER_MARK, self.flag, self.peer_ip, self.node_id)
                + self.system_info)

    def pack(self, mtype: int) -> bytes:
        return pack(mtype, self.payload())

    @classmethod
    def parse(cls, payload: bytes) -> "SystemTransfer":
        _need(payload, 0x110, "system transfer")
        kind, _mark, flag, ip, node = struct.unpack_from(">BBBxII", payload)
        return cls(kind, ip, node, payload[0x10:0x110], flag)


@dataclass
class TransferReply:
    """0x0d (to 0x0c), 0x0f (to 0x0e, kind 2 with the guest's own SystemDeliveryInfo) and 0x11 (to
    0x10): {u8 kind, 3 zero, 0x100-byte delivery info} (builder 0x435760)."""
    kind: int
    system_info: bytes = bytes(DELIVERY_INFO_SIZE)

    def pack(self, mtype: int) -> bytes:
        return pack(mtype, bytes((self.kind, 0, 0, 0)) + self.system_info)

    @classmethod
    def parse(cls, payload: bytes) -> "TransferReply":
        _need(payload, 0x104, "transfer reply")
        return cls(payload[0], payload[4:0x104])


@dataclass
class ApplicationTransfer:
    """0x14 "send `application_id` to `peer_ip`" and 0x16 "receive these content metas from
    `peer_ip`", host to guest (builder 0x435990; guest parser 0x425fb0 for 0x16): {u8 kind, 04 14,
    u8 flag, u8 key count, 3 zero, BE u32 peer IP, BE u32 node ID, BE u64 application ID}, then the
    keys (0x10 bytes each, little-endian; 0x16 only)."""
    kind: int
    peer_ip: int
    node_id: int
    application_id: int
    keys: list = field(default_factory=list)
    flag: int = 0

    def payload(self) -> bytes:
        if len(self.keys) > MAX_KEYS:
            raise ValueError(f"{len(self.keys)} keys, at most {MAX_KEYS}")
        return (struct.pack(">BBBBB3xIIQ", self.kind, 4, TRANSFER_MARK, self.flag, len(self.keys),
                            self.peer_ip, self.node_id, self.application_id)
                + b"".join(k.pack() for k in self.keys))

    def pack(self, mtype: int) -> bytes:
        return pack(mtype, self.payload())

    @classmethod
    def parse(cls, payload: bytes) -> "ApplicationTransfer":
        _need(payload, 0x18, "application transfer")
        kind, _a, _b, flag, count, ip, node, app = struct.unpack_from(">BBBBB3xIIQ", payload)
        _need(payload, 0x18 + count * 0x10, "application transfer")
        keys = [nca.ContentMetaKey.parse(payload[0x18 + i * 0x10:0x28 + i * 0x10]) for i in range(count)]
        return cls(kind, ip, node, app, keys, flag)


def application_keys(keys: list, kind: int = 2) -> bytes:
    """0x15, guest to host in answer to 0x14: {u8 2, u8 count, 6 zero} and the content-meta keys the
    guest can deliver (builder 0x435ad0, keys by 0x435bc0)."""
    return pack(SEND_APPLICATION_KEYS, bytes((kind, len(keys))) + bytes(6) + b"".join(k.pack() for k in keys))


def parse_application_keys(payload: bytes) -> list:
    _need(payload, 8, "application keys")
    count = payload[1]
    _need(payload, 8 + count * 0x10, "application keys")
    return [nca.ContentMetaKey.parse(payload[8 + i * 0x10:0x18 + i * 0x10]) for i in range(count)]
