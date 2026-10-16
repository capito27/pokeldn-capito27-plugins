"""The LDN side of an lcs group: the network parameters qlaunch 20.5.0 hosts it with and the 0x100-byte
advertise data that lists it to guests. docs/lcs.md "The LDN layer".

The advertise data is built by qlaunch's 0x432fd0, updated in place by the setters at 0x433158 ..
0x433190 as members come and go, published with SetAdvertiseData, and read back by a guest's
0x4331f0. tools/lcs_qlaunch_check.py runs both against this module.
"""

import struct
from dataclasses import dataclass, field

from switchlcs import control as c

LOCAL_COMMUNICATION_ID = 0x0100000000001000     # qlaunch's program ID
SCENE_ID = 1
LOCAL_COMMUNICATION_VERSION = c.JOIN_VERSION >> 4    # CreateNetwork takes the version byte's high nibble
SECURITY_MODE = 1
PASSPHRASE = bytes.fromhex("2d30885a658ab4e4d85092ed525a994c")
HOST_USER_NAME, GUEST_USER_NAME = "LcsHost", "LcsClient"
MAX_NODES = 8

SIZE = 0x100
NAME_AT = 0x17                   # the host's name, 0x81 bytes, as in the join
MEMBERS_AT = 0x98                # 8 x {u8, u8, 2 zero, BE u32}, filled by 0x433190; not read by 0x4331f0
APPS_AT = 0xD8
APP_ENTRY = struct.Struct(">B3xIQQ16s")         # 0x28
APP_MARK = 4                     # byte 0 of an application entry, as the builder writes it
STATE_OPEN = 1                   # byte 1 after the builder; 2 once a group is resumed (0x427ea4)


@dataclass
class App:
    """One application in the advertisement, from the 0x80-byte application info a join carries:
    the NACP's attribute flags (info +0x8), the size of the installed update (info +0x10) and the
    display version (info +0x18). No internal version: that is in the delivery infos of the 0x09."""
    application_id: int
    attributes: int = 0
    display_version: bytes = bytes(16)
    flags: int = APP_MARK
    update_size: int = 0         # +0x10 of the entry: the builder leaves 0; 0x433160 later sets it

    @classmethod
    def from_info(cls, info: bytes) -> "App":
        app_id, attributes, _, update_size = struct.unpack_from("<QIIQ", info)
        return cls(app_id, attributes, bytes(info[0x18:0x28]), update_size=update_size)


def application_info(application_id: int, display_version: bytes = b"", update_size: int = 0,
                     attributes: int = 0) -> bytes:
    """qlaunch's 0x80-byte application info (0x432ad0), as a join, a snapshot and the advertisement
    carry it: the ID (+0x0), the NACP's attribute flags (+0x8, NACP +0x3028), ns's EstimateRequiredSize
    of the update's content metas (+0x10, 0 with no update) and the NACP's display version (+0x18)."""
    out = bytearray(c.APP_INFO_SIZE)
    struct.pack_into("<QIIQ", out, 0, application_id, attributes, 0, update_size)
    out[0x18:0x28] = display_version[:16].ljust(16, b"\0")
    return bytes(out)


@dataclass
class Advertisement:
    name: str
    apps: list = field(default_factory=list)
    node_count: int = 1
    max_nodes: int = MAX_NODES
    version: int = c.JOIN_VERSION
    state: int = STATE_OPEN
    members: bytes = bytes(0x40)

    def pack(self) -> bytes:
        if len(self.apps) > 1:
            raise ValueError("an lcs advertisement holds at most one application")
        out = bytearray(SIZE)
        out[0:5] = bytes((self.version, self.state, self.node_count, self.max_nodes, len(self.apps)))
        name = self.name.encode()[:0x80]
        out[NAME_AT:NAME_AT + len(name)] = name
        out[MEMBERS_AT:APPS_AT] = self.members.ljust(0x40, b"\0")
        for i, app in enumerate(self.apps):
            APP_ENTRY.pack_into(out, APPS_AT + i * APP_ENTRY.size, app.flags, app.attributes,
                                app.application_id, app.update_size, app.display_version.ljust(16, b"\0"))
        return bytes(out)

    @classmethod
    def parse(cls, data: bytes) -> "Advertisement":
        """As a guest's 0x4331f0 does, including its checks."""
        if len(data) < SIZE:
            raise ValueError(f"advertise data of {len(data):#x} bytes, expected {SIZE:#x}")
        if data[4] > 1:
            raise ValueError(f"{data[4]} applications advertised, at most 1")
        if not 1 <= data[3] <= MAX_NODES or not 1 <= data[2] <= data[3]:
            raise ValueError(f"node count {data[2]} of {data[3]}")
        apps = []
        for i in range(data[4]):
            flags, attributes, app_id, update_size, display = APP_ENTRY.unpack_from(data, APPS_AT + i * APP_ENTRY.size)
            apps.append(App(app_id, attributes, display, flags, update_size))
        return cls(c._unname(data[NAME_AT:NAME_AT + 0x80]), apps, data[2], data[3], data[0], data[1],
                   bytes(data[MEMBERS_AT:APPS_AT]))
