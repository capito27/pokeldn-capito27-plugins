"""lcs TCP 55555 framing and messages. The hex vectors are what qlaunch 20.5.0's own builders sent
under unicorn (tools/lcs_qlaunch_check.py, which compares every message)."""

import socket
import struct

import pytest

from switchlcs import control as c, delivery, nca

IP, NODE, APP = 0xA9FE0102, 0xA9FE0103, 0x01008F6008C5E000
KEYS = [nca.ContentMetaKey(0x01008F6008C5E800, 0x10000 * (i + 1), nca.PATCH) for i in range(3)]
KEY_BYTES = "00e8c508608f0001000001008100000000e8c508608f0001000002008100000000e8c508608f00010000030081000000"


def system_info():
    return delivery.SystemDeliveryInfo(system_update_version=delivery.system_version(20, 5, 0, 100)).pack()


def test_header():
    assert c.pack(c.JOIN, b"xy") == bytes.fromhex("10050000" "00000002") + b"xy"
    a, b = socket.socketpair()
    try:
        a.sendall(c.byte_message(c.REJECT, 3) + bytes.fromhex("11070000 00000000"))
        assert c.read(b) == (c.REJECT, b"\x03\x00\x00\x00")
        with pytest.raises(c.ProtocolError, match="bad header"):
            c.read(b)
        a.sendall(struct.pack(">BBHI", 0x10, 5, 0, c.MAX_PAYLOAD + 1))
        with pytest.raises(c.ProtocolError, match="bytes"):
            c.read(b)
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("message,qlaunch", [
    (c.byte_message(c.REJECT, 9), "100800000000000409000000"),
    (c.accept(0x12345678), "100700000000000412345678"),
    (c.application_setup(APP), "101200000000000c0400000001008f6008c5e000"),
    (c.result(c.APPLICATION_SETUP_RESULT, 6), "10130000000000080600000000000000"),
    (c.SystemTransfer(1, IP, NODE, flag=1).pack(c.SEND_SYSTEM_UPDATE),
     "100e00000000011001140100a9fe0102a9fe010300000000" + "00" * 0x100),
    (c.ApplicationTransfer(1, IP, NODE, APP, flag=1).pack(c.SEND_APPLICATION),
     "10140000000000180104140100000000a9fe0102a9fe010301008f6008c5e000"),
    (c.application_keys(KEYS), "10150000000000380203000000000000" + KEY_BYTES),
    (c.ApplicationTransfer(2, IP, NODE, APP, KEYS, flag=1).pack(c.RECEIVE_APPLICATION),
     "10160000000000480204140103000000a9fe0102a9fe010301008f6008c5e000" + KEY_BYTES),
])
def test_matches_qlaunch(message, qlaunch):
    assert message.hex() == qlaunch


def test_join_layout():
    """0x188 bytes before the first application record, the system info at +0x88."""
    sdi = system_info()
    app = delivery.ApplicationDeliveryInfo(application_id=APP, application_version=786432).pack()
    info = struct.pack("<Q", APP).ljust(0x80, b"\0")
    join = c.Join(sdi, "Player", [c.AppRecord(info, [app])])
    raw = join.pack()
    assert struct.unpack_from(">I", raw, 4)[0] == 0x188 + 0x88 + 0x100 == len(raw) - 8
    p = raw[8:]
    assert p[:3] == bytes((0x13, 1, 0)) and p[3:9] == b"Player" and p[3 + 0x80] == 0
    assert p[0x88:0x188] == sdi
    assert p[0x188] == 1 and p[0x189:0x190] == bytes(7) and p[0x190:0x198] == info[:8]
    assert p[0x210:] == app
    back = c.Join.parse(p)
    assert back == join and back.apps[0].application_id == APP
    assert delivery.verify_system(back.system_info) == 0
    assert delivery.verify_application(back.apps[0].delivery_infos[0]) == 0
    assert c.Join(sdi).pack(c.JOIN_REFRESH)[1] == 0x18


def test_join_rejects_bad_records():
    p = bytearray(c.Join(system_info(), apps=[c.AppRecord(bytes(0x80))]).payload())
    p[0x188] = c.MAX_DELIVERY_INFOS + 1
    with pytest.raises(c.ProtocolError, match="delivery infos"):
        c.Join.parse(bytes(p))
    with pytest.raises(c.ProtocolError, match="cut"):
        c.Join.parse(c.Join(system_info(), apps=[c.AppRecord(bytes(0x80), [bytes(0x100)])]).payload()[:-1])


def test_round_trips():
    sdi = system_info()
    snap = c.Snapshot([c.AppRecord(struct.pack("<Q", APP).ljust(0x80, b"\0"), [bytes(0x100)])],
                      [c.Node(IP, "Host"), c.Node(NODE, "Player")])
    raw = snap.payload()
    assert raw[:2] == b"\x01\x02" and len(raw) == 8 + 0x188 + 2 * 0x8C
    assert raw[-0x8C:-0x8C + 4] == struct.pack(">I", NODE) and raw[-0x81:-0x81 + 6] == b"Player"
    assert c.Snapshot.parse(raw) == snap
    st = c.SystemTransfer(2, IP, NODE, sdi, flag=1)
    assert c.SystemTransfer.parse(st.payload()) == st
    reply = c.TransferReply(2, sdi)
    assert c.TransferReply.parse(reply.pack(c.SEND_SYSTEM_UPDATE_REPLY)[8:]) == reply
    at = c.ApplicationTransfer(2, IP, NODE, APP, KEYS)
    assert c.ApplicationTransfer.parse(at.payload()) == at
    assert c.parse_application_keys(c.application_keys(KEYS)[8:]) == KEYS
    assert c.parse_application_setup(c.application_setup(APP)[8:]) == APP
    assert c.share_completed(b"x")[8:] == b"x" + bytes(0x3F)
    with pytest.raises(ValueError):
        c.ApplicationTransfer(2, IP, NODE, APP, KEYS * 7).payload()


def nacp(name="Pokemon Violet", publisher="Nintendo", display="3.0.1"):
    raw = bytearray(c.NACP_SIZE)
    for i in (0, 2):                        # American English and Japanese
        raw[i * 0x300:i * 0x300 + len(name)] = name.encode()
        raw[i * 0x300 + 0x200:i * 0x300 + 0x200 + len(publisher)] = publisher.encode()
    raw[0x3060:0x3060 + len(display)] = display.encode()
    return bytes(raw)


def test_control_query_and_reply():
    assert c.control_query(APP) == bytes.fromhex("1003000000000008" "01008f6008c5e000")
    assert c.control_query(APP, data=False)[1] == c.CONTROL_SIZE_QUERY
    assert c.parse_control_query(c.control_query(APP)[8:]) == APP
    # qlaunch's 0x02 for 0x4f02 bytes of control data (tools/lcs_qlaunch_check.py).
    assert c.ControlReply(APP, 0x4F02).pack(c.CONTROL_SIZE) == bytes.fromhex(
        "100200000000000c" "01008f6008c5e000" "00004f02")
    data = nacp() + b"\xff\xd8icon"
    raw = c.ControlReply(APP, len(data), data).pack()
    assert raw[:8] == bytes.fromhex("10040000") + struct.pack(">I", 0xC + len(data))
    reply = c.ControlReply.parse(raw[8:])
    assert (reply.application_id, reply.size, reply.data) == (APP, len(data), data)
    control = c.ApplicationControl.parse(reply.data)
    assert (control.name, control.publisher, control.display_version) == ("Pokemon Violet", "Nintendo", "3.0.1")
    assert list(control.titles) == ["AmericanEnglish", "Japanese"] and control.icon == b"\xff\xd8icon"
    with pytest.raises(c.ProtocolError):
        c.ApplicationControl.parse(bytes(0x100))
