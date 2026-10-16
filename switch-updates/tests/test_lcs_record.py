"""Recording an lcs session (lcs_match.py / tools/lcs_host.py --capture): whole 55555 messages and
55556 headers, both directions, however the bytes arrive."""

import json

from switchlcs import content, control as c, nca, record, session
from tests.test_lcs_content import KEYS, DictSource
from tests.test_lcs_session import APP, A_IP, B_IP, Thread, add_patch, app_record, guest_source, system_info
from tests.test_tcp import link  # noqa: F401  (the fixture)


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def stream(port, records, keep=None):
    sock = record.RecordingSocket(None, type("R", (), {"write": lambda self, **r: records.append(r)})(),
                                  port, "1.2.3.4")
    out = sock._streams["out"]
    if keep is not None:
        out.keep = keep
    return out


def test_control_messages_split_however_the_bytes_arrive():
    records = []
    out = stream(c.PORT, records)
    data = c.accept(2) + c.pack(c.START_SHARE) + c.share_completed(bytes(c.COMPLETED_INFO_SIZE))
    for i in range(0, len(data), 3):
        out.feed(data[i:i + 3])
    assert [(r["name"], r["size"]) for r in records] == [("ACCEPT", 4), ("START_SHARE", 0),
                                                          ("SHARE_COMPLETED", c.COMPLETED_INFO_SIZE)]
    assert records[0]["hex"] == "00000002" and records[0]["dir"] == "out" and "kept" not in records[0]


def test_content_data_streams_past_with_only_its_start_kept():
    records = []
    out = stream(content.PORT, records)
    body = bytes(range(256)) * 4000
    out.feed(content.HEADER.pack(content.MAGIC_REPLY, content.CONTENT, 0, len(body)) + body[:5000])
    out.feed(body[5000:] + content.HEADER.pack(content.MAGIC_REQUEST, content.EXIT, 0, 0))
    assert [(r["magic"], r["name"], r["size"]) for r in records] == [("LDRs", "CONTENT", len(body)),
                                                                     ("LDRq", "EXIT", 0)]
    assert records[0]["hex"] == body[:record.CONTENT_KEEP].hex() and records[0]["kept"] == record.CONTENT_KEEP


def test_bytes_that_are_not_the_protocol_are_reported_once():
    records = []
    out = stream(c.PORT, records)
    out.feed(b"GET / HTTP/1.1\r\n\r\n")
    out.feed(b"more")
    assert len(records) == 1 and "bad header" in records[0]["error"]


def test_a_recorded_session(link, tmp_path):                 # noqa: F811
    """The host's side of a system update pull and a game update push, recorded."""
    lk = link(delay=0.001)
    gsrc, offers, _sys_data = guest_source()
    hsrc = DictSource()
    v2, _info = add_patch(hsrc, 0x20000)
    guest = session.Guest(lk.b.tcp, B_IP, c.Join(system_info(), "Switch", [app_record(0x10000)]),
                          source=gsrc, offers=offers, outdir=str(tmp_path / "guest"), keys=KEYS)
    path = tmp_path / "captures" / "lcs.jsonl"
    network, recorder = record.recording(lk.a.tcp, str(path))
    host = session.Host(network, A_IP, "pokeldn", system_info(), [app_record(0x20000)])
    listener = network.listen(c.PORT)
    listener.settimeout(10)
    g = Thread(lambda: guest.run(A_IP))
    g.start()
    conn, addr = listener.accept()
    listener.close()
    member = host.admit(conn, addr[0])
    host.start_share()
    host.pull_system_update(member, str(tmp_path / "su"), KEYS)
    host.push_application(member, APP, [v2], hsrc)
    host.finish()
    g.finish()
    conn.close()
    recorder.close()

    got = lines(path)
    control = [(r["dir"], r["name"]) for r in got if r["port"] == c.PORT and "name" in r]
    assert control == [("in", "JOIN"), ("out", "ACCEPT"), ("out", "SNAPSHOT"), ("out", "START_SHARE"),
                       ("in", "JOIN_REFRESH"), ("out", "SEND_SYSTEM_UPDATE"), ("in", "SEND_SYSTEM_UPDATE_REPLY"),
                       ("out", "APPLICATION_SETUP"), ("in", "APPLICATION_SETUP_RESULT"),
                       ("out", "RECEIVE_APPLICATION"), ("in", "RECEIVE_APPLICATION_RESULT"),
                       ("in", "JOIN_REFRESH"), ("out", "SHARE_COMPLETED")]
    join = next(r for r in got if r.get("name") == "JOIN")
    assert c.Join.parse(bytes.fromhex(join["hex"])).name == "Switch" and join["peer"] == B_IP
    events = [(r["port"], r["event"]) for r in got if "event" in r]
    assert events == [(c.PORT, "accept"), (content.PORT, "connect"), (content.PORT, "close"),
                      (content.PORT, "accept"), (content.PORT, "close"), (c.PORT, "close")]
    pulled = [r["name"] for r in got if r["port"] == content.PORT and r.get("dir") == "out"][:2]
    assert pulled == ["META_INFO", "CONTENT"]
    first = next(r for r in got if r["port"] == content.PORT and r.get("name") == "META_INFO")
    assert nca.ContentMetaKey.parse(bytes.fromhex(first["hex"])).type == nca.SYSTEM_UPDATE


def test_no_path_records_nothing(tmp_path):
    network = object()
    assert record.recording(network, "") == (network, None)
    recorder = record.Recorder(tmp_path / "x.jsonl")
    recorder.close()
    recorder.write(event="close")                     # a connection closed after the run: dropped
