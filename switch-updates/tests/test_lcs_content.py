"""The lcs TCP 55556 content transfer, sender and receiver, over a socket pair. NCAs are built here under
random test keys (a Meta NCA's header, key area and CTR PFS0 section), so no console keys are needed."""

import hashlib
import os
import socket
import struct
import threading

import pytest
from Crypto.Cipher import AES

from switchlcs import content, nca

KEYS = {"header_key": os.urandom(32), "key_area_key_application_00": os.urandom(16),
        "titlekek_00": os.urandom(16)}


def _xts_encrypt(key, data, sector_size=0x200):
    data_ecb, tweak_ecb = AES.new(key[:16], AES.MODE_ECB), AES.new(key[16:], AES.MODE_ECB)
    out = bytearray()
    for i in range(0, len(data), sector_size):
        tweak = tweak_ecb.encrypt(struct.pack(">QQ", 0, i // sector_size))
        for j in range(i, i + sector_size, 16):
            block = bytes(a ^ b for a, b in zip(data[j:j + 16], tweak))
            out += bytes(a ^ b for a, b in zip(data_ecb.encrypt(block), tweak))
            tweak = nca._gf_mul(tweak)
    return bytes(out)


def build_nca(content_type, title_id, body=b"", rights_id=bytes(16), pfs_files=None, romfs=None):
    """An NCA3: header under KEYS, one CTR section. With `pfs_files`, the section is a PFS0 of them;
    with `romfs` (an image), an IVFC section whose one level is it."""
    if romfs is not None:
        body = romfs
    elif pfs_files is not None:
        names = b"".join(n.encode() + b"\0" for n, _d in pfs_files)
        table, at, name_at = b"", 0, 0
        for n, d in pfs_files:
            table += struct.pack("<QQII", at, len(d), name_at, 0)
            at += len(d)
            name_at += len(n) + 1
        body = (b"PFS0" + struct.pack("<III", len(pfs_files), len(names), 0) + table + names
                + b"".join(d for _n, d in pfs_files))
    body += bytes(-len(body) % 0x200)
    clear = bytearray(nca.HEADER_SIZE)
    clear[0x200:0x204] = b"NCA3"
    clear[0x205] = content_type
    struct.pack_into("<QQ", clear, 0x208, nca.HEADER_SIZE + len(body), title_id)
    clear[0x230:0x240] = rights_id
    struct.pack_into("<II", clear, 0x240, 6, 6 + len(body) // 0x200)
    section_key = os.urandom(16)
    clear[0x300:0x340] = AES.new(KEYS["key_area_key_application_00"], AES.MODE_ECB).encrypt(
        bytes(0x20) + section_key + bytes(0x10))
    fs = bytearray(0x200)
    fs[2], fs[3], fs[4] = 1, 2, 3
    struct.pack_into("<QQ", fs, 0x8 + 0x38, 0, len(body))
    if romfs is not None:
        fs[2], fs[3] = 0, 3
        fs[0x8:0x18] = b"IVFC" + struct.pack("<III", 0x20000, 0, 1)
        struct.pack_into("<QQ", fs, 0x18, 0, len(romfs))
    fs[0x140:0x148] = os.urandom(8)
    clear[0x400:0x600] = fs
    ctr = bytes(fs[0x140:0x148])[::-1] + struct.pack(">Q", nca.HEADER_SIZE >> 4)
    enc = AES.new(section_key, AES.MODE_CTR, nonce=b"", initial_value=ctr).encrypt(body)
    return _xts_encrypt(KEYS["header_key"], bytes(clear)) + enc


def build_cnmt(key, contents, metas=(), extended=bytes(0x10)):
    head = struct.pack("<QIBBHHHB3xI4x", key.id, key.version, key.type, 0, len(extended), len(contents),
                       len(metas), 0, 0)
    out = head + extended + b"".join(c.pack() for c in contents)
    out += b"".join(struct.pack("<QIBB2x", m.id, m.version, m.type, 0) for m in metas)
    return out + bytes(0x20)


def info_for(raw, ctype):
    digest = hashlib.sha256(raw).digest()
    return nca.PackagedContentInfo(hash=digest, content_id=digest[:16], size=len(raw), type=ctype)


class DictSource(content.Source):
    def __init__(self):
        self.metas, self.blobs, self.tickets = {}, {}, {}

    def add_meta(self, key, contents, metas=()):
        meta_nca = build_nca(nca.NCA_META, key.id, pfs_files=[("x.cnmt", build_cnmt(key, contents, metas))])
        info = info_for(meta_nca, nca.META)
        self.metas[key], self.blobs[info.content_id] = info, meta_nca
        return info

    def add_content(self, raw, ctype):
        info = info_for(raw, ctype)
        self.blobs[info.content_id] = raw
        return info

    def meta_info(self, key):
        if key not in self.metas:
            raise LookupError(key)
        return self.metas[key]

    def content_size(self, content_id):
        return len(self.blobs[content_id])

    def read_content(self, content_id, offset, size):
        return self.blobs[content_id][offset:offset + size]

    def ticket(self, rights_id):
        return self.tickets[rights_id]


def run(source, key, tmp_path, listing=None):
    """receive() against serve() on a socket pair. A sender that fails closes its end, as nim's does."""
    a, b = socket.socketpair()
    a.settimeout(10)
    b.settimeout(10)
    out = {}

    def sender():
        try:
            out["stats"] = content.serve(a, source)
        except Exception as e:                           # noqa: BLE001
            out["error"] = e
            a.shutdown(socket.SHUT_RDWR)

    t = threading.Thread(target=sender)
    t.start()
    try:
        paths = content.receive(b, key, str(tmp_path), KEYS, listing=listing)
    finally:
        b.close()
        t.join(10)
        a.close()
    return paths, out["stats"]


def test_header_layout():
    raw = content.HEADER.pack(content.MAGIC_REQUEST, content.CONTENT, 0, 0x18)
    assert raw == bytes.fromhex("4c445271" "02" "00" "0000" "1800000000000000")
    assert raw[:4] == b"LDRq"
    assert content.HEADER.pack(content.MAGIC_REPLY, 1, 0, 0)[:4] == b"LDRs"


def test_patch_transfer(tmp_path):
    src = DictSource()
    rights = struct.pack(">Q", 0x0100000000001800) + bytes(7) + b"\x00"
    program = build_nca(0, 0x0100000000001000, body=os.urandom(0x3000), rights_id=rights)
    control = build_nca(2, 0x0100000000001000, body=b"control")
    delta = nca.PackagedContentInfo(hash=bytes(32), content_id=bytes(range(16)), size=10,
                                    type=nca.DELTA_FRAGMENT)
    infos = [src.add_content(program, nca.PROGRAM), src.add_content(control, nca.CONTROL), delta]
    key = nca.ContentMetaKey(0x0100000000001800, 0x10000, nca.PATCH)
    meta = src.add_meta(key, infos)
    src.tickets[rights] = (b"ticket", b"certificate chain")
    paths, stats = run(src, key, tmp_path)

    names = sorted(os.path.basename(p) for p in paths)
    assert names == sorted([meta.content_id.hex() + ".cnmt.nca", infos[0].content_id.hex() + ".nca",
                            infos[1].content_id.hex() + ".nca", rights.hex() + ".tik",
                            rights.hex() + ".cert"])
    assert (tmp_path / (infos[0].content_id.hex() + ".nca")).read_bytes() == program
    assert (tmp_path / (rights.hex() + ".tik")).read_bytes() == b"ticket"
    ids = [m for m, _d in stats.requests]
    assert ids[:3] == [content.META_INFO, content.CONTENT, content.TOTAL_SIZE]
    assert content.TICKET in ids and ids[-1] == content.EXIT
    assert stats.total_size == len(program) + len(control)       # the delta fragment is skipped


def test_system_update_transfer(tmp_path):
    src = DictSource()
    sub_key = nca.ContentMetaKey(0x0100000000000809, 0x50500064, 0x02)
    data = src.add_content(build_nca(4, sub_key.id, body=b"system data"), nca.DATA)
    src.add_meta(sub_key, [data])
    top = nca.ContentMetaKey(0x0100000000000816, 0x50500064, nca.SYSTEM_UPDATE)
    src.add_meta(top, [], [sub_key])
    listed = []
    paths, stats = run(src, top, tmp_path, listing=lambda done, total: listed.append((done, total)))
    assert len(paths) == 3
    assert listed == [(1, 2), (2, 2)]      # each content meta's Meta NCA, read before any content
    flags = [d[1] for m, d in stats.requests if m == content.CONTENT]
    assert flags == [1, 0, 0]              # only the system update's own Meta is uncounted


def test_sender_refuses_an_unknown_meta(tmp_path):
    src = DictSource()
    with pytest.raises(ConnectionError):
        run(src, nca.ContentMetaKey(1, 0, nca.PATCH), tmp_path)


def test_bad_hash_is_caught(tmp_path):
    src = DictSource()
    raw = build_nca(2, 1, body=b"x")
    info = src.add_content(raw, nca.CONTROL)
    src.blobs[info.content_id] = raw[:-1] + bytes([raw[-1] ^ 1])
    key = nca.ContentMetaKey(1, 1, nca.PATCH)
    src.add_meta(key, [info])
    with pytest.raises(content.ProtocolError, match="SHA-256"):
        run(src, key, tmp_path)


def test_receiver_checks_reply_ids():
    a, b = socket.socketpair()
    try:
        content.send_header(a, content.MAGIC_REPLY, content.CONTENT, 0)
        with pytest.raises(content.ProtocolError, match="reply id"):
            content.set_total_size(b, 5)
        a.sendall(content.HEADER.pack(0x12345678, 0, 0, 0))
        with pytest.raises(content.ProtocolError, match="magic"):
            content.recv_header(b)
    finally:
        a.close()
        b.close()


def test_read_cnmt_round_trip():
    key = nca.ContentMetaKey(0x0100000000001800, 0x20000, nca.PATCH)
    info = nca.PackagedContentInfo(hash=os.urandom(32), content_id=os.urandom(16), size=0x123456789,
                                   type=nca.PROGRAM)
    meta = build_nca(nca.NCA_META, key.id, pfs_files=[("a.cnmt", build_cnmt(key, [info]))])
    cnmt = nca.read_cnmt(meta, KEYS)
    assert cnmt.key == key and cnmt.contents == [info]
    assert nca.PackagedContentInfo.parse(info.pack()) == info


def build_romfs(files):
    """A one-directory RomFS holding `files` ({name: bytes}), laid out as switchbrew describes."""
    dirs = struct.pack("<6I", 0, 0xFFFFFFFF, 0xFFFFFFFF, 0 if files else 0xFFFFFFFF, 0xFFFFFFFF, 0)
    entries, data = b"", b""
    names = list(files)
    for i, name in enumerate(names):
        raw = name.encode()
        size = 0x20 + (len(raw) + 3) // 4 * 4
        sibling = len(entries) + size if i + 1 < len(names) else 0xFFFFFFFF
        entries += struct.pack("<IIQQII", 0, sibling, len(data), len(files[name]), 0xFFFFFFFF, len(raw))
        entries += raw.ljust(size - 0x20, b"\0")
        data += files[name].ljust((len(files[name]) + 15) // 16 * 16, b"\0")
    dir_at = 0x50
    file_at = dir_at + len(dirs)
    data_at = file_at + len(entries)
    header = struct.pack("<10Q", 0x50, dir_at, 0, dir_at, len(dirs), file_at, 0, file_at, len(entries), data_at)
    return header + dirs + entries + data


def test_romfs_files():
    files = {"control.nacp": bytes(range(256)) * 64, "icon_AmericanEnglish.dat": b"jpeg", "x": b""}
    assert nca.romfs_files(build_romfs(files)) == {"/" + k: v for k, v in files.items()}
    with pytest.raises(ValueError, match="RomFS"):
        nca.romfs_files(bytes(0x50))
