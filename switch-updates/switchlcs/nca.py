"""Just enough NCA, PFS0 and CNMT to run a content transfer: an NCA's header and rights id, and the
packaged content meta inside a Meta NCA. Layouts are switchbrew's (NCA, CNMT, NCM services) and match
pokeldn's tools/switch/xci_read.py, which reads whole containers for reverse engineering.
"""

import struct
from dataclasses import dataclass, field

from Crypto.Cipher import AES

HEADER_SIZE = 0xC00

# nn::ncm::ContentMetaType
SYSTEM_UPDATE, APPLICATION, PATCH, ADD_ON_CONTENT, DELTA = 0x03, 0x80, 0x81, 0x82, 0x83
# nn::ncm::ContentType
META, PROGRAM, DATA, CONTROL, HTML_DOCUMENT, LEGAL_INFORMATION, DELTA_FRAGMENT = range(7)
# nn::ncm::ContentInstallType
INSTALL_FULL = 0
# The NCA header's own content type (not ncm's): Program 0, Meta 1, Control 2, Manual 3, Data 4.
NCA_META = 1


@dataclass(frozen=True)
class ContentMetaKey:
    """nn::ncm::ContentMetaKey, 0x10 bytes."""
    id: int
    version: int
    type: int
    install_type: int = INSTALL_FULL

    STRUCT = struct.Struct("<QIBB2x")

    def pack(self):
        return self.STRUCT.pack(self.id, self.version, self.type, self.install_type)

    @classmethod
    def parse(cls, data):
        return cls(*cls.STRUCT.unpack_from(data))


@dataclass(frozen=True)
class PackagedContentInfo:
    """nn::ncm::PackagedContentInfo, 0x38 bytes: SHA-256 of the content, then its ContentInfo (15.0.0+:
    a 5-byte size and an attributes byte)."""
    hash: bytes
    content_id: bytes
    size: int
    type: int
    id_offset: int = 0
    attributes: int = 0

    SIZE = 0x38

    def pack(self):
        return (self.hash + self.content_id + self.size.to_bytes(5, "little")
                + bytes((self.attributes, self.type, self.id_offset)))

    @classmethod
    def parse(cls, data):
        return cls(hash=bytes(data[:0x20]), content_id=bytes(data[0x20:0x30]),
                   size=int.from_bytes(data[0x30:0x35], "little"), attributes=data[0x35],
                   type=data[0x36], id_offset=data[0x37])


@dataclass
class PackagedContentMeta:
    """A .cnmt: the header, the contents (Meta itself excluded), and the content meta infos a system
    update lists."""
    id: int
    version: int
    type: int
    required_download_system_version: int
    extended_header: bytes
    contents: list = field(default_factory=list)
    metas: list = field(default_factory=list)       # ContentMetaKey (install type Full)

    @property
    def key(self):
        return ContentMetaKey(self.id, self.version, self.type)

    @classmethod
    def parse(cls, data):
        mid, version, mtype, _platform, ext_size, n_content, n_meta, _attrs, req_dl = \
            struct.unpack_from("<QIBBHHHB3xI", data, 0)
        at = 0x20
        ext = bytes(data[at:at + ext_size])
        at += ext_size
        contents = [PackagedContentInfo.parse(data[at + i * 0x38:at + (i + 1) * 0x38])
                    for i in range(n_content)]
        at += n_content * 0x38
        metas = []
        for i in range(n_meta):
            cid, cver, ctype, _cattr = struct.unpack_from("<QIBB2x", data, at + i * 0x10)
            metas.append(ContentMetaKey(cid, cver, ctype))
        return cls(mid, version, mtype, req_dl, ext, contents, metas)


def load_keys(path):
    """A prod.keys file -> {name: bytes}. Malformed lines are skipped, as xci_read.py does."""
    keys = {}
    with open(path) as fh:
        for line in fh:
            name, sep, value = line.partition("=")
            value = value.strip()
            if sep and len(value) in (32, 64) and all(ch in "0123456789abcdefABCDEF" for ch in value):
                keys[name.strip()] = bytes.fromhex(value)
    return keys


def _gf_mul(t):
    n = int.from_bytes(t, "little") << 1
    if n >> 128:
        n = (n ^ 0x87) & ((1 << 128) - 1)
    return n.to_bytes(16, "little")


def xts_decrypt(key, data, sector_size=0x200):
    """Nintendo XTS: the tweak is the sector index BIG-endian."""
    data_ecb, tweak_ecb = AES.new(key[:16], AES.MODE_ECB), AES.new(key[16:], AES.MODE_ECB)
    out = bytearray()
    for i in range(0, len(data), sector_size):
        tweak = tweak_ecb.encrypt(struct.pack(">QQ", 0, i // sector_size))
        for j in range(i, min(i + sector_size, len(data)), 16):
            block = bytes(a ^ b for a, b in zip(data[j:j + 16], tweak))
            out += bytes(a ^ b for a, b in zip(data_ecb.decrypt(block), tweak))
            tweak = _gf_mul(tweak)
    return bytes(out)


@dataclass
class NcaHeader:
    content_type: int
    title_id: int
    keygen: int
    rights_id: bytes
    key_area: bytes
    sections: list            # (index, offset, size, fs header bytes)

    @classmethod
    def parse(cls, raw, header_key):
        clear = xts_decrypt(header_key, raw[:HEADER_SIZE])
        if clear[0x200:0x203] != b"NCA":
            raise ValueError("not an NCA (the header did not decrypt)")
        gen = max(clear[0x206], clear[0x220])
        sections = []
        for i in range(4):
            start, end = struct.unpack_from("<II", clear, 0x240 + i * 0x10)
            if end:
                sections.append((i, start * 0x200, (end - start) * 0x200,
                                 clear[0x400 + i * 0x200:0x600 + i * 0x200]))
        return cls(content_type=clear[0x205], title_id=struct.unpack_from("<Q", clear, 0x210)[0],
                   keygen=gen - 1 if gen else 0, rights_id=clear[0x230:0x240],
                   key_area=clear[0x300:0x340], sections=sections)

    @property
    def has_rights_id(self):
        return self.rights_id != bytes(16)


def body_key(header, keys, title_key=None):
    """The section key: key area slot 2 under key_area_key_application_<gen>, or for a rights-id NCA
    the decrypted title key (pass the ticket's encrypted one; titlekek_<gen> decrypts it)."""
    if header.has_rights_id:
        if title_key is None:
            raise ValueError("this NCA needs its ticket's title key")
        return AES.new(keys[f"titlekek_{header.keygen:02x}"], AES.MODE_ECB).decrypt(title_key)
    kaek = keys[f"key_area_key_application_{header.keygen:02x}"]
    return AES.new(kaek, AES.MODE_ECB).decrypt(header.key_area)[0x20:0x30]


def read_cnmt(meta_nca, keys):
    """The .cnmt inside a Meta NCA (one CTR PFS0 section, key-area crypto)."""
    header = NcaHeader.parse(meta_nca, keys["header_key"])
    if header.content_type != NCA_META:
        raise ValueError("not a Meta NCA")
    _i, off, size, fs = header.sections[0]
    if fs[4] != 3:
        raise ValueError(f"Meta NCA section crypt type {fs[4]}, expected CTR")
    ctr = fs[0x140:0x148][::-1] + struct.pack(">Q", off >> 4)
    body = AES.new(body_key(header, keys), AES.MODE_CTR, nonce=b"", initial_value=ctr) \
        .decrypt(meta_nca[off:off + size])
    pfs_off = struct.unpack_from("<Q", fs, 0x8 + 0x38)[0]
    count, str_size = struct.unpack_from("<II", body, pfs_off + 4)
    table = pfs_off + 0x10
    data = table + count * 0x18 + str_size
    for i in range(count):
        foff, fsize, name_off = struct.unpack_from("<QQI", body, table + i * 0x18)
        names = body[table + count * 0x18:data]
        name = names[name_off:names.index(b"\0", name_off)].decode()
        if name.endswith(".cnmt"):
            return PackagedContentMeta.parse(body[data + foff:data + foff + fsize])
    raise ValueError("no .cnmt in the Meta NCA")


def section_data(nca_bytes, header, index, key):
    """Section `index` of an in-memory NCA, decrypted (AES-CTR, crypt type 3), and the FS header's
    data region: -> (section bytes, data offset, data size). The last non-empty IVFC level for a
    RomFS, the PFS0 for a hash-type 2 section."""
    for i, off, size, fs in header.sections:
        if i == index:
            break
    else:
        raise ValueError(f"no section {index}")
    if fs[4] != 3:
        raise ValueError(f"section {index} crypt type {fs[4]}, expected CTR")
    ctr = fs[0x140:0x148][::-1] + struct.pack(">Q", off >> 4)
    body = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=ctr).decrypt(nca_bytes[off:off + size])
    if fs[3] == 3 and fs[8:0xC] == b"IVFC":
        levels = [struct.unpack_from("<QQ", fs, 0x8 + 0x10 + i * 0x18)
                  for i in range(min(struct.unpack_from("<I", fs, 0x8 + 0xC)[0], 6))]
        data_off, data_size = [lv for lv in levels if lv[1]][-1]
    else:
        data_off, data_size = struct.unpack_from("<QQ", fs, 0x8 + 0x38)
    return body, data_off, data_size


def romfs_files(romfs):
    """A RomFS image -> {path: bytes}, every file (switchbrew RomFS: a 0x50 header of ten u64, the
    directory and file tables, then the file data)."""
    header = struct.unpack_from("<10Q", romfs)
    if header[0] != 0x50:
        raise ValueError("not a RomFS (the header size is not 0x50)")
    dirs = romfs[header[3]:header[3] + header[4]]
    files = romfs[header[7]:header[7] + header[8]]
    data = header[9]
    out, stack = {}, [(0, "")]
    while stack:
        at, prefix = stack.pop()
        _parent, _sibling, child_dir, child_file = struct.unpack_from("<4I", dirs, at)
        f = child_file
        while f != 0xFFFFFFFF:
            _p, sibling, off, size, _h, name_len = struct.unpack_from("<IIQQII", files, f)
            name = files[f + 0x20:f + 0x20 + name_len].decode("utf-8", "replace")
            out[f"{prefix}/{name}"] = bytes(romfs[data + off:data + off + size])
            f = sibling
        d = child_dir
        while d != 0xFFFFFFFF:
            _p, sibling, _cd, _cf, _h, name_len = struct.unpack_from("<6I", dirs, d)
            stack.append((d, prefix + "/" + dirs[d + 0x18:d + 0x18 + name_len].decode("utf-8", "replace")))
            d = sibling
    return out


def control_data(control_nca, keys, title_key=None, language="AmericanEnglish"):
    """What ns's GetApplicationControlData returns for a game, from its Control NCA: control.nacp
    (0x4000 bytes) followed by the icon for `language` (a JPEG), as the lcs host sends in 0x04.
    `title_key` is the ticket's encrypted title key for a rights-id NCA."""
    header = NcaHeader.parse(control_nca, keys["header_key"])
    body, off, size = section_data(control_nca, header, 0, body_key(header, keys, title_key))
    files = romfs_files(body[off:off + size])
    nacp = files.get("/control.nacp")
    if nacp is None:
        raise ValueError("no control.nacp in the Control NCA")
    icon = files.get(f"/icon_{language}.dat") or next(
        (v for k, v in sorted(files.items()) if k.startswith("/icon_")), b"")
    return nacp + icon
