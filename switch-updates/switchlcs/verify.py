"""Whether an NSP is a game update a console takes: a Patch of the right game, newer than the console's,
whose every byte Nintendo signed. docs/lcs.md "Checking an update before offering it".

The chain runs from two Nintendo keys to every byte of the NSP:

- Each NCA header carries an RSA-2048 PSS signature over 0x200-0x400 under the fixed NCA header key.
  The signed part holds the SHA-256 of each FS header; the Meta NCA's FS header holds the master hash of
  its PFS0's hash table, whose block hashes cover the .cnmt. The .cnmt lists the SHA-256 of every
  other content, so a content whose hash matches is the one Nintendo listed.
- A content with a rights ID needs its ticket: a common ticket (one every console accepts, never tied to
  an account), signed by the XS certificate in the NSP, which CA00000003 signed. The CA's key is pinned:
  a different one is not Nintendo's.

The two keys are public. NCA_HEADER_MODULUS verifies every untouched NCA header pokeldn has seen, the
CA modulus is the one in every update ticket's certificate chain, and both verify signatures in
tests/test_lcs_verify.py's checks of real NSPs.
"""

import hashlib
import os
import struct
import zipfile
from dataclasses import dataclass, field

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss

from switchlcs import content, nca
from switchlcs.control import ApplicationControl

# The fixed key of signature key generation 0 (NCA header +0x221), the one every retail NCA uses.
NCA_HEADER_MODULUS = bytes.fromhex(
    "bfbe406cf4a780e9f07d0c99611d772f96bc4b9e58381b03abb175499f2b4d5834b005a37522be1a3f0373ac7068d116"
    "b904465eb707912f078b26def60007b2b451f80d0a5e58adebbc9ad649b964efa782b5cf6d7013b00f85f6a908aa4d67"
    "6687fa89ff7590181e6b3de98a68c92604d980ce3f5e92ce01ff063bf2c1a90cce026f16bc92420a4164cd52b6344dae"
    "c02edea4df27683cc1a060ad43f3fc86c13e6c46f77c299ffafdf0e3ce64e735f2f656566f6df1e242b08340a5c3202b"
    "cc9aaecaed4d7030a8701c70fd1363290279ead2a7af3528321c7be62f1aaa407e328c2742fe8278ec0debe6834b6d81"
    "04401a9e9a67f67229fa04f09de4f403")
CA_MODULUS = bytes.fromhex(
    "b279c9e2eee121c6eaf44ff639f88f078b4b77ed9f9560b0358281b50e55ab721115a177703c7a30fe3ae9ef1c60bc1d"
    "974676b23a68cc04b198525bc968f11de2db50e4d9e7f071e562dae2092233e9d363f61dd7c19ff3a4a91e8f6553d471"
    "dd7b84b9f1b8ce7335f0f5540563a1eab83963e09be901011f99546361287020e9cc0dab487f140d6626a1836d27111f"
    "2068de4772149151cf69c61ba60ef9d949a0f71f5499f2d39ad28c7005348293c431ffbd33f6bca60dc7195ea2bcc56d"
    "200baf6d06d09c41db8de9c720154ca4832b69c08c69cd3b073a0063602f462d338061a5ea6c915cd5623579c3eb64ce"
    "44ef586d14baaa8834019b3eebeed379")
CA_NAME = "CA00000003"
EXPONENT = 0x10001

# Signature types: in certificates big-endian, in tickets little-endian.
SIG_RSA4096_SHA256, SIG_RSA2048_SHA256, SIG_ECDSA_SHA256 = 0x10003, 0x10004, 0x10005
SIG_SIZES = {SIG_RSA4096_SHA256: 0x200, SIG_RSA2048_SHA256: 0x100, SIG_ECDSA_SHA256: 0x3C}
KEY_RSA4096, KEY_RSA2048, KEY_ECC = 0, 1, 2
KEY_SIZES = {KEY_RSA4096: 0x200 + 4 + 0x34, KEY_RSA2048: 0x100 + 4 + 0x34, KEY_ECC: 0x3C + 0x3C}
TICKET_BODY = 0x140              # after the RSA-2048 signature and its padding
TICKET_SIZE = 0x2C0
TITLE_KEY_COMMON = 0
PATCH_ID_BIT = 0x800
HASH_CHUNK = 8 << 20


class InvalidUpdate(ValueError):
    pass


class MissingKey(InvalidUpdate):
    """prod.keys lacks a key the check needs: the file may be whole."""


@dataclass(frozen=True)
class Trust:
    """The keys a signature must verify under; tests substitute their own."""
    header_moduli: dict = field(default_factory=lambda: {0: NCA_HEADER_MODULUS})   # signature key generation ->
    ca_modulus: bytes = CA_MODULUS


NINTENDO = Trust()


@dataclass
class UpdateInfo:
    path: str
    application_id: int
    patch_id: int
    version: int                   # the internal version, 0x10000 per release
    required_system_version: int
    size: int                      # bytes the transfer moves
    control: ApplicationControl    # the update's own title, publisher, display version and icon

    @property
    def display_version(self) -> str:
        return self.control.display_version


def _rsa(modulus: bytes, exponent: int = EXPONENT):
    return RSA.construct((int.from_bytes(modulus, "big"), exponent))


def nca_header(raw: bytes, keys: dict, trust: Trust | None = None, name: str = "") -> bytes:
    """The decrypted header of an NCA whose fixed-key signature verifies; InvalidUpdate otherwise."""
    if len(raw) < nca.HEADER_SIZE:
        raise InvalidUpdate(f"{name}: shorter than an NCA header")
    clear = nca.xts_decrypt(keys["header_key"], raw[:nca.HEADER_SIZE])
    if clear[0x200:0x204] != b"NCA3":
        raise InvalidUpdate(f"{name}: not an NCA3 (the header did not decrypt with these keys)")
    generation = clear[0x221]
    modulus = (trust or NINTENDO).header_moduli.get(generation)
    if modulus is None:
        raise InvalidUpdate(f"{name}: signed with header key generation {generation}, which pokeldn cannot check")
    try:
        pss.new(_rsa(modulus), salt_bytes=32).verify(SHA256.new(clear[0x200:0x400]), clear[:0x100])
    except (ValueError, TypeError):
        raise InvalidUpdate(f"{name}: Nintendo's signature on the NCA header does not verify; the file was "
                            "changed after Nintendo signed it (a converted or re-encrypted dump)") from None
    return clear


def _hashed_cnmt(raw: bytes, clear: bytes, keys: dict, name: str) -> nca.PackagedContentMeta:
    """The .cnmt of a Meta NCA, after checking the chain from its signed header to the .cnmt's bytes."""
    header = nca.NcaHeader.parse(raw, keys["header_key"])
    if header.content_type != nca.NCA_META or not header.sections:
        raise InvalidUpdate(f"{name}: not a Meta NCA")
    index, _off, _size, fs = header.sections[0]
    if hashlib.sha256(fs).digest() != clear[0x280 + index * 0x20:0x2A0 + index * 0x20]:
        raise InvalidUpdate(f"{name}: its FS header does not match the signed header")
    if fs[3] != 2:
        raise InvalidUpdate(f"{name}: the Meta section is not a hashed PFS0")
    master = fs[0x8:0x28]
    block, _two, table_off, table_size, pfs_off, pfs_size = struct.unpack_from("<IIQQQQ", fs, 0x28)
    try:
        body, _o, _s = nca.section_data(raw, header, index, nca.body_key(header, keys))
    except KeyError as error:
        raise MissingKey(f"prod.keys lacks {error.args[0]}, which {name} needs") from None
    except ValueError as error:
        raise InvalidUpdate(f"{name}: {error}") from None
    table = body[table_off:table_off + table_size]
    if not block or hashlib.sha256(table).digest() != master:
        raise InvalidUpdate(f"{name}: the PFS0 hash table does not match its master hash")
    for n, at in enumerate(range(pfs_off, pfs_off + pfs_size, block)):
        if hashlib.sha256(body[at:min(at + block, pfs_off + pfs_size)]).digest() != table[n * 0x20:n * 0x20 + 0x20]:
            raise InvalidUpdate(f"{name}: PFS0 block {n} does not match its hash")
    return nca.read_cnmt(raw, keys)


def split_certificates(blob: bytes) -> dict:
    """A .cert file -> {name: (issuer, signature type, signature, signed bytes, key type, modulus, exponent)}."""
    try:
        return _split_certificates(blob)
    except struct.error:
        raise InvalidUpdate("the certificate file is cut short") from None


def _split_certificates(blob: bytes) -> dict:
    out, at = {}, 0
    while at + 4 <= len(blob):
        sig_type = struct.unpack_from(">I", blob, at)[0]
        if sig_type not in SIG_SIZES:
            raise InvalidUpdate(f"certificate at {at:#x}: unknown signature type {sig_type:#x}")
        size = SIG_SIZES[sig_type]
        body = at + 4 + size + (-(4 + size) % 0x40)
        issuer = blob[body:body + 0x40].split(b"\0")[0].decode("ascii", "replace")
        key_type = struct.unpack_from(">I", blob, body + 0x40)[0]
        if key_type not in KEY_SIZES:
            raise InvalidUpdate(f"certificate at {at:#x}: unknown key type {key_type}")
        name = blob[body + 0x44:body + 0x84].split(b"\0")[0].decode("ascii", "replace")
        key = body + 0x88
        end = key + KEY_SIZES[key_type]
        if end > len(blob):
            raise InvalidUpdate("the certificate file is cut short")
        modulus = blob[key:key + (0x200 if key_type == KEY_RSA4096 else 0x100)] if key_type != KEY_ECC else b""
        exponent = struct.unpack_from(">I", blob, key + len(modulus))[0] if modulus else 0
        out[name] = (issuer, sig_type, blob[at + 4:at + 4 + size], blob[body:end], key_type, modulus, exponent)
        at = end
    return out


def ticket(tik: bytes, cert: bytes, rights_id: bytes, trust: Trust | None = None) -> bytes:
    """A common ticket for `rights_id` signed through CA00000003: -> its encrypted title key."""
    if len(tik) < TICKET_SIZE:
        raise InvalidUpdate("the ticket is cut short")
    if struct.unpack_from("<I", tik, 0)[0] != SIG_RSA2048_SHA256:
        raise InvalidUpdate("the ticket is not signed with RSA-2048")
    if tik[0x2A0:0x2B0] != rights_id:
        raise InvalidUpdate("the ticket is for another rights ID")
    if tik[0x281] != TITLE_KEY_COMMON:
        raise InvalidUpdate("the ticket is personalized: tied to the account that bought it, not one any console takes")
    issuer = tik[0x140:0x180].split(b"\0")[0].decode("ascii", "replace")
    chain = issuer.split("-")
    certs = split_certificates(cert)
    if len(chain) != 3 or chain[0] != "Root" or chain[1] != CA_NAME or chain[2] not in certs or CA_NAME not in certs:
        raise InvalidUpdate(f"the ticket's issuer {issuer!r} is not a certificate in the NSP under {CA_NAME}")
    ca, xs = certs[CA_NAME], certs[chain[2]]
    if ca[5] != (trust or NINTENDO).ca_modulus:
        raise InvalidUpdate(f"the NSP's {CA_NAME} is not Nintendo's")
    if xs[0] != f"Root-{CA_NAME}" or xs[1] != SIG_RSA2048_SHA256 or xs[4] != KEY_RSA2048:
        raise InvalidUpdate(f"the certificate {chain[2]} is not an RSA-2048 one signed by {CA_NAME}")
    try:
        pkcs1_15.new(_rsa(ca[5], ca[6])).verify(SHA256.new(xs[3]), xs[2])
    except (ValueError, TypeError):
        raise InvalidUpdate(f"{CA_NAME}'s signature on {chain[2]} does not verify") from None
    end = TICKET_SIZE + struct.unpack_from("<I", tik, 0x2B4)[0]
    try:
        pkcs1_15.new(_rsa(xs[5], xs[6])).verify(SHA256.new(tik[TICKET_BODY:end]), tik[4:0x104])
    except (ValueError, TypeError):
        raise InvalidUpdate(f"the ticket's signature does not verify under {chain[2]}; dump tools forge one "
                            "when they turn a personalized ticket into a common one") from None
    return tik[0x180:0x190]


@dataclass
class SystemInfo:
    path: str
    version: int                   # the SystemUpdate content meta's, 0x5C010014 for 23.0.1
    metas: int                     # content metas, the SystemUpdate's own included
    contents: int
    size: int                      # bytes of every NCA checked


def _hash_file(fh, name: str, expected: bytes, done: int, total: int, progress) -> int:
    digest = hashlib.sha256()
    while chunk := fh.read(HASH_CHUNK):
        digest.update(chunk)
        done += len(chunk)
        if progress:
            progress(done, total)
    if digest.digest() != expected:
        raise InvalidUpdate(f"{name} does not match the hash Nintendo listed for it")
    return done


class _Folder:
    """A system update's NCAs in a folder."""

    def __init__(self, path: str):
        self.path = path
        self.names = sorted(n for n in os.listdir(path) if n.endswith(".nca"))

    def size(self, name: str) -> int:
        return os.path.getsize(os.path.join(self.path, name))

    def open(self, name: str):
        return open(os.path.join(self.path, name), "rb")

    def close(self) -> None:
        pass


class _Zip:
    """A system update's NCAs in a ZIP, as the library keeps one (switchlcs.library.zip_system)."""

    def __init__(self, path: str):
        self.zip = zipfile.ZipFile(path)
        self.sizes = {i.filename: i.file_size for i in self.zip.infolist() if i.filename.endswith(".nca")}
        self.names = sorted(self.sizes)

    def size(self, name: str) -> int:
        return self.sizes[name]

    def open(self, name: str):
        return self.zip.open(name)

    def close(self) -> None:
        self.zip.close()


def check_system(source, keys: dict, progress=None, trust: Trust | None = None) -> SystemInfo:
    """Check a saved system update, a ZIP of <content id>.nca as the library keeps one or a folder of them, is
    whole and Nintendo's: InvalidUpdate says why not. Every Meta NCA's signed header covers its .cnmt (as in
    check_update); the SystemUpdate's .cnmt names every content meta, each must be there, and each of those lists
    the SHA-256 of its contents, which must all be there and match. System contents carry no rights ID, so no
    tickets."""
    source = str(source)
    try:
        files = _Folder(source) if os.path.isdir(source) else _Zip(source)
    except (OSError, zipfile.BadZipFile) as error:
        raise InvalidUpdate(f"cannot be read: {error}") from None
    try:
        return _check_system(source, files, keys, progress, trust)
    finally:
        files.close()


def _check_system(source: str, files, keys: dict, progress, trust) -> SystemInfo:
    metas = {}
    for name in (n for n in files.names if n.endswith(".cnmt.nca")):
        with files.open(name) as fh:
            raw = fh.read()
        clear = nca_header(raw, keys, trust, name)
        cnmt = _hashed_cnmt(raw, clear, keys, name)
        metas[cnmt.key] = (len(raw), cnmt)
    tops = [k for k in metas if k.type == nca.SYSTEM_UPDATE]
    if len(tops) != 1:
        raise InvalidUpdate(f"a system update holds one SystemUpdate content meta; this one holds {len(tops)}")
    top = metas[tops[0]][1]
    missing = [k for k in top.metas if nca.ContentMetaKey(k.id, k.version, k.type) not in metas]
    if missing:
        raise InvalidUpdate(f"{len(missing)} of the {len(top.metas)} content metas the system update lists are "
                            f"missing, {missing[0].id:016x} first")
    needed = {}
    for k in top.metas:
        for info in metas[nca.ContentMetaKey(k.id, k.version, k.type)][1].contents:
            if info.type != nca.DELTA_FRAGMENT:
                needed[info.content_id] = info
    total = sum(size for size, _c in metas.values()) + sum(info.size for info in needed.values())
    done = sum(size for size, _c in metas.values())
    present = set(files.names)
    for content_id, info in needed.items():
        name = content_id.hex() + ".nca"
        if name not in present:
            raise InvalidUpdate(f"{name}, listed by a content meta, is missing")
        if files.size(name) != info.size:
            raise InvalidUpdate(f"{name}: {files.size(name)} bytes, the content meta says {info.size}")
        with files.open(name) as fh:
            done = _hash_file(fh, name, info.hash, done, total, progress)
    return SystemInfo(path=source, version=top.version, metas=len(metas), contents=len(needed), size=total)


def check_update(path, keys: dict, application_id: int | None = None, installed_version: int | None = None,
                 hash_contents: bool = True, progress=None, trust: Trust | None = None) -> UpdateInfo:
    """Check the NSP at `path` is an update a console takes: InvalidUpdate says why not.

    `application_id` and `installed_version` are the console's game and its installed version; the update
    must be of that game and newer. `hash_contents` reads every content once to compare its SHA-256 with
    the .cnmt's (a 5 GB update takes seconds to a minute); `progress(done, total)` follows that."""
    path = str(path)
    try:
        entries = dict(content._pfs0_entries(path))
    except (OSError, ValueError, UnicodeDecodeError, struct.error) as error:
        raise InvalidUpdate(f"not an NSP: {error}") from None
    end = os.path.getsize(path)
    cut = [name for name, (offset, size) in entries.items() if offset + size > end]
    if cut:
        raise InvalidUpdate(f"the NSP is cut short: {cut[0]} ends past the end of the file")
    metas = [name for name in entries if name.endswith(".cnmt.nca")]
    if len(metas) != 1:
        raise InvalidUpdate(f"an update NSP holds one content meta; this one holds {len(metas)}")
    meta_name = metas[0]
    raw = content._read(path, *entries[meta_name])
    clear = nca_header(raw, keys, trust, meta_name)
    cnmt = _hashed_cnmt(raw, clear, keys, meta_name)
    if cnmt.type != nca.PATCH:
        raise InvalidUpdate(f"the content meta is not an update (type {cnmt.type:#x}); a base game or DLC "
                            "is not shared this way")
    base_id, required_system = struct.unpack_from("<QI", cnmt.extended_header) if len(cnmt.extended_header) >= 12 \
        else (0, 0)
    if cnmt.id != base_id | PATCH_ID_BIT or struct.unpack_from("<Q", clear, 0x210)[0] != cnmt.id:
        raise InvalidUpdate(f"update ID {cnmt.id:016x} does not belong to game {base_id:016x}")
    if application_id is not None and base_id != application_id:
        raise InvalidUpdate(f"this is an update of {base_id:016x}; the console's game is {application_id:016x}")
    if installed_version is not None and cnmt.version <= installed_version:
        raise InvalidUpdate(f"version {cnmt.version} is not newer than the console's {installed_version}")
    needed = [info for info in cnmt.contents if info.type != nca.DELTA_FRAGMENT]
    title_keys, total = {}, len(raw) + sum(info.size for info in needed)
    for info in needed:
        name = info.content_id.hex() + ".nca"
        if name not in entries:
            compressed = info.content_id.hex() + ".ncz"
            raise InvalidUpdate(f"{compressed}: compressed (NCZ); decompress it to an NSP first" if compressed in entries
                                else f"{name}, listed by the content meta, is missing")
        offset, size = entries[name]
        if size != info.size:
            raise InvalidUpdate(f"{name}: {size} bytes, the content meta says {info.size}")
        head = nca_header(content._read(path, offset, nca.HEADER_SIZE), keys, trust, name)
        # An update's contents carry the game's ID; only its Meta NCA carries the update's.
        if struct.unpack_from("<Q", head, 0x210)[0] not in (base_id, cnmt.id):
            raise InvalidUpdate(f"{name}: belongs to {struct.unpack_from('<Q', head, 0x210)[0]:016x}, not this game")
        rights_id = head[0x230:0x240]
        if rights_id != bytes(16) and rights_id not in title_keys:
            rid = rights_id.hex()
            if rid + ".tik" not in entries or rid + ".cert" not in entries:
                raise InvalidUpdate(f"{name} needs the ticket {rid}.tik and its {rid}.cert, which the NSP lacks")
            title_keys[rights_id] = ticket(content._read(path, *entries[rid + ".tik"]),
                                           content._read(path, *entries[rid + ".cert"]), rights_id, trust)
    if hash_contents:
        done = len(raw)
        for info in needed:
            offset, size = entries[info.content_id.hex() + ".nca"]
            digest = hashlib.sha256()
            with open(path, "rb") as fh:
                fh.seek(offset)
                left = size
                while left:
                    chunk = fh.read(min(HASH_CHUNK, left))
                    if not chunk:
                        raise InvalidUpdate(f"{info.content_id.hex()}.nca is cut short")
                    digest.update(chunk)
                    left -= len(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, total)
            if digest.digest() != info.hash:
                raise InvalidUpdate(f"{info.content_id.hex()}.nca does not match the hash Nintendo listed for it")
    try:
        _app, data = content.nsp_control_data(path, keys)
        control = ApplicationControl.parse(data)
    except KeyError as error:
        raise MissingKey(f"prod.keys lacks {error.args[0]}, which its Control NCA needs") from None
    except ValueError as error:
        raise InvalidUpdate(f"its Control NCA does not open with the ticket's title key: {error}") from None
    return UpdateInfo(path=path, application_id=base_id, patch_id=cnmt.id, version=cnmt.version,
                      required_system_version=required_system, size=total, control=control)
