"""The update check before pokeldn offers an NSP to a console (switchlcs.verify): an update NSP built and
signed here under test keys passes, and each kind of tampering is refused. The real Nintendo keys are checked
on real update NSPs when a dump folder and prod.keys are present."""

import glob
import hashlib
import os
import struct

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss

from switchlcs import nca, verify
from tests.test_lcs_content import KEYS, _xts_encrypt, build_romfs, info_for
from tests.test_lcs_control import nacp
from tests.test_lcs_simulate import write_nsp

APP = 0x0100187003A36000
PATCH = APP | verify.PATCH_ID_BIT
VERSION = 0x20000
BLOCK = 0x1000


@pytest.fixture(scope="module")
def signers():
    keys = {name: RSA.generate(2048) for name in ("header", "ca", "xs")}
    trust = verify.Trust(header_moduli={0: keys["header"].n.to_bytes(0x100, "big")},
                         ca_modulus=keys["ca"].n.to_bytes(0x100, "big"))
    return keys, trust


def signed_nca(signer, content_type, title_id, *, pfs_files=None, romfs=None, body=b"", title_key=None,
               rights_id=bytes(16)):
    """An NCA3 whose header is signed with `signer` and whose FS header hash is in the signed part. A PFS0
    section carries its hash table and master hash; `title_key` (the section key) is used for a rights ID."""
    if pfs_files is not None:
        names = b"".join(n.encode() + b"\0" for n, _d in pfs_files)
        table, at, name_at = b"", 0, 0
        for n, d in pfs_files:
            table += struct.pack("<QQII", at, len(d), name_at, 0)
            at += len(d)
            name_at += len(n) + 1
        pfs0 = b"PFS0" + struct.pack("<III", len(pfs_files), len(names), 0) + table + names + \
            b"".join(d for _n, d in pfs_files)
        hashes = b"".join(hashlib.sha256(pfs0[i:i + BLOCK]).digest() for i in range(0, len(pfs0), BLOCK))
        pfs_off = len(hashes) + (-len(hashes) % 0x200)
        body = hashes.ljust(pfs_off, b"\0") + pfs0
    elif romfs is not None:
        body = romfs
    body += bytes(-len(body) % 0x200)
    section_key = title_key or os.urandom(16)
    clear = bytearray(nca.HEADER_SIZE)
    clear[0x200:0x204] = b"NCA3"
    clear[0x205] = content_type
    struct.pack_into("<QQ", clear, 0x208, nca.HEADER_SIZE + len(body), title_id)
    clear[0x230:0x240] = rights_id
    struct.pack_into("<II", clear, 0x240, 6, 6 + len(body) // 0x200)
    clear[0x300:0x340] = AES.new(KEYS["key_area_key_application_00"], AES.MODE_ECB).encrypt(
        bytes(0x20) + section_key + bytes(0x10))
    fs = bytearray(0x200)
    fs[2], fs[3], fs[4] = 1, 2, 3
    if pfs_files is not None:
        fs[0x8:0x28] = hashlib.sha256(hashes).digest()
        struct.pack_into("<IIQQQQ", fs, 0x28, BLOCK, 2, 0, len(hashes), pfs_off, len(pfs0))
    else:
        fs[2], fs[3] = 0, 3
        fs[0x8:0x18] = b"IVFC" + struct.pack("<III", 0x20000, 0, 1)
        struct.pack_into("<QQ", fs, 0x18, 0, len(romfs))
    fs[0x140:0x148] = os.urandom(8)
    clear[0x400:0x600] = fs
    clear[0x280:0x2A0] = hashlib.sha256(fs).digest()
    clear[0:0x100] = pss.new(signer, salt_bytes=32).sign(SHA256.new(bytes(clear[0x200:0x400])))
    ctr = bytes(fs[0x140:0x148])[::-1] + struct.pack(">Q", nca.HEADER_SIZE >> 4)
    return _xts_encrypt(KEYS["header_key"], bytes(clear)) + \
        AES.new(section_key, AES.MODE_CTR, nonce=b"", initial_value=ctr).encrypt(body)


def certificate(signer, sig_type, issuer, name, key):
    size = verify.SIG_SIZES[sig_type]
    body = (issuer.encode().ljust(0x40, b"\0") + struct.pack(">I", verify.KEY_RSA2048) + name.encode().ljust(0x40, b"\0")
            + bytes(4) + key.n.to_bytes(0x100, "big") + struct.pack(">I", key.e) + bytes(0x34))
    sig = pkcs1_15.new(signer).sign(SHA256.new(body)) if signer else os.urandom(size)
    return struct.pack(">I", sig_type) + sig + bytes(-(4 + size) % 0x40) + body


def ticket_for(xs, rights_id, encrypted_key, key_type=verify.TITLE_KEY_COMMON):
    tik = bytearray(verify.TICKET_SIZE)
    struct.pack_into("<I", tik, 0, verify.SIG_RSA2048_SHA256)
    tik[0x140:0x180] = b"Root-CA00000003-XS00000020".ljust(0x40, b"\0")
    tik[0x180:0x190] = encrypted_key
    tik[0x280], tik[0x281] = 2, key_type
    tik[0x2A0:0x2B0] = rights_id
    struct.pack_into("<II", tik, 0x2B4, 0, verify.TICKET_SIZE)
    tik[4:0x104] = pkcs1_15.new(xs).sign(SHA256.new(bytes(tik[0x140:])))
    return bytes(tik)


def cnmt(meta_id, version, meta_type, contents, base=APP, required_system=0x20100000):
    ext = struct.pack("<QII", base, required_system, 0)
    head = struct.pack("<QIBBHHHB3xI4x", meta_id, version, meta_type, 0, len(ext), len(contents), 0, 0, 0)
    return head + ext + b"".join(c.pack() for c in contents) + bytes(0x20)


def update_files(signers, *, meta_type=nca.PATCH, version=VERSION, key_type=verify.TITLE_KEY_COMMON,
                 foreign_ca=False):
    keys, _trust = signers
    rights = struct.pack(">Q", PATCH) + bytes(7) + b"\x00"
    section_key = os.urandom(16)
    encrypted = AES.new(KEYS["titlekek_00"], AES.MODE_ECB).encrypt(section_key)
    program = signed_nca(keys["header"], 0, APP, romfs=os.urandom(0x3000), title_key=section_key, rights_id=rights)
    control = signed_nca(keys["header"], 2, APP, romfs=build_romfs({"control.nacp": nacp("Game", "Maker", "1.0.2"),
                                                                     "icon_AmericanEnglish.dat": b"\xff\xd8icon"}),
                         title_key=section_key, rights_id=rights)
    infos = [info_for(program, nca.PROGRAM), info_for(control, nca.CONTROL)]
    meta_id = PATCH if meta_type == nca.PATCH else APP
    meta = signed_nca(keys["header"], nca.NCA_META, meta_id,
                      pfs_files=[("x.cnmt", cnmt(meta_id, version, meta_type, infos))])
    ca = RSA.generate(2048) if foreign_ca else keys["ca"]
    certs = certificate(None, verify.SIG_RSA4096_SHA256, "Root", "CA00000003", ca) + \
        certificate(ca, verify.SIG_RSA2048_SHA256, "Root-CA00000003", "XS00000020", keys["xs"])
    files = {info_for(meta, nca.META).content_id.hex() + ".cnmt.nca": meta,
             infos[0].content_id.hex() + ".nca": program, infos[1].content_id.hex() + ".nca": control,
             rights.hex() + ".tik": ticket_for(keys["xs"], rights, encrypted, key_type), rights.hex() + ".cert": certs}
    return files, infos


def nsp(tmp_path, files, name="update.nsp"):
    path = tmp_path / name
    write_nsp(path, files)
    return str(path)


def test_a_signed_update_passes(signers, tmp_path):
    files, _infos = update_files(signers)
    seen = []
    info = verify.check_update(nsp(tmp_path, files), KEYS, APP, 0x10000, progress=lambda d, t: seen.append((d, t)),
                               trust=signers[1])
    assert (info.application_id, info.patch_id, info.version) == (APP, PATCH, VERSION)
    assert info.display_version == "1.0.2" and info.control.name == "Game" and info.control.icon == b"\xff\xd8icon"
    assert info.required_system_version == 0x20100000 and seen[-1][0] == seen[-1][1] == info.size


@pytest.mark.parametrize("change, refusal", [
    ("other game", "the console's game is"),
    ("not newer", "is not newer than the console's"),
    ("base game", "not an update"),
    ("content byte", "does not match the hash Nintendo listed"),
    ("header byte", "signature on the NCA header does not verify"),
    ("cnmt byte", "does not match its hash"),
    ("forged ticket", "ticket's signature does not verify"),
    ("personalized", "personalized"),
    ("foreign CA", "is not Nintendo's"),
    ("missing content", "is missing"),
    ("ncz", "compressed (NCZ)"),
    ("no ticket", "needs the ticket"),
    ("not an nsp", "not an NSP"),
    ("cut short", "the NSP is cut short"),
])
def test_a_changed_update_is_refused(signers, tmp_path, change, refusal):
    trust = signers[1]
    files, infos = update_files(signers, meta_type=nca.APPLICATION if change == "base game" else nca.PATCH,
                                key_type=1 if change == "personalized" else 0, foreign_ca=change == "foreign CA")
    program = infos[0].content_id.hex() + ".nca"
    meta = next(n for n in files if n.endswith(".cnmt.nca"))
    tik = next(n for n in files if n.endswith(".tik"))
    app, installed = APP, 0x10000
    if change == "other game":
        app = APP + 0x1000
    elif change == "not newer":
        installed = VERSION
    elif change == "content byte":
        files[program] = files[program][:-1] + bytes([files[program][-1] ^ 1])
    elif change == "header byte":
        files[program] = files[program][:0x300] + bytes([files[program][0x300] ^ 1]) + files[program][0x301:]
    elif change == "cnmt byte":
        at = nca.HEADER_SIZE + 0x200 + 0x40          # inside the PFS0, after its one-block hash table
        files[meta] = files[meta][:at] + bytes([files[meta][at] ^ 1]) + files[meta][at + 1:]
    elif change == "forged ticket":
        files[tik] = files[tik][:4] + b"\xff" * 0x100 + files[tik][0x104:]
    elif change == "missing content":
        del files[program]
    elif change == "ncz":
        files[program[:-4] + ".ncz"] = files.pop(program)
    elif change == "no ticket":
        del files[tik]
    path = nsp(tmp_path, files)
    if change == "not an nsp":
        with open(path, "r+b") as fh:
            fh.write(b"XXXX")
    elif change == "cut short":                     # an interrupted copy: the last entry ends past the file
        with open(path, "r+b") as fh:
            fh.truncate(os.path.getsize(path) - 1)
    with pytest.raises(verify.InvalidUpdate, match=refusal.replace("(", r"\(").replace(")", r"\)")):
        verify.check_update(path, KEYS, app, installed, trust=trust)


def test_without_hashing_a_changed_content_body_goes_unseen_but_its_header_does_not(signers, tmp_path):
    """The page hashes every content before Upload; the run checks headers and tickets again, quickly."""
    files, infos = update_files(signers)
    program = infos[0].content_id.hex() + ".nca"
    files[program] = files[program][:-1] + bytes([files[program][-1] ^ 1])
    assert verify.check_update(nsp(tmp_path, files), KEYS, hash_contents=False, trust=signers[1]).version == VERSION


def _real():
    keys_path = os.path.expanduser(os.environ.get("POKELDN_SWITCH_KEYS", "~/.switch/prod.keys"))
    updates = sorted(glob.glob(os.path.join(os.environ.get("POKELDN_SWITCH_DUMPS", r"D:\Switch_emu"), "Updates",
                                            "*Let's Go*.nsp")))
    return (nca.load_keys(keys_path), updates) if os.path.isfile(keys_path) and updates else (None, [])


SYSTEM_UPDATE = 0x0100000000000816
SYSTEM_DATA = 0x0100000000000809


def system_folder(signers, tmp_path):
    """A system update as pokeldn saves one: the SystemUpdate Meta NCA, the Meta NCA it lists, its content.
    -> (the folder, {role: file name})."""
    keys, _trust = signers
    data = signed_nca(keys["header"], 4, SYSTEM_DATA, romfs=os.urandom(0x2000))
    info = info_for(data, nca.DATA)
    sub = signed_nca(keys["header"], nca.NCA_META, SYSTEM_DATA,
                     pfs_files=[("x.cnmt", cnmt(SYSTEM_DATA, 0x5C010014, 0x02, [info], base=0))])
    head = struct.pack("<QIBBHHHB3xI4x", SYSTEM_UPDATE, 0x5C010014, nca.SYSTEM_UPDATE, 0, 0, 0, 1, 0, 0)
    listed = nca.ContentMetaKey(SYSTEM_DATA, 0x5C010014, 0x02).pack()
    top = signed_nca(keys["header"], nca.NCA_META, SYSTEM_UPDATE, pfs_files=[("x.cnmt", head + listed + bytes(0x20))])
    folder = tmp_path / "23.0.1"
    folder.mkdir()
    names = {"top": info_for(top, nca.META).content_id.hex() + ".cnmt.nca",
             "sub": info_for(sub, nca.META).content_id.hex() + ".cnmt.nca", "data": info.content_id.hex() + ".nca"}
    for role, raw in (("top", top), ("sub", sub), ("data", data)):
        (folder / names[role]).write_bytes(raw)
    return folder, names


def test_a_whole_system_update_passes(signers, tmp_path):
    folder, _names = system_folder(signers, tmp_path)
    seen = []
    info = verify.check_system(folder, KEYS, progress=lambda d, t: seen.append((d, t)), trust=signers[1])
    assert (info.version, info.metas, info.contents) == (0x5C010014, 2, 1)
    assert seen[-1] == (info.size, info.size)
    with pytest.raises(verify.InvalidUpdate, match="signature on the NCA header"):
        verify.check_system(folder, KEYS)                   # the test signer is not Nintendo


@pytest.mark.parametrize("change, refusal", [
    ("no content", "listed by a content meta, is missing"),
    ("no listed meta", "1 of the 1 content metas the system update lists are missing"),
    ("changed content", "does not match the hash Nintendo listed"),
    ("cut content", "bytes, the content meta says"),
    ("changed meta", "signature on the NCA header does not verify"),
])
def test_a_system_update_with_a_part_missing_or_changed_is_refused(signers, tmp_path, change, refusal):
    folder, names = system_folder(signers, tmp_path)
    data, sub = folder / names["data"], folder / names["sub"]
    if change == "no content":
        data.unlink()
    elif change == "no listed meta":
        sub.unlink()
    elif change == "changed content":
        raw = bytearray(data.read_bytes())
        raw[-1] ^= 1
        data.write_bytes(bytes(raw))
    elif change == "cut content":
        data.write_bytes(data.read_bytes()[:-0x200])
    else:
        raw = bytearray(sub.read_bytes())
        raw[0x10] ^= 1                                       # inside the header's encrypted signature
        sub.write_bytes(bytes(raw))
    with pytest.raises(verify.InvalidUpdate, match=refusal):
        verify.check_system(folder, KEYS, trust=signers[1])


def test_real_update_verifies_under_nintendos_keys():
    """Nintendo's NCA header key and CA00000003 verify an untouched eShop update (35 MB, Let's Go)."""
    keys, updates = _real()
    if not updates:
        pytest.skip("no Let's Go update NSP and prod.keys on this machine")
    info = verify.check_update(updates[0], keys)
    assert info.version >= 0x10000 and info.display_version
