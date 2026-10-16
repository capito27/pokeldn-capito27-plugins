"""The TCP 55556 content transfer `nim` runs for lcs: the receiver (client) pulls, the sender (server)
answers. docs/lcs.md "The content channel — TCP 55556"; switchbrew NIM services "Contents Delivery".

Every message is a 16-byte little-endian header {u32 magic, u8 id, pad, u16 meta_size, s64 data_size}
then data_size bytes. 20.5.0 nim builds request headers at 0x114cf0 and reply headers at 0x114d10;
replies carry the request's id. `sock` is anything with sendall() and recv() (a socket, or a
switchlcs.tcp connection).
"""

import hashlib
import os
import re
import struct
from dataclasses import dataclass, field

from switchlcs import nca

PORT = 55556
MAGIC_REQUEST = 0x7152444C       # "LDRq"
MAGIC_REPLY = 0x7352444C         # "LDRs"
HEADER = struct.Struct("<IBxHq")
MAX_META = 0x1000

EXIT, META_INFO, CONTENT, TICKET, TOTAL_SIZE = range(5)
REQUEST_SIZES = {EXIT: 0, META_INFO: 0x10, CONTENT: 0x18, TICKET: 0x10, TOTAL_SIZE: 8}
CHUNK = 1 << 20


class ProtocolError(Exception):
    pass


def recv_exactly(sock, n):
    out = bytearray()
    while len(out) < n:
        part = sock.recv(min(n - len(out), CHUNK))
        if not part:
            raise ConnectionError(f"peer closed with {n - len(out)} of {n} bytes outstanding")
        out += part
    return bytes(out)


def send_header(sock, magic, mid, data_size):
    sock.sendall(HEADER.pack(magic, mid, 0, data_size))


def recv_header(sock, want_magic=None):
    """-> (magic, id, data_size). Both magics are accepted unless `want_magic` is given, as nim checks
    both; the meta block (always empty when nim sends) is read and dropped."""
    magic, mid, meta_size, data_size = HEADER.unpack(recv_exactly(sock, HEADER.size))
    if magic not in (MAGIC_REQUEST, MAGIC_REPLY) or (want_magic and magic != want_magic):
        raise ProtocolError(f"bad magic {magic:#010x}")
    if meta_size > MAX_META or data_size < 0:
        raise ProtocolError(f"bad sizes: meta {meta_size:#x}, data {data_size}")
    if meta_size:
        recv_exactly(sock, meta_size)
    return magic, mid, data_size


# ---- the sender (server) ----

class Source:
    """What a sender serves. Lookups raise LookupError for anything outside the transfer."""

    def meta_info(self, key):
        """-> PackagedContentInfo of the Meta content of `key` (a ContentMetaKey)."""
        raise NotImplementedError

    def content_size(self, content_id):
        raise NotImplementedError

    def read_content(self, content_id, offset, size):
        raise NotImplementedError

    def ticket(self, rights_id):
        """-> (ticket, certificate chain)."""
        raise NotImplementedError


class NspSource(Source):
    """Serve the contents of one or more NSPs (a backup): their Meta NCAs, the NCAs their content metas
    list, and their tickets. `keys` (prod.keys) is needed to read each content meta's key."""

    def __init__(self, paths, keys):
        self.files = {}           # content id (bytes) -> (path, offset, size)
        self.tickets = {}         # rights id -> (ticket, cert)
        self.metas = {}           # ContentMetaKey -> PackagedContentInfo of its Meta NCA
        self.allowed = {}         # ContentMetaKey -> set of content ids it may serve
        for path in ([paths] if isinstance(paths, (str, os.PathLike)) else paths):
            entries = dict(_pfs0_entries(path))
            certs = {name[:-5]: _read(path, *at) for name, at in entries.items()
                     if name.endswith(".cert")}
            for name, at in entries.items():
                if name.endswith(".tik"):
                    rid = bytes.fromhex(name[:-4])
                    self.tickets[rid] = (_read(path, *at), certs.get(name[:-4], b""))
                elif name.endswith(".nca") or name.endswith(".ncz"):
                    self.files[bytes.fromhex(name[:32])] = (path, *at)
            for name, at in entries.items():
                if not name.endswith(".cnmt.nca"):
                    continue
                raw = _read(path, *at)
                cnmt = nca.read_cnmt(raw, keys)
                digest = hashlib.sha256(raw).digest()
                meta = nca.PackagedContentInfo(hash=digest, content_id=bytes.fromhex(name[:32]),
                                               size=len(raw), type=nca.META)
                self.metas[cnmt.key] = meta
                self.allowed[cnmt.key] = {meta.content_id} | {
                    c.content_id for c in cnmt.contents if c.content_id in self.files}

    def meta_info(self, key):
        found = self.metas.get(nca.ContentMetaKey(key.id, key.version, key.type))
        if found is None:
            raise LookupError(f"no content meta {key}")
        return found

    def content_size(self, content_id):
        if not any(content_id in ids for ids in self.allowed.values()):
            raise LookupError(f"content {content_id.hex()} is not in any served content meta")
        return self.files[content_id][2]

    def read_content(self, content_id, offset, size):
        path, base, total = self.files[content_id]
        return _read(path, base + offset, min(size, total - offset))

    def ticket(self, rights_id):
        if rights_id not in self.tickets:
            raise LookupError(f"no ticket for rights id {rights_id.hex()}")
        return self.tickets[rights_id]


NCA_NAME = re.compile(r"^[0-9a-fA-F]{32}(\.cnmt)?\.nca$")


class DirSource(Source):
    """Serve installed contents: a folder of <content id>.nca files, as pokeldn saves a system update,
    or as Ryujinx installs firmware (bis/system/Contents/registered), where each <content id>.nca is a
    folder of parts 00, 01, ... Meta NCAs are found by their header's content type; system contents
    carry no rights ID, so there are no tickets."""

    def __init__(self, root, keys):
        self.parts = {}           # content id -> [(path, size)] in order
        self.metas = {}           # ContentMetaKey -> PackagedContentInfo of its Meta NCA
        self.allowed = {}         # ContentMetaKey -> set of content ids it may serve
        cnmts = {}
        for folder, dirs, files in os.walk(root):
            for name in [d for d in dirs if NCA_NAME.match(d)]:
                dirs.remove(name)
                parts = sorted(os.listdir(os.path.join(folder, name)))
                self._add(name, [os.path.join(folder, name, p) for p in parts], keys, cnmts)
            for name in files:
                if NCA_NAME.match(name):
                    self._add(name, [os.path.join(folder, name)], keys, cnmts)
        for key, meta in self.metas.items():
            self.allowed[key] = {meta.content_id} | {
                c.content_id for c in cnmts[key].contents if c.content_id in self.parts}

    def _add(self, name, paths, keys, cnmts):
        content_id = bytes.fromhex(name[:32])
        self.parts[content_id] = [(p, os.path.getsize(p)) for p in paths]
        head = self.read_content(content_id, 0, nca.HEADER_SIZE)
        if nca.NcaHeader.parse(head, keys["header_key"]).content_type != nca.NCA_META:
            return
        raw = self.read_content(content_id, 0, self.content_size(content_id, check=False))
        cnmt = nca.read_cnmt(raw, keys)
        self.metas[cnmt.key] = nca.PackagedContentInfo(hash=hashlib.sha256(raw).digest(), content_id=content_id,
                                                        size=len(raw), type=nca.META)
        cnmts[cnmt.key] = cnmt

    def system_update(self):
        """-> the newest SystemUpdate content meta key in the folder, or None."""
        found = [k for k in self.metas if k.type == nca.SYSTEM_UPDATE]
        return max(found, key=lambda k: k.version, default=None)

    def meta_info(self, key):
        found = self.metas.get(nca.ContentMetaKey(key.id, key.version, key.type))
        if found is None:
            raise LookupError(f"no content meta {key}")
        return found

    def content_size(self, content_id, check=True):
        if check and not any(content_id in ids for ids in self.allowed.values()):
            raise LookupError(f"content {content_id.hex()} is not in any served content meta")
        return sum(size for _p, size in self.parts[content_id])

    def read_content(self, content_id, offset, size):
        out = bytearray()
        for path, part in self.parts[content_id]:
            if offset < part and size > len(out):
                out += _read(path, offset, min(size - len(out), part - offset))
            offset = max(0, offset - part)
        return bytes(out)

    def ticket(self, rights_id):
        raise LookupError(f"no ticket for rights id {rights_id.hex()}: installed system contents have none")


def nsp_control_data(path, keys, language="AmericanEnglish"):
    """-> (application ID, the game's control data: NACP and icon) from an NSP's Control NCA, as a
    console host answers an lcs 0x03 (control.ControlReply)."""
    entries = dict(_pfs0_entries(path))
    for name, at in entries.items():
        if not name.endswith(".cnmt.nca"):
            continue
        cnmt = nca.read_cnmt(_read(path, *at), keys)
        for info in cnmt.contents:
            if info.type != nca.CONTROL or info.content_id.hex() + ".nca" not in entries:
                continue
            raw = _read(path, *entries[info.content_id.hex() + ".nca"])
            header = nca.NcaHeader.parse(raw, keys["header_key"])
            title_key = None
            if header.has_rights_id:
                tik = entries.get(header.rights_id.hex() + ".tik")
                if tik is None:
                    raise ValueError(f"{path}: no ticket for the Control NCA")
                title_key = _read(path, *tik)[0x180:0x190]
            return cnmt.id & ~0xFFF, nca.control_data(raw, keys, title_key, language)
    raise ValueError(f"{path}: no Control NCA")


def file_name(text, fallback="update"):
    """Text as part of a file name on every system: the characters Windows refuses and controls taken out."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "", text).strip(" .") or fallback


def update_name(title, patch_id, version, display_version=""):
    """A saved update's file name: `<title> [<update ID>][v<internal version>](<display version>).nsp`, the
    display version left out when unknown."""
    display = file_name(display_version, "")
    return f"{file_name(title)} [{patch_id:016X}][v{version}]" + (f"({display})" if display else "") + ".nsp"


def write_nsp(out_path, paths, progress=None):
    """Pack the files at `paths` into an NSP (a PFS0 named after each file), copying them in chunks:
    -> out_path. Written to a .part file first, so a cut-short copy never looks finished."""
    names = b"".join(os.path.basename(p).encode() + b"\0" for p in paths)
    names += bytes(-(16 + 24 * len(paths) + len(names)) % 0x20)
    sizes = [os.path.getsize(p) for p in paths]
    table, at, name_at = b"", 0, 0
    for p, size in zip(paths, sizes):
        table += struct.pack("<QQII", at, size, name_at, 0)
        at += size
        name_at += len(os.path.basename(p).encode()) + 1
    part, done, total = str(out_path) + ".part", 0, sum(sizes)
    with open(part, "wb") as out:
        out.write(b"PFS0" + struct.pack("<III", len(paths), len(names), 0) + table + names)
        for p in paths:
            with open(p, "rb") as fh:
                while chunk := fh.read(CHUNK * 8):
                    out.write(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, total)
    os.replace(part, out_path)
    return out_path


def _pfs0_entries(path):
    with open(path, "rb") as fh:
        magic, count, str_size, _ = struct.unpack("<4sIII", fh.read(16))
        if magic != b"PFS0":
            raise ValueError(f"{path}: not an NSP (PFS0)")
        table = [struct.unpack("<QQII", fh.read(24)) for _ in range(count)]
        names = fh.read(str_size)
    data = 16 + 24 * count + str_size
    for off, size, name_off, _ in table:
        yield names[name_off:names.index(b"\0", name_off)].decode(), (data + off, size)


def _read(path, offset, size):
    with open(path, "rb") as fh:
        fh.seek(offset)
        return fh.read(size)


@dataclass
class ServeStats:
    requests: list = field(default_factory=list)      # (id, detail) in arrival order
    bytes_sent: int = 0
    total_size: int | None = None


def serve(sock, source, progress=None):
    """Answer one receiver until it sends EXIT (0x0). Any order of requests is accepted, as nim's
    sender does. -> ServeStats. `progress(sent, total)` is called as content goes out."""
    stats = ServeStats()
    while True:
        _magic, mid, size = recv_header(sock, MAGIC_REQUEST)
        if mid not in REQUEST_SIZES:
            raise ProtocolError(f"unknown request {mid:#x}")
        if size != REQUEST_SIZES[mid]:
            raise ProtocolError(f"request {mid:#x}: data size {size:#x}, expected "
                                f"{REQUEST_SIZES[mid]:#x}")
        body = recv_exactly(sock, size)
        if mid == EXIT:
            stats.requests.append((EXIT, None))
            return stats
        if mid == META_INFO:
            key = nca.ContentMetaKey.parse(body)
            stats.requests.append((META_INFO, key))
            reply = source.meta_info(key).pack()
            send_header(sock, MAGIC_REPLY, META_INFO, len(reply))
            sock.sendall(reply)
        elif mid == CONTENT:
            content_id, flag = body[:16], body[16]
            stats.requests.append((CONTENT, (content_id, flag)))
            total = source.content_size(content_id)
            send_header(sock, MAGIC_REPLY, CONTENT, total)
            at = 0
            while at < total:
                chunk = source.read_content(content_id, at, min(CHUNK, total - at))
                sock.sendall(chunk)
                at += len(chunk)
                if not flag:
                    stats.bytes_sent += len(chunk)
                    if progress:
                        progress(stats.bytes_sent, stats.total_size)
        elif mid == TICKET:
            stats.requests.append((TICKET, body))
            ticket, cert = source.ticket(body)
            send_header(sock, MAGIC_REPLY, TICKET, 8 + len(ticket) + len(cert))
            sock.sendall(struct.pack("<II", len(ticket), len(cert)) + ticket + cert)
        elif mid == TOTAL_SIZE:
            stats.total_size = struct.unpack("<q", body)[0]
            stats.requests.append((TOTAL_SIZE, stats.total_size))
            send_header(sock, MAGIC_REPLY, TOTAL_SIZE, 0)


# ---- the receiver (client) ----

def _request(sock, mid, body=b""):
    send_header(sock, MAGIC_REQUEST, mid, len(body))
    if body:
        sock.sendall(body)
    _magic, rid, size = recv_header(sock, MAGIC_REPLY)
    if rid != mid:
        raise ProtocolError(f"reply id {rid:#x} to request {mid:#x}")
    return size


def get_meta_info(sock, key):
    size = _request(sock, META_INFO, key.pack())
    if size != nca.PackagedContentInfo.SIZE:
        raise ProtocolError(f"meta info reply of {size:#x} bytes")
    return nca.PackagedContentInfo.parse(recv_exactly(sock, size))


def get_content(sock, info, write, counted=True):
    """Stream one content into `write(bytes)`, checking its size and SHA-256. `counted=False` is the
    flag nim sets for a system update's own Meta content (kept out of the sender's progress)."""
    size = _request(sock, CONTENT, info.content_id + bytes((0 if counted else 1,)) + bytes(7))
    if size != info.size:
        raise ProtocolError(f"content {info.content_id.hex()}: {size} bytes, expected {info.size}")
    digest, left = hashlib.sha256(), size
    while left:
        chunk = sock.recv(min(left, CHUNK))
        if not chunk:
            raise ConnectionError("peer closed mid-content")
        digest.update(chunk)
        write(chunk)
        left -= len(chunk)
    if digest.digest() != info.hash:
        raise ProtocolError(f"content {info.content_id.hex()}: SHA-256 mismatch")


def get_ticket(sock, rights_id):
    size = _request(sock, TICKET, rights_id)
    data = recv_exactly(sock, size)
    tik_size, cert_size = struct.unpack_from("<II", data)
    if 8 + tik_size + cert_size != size:
        raise ProtocolError("ticket reply sizes do not add up")
    return data[8:8 + tik_size], data[8 + tik_size:]


def set_total_size(sock, total):
    if _request(sock, TOTAL_SIZE, struct.pack("<q", total)):
        raise ProtocolError("total-size reply carried data")


def exit_session(sock):
    send_header(sock, MAGIC_REQUEST, EXIT, 0)


def receive(sock, key, outdir, keys, progress=None, listing=None):
    """Pull one content meta, or a list of them on one connection (and, for a system update, every
    content meta it lists) into `outdir` as <content id>.nca / .cnmt.nca files, plus <rights id>.tik /
    .cert for rights-id NCAs. Delta fragments are skipped: an installed update does not keep them.
    Before any content, every content meta's Meta NCA is fetched, one round trip each: listing(done,
    total) reports that (a 23.0.1 system update lists 120, some 15 seconds over the board).
    -> list of written paths."""
    os.makedirs(outdir, exist_ok=True)
    written, plan, rights = [], [], set()
    done, total = 0, 0

    def fetch(info, suffix, counted):
        path = os.path.join(outdir, info.content_id.hex() + suffix)
        with open(path, "wb") as fh:
            def write(chunk):
                nonlocal done
                fh.write(chunk)
                if total:
                    done += len(chunk)
                    if progress:
                        progress(done, total)
            get_content(sock, info, write, counted)
        written.append(path)
        return path

    queue = list(key) if isinstance(key, (list, tuple)) else [key]
    listed = 0
    while queue:
        k = queue.pop(0)
        meta = get_meta_info(sock, k)
        path = fetch(meta, ".cnmt.nca", counted=k.type != nca.SYSTEM_UPDATE)
        with open(path, "rb") as fh:
            cnmt = nca.read_cnmt(fh.read(), keys)
        queue += [nca.ContentMetaKey(m.id, m.version, m.type) for m in cnmt.metas]
        listed += 1
        if listing:
            listing(listed, listed + len(queue))
        plan += [(c, cnmt.type) for c in cnmt.contents if c.type != nca.DELTA_FRAGMENT]

    total = sum(c.size for c, _t in plan)
    set_total_size(sock, total)
    for info, meta_type in plan:
        path = fetch(info, ".nca", counted=True)
        if meta_type in (nca.APPLICATION, nca.PATCH):            # as nim's InstallTicket
            with open(path, "rb") as fh:
                header = nca.NcaHeader.parse(fh.read(nca.HEADER_SIZE), keys["header_key"])
            if header.has_rights_id and header.rights_id not in rights:
                rights.add(header.rights_id)
                ticket, cert = get_ticket(sock, header.rights_id)
                for suffix, data in ((".tik", ticket), (".cert", cert)):
                    out = os.path.join(outdir, header.rights_id.hex() + suffix)
                    with open(out, "wb") as fh:
                        fh.write(data)
                    written.append(out)
    exit_session(sock)
    return written
