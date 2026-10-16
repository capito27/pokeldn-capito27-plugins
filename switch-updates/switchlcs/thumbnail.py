"""A game icon at a quarter of its size, as a PNG, without an imaging library (the app ships none): the library's
notes show this instead of the whole icon, which made the page slow to open (a 256 x 256 icon is about 90 KB; its
64 x 64 thumbnail a few KB).

Each pixel is the average of a 4 x 4 square of the icon. A baseline JPEG gives that without decoding the picture:
the average over any part of an 8 x 8 block is a fixed sum of its DCT coefficients. A block of a full-size
component splits into 2 x 2 parts; one of a colour component stored at half size covers twice the picture, so it
splits into 4 x 4.

    png = thumbnail.from_jpeg(icon)          # None for a progressive or arithmetic-coded JPEG
"""

import math
import struct
import zlib

LARGEST = 1024          # a Switch icon is 256 x 256: anything past this is not one
# The natural (row * 8 + column) index of each coefficient in the order a JPEG stores them.
ZIGZAG = (0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7,
          14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46,
          53, 60, 61, 54, 47, 55, 62, 63)


_WEIGHTS = {}


def _weights(across: int, down: int) -> list[tuple[int, int, list[tuple[int, float]]]]:
    """A block split into `across` x `down` parts: for each, its (column, row) and the (stored index, weight) pairs
    whose sum over the block's dequantised coefficients is that part's average, less 128."""
    if (across, down) not in _WEIGHTS:
        if across not in (1, 2, 4, 8) or down not in (1, 2, 4, 8):
            raise Unsupported("a sampling these parts do not divide")
        scale = [1 / math.sqrt(2)] + [1.0] * 7

        def total(u, part, parts):
            width = 8 // parts
            return sum(math.cos((2 * x + 1) * u * math.pi / 16) for x in range(width * part, width * part + width))
        _WEIGHTS[(across, down)] = [
            (px, py, [(k, w) for k, n in enumerate(ZIGZAG)
                      if abs(w := scale[n % 8] * scale[n // 8] / 4 * total(n % 8, px, across) * total(n // 8, py, down)
                             / (64 // (across * down))) > 1e-9])
            for py in range(down) for px in range(across)]
    return _WEIGHTS[(across, down)]


class Unsupported(ValueError):
    """Not a baseline Huffman JPEG this reader takes."""


class _Bits:
    """The entropy-coded data: bytes with 0xFF 0x00 stuffing, read MSB first, stopping at a marker."""

    def __init__(self, data: bytes, at: int):
        self.data, self.at, self.value, self.count = data, at, 0, 0

    def _byte(self) -> int:
        data, at = self.data, self.at
        if at >= len(data):
            return 0
        byte = data[at]
        if byte == 0xFF:
            if (data[at + 1] if at + 1 < len(data) else 0) == 0x00:
                self.at = at + 2
                return 0xFF
            return 0                                # a marker: pad with zeros, as decoders do
        self.at = at + 1
        return byte

    def bits(self, n: int) -> int:
        while self.count < n:
            self.value = ((self.value << 8) | self._byte()) & 0xFFFFFFFF
            self.count += 8
        self.count -= n
        return (self.value >> self.count) & ((1 << n) - 1)

    def restart(self) -> None:
        """Skip to the byte after the next RSTn marker."""
        self.value = self.count = 0
        data, at = self.data, self.at
        while at + 1 < len(data) and not (data[at] == 0xFF and 0xD0 <= data[at + 1] <= 0xD7):
            at += 1
        self.at = at + 2


def _huffman(counts: bytes, symbols: bytes) -> dict:
    """{(length, code): symbol} from a DHT table's 16 counts and its symbols."""
    table, code, k = {}, 0, 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            table[(length, code)] = symbols[k]
            code, k = code + 1, k + 1
        code <<= 1
    return table


def _decode(bits: _Bits, table: dict) -> int:
    code = 0
    for length in range(1, 17):
        code = (code << 1) | bits.bits(1)
        if (length, code) in table:
            return table[(length, code)]
    raise Unsupported("a Huffman code no table holds")


def _extend(value: int, size: int) -> int:
    return value - (1 << size) + 1 if size and value < 1 << (size - 1) else value


def _planes(data: bytes):
    """-> (width, height, [per component: {(x, y): the average of the picture's 4 x 4 square there}])."""
    if data[:2] != b"\xff\xd8":
        raise Unsupported("not a JPEG")
    quant, dc_tables, ac_tables, frame, interval, at = {}, {}, {}, None, 0, 2
    while at + 4 <= len(data):
        if data[at] != 0xFF:
            raise Unsupported("a segment does not start with a marker")
        marker = data[at + 1]
        if marker == 0xFF:
            at += 1
            continue
        length = struct.unpack_from(">H", data, at + 2)[0]
        body = data[at + 4:at + 2 + length]
        if marker == 0xDB:                                      # DQT, in stored order
            i = 0
            while i < len(body):
                precision, table = body[i] >> 4, body[i] & 15
                quant[table] = (struct.unpack_from(">64H", body, i + 1) if precision else tuple(body[i + 1:i + 65]))
                i += 1 + 64 * (2 if precision else 1)
        elif marker in (0xC0, 0xC1):                            # SOF0 / SOF1: baseline or extended, Huffman
            height, width, n = struct.unpack_from(">HHB", body, 1)
            if not (0 < width <= LARGEST and 0 < height <= LARGEST and n in (1, 3)):
                raise Unsupported("not an icon's size, or not grey or colour")
            frame = (width, height, {body[6 + 3 * k]: (body[7 + 3 * k] >> 4, body[7 + 3 * k] & 15, body[8 + 3 * k])
                                     for k in range(n)}, [body[6 + 3 * k] for k in range(n)])
        elif 0xC2 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            raise Unsupported("a progressive, lossless or arithmetic-coded JPEG")
        elif marker == 0xC4:                                    # DHT
            i = 0
            while i < len(body):
                kind, table = body[i] >> 4, body[i] & 15
                counts = body[i + 1:i + 17]
                symbols = body[i + 17:i + 17 + sum(counts)]
                (ac_tables if kind else dc_tables)[table] = _huffman(counts, symbols)
                i += 17 + sum(counts)
        elif marker == 0xDD:                                    # DRI
            interval = struct.unpack_from(">H", body)[0]
        elif marker == 0xDA:                                    # SOS: one interleaved scan of every component
            if frame is None:
                raise Unsupported("a scan before the frame")
            return _scan(data, at + 2 + length, body, frame, quant, dc_tables, ac_tables, interval)
        at += 2 + length
    raise Unsupported("no scan")


def _scan(data, at, header, frame, quant, dc_tables, ac_tables, interval):
    width, height, components, order = frame
    n = header[0]
    if n != len(order):
        raise Unsupported("a scan that does not hold every component")
    scan = [(header[1 + 2 * k], header[2 + 2 * k] >> 4, header[2 + 2 * k] & 15) for k in range(n)]
    hmax = max(h for h, _v, _q in components.values())
    vmax = max(v for _h, v, _q in components.values())
    mcus_x, mcus_y = -(-width // (8 * hmax)), -(-height // (8 * vmax))
    parts = {cid: _weights(2 * hmax // h, 2 * vmax // v) if hmax % h == 0 and vmax % v == 0 else _weights(3, 3)
             for cid, (h, v, _q) in components.items()}
    bits = _Bits(data, at)
    out = {cid: {} for cid, _d, _a in scan}
    predictions = {cid: 0 for cid, _d, _a in scan}
    for mcu in range(mcus_x * mcus_y):
        if interval and mcu and mcu % interval == 0:
            bits.restart()
            predictions = dict.fromkeys(predictions, 0)
        mx, my = mcu % mcus_x, mcu // mcus_x
        for cid, dc, ac in scan:
            h, v, q = components[cid]
            dc_table, ac_table, table, plane = dc_tables[dc], ac_tables[ac], quant[q], out[cid]
            for by in range(v):
                for bx in range(h):
                    size = _decode(bits, dc_table)
                    predictions[cid] += _extend(bits.bits(size), size) if size else 0
                    coefficients = {0: predictions[cid] * table[0]}
                    k = 1
                    while k < 64:
                        symbol = _decode(bits, ac_table)
                        run, size = symbol >> 4, symbol & 15
                        if size == 0:
                            if run != 15:
                                break
                            k += 16
                            continue
                        k += run
                        if k < 64:
                            coefficients[k] = _extend(bits.bits(size), size) * table[k]
                        k += 1
                    across, down = 2 * hmax // h, 2 * vmax // v
                    x, y = (mx * h + bx) * across, (my * v + by) * down
                    for px, py, weights in parts[cid]:
                        plane[(x + px, y + py)] = 128 + sum(w * coefficients[i] for i, w in weights if i in coefficients)
    return width, height, [out[cid] for cid in order]


def _png(width: int, height: int, rgb: bytes) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    rows = b"".join(b"\0" + rgb[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def from_jpeg(data: bytes) -> bytes | None:
    """The JPEG at a quarter of its width and height, as a PNG; None for one this reader does not take."""
    try:
        width, height, planes = _planes(data)
    except (ValueError, IndexError, KeyError, ZeroDivisionError, struct.error):     # Unsupported is a ValueError
        return None
    columns, rows = -(-width // 4), -(-height // 4)
    pixels = bytearray()
    for y in range(rows):
        for x in range(columns):
            values = [plane.get((x, y), 128) for plane in planes]
            if len(values) == 1:
                luma, cb, cr = values[0], 0, 0
            else:
                luma, cb, cr = values[0], values[1] - 128, values[2] - 128
            pixels += bytes(min(255, max(0, round(c))) for c in (
                luma + 1.402 * cr, luma - 0.344136 * cb - 0.714136 * cr, luma + 1.772 * cb))
    return _png(columns, rows, bytes(pixels))
