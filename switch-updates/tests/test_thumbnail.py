"""A game icon's thumbnail for the library's notes (switchlcs.thumbnail): each pixel the average of a 4 x 4 square,
read from a baseline JPEG's coefficients, checked against Pillow's own decode and box reduction."""

import io
import os

import pytest

from switchlcs import cards, thumbnail

Image = pytest.importorskip("PIL.Image")


def jpeg(size=(256, 256), mode="RGB", **options) -> bytes:
    """A picture with edges and gradients in every block, saved as a JPEG."""
    picture = Image.new("RGB", size)
    picture.putdata([((x * 7 + y) % 256, (x * y) % 256, 255 - (y * 5) % 256) if (x // 24 + y // 40) % 3 else
                     (250, 240 - x % 64, 20) for y in range(size[1]) for x in range(size[0])])
    out = io.BytesIO()
    picture.convert(mode).save(out, "JPEG", quality=90, **options)
    return out.getvalue()


def difference(png: bytes, data: bytes) -> list[float]:
    """The mean difference, out of 255, in brightness and in each colour channel, between the thumbnail and
    Pillow's decode reduced 4 x 4."""
    mine = Image.open(io.BytesIO(png)).convert("RGB").convert("YCbCr")
    reference = Image.open(io.BytesIO(data)).convert("RGB").reduce(4).convert("YCbCr")
    assert mine.size == reference.size
    return [sum(abs(x - y) for x, y in zip(a.tobytes(), b.tobytes())) / (mine.width * mine.height)
            for a, b in zip(mine.split(), reference.split())]


def close(png: bytes, data: bytes, colour: float = 0.5) -> bool:
    """Brightness within a level; colour stored at half size within a few, as Pillow smooths it back up where this
    averages what is stored."""
    luma, *chroma = difference(png, data)
    return luma < 1 and max(chroma) < colour


@pytest.mark.parametrize("subsampling, colour", [(0, 0.5), (1, 3), (2, 5)])
def test_a_colour_icon_is_its_4x4_averages_in_any_chroma_sampling(subsampling, colour):
    data = jpeg(subsampling=subsampling)
    png = thumbnail.from_jpeg(data)
    assert png.startswith(b"\x89PNG") and len(png) < len(data) / 3
    assert close(png, data, colour)


def test_grey_odd_sizes_and_restart_markers_are_read():
    for data, colour in ((jpeg(mode="L"), 0.5), (jpeg((100, 60), subsampling=0), 0.5),
                         (jpeg((100, 60), subsampling=2), 5), (jpeg(restart_marker_blocks=3, subsampling=0), 0.5)):
        png = thumbnail.from_jpeg(data)
        assert png is not None and close(png, data, colour)


def test_a_jpeg_this_reader_does_not_take_has_no_thumbnail():
    assert thumbnail.from_jpeg(jpeg(progressive=True)) is None
    assert thumbnail.from_jpeg(b"\xff\xd8\xff\xe0" + os.urandom(3000)) is None
    assert thumbnail.from_jpeg(b"PNG") is None
    assert thumbnail.from_jpeg(jpeg((1100, 8))) is None       # not an icon's size


def test_the_notes_show_a_thumbnail_made_once_beside_the_icon(tmp_path):
    icon = tmp_path / "0100187003A36000.jpg"
    icon.write_bytes(jpeg())
    small = cards.small(icon)
    assert small == icon.with_suffix(".png") and small.read_bytes().startswith(b"\x89PNG")
    made = small.stat().st_mtime_ns
    assert cards.small(str(icon)) == small and small.stat().st_mtime_ns == made
    os.utime(icon, ns=(made + 10**9, made + 10**9))     # a game keeps its icon: the thumbnail is never made again
    cards.small(icon)
    assert small.stat().st_mtime_ns == made
    unread = tmp_path / "progressive.jpg"
    unread.write_bytes(jpeg(progressive=True))
    assert cards.small(unread) == unread and cards.small(None) is None
