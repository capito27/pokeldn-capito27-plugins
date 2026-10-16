#!/usr/bin/env python3
"""Draw the plugin's icons: a pixel-art Switch console with a green update arrow over its top right, 18 x 18 as the
Games page's game sprites are, and the same drawing scaled to 96 x 96 for the Plugins page.

    python tools/make_icons.py          # writes switch.png and icon.png at the plugin's top
"""
import math
import os

from PIL import Image

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SIZE, TOP, BOTTOM = 18, 3, 14           # the console fills rows TOP..BOTTOM

OUTLINE = (0, 0, 0)
BLUE, BLUE_LIGHT, BLUE_DARK = (10, 185, 230), (127, 220, 245), (8, 128, 176)
RED, RED_LIGHT, RED_DARK = (255, 78, 60), (255, 154, 138), (196, 42, 30)
BEZEL, GLASS, GLINT = (60, 64, 72), (31, 41, 51), (74, 93, 115)
CONTROL = (26, 26, 26)
GREEN, GREEN_LIGHT, GREEN_DARK = (46, 204, 64), (134, 239, 128), (22, 140, 42)


def inside(x, y):
    """The console's rounded rectangle."""
    if not (0 <= x < SIZE and TOP <= y <= BOTTOM):
        return False
    corner = {(0, 0), (1, 0), (0, 1)}
    cx = x if x < SIZE // 2 else SIZE - 1 - x
    cy = y - TOP if y - TOP < 6 else BOTTOM - y
    return (cx, cy) not in corner


def colour(x, y):
    if not inside(x, y):
        return None
    if any(not inside(x + dx, y + dy) for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1))) or x in (4, 13):
        return OUTLINE
    if x < 4:                                               # the left Joy-Con: a stick, then the buttons
        if (x, y) == (2, 6) or (x, y) in ((2, 9), (1, 10), (3, 10), (2, 11)):
            return CONTROL
        return BLUE_LIGHT if (x == 1 and y < 9) or y == TOP + 1 else BLUE_DARK if y == BOTTOM - 1 else BLUE
    if x > 13:                                              # the right Joy-Con: the buttons, then a stick
        if (x, y) in ((15, 5), (14, 6), (16, 6), (15, 7)) or (x, y) == (15, 10):
            return CONTROL
        return RED_LIGHT if y == TOP + 1 and x < 16 else RED_DARK if y == BOTTOM - 1 or x == 16 else RED
    if 6 <= x <= 11 and 5 <= y <= 12:                       # the screen, a glint at its top left
        return GLINT if (x, y) in ((6, 5), (7, 5), (6, 6)) else GLASS
    return BEZEL


# The update arrow over the top right: a quarter circle around the sprite's top right corner that comes in from the
# right edge and turns up into the head, outlined so it reads against the right Joy-Con.
CENTRE, INNER, OUTER = (17.5, 3.5), 3.4, 5.6


def _distance(x, y) -> float:
    return math.hypot(x + .5 - CENTRE[0], y + .5 - CENTRE[1])


BAND = {(x, y) for x in range(SIZE) for y in range(3, SIZE) if INNER <= _distance(x, y) <= OUTER}
HEAD = {(12, 0), (13, 0), *((x, 1) for x in range(11, 15)), *((x, 2) for x in range(10, 16))}
ARROW = BAND | HEAD


def arrow(x, y):
    if (x, y) in ARROW:
        if (x, y) in BAND and _distance(x, y) > OUTER - 1:
            return GREEN_LIGHT if y < 6 else GREEN_DARK     # the outer rim: lit up the shaft, shaded round the turn
        if (x, y) in HEAD and (x - 1, y) not in HEAD:
            return GREEN_LIGHT
        return GREEN
    if any((x + dx, y + dy) in ARROW for dx in (-1, 0, 1) for dy in (-1, 0, 1)):
        return OUTLINE
    return None


def sprite() -> Image.Image:
    image = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    for y in range(SIZE):
        for x in range(SIZE):
            if (c := arrow(x, y) or colour(x, y)) is not None:
                image.putpixel((x, y), (*c, 255))
    return image


def main():
    small = sprite()
    small.save(os.path.join(ROOT, "switch.png"))
    large = Image.new("RGBA", (96, 96), (0, 0, 0, 0))
    large.paste(small.resize((90, 90), Image.NEAREST), (3, 3))     # 5 x 5 pixels each, centred
    large.save(os.path.join(ROOT, "icon.png"))


if __name__ == "__main__":
    main()
