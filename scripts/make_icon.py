"""Draw the CE Board icon and write it as a multi-size .ico file.

Nothing is installed to do this: the icon is rasterised here and encoded as
PNG-inside-ICO (supported by Windows Vista and later) using only zlib and
struct from the standard library. That matters because the machines this tool
targets cannot install image libraries -- or anything else.

  python make_icon.py [path\\to\\ce-board.ico]

The drawing is three rising bars on a rounded navy tile, with an amber dot in
the corner for the "escalation" part. It is deliberately blocky so that it is
still readable at 16x16 in the taskbar.
"""

import os
import struct
import sys
import zlib

ICON_NAME = "ce-board.ico"
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
SUPERSAMPLE = 4

BACKDROP = (16, 58, 94)       # navy tile
BAR = (255, 255, 255)         # bars
BAR_LOW = (110, 178, 227)     # shortest bar, so the three read apart at 16px
DOT = (240, 168, 48)          # escalation marker


def _rounded(x, y, left, top, right, bottom, radius):
    """Is (x, y) inside this rounded rectangle?"""
    if not (left <= x < right and top <= y < bottom):
        return False
    for cx, cy in ((left + radius, top + radius), (right - radius, top + radius),
                   (left + radius, bottom - radius),
                   (right - radius, bottom - radius)):
        # Only the area diagonally outside a corner centre needs the circle
        # test; everything else is already inside the straight edges.
        if ((x < left + radius or x > right - radius)
                and (y < top + radius or y > bottom - radius)):
            if abs(x - cx) <= radius and abs(y - cy) <= radius:
                if (x - cx) ** 2 + (y - cy) ** 2 <= radius * radius:
                    return True
            continue
        return True
    return False


def _render(size):
    """Draw one frame, supersampled, and box-filter it down for smooth edges."""
    big = size * SUPERSAMPLE
    unit = big / 32.0
    tile = (0.0 * unit, big - 0.0 * unit)
    radius = 7 * unit

    bars = [  # left, top, width, height in 32x32 units, then colour
        (6, 19, 5, 8, BAR_LOW),
        (13.5, 14, 5, 13, BAR),
        (21, 9, 5, 18, BAR),
    ]
    dot_cx, dot_cy, dot_r = 24.5 * unit, 8.0 * unit, 4.4 * unit

    acc = [[0, 0, 0, 0] for _ in range(size * size)]
    for py in range(big):
        row_out = (py // SUPERSAMPLE) * size
        for px in range(big):
            colour = None
            if _rounded(px + 0.5, py + 0.5, tile[0], tile[0], tile[1], tile[1],
                        radius):
                colour = BACKDROP
                for bx, by, bw, bh, shade in bars:
                    if (bx * unit <= px < (bx + bw) * unit
                            and by * unit <= py < (by + bh) * unit):
                        colour = shade
                if (px + 0.5 - dot_cx) ** 2 + (py + 0.5 - dot_cy) ** 2 <= dot_r ** 2:
                    colour = DOT
            cell = acc[row_out + px // SUPERSAMPLE]
            if colour is not None:
                cell[0] += colour[0]
                cell[1] += colour[1]
                cell[2] += colour[2]
                cell[3] += 255

    n = float(SUPERSAMPLE * SUPERSAMPLE)
    out = bytearray()
    for y in range(size):
        out.append(0)  # PNG filter type 0 for this scanline
        for x in range(size):
            r, g, b, a = acc[y * size + x]
            if a:
                # Un-premultiply so edge pixels keep their colour as they fade.
                covered = a / 255.0
                out += bytes((int(round(r / covered)), int(round(g / covered)),
                              int(round(b / covered)), int(round(a / n))))
            else:
                out += b"\0\0\0\0"
    return bytes(out)


def _chunk(tag, data):
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def _png(size, raw):
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", header)
            + _chunk(b"IDAT", zlib.compress(raw, 9)) + _chunk(b"IEND", b""))


def build(path):
    frames = [(size, _png(size, _render(size))) for size in SIZES]
    header = struct.pack("<HHH", 0, 1, len(frames))
    offset = len(header) + 16 * len(frames)
    entries, blobs = b"", b""
    for size, blob in frames:
        entries += struct.pack("<BBBBHHII", size if size < 256 else 0,
                               size if size < 256 else 0, 0, 0, 1, 32,
                               len(blob), offset)
        offset += len(blob)
        blobs += blob
    with open(path, "wb") as handle:
        handle.write(header + entries + blobs)
    return path


def ensure(folder):
    """Return the icon path, drawing it once if it is not there yet."""
    path = os.path.join(folder, ICON_NAME)
    if not os.path.exists(path):
        try:
            build(path)
        except (IOError, OSError):
            return ""
    return path


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ICON_NAME)
    build(target)
    print("Wrote {} ({} bytes, {} sizes)".format(
        target, os.path.getsize(target), len(SIZES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
