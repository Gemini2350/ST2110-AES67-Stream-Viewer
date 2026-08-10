#!/usr/bin/env python3
"""Generate icon_1024.png (app icon master) - dark rounded square,
orange video-frame outlines and a cyan waveform. Pure stdlib."""
import binascii
import math
import struct
import zlib

S = 2048          # render size (downsampled 2x -> 1024)
R = 460           # corner radius

TOP = (35, 47, 62)
BOT = (14, 20, 30)
ORANGE = (255, 159, 67)
CYAN = (79, 195, 247)

rows = [bytearray(4 * S) for _ in range(S)]


def grad(y):
    t = y / (S - 1)
    return tuple(round(a + (b - a) * t) for a, b in zip(TOP, BOT))


def inset(y):
    if y < R:
        dy = R - y
    elif y >= S - R:
        dy = y - (S - R - 1)
    else:
        return 0
    if dy > R:
        return R
    return R - int(math.sqrt(R * R - dy * dy))


def px(x, y, color):
    if 0 <= x < S and 0 <= y < S and rows[y][4 * x + 3]:
        rows[y][4 * x:4 * x + 4] = bytes((*color, 255))


def fill(x0, y0, x1, y1, color=None):
    """Fill rect; color None -> restore background gradient."""
    for y in range(max(0, y0), min(S, y1)):
        c = color or grad(y)
        b = bytes((*c, 255))
        for x in range(max(0, x0), min(S, x1)):
            if rows[y][4 * x + 3]:
                rows[y][4 * x:4 * x + 4] = b


# background: rounded square with vertical gradient
for y in range(S):
    ins = inset(y)
    c = bytes((*grad(y), 255))
    rows[y][4 * ins:4 * (S - ins)] = c * (S - 2 * ins)

# three orange frame outlines (video), slightly overlapping row
fw, fh, th, gap, fy = 420, 340, 34, 76, 480
x = (S - 3 * fw - 2 * gap) // 2
for _ in range(3):
    fill(x, fy, x + fw, fy + fh, ORANGE)
    fill(x + th, fy + th, x + fw - th, fy + fh - th)  # restore bg inside
    x += fw + gap

# cyan waveform (audio)
mid, amp, th2 = 1430, 210, 30
for x in range(120, S - 120):
    ph = (x - 120) / (S - 240)
    cy = mid + amp * math.sin(2 * math.pi * 2.5 * ph) * math.sin(math.pi * ph)
    for y in range(int(cy) - th2, int(cy) + th2):
        px(x, y, CYAN)

# downsample 2x with box filter -> 1024 RGBA
OUT = S // 2
out = bytearray(OUT * OUT * 4)
for y in range(OUT):
    r0, r1 = rows[2 * y], rows[2 * y + 1]
    o = y * OUT * 4
    for x in range(OUT):
        i = 8 * x
        for c in range(4):
            out[o + 4 * x + c] = (r0[i + c] + r0[i + 4 + c] +
                                  r1[i + c] + r1[i + 4 + c]) >> 2


def chunk(tag, data):
    return (struct.pack('>I', len(data)) + tag + data +
            struct.pack('>I', binascii.crc32(tag + data) & 0xFFFFFFFF))


def png_bytes(size, rgba):
    raw = b''.join(b'\x00' + bytes(rgba[y * size * 4:(y + 1) * size * 4])
                   for y in range(size))
    return (b'\x89PNG\r\n\x1a\n' +
            chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(raw, 9)) +
            chunk(b'IEND', b''))


with open('icon_1024.png', 'wb') as f:
    f.write(png_bytes(OUT, out))
print("icon_1024.png geschrieben")

# 256px variant wrapped as .ico (PNG-compressed entry, Vista+) for Windows
SM, F = 256, OUT // 256
small = bytearray(SM * SM * 4)
for y in range(SM):
    for x in range(SM):
        acc = [0, 0, 0, 0]
        for dy in range(F):
            base = ((y * F + dy) * OUT + x * F) * 4
            for dx in range(F):
                for c in range(4):
                    acc[c] += out[base + 4 * dx + c]
        for c in range(4):
            small[(y * SM + x) * 4 + c] = acc[c] // (F * F)
png = png_bytes(SM, small)
with open('icon.ico', 'wb') as f:
    f.write(struct.pack('<HHH', 0, 1, 1))
    f.write(struct.pack('<BBBBHHII', 0, 0, 0, 0, 1, 32, len(png), 22))
    f.write(png)
print("icon.ico geschrieben")
