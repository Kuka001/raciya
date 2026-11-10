"""Рисует значок приложения (тёмный скруглённый квадрат с четырьмя полосками «звуковой волны»)
и сохраняет его как client/assets/icon.ico. Без сторонних библиотек.

Запуск:  python tools/make_icon.py
"""
import os
import struct
import zlib

BG = (28, 30, 34)
FG = (236, 237, 238)
ACCENT = (76, 195, 138)
SS = 4  # сглаживание: 4x4 выборки на пиксель

# Полоски: (центр по X, половина высоты) в долях размера; третья — акцентная.
BARS = [(0.27, 0.11), (0.42, 0.24), (0.58, 0.33), (0.73, 0.17)]
BAR_HALF_W = 0.045


def inside_rounded(x, y, x0, y0, x1, y1, r):
    if x < x0 or x > x1 or y < y0 or y > y1:
        return False
    cx = min(max(x, x0 + r), x1 - r)
    cy = min(max(y, y0 + r), y1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def sample(u, v):
    """Цвет и непрозрачность в точке (u, v), координаты 0..1."""
    if not inside_rounded(u, v, 0.03, 0.03, 0.97, 0.97, 0.22):
        return None
    for i, (cx, hh) in enumerate(BARS):
        if inside_rounded(u, v, cx - BAR_HALF_W, 0.5 - hh, cx + BAR_HALF_W, 0.5 + hh, BAR_HALF_W):
            return ACCENT if i == 2 else FG
    return BG


def render(size):
    px = bytearray(size * size * 4)
    n = SS * SS
    for y in range(size):
        for x in range(size):
            r = g = b = a = 0
            for sy in range(SS):
                for sx in range(SS):
                    c = sample((x + (sx + 0.5) / SS) / size, (y + (sy + 0.5) / SS) / size)
                    if c:
                        r += c[0]
                        g += c[1]
                        b += c[2]
                        a += 1
            i = (y * size + x) * 4
            if a:
                px[i] = r // a
                px[i + 1] = g // a
                px[i + 2] = b // a
                px[i + 3] = 255 * a // n
    return bytes(px)


def png(size, rgba):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def dib(size, rgba):
    """32-битный BMP для записи внутри .ico (строки снизу вверх, BGRA, плюс пустая маска)."""
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    rows = []
    for y in range(size - 1, -1, -1):
        row = bytearray()
        for x in range(size):
            i = (y * size + x) * 4
            row += bytes((rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]))
        rows.append(bytes(row))
    mask_row = b"\x00" * (((size + 31) // 32) * 4)
    return header + b"".join(rows) + mask_row * size


def main():
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client", "assets")
    os.makedirs(out_dir, exist_ok=True)
    images = []
    for size in (16, 24, 32, 48, 256):
        rgba = render(size)
        images.append((size, png(size, rgba) if size == 256 else dib(size, rgba)))
    data = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for size, blob in images:
        data += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    for _, blob in images:
        data += blob
    path = os.path.join(out_dir, "icon.ico")
    with open(path, "wb") as f:
        f.write(data)
    with open(os.path.join(out_dir, "icon.png"), "wb") as f:
        f.write(png(256, render(256)))
    print("written", os.path.normpath(path), len(data), "bytes")


main()
