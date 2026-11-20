#!/usr/bin/env python3
"""Draw the headerhawk pipeline diagram as a PNG.

The stages below are the real call order in ``headerhawk/cli.py``:

    fetch() -> header_checks() + cookie_checks() + tls_checks()
            -> [exposure_checks() when --probe]
            -> score() -> render()

    python tools/render_pipeline.py docs/pipeline.png
"""

from __future__ import annotations

import os
import sys

from PIL import Image, ImageDraw, ImageFont

S = 2
W, H = 1140 * S, 340 * S
BG = (11, 15, 20)
PANEL = (17, 24, 35)
LINE = (30, 42, 58)
TEXT = (219, 230, 243)
DIM = (125, 143, 166)
ACCENT = (74, 168, 255)
GREEN = (46, 204, 113)
AMBER = (245, 176, 65)

MONO = [r"C:\Windows\Fonts\consola.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]
SANS = [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\Arial Bold.ttf"]


def font(paths, size):
    for path in paths:
        if os.path.isfile(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def box(draw, x, y, w, h, title, lines, accent=ACCENT, fill=PANEL):
    draw.rounded_rectangle([(x, y), (x + w, y + h)], radius=10 * S, fill=fill, outline=LINE, width=S)
    draw.rounded_rectangle([(x, y), (x + 4 * S, y + h)], radius=2 * S, fill=accent)
    draw.text((x + 18 * S, y + 14 * S), title, font=font(SANS, 15 * S), fill=TEXT)
    for index, line in enumerate(lines):
        draw.text((x + 18 * S, y + 40 * S + index * 18 * S), line, font=font(MONO, 11 * S), fill=DIM)


def arrow(draw, x1, y1, x2, y2, label=""):
    draw.line([(x1, y1), (x2, y2)], fill=(60, 78, 100), width=2 * S)
    draw.polygon(
        [(x2, y2), (x2 - 8 * S, y2 - 5 * S), (x2 - 8 * S, y2 + 5 * S)],
        fill=(60, 78, 100),
    )
    if label:
        draw.text(((x1 + x2) // 2, y1 - 16 * S), label, font=font(MONO, 10 * S), fill=DIM, anchor="mm")


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "docs/pipeline.png"
    image = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(image)

    draw.text((28 * S, 22 * S), "headerhawk — audit pipeline", font=font(SANS, 20 * S), fill=TEXT)
    draw.text(
        (28 * S, 50 * S),
        "standard library only · 13 assertions · no crawling, no auth, read-only GET requests",
        font=font(MONO, 11 * S),
        fill=DIM,
    )

    bw, bh = 176 * S, 118 * S
    y = 96 * S
    xs = [28 * S, 246 * S, 464 * S, 682 * S, 900 * S]

    box(draw, xs[0], y, bw, bh, "target", ["URL or hostname", "http(s) only", "one page per run"])
    box(draw, xs[1], y, bw, bh, "fetch.py", ["manual redirects", "raw headers", "cipher + cert"], accent=ACCENT)
    box(draw, xs[2], y, bw, bh, "checks.py", ["8 header checks", "1 cookie check", "3 TLS checks"], accent=GREEN)
    box(draw, xs[3], y, bw, bh, "scoring.py", ["weighted 0-100", "warn = 50% credit", "A-F grade"], accent=AMBER)
    box(draw, xs[4], y, bw, bh, "report.py", ["text · markdown", "html · json", "exit code 0/1/2"], accent=ACCENT)

    for index in range(4):
        arrow(draw, xs[index] + bw + 4 * S, y + bh // 2, xs[index + 1] - 4 * S, y + bh // 2)

    # probe branch
    py = 244 * S
    box(
        draw,
        xs[2],
        py,
        300 * S,
        70 * S,
        "exposure_checks()  --probe",
        ["8 fixed paths · signature-verified · opt-in"],
        accent=(231, 76, 60),
    )
    arrow(draw, xs[2] + 60 * S, y + bh + 4 * S, xs[2] + 60 * S, py - 4 * S)
    draw.line([(xs[2] + 300 * S, py + 35 * S), (xs[3] + 40 * S, py + 35 * S), (xs[3] + 40 * S, y + bh + 4 * S)], fill=(60, 78, 100), width=2 * S)
    draw.polygon([(xs[3] + 40 * S, y + bh + 2 * S), (xs[3] + 35 * S, y + bh + 12 * S), (xs[3] + 45 * S, y + bh + 12 * S)], fill=(60, 78, 100))
    draw.text((xs[2] + 310 * S, py + 22 * S), "critical finding feeds the score", font=font(MONO, 10 * S), fill=DIM)

    draw.text(
        (28 * S, H - 26 * S),
        "Every request is a single GET; nothing is written to the target. Audit only systems you own or are authorised to test.",
        font=font(MONO, 10 * S),
        fill=DIM,
    )

    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    image.save(target, "PNG", optimize=True)
    print(f"wrote {target} ({image.width}x{image.height}, {os.path.getsize(target)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
