#!/usr/bin/env python3
"""Render a headerhawk JSON report to a PNG summary card.

Every value is read from the report file — no hand-typed numbers — so the image
in the README cannot drift from real tool output.

    python tools/render_report_card.py examples/report-example.json docs/report-card.png
"""

from __future__ import annotations

import json
import os
import sys

from PIL import Image, ImageDraw, ImageFont

S = 2  # supersampling factor for crisp text
W = 720 * S
BG = (11, 15, 20)
PANEL = (17, 24, 35)
LINE = (30, 42, 58)
TEXT = (219, 230, 243)
DIM = (125, 143, 166)
ACCENT = (74, 168, 255)
STATUS = {"pass": (46, 204, 113), "warn": (245, 176, 65), "fail": (231, 76, 60), "skip": (84, 101, 122)}
SEVERITY = {"critical": (231, 76, 60), "high": (231, 76, 60), "medium": (245, 176, 65), "low": (125, 143, 166), "info": (125, 143, 166)}
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

MONO_CANDIDATES = [r"C:\Windows\Fonts\consola.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]
SANS_CANDIDATES = [r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\Arial Bold.ttf"]


def font(paths: list[str], size: int) -> ImageFont.FreeTypeFont:
    for path in paths:
        if os.path.isfile(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def fit(text: str, fnt: ImageFont.FreeTypeFont, max_width: float) -> str:
    """Truncate with an ellipsis so text never overflows its column."""

    if fnt.getlength(text) <= max_width:
        return text
    out = text
    while out and fnt.getlength(out + "…") > max_width:
        out = out[:-1]
    return out + "…"


def main() -> int:
    source = sys.argv[1] if len(sys.argv) > 1 else "examples/report-example.json"
    target = sys.argv[2] if len(sys.argv) > 2 else "docs/report-card.png"

    with open(source, encoding="utf-8") as handle:
        data = json.load(handle)

    findings = [c for c in data["checks"] if c["status"] in ("fail", "warn")]
    findings.sort(key=lambda c: (ORDER.get(c["severity"], 9), c["id"]))

    f_title = font(SANS_CANDIDATES, 22 * S)
    f_url = font(MONO_CANDIDATES, 13 * S)
    f_meta = font(MONO_CANDIDATES, 11 * S)
    f_body = font(MONO_CANDIDATES, 12 * S)
    f_small = font(MONO_CANDIDATES, 10 * S)
    f_score = font(SANS_CANDIDATES, 30 * S)

    row_h = 46 * S
    header_h = 130 * S
    pad = 26 * S
    height = header_h + 58 * S + row_h * len(findings) + 70 * S

    image = Image.new("RGB", (W, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle([(S, S), (W - S, height - S)], radius=12 * S, outline=LINE, width=S)

    # --- header
    draw.text((pad, 28 * S), "headerhawk audit", font=f_title, fill=TEXT)
    draw.text((pad, 58 * S), fit(data["final_url"], f_url, W - 320 * S), font=f_url, fill=DIM)
    meta = f'{data["generated_at"]} · HTTP {data["response"]["status"]} · {len(data["response"]["redirects"])} redirect(s)'
    draw.text((pad, 80 * S), meta, font=f_meta, fill=DIM)

    # --- score ring
    cx, cy, radius = W - 110 * S, 62 * S, 40 * S
    box = [(cx - radius, cy - radius), (cx + radius, cy + radius)]
    draw.arc(box, start=0, end=360, fill=(27, 37, 52), width=9 * S)
    draw.arc(box, start=-90, end=-90 + 360 * data["score"] / 100, fill=ACCENT, width=9 * S)
    draw.text((cx, cy - 2 * S), str(data["score"]), font=f_score, fill=TEXT, anchor="mm")
    draw.text((cx, cy + 22 * S), "/100", font=f_small, fill=DIM, anchor="mm")
    draw.text((cx - radius - 16 * S, cy - 12 * S), "GRADE", font=f_small, fill=DIM, anchor="rm")
    draw.text((cx - radius - 16 * S, cy + 12 * S), data["grade"], font=f_title, fill=TEXT, anchor="rm")

    # --- counts strip
    counts = data["counts"]
    x = pad
    for key in ("pass", "warn", "fail", "skip"):
        draw.rounded_rectangle([(x, header_h - 22 * S), (x + 10 * S, header_h - 12 * S)], radius=2 * S, fill=STATUS[key])
        draw.text((x + 16 * S, header_h - 23 * S), f"{key} {counts.get(key, 0)}", font=f_small, fill=DIM)
        x += 84 * S

    # --- table header
    draw.line([(pad, header_h + 12 * S), (W - pad, header_h + 12 * S)], fill=LINE, width=S)
    cols = {"id": pad, "check": 100 * S, "sev": 380 * S, "evidence": 480 * S}
    for label, key in (("ID", "id"), ("CHECK", "check"), ("SEVERITY", "sev"), ("EVIDENCE", "evidence")):
        draw.text((cols[key], header_h + 28 * S), label, font=f_small, fill=DIM)

    # --- rows
    y = header_h + 58 * S
    for item in findings:
        colour = SEVERITY.get(item["severity"], DIM)
        draw.rounded_rectangle([(pad, y - 12 * S), (pad + 3 * S, y + 14 * S)], radius=1 * S, fill=colour)
        draw.text((cols["id"], y), item["id"], font=f_body, fill=DIM)
        draw.text(
            (cols["check"], y),
            fit(item["title"], f_body, cols["sev"] - cols["check"] - 20 * S),
            font=f_body,
            fill=TEXT,
        )
        draw.text((cols["sev"], y), item["severity"].upper(), font=f_small, fill=colour)
        draw.text(
            (cols["evidence"], y),
            fit(item["evidence"], f_body, W - pad - cols["evidence"]),
            font=f_body,
            fill=DIM,
        )
        y += row_h

    draw.text(
        (pad, height - 34 * S),
        f"generated from {os.path.basename(source)} · passive, read-only checks · weights documented in README",
        font=f_small,
        fill=DIM,
    )

    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    image.save(target, "PNG", optimize=True)
    print(f"wrote {target} ({image.width}x{image.height}, {os.path.getsize(target)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
