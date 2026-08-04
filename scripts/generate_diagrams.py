#!/usr/bin/env python3
"""Generate the v0.2 documentation diagrams as PNG files."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
INK = "#172033"
MUTED = "#5B6475"
BLUE = "#2563EB"
BLUE_PALE = "#EAF1FF"
GREEN = "#15803D"
GREEN_PALE = "#EAF8EF"
AMBER = "#B45309"
AMBER_PALE = "#FFF5E6"
LINE = "#CBD5E1"
WHITE = "#FFFFFF"


def font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont:
    mac_font = (
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf"
        if bold
        else "/System/Library/Fonts/Supplemental/Arial.ttf"
    )
    linux_font = (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    )
    candidates = [
        "/System/Library/Fonts/SFNS.ttf",
        mac_font,
        linux_font,
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    return ImageFont.load_default()


TITLE = font(34, bold=True)
LABEL = font(22, bold=True)
BODY = font(17)
SMALL = font(15)


def canvas(title: str, subtitle: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (1600, 900), WHITE)
    draw = ImageDraw.Draw(image)
    draw.text((70, 55), title, fill=INK, font=TITLE)
    draw.text((70, 105), subtitle, fill=MUTED, font=BODY)
    return image, draw


def box(
    draw: ImageDraw.ImageDraw,
    bounds: tuple[int, int, int, int],
    title: str,
    lines: list[str],
    *,
    fill: str = BLUE_PALE,
    outline: str = BLUE,
) -> None:
    draw.rounded_rectangle(bounds, radius=22, fill=fill, outline=outline, width=3)
    x1, y1, _, _ = bounds
    draw.text((x1 + 26, y1 + 24), title, fill=INK, font=LABEL)
    y = y1 + 70
    for line in lines:
        draw.text((x1 + 26, y), line, fill=MUTED, font=BODY)
        y += 28


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    label: str | None = None,
) -> None:
    draw.line((start, end), fill=INK, width=4)
    ex, ey = end
    sx, sy = start
    if abs(ex - sx) > abs(ey - sy):
        direction = 1 if ex > sx else -1
        points = [
            (ex, ey),
            (ex - 16 * direction, ey - 10),
            (ex - 16 * direction, ey + 10),
        ]
    else:
        direction = 1 if ey > sy else -1
        points = [
            (ex, ey),
            (ex - 10, ey - 16 * direction),
            (ex + 10, ey - 16 * direction),
        ]
    draw.polygon(points, fill=INK)
    if label:
        draw.text(
            ((sx + ex) // 2 - 45, (sy + ey) // 2 - 30),
            label,
            fill=MUTED,
            font=SMALL,
        )


def interactions() -> None:
    image, draw = canvas(
        "Governed context: declared inputs and deterministic execution",
        "The declared root anchors this mechanism; it does not prove real-world "
        "authority.",
    )
    box(
        draw,
        (70, 250, 370, 470),
        "Question",
        ["Natural-language", "release reference"],
    )
    box(
        draw,
        (485, 220, 830, 500),
        "One agent",
        ["Resolves intent", "Calls one repository tool", "Returns typed output"],
    )
    box(
        draw,
        (945, 165, 1515, 330),
        "Declared synthetic root",
        ["Claimed authority + owners", "Contract digests + policy epoch"],
        fill=AMBER_PALE,
        outline=AMBER,
    )
    box(
        draw,
        (945, 405, 1515, 680),
        "Context evaluator",
        [
            "Verify contracts first",
            "Declared identity + grants",
            "Policy + typed ontology",
            "Exact evidence checks",
            "Fail closed before evidence",
        ],
        fill=GREEN_PALE,
        outline=GREEN,
    )
    box(
        draw,
        (400, 670, 850, 835),
        "Deterministic output",
        ["Exact serialization + digest", "Trust state + issues", "Tool count = 1"],
        fill=AMBER_PALE,
        outline=AMBER,
    )
    arrow(draw, (370, 360), (485, 360), "asks")
    arrow(draw, (830, 360), (945, 500), "calls")
    arrow(draw, (1230, 330), (1230, 405), "anchors")
    arrow(draw, (945, 590), (850, 730), "returns")
    arrow(draw, (600, 670), (660, 500), "explains")
    image.save(DOCS / "agent-interactions.png")


def sequence() -> None:
    image, draw = canvas(
        "Matched evaluation sequence",
        "Eight fixed cases repeated three times. Expected labels withheld from "
        "both prompts.",
    )
    columns = [
        (95, "Case"),
        (450, "Governed"),
        (850, "Oracle"),
        (1240, "Packet baseline"),
    ]
    for x, label in columns:
        draw.text((x, 180), label, fill=INK, font=LABEL)
        draw.line((x + 65, 230, x + 65, 790), fill=LINE, width=3)
    steps = [
        (285, "same question", 160, 515),
        (390, "one context tool call", 515, 915),
        (500, "exact decision + digest", 915, 515),
        (615, "question + all files + digests", 160, 1305),
        (720, "decision graded", 1305, 915),
    ]
    for y, label, start_x, end_x in steps:
        arrow(draw, (start_x, y), (end_x, y), label)
    draw.rounded_rectangle((70, 810, 1530, 865), radius=16, fill=GREEN_PALE)
    draw.text(
        (110, 826),
        "Observed: governed = oracle in all 3 repeats of 8 fixed cases; one tool "
        "call and zero false READY.",
        fill=GREEN,
        font=BODY,
    )
    image.save(DOCS / "agent-sequence.png")


def main() -> None:
    DOCS.mkdir(parents=True, exist_ok=True)
    interactions()
    sequence()


if __name__ == "__main__":
    main()
