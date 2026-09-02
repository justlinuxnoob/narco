#!/usr/bin/env python3
"""Draw the narco icon set from one definition.

The mark is an arch — the letter n as a doorway, which is what a room two
people meet in ought to look like. White on black, matching the app itself.

Run from the repo root:  python3 tools/make_icons.py

Every tile is drawn at 8x and downsampled, so the hard geometric edges come out
antialiased instead of stair-stepped. Sizes are not guesses; they are what each
platform actually asks for, and the previous set got several of them wrong.
"""

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ICONS = ROOT / "app/src-tauri/icons"

SS = 8  # supersampling factor
BLACK = (0, 0, 0, 255)
WHITE = (255, 255, 255, 255)

# Height of the mark as a fraction of a tile it fills edge to edge. The old set
# sat at 0.35 and read as a small glyph adrift in a large black square.
FILL_MARK = 0.46

# Android draws an adaptive icon's foreground on a 108dp canvas but only
# guarantees the middle 72dp is visible — the launcher crops the rest to
# whatever shape it likes. Content sized against the full canvas gets eaten.
SAFE_ZONE = 72 / 108

ARCH_ASPECT = 0.94  # width / height; a touch narrower than square, like the letter
STROKE = 0.25  # of the mark's width


def draw_mark(size: int, mark_frac: float, bg) -> Image.Image:
    """One square tile: the arch centred on `bg` (a colour, or None for clear)."""
    big = size * SS
    img = Image.new("RGBA", (big, big), bg if bg else (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    h = big * mark_frac
    w = h * ARCH_ASPECT
    t = w * STROKE
    x0 = (big - w) / 2
    y0 = (big - h) / 2

    # Optically centred, not arithmetically. The arch is open at the bottom, so
    # centring the bounding box leaves it looking low; lifting it by a fraction
    # of the stroke puts its visual mass in the middle.
    y0 -= t * 0.18

    d.rectangle([x0, y0, x0 + w, y0 + t], fill=WHITE)  # top bar
    d.rectangle([x0, y0, x0 + t, y0 + h], fill=WHITE)  # left leg
    d.rectangle([x0 + w - t, y0, x0 + w, y0 + h], fill=WHITE)  # right leg

    return img.resize((size, size), Image.LANCZOS)


def rounded(size: int, radius_frac: float, mark_frac: float) -> Image.Image:
    """A tile with rounded corners, for Android's legacy launcher icon."""
    big = size * SS
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, big - 1, big - 1], radius=big * radius_frac, fill=255
    )
    tile = draw_mark(size, mark_frac, BLACK).resize((big, big), Image.NEAREST)
    tile.putalpha(mask)
    return tile.resize((size, size), Image.LANCZOS)


def circle(size: int, mark_frac: float) -> Image.Image:
    big = size * SS
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).ellipse([0, 0, big - 1, big - 1], fill=255)
    tile = draw_mark(size, mark_frac, BLACK).resize((big, big), Image.NEAREST)
    tile.putalpha(mask)
    return tile.resize((size, size), Image.LANCZOS)


def save(img: Image.Image, path: Path, *, flatten: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if flatten:
        # Apple rejects an app icon carrying an alpha channel, and every icon in
        # the previous set was RGBA.
        bg = Image.new("RGB", img.size, (0, 0, 0))
        bg.paste(img, mask=img.split()[3])
        img = bg
    img.save(path)
    print(f"  {path.relative_to(ROOT)}  {img.size[0]}x{img.size[1]} {img.mode}")


def main() -> None:
    print("android — adaptive foreground (transparent, mark inside the safe zone)")
    # The old foreground was an opaque black square, which defeats the whole
    # mechanism: the launcher could not compose it over the background, and the
    # white background declared in values/ never showed. Foreground now carries
    # only the mark; the background layer supplies the black.
    for bucket, px in [
        ("mdpi", 108),
        ("hdpi", 162),
        ("xhdpi", 216),
        ("xxhdpi", 324),
        ("xxxhdpi", 432),
    ]:
        save(
            draw_mark(px, FILL_MARK * SAFE_ZONE, None),
            ICONS / f"android/mipmap-{bucket}/ic_launcher_foreground.png",
        )

    print("android — legacy launcher icons")
    # 72 for hdpi, not the 49 the old set shipped, which Android upscaled to 72
    # and blurred.
    for bucket, px in [
        ("mdpi", 48),
        ("hdpi", 72),
        ("xhdpi", 96),
        ("xxhdpi", 144),
        ("xxxhdpi", 192),
    ]:
        save(rounded(px, 0.22, FILL_MARK), ICONS / f"android/mipmap-{bucket}/ic_launcher.png")
        save(circle(px, FILL_MARK), ICONS / f"android/mipmap-{bucket}/ic_launcher_round.png")

    print("ios — opaque, no alpha channel")
    for name, px in [
        ("AppIcon-20x20@1x", 20),
        ("AppIcon-20x20@2x", 40),
        ("AppIcon-20x20@2x-1", 40),
        ("AppIcon-20x20@3x", 60),
        ("AppIcon-29x29@1x", 29),
        ("AppIcon-29x29@2x", 58),
        ("AppIcon-29x29@2x-1", 58),
        ("AppIcon-29x29@3x", 87),
        ("AppIcon-40x40@1x", 40),
        ("AppIcon-40x40@2x", 80),
        ("AppIcon-40x40@2x-1", 80),
        ("AppIcon-40x40@3x", 120),
        ("AppIcon-60x60@2x", 120),
        ("AppIcon-60x60@3x", 180),
        ("AppIcon-76x76@1x", 76),
        ("AppIcon-76x76@2x", 152),
        ("AppIcon-83.5x83.5@2x", 167),
        ("AppIcon-512@2x", 1024),
    ]:
        save(draw_mark(px, FILL_MARK, BLACK), ICONS / f"ios/{name}.png", flatten=True)

    print("desktop")
    for name, px in [
        ("32x32", 32),
        ("64x64", 64),
        ("128x128", 128),
        ("128x128@2x", 256),
        ("icon", 512),
    ]:
        save(draw_mark(px, FILL_MARK, BLACK), ICONS / f"{name}.png")

    print("windows store tiles")
    for name, px in [
        ("Square30x30Logo", 30),
        ("Square44x44Logo", 44),
        ("Square71x71Logo", 71),
        ("Square89x89Logo", 89),
        ("Square107x107Logo", 107),
        ("Square142x142Logo", 142),
        ("Square150x150Logo", 150),
        ("Square284x284Logo", 284),
        ("Square310x310Logo", 310),
        ("StoreLogo", 50),
    ]:
        save(draw_mark(px, FILL_MARK, BLACK), ICONS / f"{name}.png")

    print("windows .ico")
    ico = draw_mark(256, FILL_MARK, BLACK)
    ico.save(
        ICONS / "icon.ico",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print("  app/src-tauri/icons/icon.ico")


if __name__ == "__main__":
    main()
