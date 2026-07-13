"""Generate NeuralGuard's icon set: the app-tile brand mark and the four
tray-state glyphs, each hand-drawn per size tier (not rasterized from one SVG,
so small sizes stay crisp instead of inheriting antialiasing artifacts from a
generic vector rasterizer) and packed into multi-resolution .ico files.

Run from the repo root:  python scripts/gen_icons.py
Requires only Pillow (already a dev dependency here). Writes to assets/icons/.
"""
import struct
from pathlib import Path
from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "assets" / "icons"
OUT.mkdir(parents=True, exist_ok=True)

CYAN_A = (0, 229, 255, 255)
BLUE_A = (0, 102, 255, 255)
DARK_ON_CYAN = (4, 37, 43, 255)      # NG.Brush "on cyan" - matches the button/title-bar treatment
GREEN = (0, 255, 136, 255)
RED = (255, 51, 102, 255)
AMBER = (255, 170, 0, 255)           # unused for tray today, kept for a future "review" state
OFFLINE_GREY = (90, 98, 112, 255)
TRAY_DARK = (10, 11, 15, 220)        # mesh lines/nodes on a colored tray shield


def _lerp(c0, c1, t):
    return tuple(int(c0[i] + (c1[i] - c0[i]) * t) for i in range(4))


def _tile_gradient(size):
    """Diagonal cyan->blue gradient tile, matching the title-bar brand chip."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    px = img.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * (size - 1)) if size > 1 else 0
            px[x, y] = _lerp(CYAN_A, BLUE_A, t)
    return img


def _rounded_mask(size, radius):
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return mask


def _quad_bezier(p0, p1, p2, steps=8):
    pts = []
    for i in range(1, steps + 1):
        t = i / steps
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]
        pts.append((x, y))
    return pts


def _shield_polygon(size):
    """Shield: pointed top, straight shoulders, ROUNDED bottom point (two
    quadratic beziers) - matches the approved concept, not a hexagon."""
    s = size
    top = (0.50 * s, 0.18 * s)
    up_r = (0.74 * s, 0.28 * s)
    mid_r = (0.74 * s, 0.50 * s)
    bottom = (0.50 * s, 0.86 * s)
    mid_l = (0.26 * s, 0.50 * s)
    up_l = (0.26 * s, 0.28 * s)
    ctrl_r = (0.74 * s, 0.74 * s)
    ctrl_l = (0.26 * s, 0.74 * s)

    pts = [top, up_r, mid_r]
    pts += _quad_bezier(mid_r, ctrl_r, bottom)
    pts += _quad_bezier(bottom, ctrl_l, mid_l)
    pts += [up_l]
    return pts


def draw_tile_icon(size, with_mesh):
    """App-tile brand mark: rounded gradient square + dark shield (+ 3-node mesh)."""
    img = _tile_gradient(size)
    radius = max(2, int(size * 0.22))
    mask = _rounded_mask(size, radius)
    tile = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    tile.paste(img, (0, 0), mask)

    d = ImageDraw.Draw(tile)
    stroke = max(1, round(size * 0.05))
    d.line(_shield_polygon(size) + [_shield_polygon(size)[0]], fill=DARK_ON_CYAN, width=stroke, joint="curve")

    if with_mesh:
        r = max(1, round(size * 0.045))
        n1 = (0.50 * size, 0.42 * size)
        n2 = (0.40 * size, 0.58 * size)
        n3 = (0.60 * size, 0.58 * size)
        lw = max(1, round(size * 0.03))
        d.line([n1, n2], fill=DARK_ON_CYAN, width=lw)
        d.line([n1, n3], fill=DARK_ON_CYAN, width=lw)
        d.line([n2, n3], fill=DARK_ON_CYAN, width=lw)
        for n in (n1, n2, n3):
            d.ellipse([n[0] - r, n[1] - r, n[0] + r, n[1] + r], fill=DARK_ON_CYAN)
    else:
        # Below the mesh's legibility floor, a single solid dot keeps the "core" hint.
        r = max(1, round(size * 0.07))
        cx, cy = size * 0.50, size * 0.50
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=DARK_ON_CYAN)
    return tile


def draw_tray_icon(size, color, with_mesh):
    """Transparent-background solid shield glyph for the notification area."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.polygon(_shield_polygon(size), fill=color)

    if with_mesh:
        r = max(1, round(size * 0.05))
        n1 = (0.50 * size, 0.41 * size)
        n2 = (0.38 * size, 0.59 * size)
        n3 = (0.62 * size, 0.59 * size)
        lw = max(1, round(size * 0.035))
        d.line([n1, n2], fill=TRAY_DARK, width=lw)
        d.line([n1, n3], fill=TRAY_DARK, width=lw)
        for n in (n1, n2, n3):
            d.ellipse([n[0] - r, n[1] - r, n[0] + r, n[1] + r], fill=TRAY_DARK)
    return img


def write_ico(path, images):
    """Minimal ICO writer: embeds each given RGBA PNG image at its own native
    size (no internal resampling), so small sizes keep their hand-tuned detail
    instead of being downscaled from one master."""
    entries = []
    blobs = []
    offset = 6 + 16 * len(images)
    for im in images:
        import io
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        data = buf.getvalue()
        w = im.width if im.width < 256 else 0
        h = im.height if im.height < 256 else 0
        entries.append(struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(data), offset))
        blobs.append(data)
        offset += len(data)
    with open(path, "wb") as f:
        f.write(struct.pack("<HHH", 0, 1, len(images)))
        for e in entries:
            f.write(e)
        for b in blobs:
            f.write(b)


def main():
    tile_sizes_full = [256, 128, 64, 48, 32]
    tile_sizes_flat = [20, 16]
    tile_images = [draw_tile_icon(s, with_mesh=True) for s in tile_sizes_full]
    tile_images += [draw_tile_icon(s, with_mesh=False) for s in tile_sizes_flat]
    write_ico(OUT / "neuralguard.ico", tile_images)

    # Mesh detail reads clean at 32px but muddies into a smudge at 24px and
    # below (verified visually) - drop to the solid silhouette one size earlier
    # than the tile mark, which has more contrast headroom (dark-on-gradient).
    tray_sizes_full = [32]
    tray_sizes_flat = [24, 20, 16]
    states = {
        "tray-learning": CYAN_A,
        "tray-enforcing": GREEN,
        "tray-panic": RED,
        "tray-offline": OFFLINE_GREY,
    }
    for name, color in states.items():
        imgs = [draw_tray_icon(s, color, with_mesh=True) for s in tray_sizes_full]
        imgs += [draw_tray_icon(s, color, with_mesh=False) for s in tray_sizes_flat]
        write_ico(OUT / f"{name}.ico", imgs)

    print(f"Wrote {1 + len(states)} .ico files to {OUT}")


if __name__ == "__main__":
    main()
