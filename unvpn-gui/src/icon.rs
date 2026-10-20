//! Procedural app icon: a padlock glyph with a round status dot in the bottom-right
//! corner, rendered to ARGB32 for the ksni system-tray pixmap (and to RGBA via
//! [`app_icon_rgba`] for `--dump-rgba`). Drawn from scratch so the tray icon shows
//! consistently on every desktop regardless of the installed icon theme.
//!
//! In the tray the lock is a light flat glyph (like the other tray icons) and the
//! dot carries the state colour (green/amber/red/grey); the keyhole and the gap
//! around the dot are transparent so it sits on any panel background. The app icon
//! puts the same glyph, white, on a blue rounded tile with a green dot.
//!
//! Geometry is in a 24×24 design grid (x right, y down).

const GRID: f32 = 24.0;

/// Light glyph colour used for the lock in the tray.
const TRAY_GLYPH: [u8; 3] = [232, 232, 232];

/// Distance from point to segment ab.
fn seg_dist(px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32) -> f32 {
    let (dx, dy) = (bx - ax, by - ay);
    let len2 = dx * dx + dy * dy;
    let t = if len2 <= f32::EPSILON {
        0.0
    } else {
        (((px - ax) * dx + (py - ay) * dy) / len2).clamp(0.0, 1.0)
    };
    let (cx, cy) = (ax + t * dx, ay + t * dy);
    ((px - cx).powi(2) + (py - cy).powi(2)).sqrt()
}

/// Rounded-rectangle membership (rounded-rect SDF).
fn in_rrect(x: f32, y: f32, x0: f32, y0: f32, x1: f32, y1: f32, r: f32) -> bool {
    if x < x0 || x > x1 || y < y0 || y > y1 {
        return false;
    }
    let cx = x.clamp(x0 + r, x1 - r);
    let cy = y.clamp(y0 + r, y1 - r);
    (x - cx).powi(2) + (y - cy).powi(2) <= r * r
}

fn in_circle(x: f32, y: f32, cx: f32, cy: f32, r: f32) -> bool {
    (x - cx).powi(2) + (y - cy).powi(2) <= r * r
}

/// Padlock: a stroked shackle over a rounded body, minus a keyhole.
fn in_lock(x: f32, y: f32) -> bool {
    let (scx, scy, sr, half) = (12.0, 7.8, 4.0, 1.1);
    let shackle = if y < scy {
        (((x - scx).powi(2) + (y - scy).powi(2)).sqrt() - sr).abs() < half
    } else {
        seg_dist(x, y, 8.0, scy, 8.0, 10.5) < half || seg_dist(x, y, 16.0, scy, 16.0, 10.5) < half
    };
    let body = in_rrect(x, y, 4.5, 10.0, 19.5, 21.0, 3.0);
    let keyhole = in_circle(x, y, 12.0, 15.0, 1.6) || (x > 11.35 && x < 12.65 && y > 15.0 && y < 18.0);
    shackle || (body && !keyhole)
}

const DOT: (f32, f32, f32) = (18.5, 18.5, 4.2);
const DOT_GAP: f32 = 1.6;

/// Render to non-premultiplied RGBA bytes. `tile` (if any) is a rounded background
/// square; without it the background, keyhole and dot gap are transparent.
fn render_rgba(size: u32, glyph: [u8; 3], dot: [u8; 3], tile: Option<[u8; 3]>) -> Vec<u8> {
    // On a tile the glyph is shrunk to leave a margin. In the tray it is enlarged and
    // centred on its bounding box (x 4.5..22.7, y 2.7..22.7) so it fills the canvas.
    let (scale, cx, cy) = if tile.is_some() { (0.68, 12.0, 12.0) } else { (1.17, 13.6, 12.7) };
    let ss = 4u32; // supersampling for anti-aliasing
    let big = (size * ss) as f32;
    let mut out = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let (mut cov, mut sr, mut sg, mut sb) = (0u32, 0u32, 0u32, 0u32);
            for sy in 0..ss {
                for sx in 0..ss {
                    let fx = (x * ss + sx) as f32 / big;
                    let fy = (y * ss + sy) as f32 / big;
                    // Glyph-space coordinates in the 24×24 grid, scaled about (cx, cy).
                    let gx = cx + (fx - 0.5) * GRID / scale;
                    let gy = cy + (fy - 0.5) * GRID / scale;
                    let on_tile = tile.is_some() && in_rrect(fx, fy, 0.06, 0.06, 0.94, 0.94, 0.24);
                    let (dcx, dcy, dr) = DOT;
                    let c = if in_circle(gx, gy, dcx, dcy, dr) {
                        Some(dot)
                    } else if in_circle(gx, gy, dcx, dcy, dr + DOT_GAP) {
                        tile.filter(|_| on_tile)
                    } else if in_lock(gx, gy) {
                        Some(glyph)
                    } else {
                        tile.filter(|_| on_tile)
                    };
                    if let Some([r, g, b]) = c {
                        cov += 1;
                        sr += r as u32;
                        sg += g as u32;
                        sb += b as u32;
                    }
                }
            }
            let n = ss * ss;
            let i = ((y * size + x) * 4) as usize;
            if cov > 0 {
                out[i] = (sr / cov) as u8;
                out[i + 1] = (sg / cov) as u8;
                out[i + 2] = (sb / cov) as u8;
                out[i + 3] = (cov * 255 / n) as u8;
            }
        }
    }
    out
}

/// The app icon as RGBA at an arbitrary size: white lock on a blue tile, green dot.
pub fn app_icon_rgba(size: u32) -> Vec<u8> {
    render_rgba(size, [255, 255, 255], [46, 194, 126], Some([53, 132, 228]))
}

/// Tray icon with a state-coloured dot (ARGB32, network byte order), at a few
/// sizes so the host can pick a crisp one.
pub fn tray_pixmaps(color: [u8; 3]) -> Vec<ksni::Icon> {
    [22u32, 32, 48]
        .into_iter()
        .map(|size| {
            let rgba = render_rgba(size, TRAY_GLYPH, color, None);
            let mut data = vec![0u8; rgba.len()];
            for p in 0..(rgba.len() / 4) {
                let (r, g, b, a) = (rgba[p * 4], rgba[p * 4 + 1], rgba[p * 4 + 2], rgba[p * 4 + 3]);
                data[p * 4] = a;
                data[p * 4 + 1] = r;
                data[p * 4 + 2] = g;
                data[p * 4 + 3] = b;
            }
            ksni::Icon {
                width: size as i32,
                height: size as i32,
                data,
            }
        })
        .collect()
}
