//! Procedural app icon: a rounded badge ("squircle") with a check mark, rendered
//! to ARGB32 for the ksni system-tray pixmap (and to RGBA via [`app_icon_rgba`] for
//! `--dump-rgba`). Drawn from scratch so the tray icon shows consistently on every
//! desktop regardless of the installed icon theme. The badge is filled with a state
//! colour (green/amber/red/grey); the check mark is always white.

/// Rounded-square ("badge") membership in normalized [0,1] coords (x right, y down).
fn in_badge(x: f32, y: f32) -> bool {
    let m = 0.10; // margin around the badge
    let r = 0.30; // corner radius
    let (x0, x1, y0, y1) = (m, 1.0 - m, m, 1.0 - m);
    if x < x0 || x > x1 || y < y0 || y > y1 {
        return false;
    }
    // Inside iff within `r` of the rectangle shrunk by `r` (rounded-rect SDF).
    let cx = x.clamp(x0 + r, x1 - r);
    let cy = y.clamp(y0 + r, y1 - r);
    let (dx, dy) = (x - cx, y - cy);
    dx * dx + dy * dy <= r * r
}

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

/// A check mark stroke inside the badge (round caps come from the segment distance).
fn near_check(x: f32, y: f32) -> bool {
    let th = 0.056;
    seg_dist(x, y, 0.34, 0.53, 0.46, 0.64) < th || seg_dist(x, y, 0.46, 0.64, 0.70, 0.37) < th
}

/// Render the badge to non-premultiplied RGBA bytes, `color` the badge fill.
fn render_rgba(size: u32, color: [u8; 3]) -> Vec<u8> {
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
                    if in_badge(fx, fy) {
                        cov += 1;
                        let (r, g, b) = if near_check(fx, fy) {
                            (255u32, 255, 255)
                        } else {
                            (color[0] as u32, color[1] as u32, color[2] as u32)
                        };
                        sr += r;
                        sg += g;
                        sb += b;
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

/// The app icon as RGBA at an arbitrary size, transparent background (accent blue).
pub fn app_icon_rgba(size: u32) -> Vec<u8> {
    render_rgba(size, [53, 132, 228])
}

/// State-colored badge for the system tray (ARGB32, network byte order).
pub fn tray_pixmap(color: [u8; 3]) -> ksni::Icon {
    let size = 32i32;
    let rgba = render_rgba(size as u32, color);
    let mut data = vec![0u8; rgba.len()];
    for p in 0..(rgba.len() / 4) {
        let (r, g, b, a) = (rgba[p * 4], rgba[p * 4 + 1], rgba[p * 4 + 2], rgba[p * 4 + 3]);
        data[p * 4] = a;
        data[p * 4 + 1] = r;
        data[p * 4 + 2] = g;
        data[p * 4 + 3] = b;
    }
    ksni::Icon {
        width: size,
        height: size,
        data,
    }
}
