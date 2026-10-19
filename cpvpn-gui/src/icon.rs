//! Procedural app icon: a shield with a check mark, rendered to ARGB32 for the
//! ksni system-tray pixmap (and RGBA via [`app_icon_rgba`] for `--dump-rgba`).
//! Drawn from scratch so the tray icon shows consistently on every desktop
//! regardless of the installed icon theme.

/// Shield silhouette membership in normalized [0,1] coords (x right, y down).
fn in_shield(x: f32, y: f32) -> bool {
    if !(0.12..=0.92).contains(&y) {
        return false;
    }
    let dx = (x - 0.5).abs();
    let half = if y <= 0.56 {
        // straight sides with slightly rounded top corners
        let top_round = if y < 0.2 {
            let t = (0.2 - y) / 0.08; // 0..1 near the very top
            0.34 - 0.10 * t.clamp(0.0, 1.0).powi(2)
        } else {
            0.34
        };
        top_round
    } else {
        // taper to a point at the bottom
        let t = (y - 0.56) / (0.92 - 0.56);
        0.34 * (1.0 - t)
    };
    dx <= half
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

/// A check mark stroke inside the shield.
fn near_check(x: f32, y: f32) -> bool {
    let th = 0.052;
    seg_dist(x, y, 0.34, 0.52, 0.45, 0.63) < th || seg_dist(x, y, 0.45, 0.63, 0.69, 0.37) < th
}

/// Render the shield to non-premultiplied RGBA bytes, `color` the shield fill.
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
                    if in_shield(fx, fy) {
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

/// The app icon as RGBA at an arbitrary size, transparent background.
pub fn app_icon_rgba(size: u32) -> Vec<u8> {
    render_rgba(size, [46, 120, 230])
}

/// State-colored shield for the system tray (ARGB32, network byte order).
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
