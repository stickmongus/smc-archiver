use eframe::egui::IconData;
use std::sync::Arc;

/// Generates the custom SMC icon (RGBA 64x64) for the GUI window titlebar and taskbar
pub fn build_window_icon() -> Arc<IconData> {
    let size = 64u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let center = (size as f32 - 1.0) / 2.0;

    for y in 0..size {
        for x in 0..size {
            let fx = x as f32;
            let fy = y as f32;
            let idx = ((y * size + x) * 4) as usize;

            let dx = (fx - center).abs() / (center - 2.0);
            let dy = (fy - center).abs() / (center - 2.0);
            let dist = (dx.powi(4) + dy.powi(4)).powf(0.25);

            if dist > 1.0 {
                rgba[idx..idx + 4].copy_from_slice(&[0, 0, 0, 0]);
                continue;
            }

            let grad = fy / (size as f32);
            let mut r = (18.0 + grad * 16.0) as u8;
            let mut g = (28.0 + grad * 32.0) as u8;
            let mut b = (56.0 + grad * 52.0) as u8;

            if dist > 0.88 {
                r = 56;
                g = 189;
                b = 248;
            }

            let in_zipper_x = (fx - center).abs() <= 4.5;
            if in_zipper_x && fy >= 8.0 && fy <= 22.0 {
                if ((y / 3) % 2) == 0 {
                    r = 148;
                    g = 210;
                    b = 255;
                } else {
                    r = 30;
                    g = 58;
                    b = 95;
                }
            }

            let nx = (fx - center) / (size as f32 * 0.34);
            let ny = (fy - center - 2.0) / (size as f32 * 0.36);

            let upper_bolt = ny >= -0.85
                && ny <= 0.10
                && nx >= -0.55 - ny * 0.45
                && nx <= 0.25 - ny * 0.55;
            let lower_bolt = ny >= -0.10
                && ny <= 0.85
                && nx >= -0.25 - ny * 0.55
                && nx <= 0.55 - ny * 0.45;

            if upper_bolt || lower_bolt {
                r = 255;
                g = (225.0 - (ny + 0.85) * 40.0).clamp(170.0, 255.0) as u8;
                b = 45;
            }

            rgba[idx] = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = 255;
        }
    }

    Arc::new(IconData {
        rgba,
        width: size,
        height: size,
    })
}
