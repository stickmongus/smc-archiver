use std::fs;
use std::path::Path;

fn main() {
    let assets_dir = Path::new("assets");
    let _ = fs::create_dir_all(assets_dir);
    let ico_path = assets_dir.join("smc.ico");

    if let Ok(ico_bytes) = generate_smc_ico(64) {
        let _ = fs::write(&ico_path, ico_bytes);
    }

    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/smc.ico");
        res.set("ProductName", "SMC Archiver");
        res.set("FileDescription", "SMC (.smc) Ultra-Fast Multi-core Archiver");
        let _ = res.compile();
    }
}

/// Generates a valid 32-bit BGRA Windows .ico file with a sleek SMC Archive + Lightning Bolt design
fn generate_smc_ico(size: u32) -> Result<Vec<u8>, std::io::Error> {
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let center = (size as f32 - 1.0) / 2.0;

    for y in 0..size {
        for x in 0..size {
            let fx = x as f32;
            let fy = y as f32;
            let idx = ((y * size + x) * 4) as usize;

            // Rounded squircle distance check
            let dx = (fx - center).abs() / (center - 2.0);
            let dy = (fy - center).abs() / (center - 2.0);
            let dist = (dx.powi(4) + dy.powi(4)).powf(0.25);

            if dist > 1.0 {
                rgba[idx..idx + 4].copy_from_slice(&[0, 0, 0, 0]);
                continue;
            }

            // Deep navy/indigo gradient background
            let grad = fy / (size as f32);
            let mut r = (18.0 + grad * 16.0) as u8;
            let mut g = (28.0 + grad * 32.0) as u8;
            let mut b = (56.0 + grad * 52.0) as u8;

            // Glowing cyan border
            if dist > 0.88 {
                r = 56;
                g = 189;
                b = 248;
            }

            // Top zipper / archive track (upper center)
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

            // Golden Lightning Bolt in center (symbolizing ultra-fast compression)
            let nx = (fx - center) / (size as f32 * 0.34);
            let ny = (fy - center - 2.0) / (size as f32 * 0.36);

            let upper_bolt = ny >= -0.85 && ny <= 0.10 && nx >= -0.55 - ny * 0.45 && nx <= 0.25 - ny * 0.55;
            let lower_bolt = ny >= -0.10 && ny <= 0.85 && nx >= -0.25 - ny * 0.55 && nx <= 0.55 - ny * 0.45;

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

    // Build standard Windows ICO binary (ICONDIR + ICONDIRENTRY + BITMAPINFOHEADER + BGRA bottom-up + mask)
    let mask_row_bytes = ((size + 31) / 32) * 4;
    let mask_size = mask_row_bytes * size;
    let xor_size = size * size * 4;
    let dib_header_size = 40u32;
    let image_bytes_size = dib_header_size + xor_size + mask_size;

    let mut ico = Vec::with_capacity((22 + image_bytes_size) as usize);

    // ICONDIR (6 bytes)
    ico.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // Type = 1 (Icon)
    ico.extend_from_slice(&1u16.to_le_bytes()); // Count = 1

    // ICONDIRENTRY (16 bytes)
    ico.push(size as u8); // Width
    ico.push(size as u8); // Height
    ico.push(0); // ColorCount
    ico.push(0); // Reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // Planes
    ico.extend_from_slice(&32u16.to_le_bytes()); // BitCount = 32
    ico.extend_from_slice(&image_bytes_size.to_le_bytes()); // BytesInRes
    ico.extend_from_slice(&22u32.to_le_bytes()); // ImageOffset

    // BITMAPINFOHEADER (40 bytes)
    ico.extend_from_slice(&dib_header_size.to_le_bytes());
    ico.extend_from_slice(&(size as i32).to_le_bytes());
    ico.extend_from_slice(&((size * 2) as i32).to_le_bytes()); // Height * 2 for XOR + AND mask
    ico.extend_from_slice(&1u16.to_le_bytes()); // Planes
    ico.extend_from_slice(&32u16.to_le_bytes()); // BitCount
    ico.extend_from_slice(&0u32.to_le_bytes()); // Compression = BI_RGB
    ico.extend_from_slice(&(xor_size + mask_size).to_le_bytes());
    ico.extend_from_slice(&0i32.to_le_bytes());
    ico.extend_from_slice(&0i32.to_le_bytes());
    ico.extend_from_slice(&0u32.to_le_bytes());
    ico.extend_from_slice(&0u32.to_le_bytes());

    // Bottom-up BGRA pixels
    for y in (0..size).rev() {
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;
            let r = rgba[idx];
            let g = rgba[idx + 1];
            let b = rgba[idx + 2];
            let a = rgba[idx + 3];
            ico.extend_from_slice(&[b, g, r, a]);
        }
    }

    // AND Mask (all 0s since 32-bit alpha channel handles transparency)
    ico.extend(std::iter::repeat(0u8).take(mask_size as usize));

    Ok(ico)
}
