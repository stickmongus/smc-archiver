#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod archiver;
pub mod crypto;
pub mod explorer;
pub mod external_archive;
pub mod format;
pub mod gui;
pub mod icon;

use eframe::egui;
use gui::{SmcGuiApp, StartupAction};
use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    // Clean up stale (>12h) instant-preview/double-click temp folders in %TEMP%\smc_instant_open
    archiver::cleanup_stale_temp_files();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut startup_path: Option<PathBuf> = None;
    let mut startup_action = StartupAction::None;

    if args.len() >= 2 && args[0] == "--pack" {
        startup_path = Some(PathBuf::from(&args[1]));
        startup_action = StartupAction::AutoPack;
    } else if args.len() >= 2 && args[0] == "--extract" {
        startup_path = Some(PathBuf::from(&args[1]));
        startup_action = StartupAction::AutoExtract;
    } else if let Some(first) = args.first() {
        let p = PathBuf::from(first);
        if p.exists() {
            if external_archive::is_supported_archive_path(&p) {
                startup_action = StartupAction::OpenArchive;
            }
            startup_path = Some(p);
        }
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("⚡ SMC Archiver v1.2 - 초고속 멀티코어 압축기 (.smc / .zip / .7z)")
            .with_inner_size([980.0, 680.0])
            .with_min_inner_size([800.0, 520.0])
            .with_drag_and_drop(true)
            .with_icon(icon::build_window_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "SMC Archiver",
        native_options,
        Box::new(move |cc| Ok(Box::new(SmcGuiApp::new(cc, startup_path, startup_action)))),
    )
}

#[cfg(test)]
mod tests {
    use super::archiver::{
        extract_entry_to_bytes, pack_archive, read_archive_index, sanitize_join, unpack_archive,
        verify_smc_archive, PackConfig, ProgressTracker,
    };
    use super::crypto::{derive_key_versioned, encrypt_block, generate_salt, INDEX_BLOCK_ID};
    use super::external_archive::{
        decode_archive_filename, extract_any_preview_bytes, pack_zip_archive,
        read_any_archive_index, smart_extract_dir, unpack_any_archive, verify_any_archive,
    };
    use super::format::{
        volume_path_for, ArchiveFormat, ArchiveIndex, ChunkMethod, CompressionMode, FLAG_ENCRYPTED,
        FLAG_KDF_V2, SMC_FOOTER_MAGIC, SMC_MAGIC, DEFAULT_DEV_EXCLUDES,
    };
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn test_smc_pack_unpack_encrypted_and_smart_bypass() {
        let temp_root = std::env::temp_dir().join("smc_unit_test_dir");
        let _ = fs::remove_dir_all(&temp_root);
        let src_dir = temp_root.join("input_project");
        let out_smc = temp_root.join("bundle.smc");
        let extract_dir = temp_root.join("extracted");

        fs::create_dir_all(src_dir.join("src")).unwrap();
        fs::create_dir_all(src_dir.join("media")).unwrap();
        fs::create_dir_all(src_dir.join("node_modules/pkg")).unwrap();

        let text_data =
            "Hello SMC Custom Format! Fast multi-core compression test.\n".repeat(2000);
        fs::write(src_dir.join("src/main.txt"), &text_data).unwrap();

        let media_data = vec![42u8; 65536];
        fs::write(src_dir.join("media/clip.mp4"), &media_data).unwrap();

        fs::write(src_dir.join("node_modules/pkg/index.js"), "ignored").unwrap();

        let config = PackConfig {
            mode: CompressionMode::SmartAuto,
            smart_bypass: true,
            filter_dev_dirs: true,
            custom_excludes: DEFAULT_DEV_EXCLUDES.iter().map(|s| s.to_string()).collect(),
            password: Some("my_secret_256".to_string()),
            split_size_bytes: None,
        };

        let stats = pack_archive(
            &[src_dir.clone()],
            &out_smc,
            &config,
            ProgressTracker::new(),
        )
        .expect("pack_archive should succeed");

        assert_eq!(stats.file_count, 2, "node_modules should be filtered out");
        assert_eq!(
            stats.smart_bypassed_count, 1,
            "clip.mp4 should be smart-bypassed"
        );
        assert_eq!(stats.volume_count, 1);

        // Verify KDF v2 flag is written in the header of newly created encrypted archives
        let header_bytes = fs::read(&out_smc).unwrap();
        let flags = u32::from_le_bytes(header_bytes[4..8].try_into().unwrap());
        assert_ne!(flags & FLAG_ENCRYPTED, 0);
        assert_ne!(flags & FLAG_KDF_V2, 0);

        assert!(read_archive_index(&out_smc, Some("wrong_pw")).is_err());

        let index = read_archive_index(&out_smc, Some("my_secret_256")).expect("index read");
        assert!(index.encrypted);
        assert_eq!(index.files.len(), 2);

        let mp4_entry = index
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("clip.mp4"))
            .unwrap();
        assert_eq!(mp4_entry.primary_method(), ChunkMethod::Store);

        // Verify integrity check passes without disk writes
        let verify_stats =
            verify_smc_archive(&out_smc, Some("my_secret_256"), ProgressTracker::new())
                .expect("verify_smc_archive should succeed");
        assert_eq!(verify_stats.file_count, 2);

        let unpack_stats = unpack_archive(
            &out_smc,
            &extract_dir,
            Some("my_secret_256"),
            None,
            ProgressTracker::new(),
        )
        .expect("unpack_archive should succeed");
        assert_eq!(unpack_stats.file_count, 2);

        let restored_txt =
            fs::read_to_string(extract_dir.join("input_project/src/main.txt")).unwrap();
        assert_eq!(restored_txt, text_data);

        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn test_smc_split_volume_and_instant_preview() {
        let temp_root = std::env::temp_dir().join("smc_split_test_dir");
        let _ = fs::remove_dir_all(&temp_root);
        let src_dir = temp_root.join("data");
        let out_smc = temp_root.join("split_test.smc");
        let extract_dir = temp_root.join("extracted_split");

        fs::create_dir_all(&src_dir).unwrap();

        // Write ~300 KB of uncompressible pseudo-random media data so it splits across 64KB volumes
        let pseudo_random: Vec<u8> = (0..300_000u32)
            .map(|i| ((i.wrapping_mul(1664525).wrapping_add(1013904223)) >> 24) as u8)
            .collect();
        fs::write(src_dir.join("video.mp4"), &pseudo_random).unwrap();

        let preview_txt = "Instant preview inside split volume archive works!";
        fs::write(src_dir.join("readme.txt"), preview_txt).unwrap();

        let config = PackConfig {
            mode: CompressionMode::SmartAuto,
            smart_bypass: true,
            filter_dev_dirs: true,
            custom_excludes: vec![],
            password: None,
            split_size_bytes: Some(64 * 1024), // 64 KB split volumes (.smc, .s01, .s02, ...)
        };

        let stats = pack_archive(&[src_dir], &out_smc, &config, ProgressTracker::new()).unwrap();
        assert!(
            stats.volume_count >= 4,
            "Expected at least 4 volumes, got {}",
            stats.volume_count
        );
        assert!(volume_path_for(&out_smc, 1).exists(), ".s01 should exist");
        assert!(volume_path_for(&out_smc, 2).exists(), ".s02 should exist");

        // Open via .s01 part path to verify automatic resolution to .smc
        let s01_path = volume_path_for(&out_smc, 1);
        let index = read_archive_index(&s01_path, None).unwrap();
        assert_eq!(index.volume_count, stats.volume_count);

        // Verify instant in-memory single-file extraction (used for Preview / Double-Click)
        let readme_entry = index
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("readme.txt"))
            .unwrap();
        let preview_bytes = extract_entry_to_bytes(&out_smc, readme_entry, None).unwrap();
        assert_eq!(std::str::from_utf8(&preview_bytes).unwrap(), preview_txt);

        // Verify full extraction across all split volumes
        unpack_archive(&out_smc, &extract_dir, None, None, ProgressTracker::new()).unwrap();
        let restored_video = fs::read(extract_dir.join("data/video.mp4")).unwrap();
        assert_eq!(restored_video, pseudo_random);

        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn test_edge_cases_korean_utf8_truncation_and_self_inclusion() {
        // 1. Korean multi-byte UTF-8 boundary truncation test (3 bytes per char: "가나다라")
        let korean = "가나다라마바사".repeat(100);
        // Slice at byte 10 (not a multiple of 3! Lands inside a 3-byte Hangul char)
        let (decoded, truncated) =
            super::gui::decode_text_preview(korean.as_bytes(), 10).expect("should decode cleanly");
        assert!(truncated);
        assert_eq!(decoded, "가나다"); // 9 valid bytes = 3 Korean chars

        // 1b. Korean CP949 (EUC-KR / ANSI) decoding test: [0xB0, 0xA1, 0xB3, 0xAA] = "가나"
        let cp949_bytes = [0xB0u8, 0xA1, 0xB3, 0xAA];
        let (cp949_decoded, _, enc_label) =
            super::gui::decode_text_preview_with_encoding(&cp949_bytes, 1024)
                .expect("CP949 should decode cleanly on Windows");
        assert_eq!(cp949_decoded, "가나");
        assert_eq!(enc_label, "CP949/EUC-KR");

        // 2. Self-inclusion & duplicate filename disambiguation test
        let temp_root = std::env::temp_dir().join("smc_edge_test_dir");
        let _ = fs::remove_dir_all(&temp_root);
        let dir_a = temp_root.join("dir_a");
        let dir_b = temp_root.join("dir_b");
        fs::create_dir_all(&dir_a).unwrap();
        fs::create_dir_all(&dir_b).unwrap();

        fs::write(dir_a.join("same.txt"), "from_a").unwrap();
        fs::write(dir_b.join("same.txt"), "from_b").unwrap();

        // Output archive placed right inside dir_a (with a pre-existing stale file)
        let out_smc = dir_a.join("inside_input.smc");
        fs::write(&out_smc, "stale_archive_bytes").unwrap();

        let config = PackConfig {
            mode: CompressionMode::SmartAuto,
            smart_bypass: true,
            filter_dev_dirs: true,
            custom_excludes: vec![],
            password: None,
            split_size_bytes: None,
        };

        let stats = pack_archive(
            &[dir_a.join("same.txt"), dir_b.join("same.txt"), dir_a.clone()],
            &out_smc,
            &config,
            ProgressTracker::new(),
        )
        .unwrap();

        // Only the 2 distinct files should be packed (no duplicate canonical path, no self-inclusion of inside_input.smc)
        assert_eq!(stats.file_count, 2);

        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn test_bin_dist_build_and_empty_dirs_preserved() {
        let temp_root = std::env::temp_dir().join("smc_bin_empty_test_dir");
        let _ = fs::remove_dir_all(&temp_root);
        let app_dir = temp_root.join("OBS.Studio.30.2");
        let out_smc = temp_root.join("obs.smc");
        let extract_dir = temp_root.join("restored");

        // Even with filter_dev_dirs = true & DEFAULT_DEV_EXCLUDES, bin/dist/build MUST be preserved!
        fs::create_dir_all(app_dir.join("bin/64bit")).unwrap();
        fs::create_dir_all(app_dir.join("dist")).unwrap();
        fs::create_dir_all(app_dir.join("build")).unwrap();
        fs::create_dir_all(app_dir.join("plugins/empty_leaf_a/sub_empty")).unwrap();
        fs::create_dir_all(app_dir.join("logs_empty")).unwrap();

        fs::write(app_dir.join("bin/64bit/obs64.dll"), b"binary_payload").unwrap();
        fs::write(app_dir.join("dist/bundle.js"), b"bundle_payload").unwrap();
        fs::write(app_dir.join("build/config.ini"), b"build_payload").unwrap();

        let config = PackConfig {
            mode: CompressionMode::SmartAuto,
            smart_bypass: true,
            filter_dev_dirs: true,
            custom_excludes: DEFAULT_DEV_EXCLUDES.iter().map(|s| s.to_string()).collect(),
            password: None,
            split_size_bytes: None,
        };

        let stats = pack_archive(
            &[app_dir.clone()],
            &out_smc,
            &config,
            ProgressTracker::new(),
        )
        .expect("pack_archive with bin/dist/build and empty dirs should succeed");
        assert_eq!(stats.file_count, 3);

        let index = read_archive_index(&out_smc, None).unwrap();
        assert_eq!(index.empty_dirs.len(), 2, "2 leaf empty dirs should be recorded");

        unpack_archive(&out_smc, &extract_dir, None, None, ProgressTracker::new()).unwrap();
        assert!(extract_dir.join("OBS.Studio.30.2/bin/64bit/obs64.dll").exists());
        assert!(extract_dir.join("OBS.Studio.30.2/dist/bundle.js").exists());
        assert!(extract_dir.join("OBS.Studio.30.2/build/config.ini").exists());
        assert!(extract_dir
            .join("OBS.Studio.30.2/plugins/empty_leaf_a/sub_empty")
            .is_dir());
        assert!(extract_dir.join("OBS.Studio.30.2/logs_empty").is_dir());

        // Also verify packing a directory containing ONLY empty folders works cleanly
        let only_empty_src = temp_root.join("only_empty_root");
        fs::create_dir_all(only_empty_src.join("nested_1/nested_2")).unwrap();
        let only_empty_smc = temp_root.join("only_empty.smc");
        let only_empty_out = temp_root.join("only_empty_restored");

        let empty_stats = pack_archive(
            &[only_empty_src],
            &only_empty_smc,
            &config,
            ProgressTracker::new(),
        )
        .expect("packing empty-only folder tree should succeed");
        assert_eq!(empty_stats.file_count, 0);

        unpack_archive(
            &only_empty_smc,
            &only_empty_out,
            None,
            None,
            ProgressTracker::new(),
        )
        .expect("unpacking empty-only folder tree should succeed");
        assert!(only_empty_out
            .join("only_empty_root/nested_1/nested_2")
            .is_dir());

        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn test_kdf_v1_backward_compat_and_corrupted_header_oom_guard() {
        let temp_root = std::env::temp_dir().join("smc_kdf_oom_test_dir");
        let _ = fs::remove_dir_all(&temp_root);
        fs::create_dir_all(&temp_root).unwrap();

        // 1. Construct a legacy v1.1 encrypted .smc archive (FLAG_ENCRYPTED without FLAG_KDF_V2, 60k iterations)
        let legacy_smc = temp_root.join("legacy_v1.smc");
        let salt = generate_salt();
        let legacy_key = derive_key_versioned("legacy_pass_11", &salt, false); // 60,000 iterations

        let empty_index = ArchiveIndex {
            version: 1,
            created_unix: 1_700_000_000,
            mode_used: CompressionMode::SmartAuto,
            encrypted: true,
            total_original_size: 0,
            total_compressed_size: 0,
            volume_count: 1,
            split_size_bytes: 0,
            files: vec![],
            empty_dirs: vec!["legacy_empty".to_string()],
            format: ArchiveFormat::Smc,
        };
        let json_bytes = serde_json::to_vec(&empty_index).unwrap();
        let zstd_index = zstd::bulk::compress(&json_bytes, 3).unwrap();
        let enc_index = encrypt_block(&zstd_index, &legacy_key, &salt, INDEX_BLOCK_ID).unwrap();

        let index_offset: u64 = 32;
        let mut f = File::create(&legacy_smc).unwrap();
        f.write_all(SMC_MAGIC).unwrap();
        f.write_all(&FLAG_ENCRYPTED.to_le_bytes()).unwrap(); // Note: NO FLAG_KDF_V2!
        f.write_all(&salt).unwrap();
        f.write_all(&index_offset.to_le_bytes()).unwrap();
        f.write_all(&(enc_index.len() as u64).to_le_bytes()).unwrap();
        f.write_all(&(json_bytes.len() as u64).to_le_bytes()).unwrap();
        f.write_all(&enc_index).unwrap();
        f.write_all(SMC_FOOTER_MAGIC).unwrap();
        f.flush().unwrap();
        drop(f);

        let unlocked = read_archive_index(&legacy_smc, Some("legacy_pass_11"))
            .expect("v1.1 60k-iteration archive must still unlock seamlessly");
        assert_eq!(unlocked.empty_dirs, vec!["legacy_empty".to_string()]);

        // 2. Corrupted header with u64::MAX comp_len / uncomp_len must fail immediately without OOM panic!
        let corrupt_smc = temp_root.join("corrupt_oom.smc");
        let mut cf = File::create(&corrupt_smc).unwrap();
        cf.write_all(SMC_MAGIC).unwrap();
        cf.write_all(&0u32.to_le_bytes()).unwrap();
        cf.write_all(&[0u8; 16]).unwrap();
        cf.write_all(&32u64.to_le_bytes()).unwrap(); // index_offset = 32
        cf.write_all(&u64::MAX.to_le_bytes()).unwrap(); // malicious comp_len = 18 EB!
        cf.write_all(&u64::MAX.to_le_bytes()).unwrap(); // malicious uncomp_len = 18 EB!
        cf.write_all(SMC_FOOTER_MAGIC).unwrap();
        cf.flush().unwrap();
        drop(cf);

        let err = read_archive_index(&corrupt_smc, None)
            .expect_err("Corrupted u64::MAX header must return Err cleanly without OOM");
        assert!(
            err.to_string().contains("손상") || err.to_string().contains("크기"),
            "Unexpected error message: {}",
            err
        );

        // 3. Hardened sanitize_join Zip-Slip / drive-letter / NTFS ADS protection
        assert!(sanitize_join(Path::new("C:/out"), "../../Windows/System32/cmd.exe").is_err());
        assert!(sanitize_join(Path::new("C:/out"), "C:/evil.exe").is_err());
        assert!(sanitize_join(Path::new("C:/out"), "file.txt:hidden_ads").is_err());

        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn test_zip_pack_encrypted_cp949_verify_and_parallel_unpack() {
        let temp_root = std::env::temp_dir().join("smc_zip_support_test_dir");
        let _ = fs::remove_dir_all(&temp_root);
        let src_dir = temp_root.join("zip_proj");
        let out_zip = temp_root.join("encrypted_bundle.zip");
        let extract_dir = temp_root.join("zip_extracted");

        fs::create_dir_all(src_dir.join("docs")).unwrap();
        fs::create_dir_all(src_dir.join("empty_folder")).unwrap();
        let doc_text = "ZIP AES-256 + Parallel Rayon Unpack + Integrity Check!\n".repeat(500);
        fs::write(src_dir.join("docs/guide_한글.txt"), &doc_text).unwrap();
        fs::write(src_dir.join("docs/photo.jpg"), vec![77u8; 8192]).unwrap();

        let config = PackConfig {
            mode: CompressionMode::ZstdBalanced,
            smart_bypass: true,
            filter_dev_dirs: false,
            custom_excludes: vec![],
            password: Some("zip_aes_pw!".to_string()),
            split_size_bytes: None,
        };

        let pack_stats = pack_zip_archive(
            &[src_dir.clone()],
            &out_zip,
            &config,
            ProgressTracker::new(),
        )
        .expect("pack_zip_archive should succeed");
        assert_eq!(pack_stats.file_count, 2);
        assert_eq!(pack_stats.smart_bypassed_count, 1);

        // Missing or wrong password must be rejected
        assert!(read_any_archive_index(&out_zip, None).is_err());
        assert!(read_any_archive_index(&out_zip, Some("wrong_pw")).is_err());

        let idx = read_any_archive_index(&out_zip, Some("zip_aes_pw!"))
            .expect("read_any_archive_index for encrypted .zip should succeed");
        assert_eq!(idx.format, ArchiveFormat::Zip);
        assert!(idx.encrypted);
        assert_eq!(idx.files.len(), 2);
        assert_eq!(idx.empty_dirs.len(), 1);

        // Preview encrypted ZIP entry
        let txt_entry = idx
            .files
            .iter()
            .find(|e| e.rel_path.ends_with("guide_한글.txt"))
            .unwrap();
        let preview =
            extract_any_preview_bytes(&out_zip, txt_entry, Some("zip_aes_pw!"), 128).unwrap();
        assert!(std::str::from_utf8(&preview)
            .unwrap()
            .starts_with("ZIP AES-256"));

        // Verify archive integrity
        let v_stats = verify_any_archive(&out_zip, Some("zip_aes_pw!"), ProgressTracker::new())
            .expect("verify_any_archive on encrypted .zip should succeed");
        assert_eq!(v_stats.file_count, 2);

        // Parallel unpack
        let u_stats = unpack_any_archive(
            &out_zip,
            &extract_dir,
            Some("zip_aes_pw!"),
            None,
            ProgressTracker::new(),
        )
        .expect("unpack_any_archive on encrypted .zip should succeed");
        assert_eq!(u_stats.file_count, 2);
        assert_eq!(
            fs::read_to_string(extract_dir.join("zip_proj/docs/guide_한글.txt")).unwrap(),
            doc_text
        );
        assert!(extract_dir.join("zip_proj/empty_folder").is_dir());

        // Verify legacy Korean CP949 filename fallback: [0xBA, 0xB8, 0xB0, 0xED, 0xBC, 0xAD] = "보고서"
        let raw_cp949_name = [0xBAu8, 0xB8, 0xB0, 0xED, 0xBC, 0xAD, b'.', b't', b'x', b't'];
        assert_eq!(decode_archive_filename(&raw_cp949_name), "보고서.txt");

        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn test_7z_encrypted_and_split_volumes_and_smart_extract() {
        let temp_root = std::env::temp_dir().join("smc_7z_support_test_dir");
        let _ = fs::remove_dir_all(&temp_root);
        let src_dir = temp_root.join("sevenz_src");
        let full_7z = temp_root.join("encrypted.7z");
        let extract_dir = temp_root.join("sevenz_extracted");

        fs::create_dir_all(src_dir.join("sub")).unwrap();
        let payload_a = "7-Zip AES-256 + LZMA2 decompression & verification test!\n".repeat(400);
        let payload_b: Vec<u8> = (0..90_000u32)
            .map(|i| ((i.wrapping_mul(214013).wrapping_add(2531011)) >> 16) as u8)
            .collect();
        fs::write(src_dir.join("sub/hello.txt"), &payload_a).unwrap();
        fs::write(src_dir.join("sub/blob.bin"), &payload_b).unwrap();

        // Create a real AES-256 encrypted .7z archive
        {
            let f = File::create(&full_7z).unwrap();
            sevenz_rust2::compress_encrypted(
                &src_dir,
                f,
                sevenz_rust2::Password::from("7z_secret!"),
            )
            .expect("sevenz_rust2::compress_encrypted should create valid encrypted .7z");
        }

        // Split the .7z bytes into multi-volume .7z.001, .7z.002, .7z.003...
        let raw_7z = fs::read(&full_7z).unwrap();
        let part_size = (raw_7z.len() / 3).max(64);
        let mut part_paths = Vec::new();
        for (i, chunk) in raw_7z.chunks(part_size).enumerate() {
            let p = temp_root.join(format!("split_arch.7z.{:03}", i + 1));
            fs::write(&p, chunk).unwrap();
            part_paths.push(p);
        }
        assert!(part_paths.len() >= 3);

        // Open via .7z.002 to verify automatic resolution to .7z.001 + multi-part stream reading!
        let part2 = &part_paths[1];
        assert!(read_any_archive_index(part2, None).is_err());

        let idx = read_any_archive_index(part2, Some("7z_secret!"))
            .expect("Opening .7z.002 with password should resolve .7z.001 and read index");
        assert_eq!(idx.format, ArchiveFormat::SevenZ);
        assert!(idx.encrypted);
        assert_eq!(idx.volume_count, part_paths.len());
        assert_eq!(idx.files.len(), 2);

        let hello_entry = idx
            .files
            .iter()
            .find(|e| e.rel_path.ends_with("hello.txt"))
            .unwrap();
        let preview =
            extract_any_preview_bytes(part2, hello_entry, Some("7z_secret!"), 64).unwrap();
        assert!(std::str::from_utf8(&preview)
            .unwrap()
            .starts_with("7-Zip AES-256"));

        let v_stats = verify_any_archive(part2, Some("7z_secret!"), ProgressTracker::new())
            .expect("verify_any_archive on split encrypted .7z should succeed");
        assert_eq!(v_stats.file_count, 2);

        let u_stats = unpack_any_archive(
            part2,
            &extract_dir,
            Some("7z_secret!"),
            None,
            ProgressTracker::new(),
        )
        .expect("unpack_any_archive on split encrypted .7z should succeed");
        assert_eq!(u_stats.file_count, 2);
        assert_eq!(
            fs::read_to_string(extract_dir.join("sub/hello.txt")).unwrap(),
            payload_a
        );
        assert_eq!(
            fs::read(extract_dir.join("sub/blob.bin")).unwrap(),
            payload_b
        );

        // Verify smart_extract_dir ("알아서 풀기") rules:
        // 1) Archive with single root folder "sub" when `<parent>/sub` does NOT exist -> extracts directly to `<parent>` (no sub/sub!)
        let target_clean = smart_extract_dir(part2, &idx);
        assert_eq!(target_clean, temp_root);

        // 2) If `<parent>/sub` ALREADY exists on disk -> disambiguates to `<parent>/split_arch` (never overwrites!)
        fs::create_dir_all(temp_root.join("sub")).unwrap();
        let target_collision = smart_extract_dir(part2, &idx);
        assert_eq!(target_collision, temp_root.join("split_arch"));

        // 3) If `<parent>/split_arch` ALSO exists -> disambiguates to `<parent>/split_arch (2)`
        fs::create_dir_all(temp_root.join("split_arch")).unwrap();
        let target_collision_2 = smart_extract_dir(part2, &idx);
        assert_eq!(target_collision_2, temp_root.join("split_arch (2)"));

        let _ = fs::remove_dir_all(&temp_root);
    }
}
