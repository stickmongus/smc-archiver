use crate::archiver::{
    collect_input_items, pack_archive, InputFileItem, OperationStats, PackConfig, ProgressTracker,
};
use crate::explorer::{
    is_explorer_registered, register_explorer_integration, unregister_explorer_integration,
};
use crate::external_archive::{
    extract_any_preview_bytes, extract_any_to_temp_file, is_supported_archive_path,
    pack_zip_archive, read_any_archive_index, smart_extract_dir, unpack_any_archive,
    verify_any_archive,
};
use crate::format::{
    format_bytes, is_previewable_image, resolve_base_smc_path, ArchiveFormat, ArchiveIndex,
    ChunkMethod, CompressionMode, FileEntry, OutputFormat, SplitPreset, DEFAULT_DEV_EXCLUDES,
};
use eframe::egui::{
    self, Color32, ColorImage, FontData, FontDefinitions, FontFamily, RichText, ScrollArea,
    TextureHandle, TextureOptions,
};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::thread;

#[derive(PartialEq, Eq, Clone, Copy)]
enum AppTab {
    Packer,
    Viewer,
}

enum WorkerResult {
    PackFinished(PathBuf, Result<OperationStats, String>),
    UnpackFinished(PathBuf, Result<OperationStats, String>),
    VerifyFinished(PathBuf, Result<OperationStats, String>),
    InstantOpenFinished(String, Result<PathBuf, String>),
}

#[derive(Clone, Copy)]
pub enum StartupAction {
    None,
    OpenArchive,
    AutoPack,
    AutoExtract,
}

/// Content loaded into the built-in instant preview modal
enum PreviewPayload {
    Text {
        content: String,
        line_count: usize,
        truncated: bool,
        encoding_label: &'static str,
    },
    Image {
        texture: TextureHandle,
        width: u32,
        height: u32,
    },
    HexDump {
        dump: String,
        total_bytes: u64,
    },
}

struct ActivePreview {
    entry: FileEntry,
    payload: PreviewPayload,
}

pub struct SmcGuiApp {
    tab: AppTab,

    // Pack staging state
    input_roots: Vec<PathBuf>,
    staged_files: Vec<InputFileItem>,
    staged_empty_dirs_count: usize,
    staged_excluded_count: usize,
    staged_total_bytes: u64,
    staged_smart_count: usize,

    // Pack options
    output_format: OutputFormat,
    comp_mode: CompressionMode,
    split_preset: SplitPreset,
    custom_split_mb: u64,
    smart_bypass: bool,
    filter_dev_dirs: bool,
    exclude_text: String,
    pack_password: String,
    show_pack_password: bool,

    // Archive viewer state
    opened_smc_path: Option<PathBuf>,
    opened_index: Option<ArchiveIndex>,
    selected_entries: HashSet<String>,
    search_query: String,
    viewer_password: String,
    password_modal_error: Option<String>,
    needs_password_modal: bool,
    pending_auto_extract: bool,
    active_preview: Option<ActivePreview>,

    // Background worker & progress state
    is_working: bool,
    work_title: String,
    progress: Arc<ProgressTracker>,
    worker_rx: Option<mpsc::Receiver<WorkerResult>>,
    last_stats: Option<(String, OperationStats, Option<PathBuf>)>,

    // Status & Explorer integration
    status_msg: String,
    is_error_status: bool,
    explorer_registered: bool,
}

impl SmcGuiApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        startup_path: Option<PathBuf>,
        startup_action: StartupAction,
    ) -> Self {
        setup_korean_fonts(&cc.egui_ctx);
        setup_visual_style(&cc.egui_ctx);

        let default_excludes = DEFAULT_DEV_EXCLUDES.join(", ");
        let mut app = Self {
            tab: AppTab::Packer,
            input_roots: Vec::new(),
            staged_files: Vec::new(),
            staged_empty_dirs_count: 0,
            staged_excluded_count: 0,
            staged_total_bytes: 0,
            staged_smart_count: 0,
            output_format: OutputFormat::Smc,
            comp_mode: CompressionMode::SmartAuto,
            split_preset: SplitPreset::None,
            custom_split_mb: 10,
            smart_bypass: true,
            filter_dev_dirs: false,
            exclude_text: default_excludes,
            pack_password: String::new(),
            show_pack_password: false,
            opened_smc_path: None,
            opened_index: None,
            selected_entries: HashSet::new(),
            search_query: String::new(),
            viewer_password: String::new(),
            password_modal_error: None,
            needs_password_modal: false,
            pending_auto_extract: false,
            active_preview: None,
            is_working: false,
            work_title: String::new(),
            progress: ProgressTracker::new(),
            worker_rx: None,
            last_stats: None,
            status_msg: format!(
                "준비 완료 · 활성 CPU 스레드: {}개 멀티코어 엔진 대기 중 (.smc / .zip / .7z 지원)",
                rayon::current_num_threads()
            ),
            is_error_status: false,
            explorer_registered: is_explorer_registered(),
        };

        if let Some(path) = startup_path {
            match startup_action {
                StartupAction::OpenArchive => {
                    app.open_smc_file(path, false);
                }
                StartupAction::AutoExtract => {
                    app.open_smc_file(path, true);
                }
                StartupAction::AutoPack => {
                    app.input_roots.push(path.clone());
                    app.refresh_staged_files();
                    let out_smc = default_output_archive_path(&path, OutputFormat::Smc);
                    app.start_packing(out_smc);
                }
                StartupAction::None => {
                    if is_supported_archive_path(&path) {
                        app.open_smc_file(path, false);
                    } else {
                        app.input_roots.push(path);
                        app.refresh_staged_files();
                    }
                }
            }
        }

        app
    }

    fn parse_excludes(&self) -> Vec<String> {
        self.exclude_text
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    fn refresh_staged_files(&mut self) {
        let excludes = self.parse_excludes();
        match collect_input_items(
            &self.input_roots,
            self.filter_dev_dirs,
            &excludes,
            self.smart_bypass,
        ) {
            Ok((items, empty_dirs, excluded)) => {
                self.staged_total_bytes = items.iter().map(|i| i.size).sum();
                self.staged_smart_count = items.iter().filter(|i| i.will_smart_bypass).count();
                self.staged_files = items;
                self.staged_empty_dirs_count = empty_dirs.len();
                self.staged_excluded_count = excluded;
                self.is_error_status = false;
                let empty_note = if self.staged_empty_dirs_count > 0 {
                    format!(" · 빈 폴더 {}개 보존", self.staged_empty_dirs_count)
                } else {
                    String::new()
                };
                self.status_msg = format!(
                    "대상 파일 {}개 ({}) 준비됨 · 스마트패스 {}개{} · 제외된 개발 항목 {}개",
                    self.staged_files.len(),
                    format_bytes(self.staged_total_bytes),
                    self.staged_smart_count,
                    empty_note,
                    self.staged_excluded_count
                );
            }
            Err(e) => {
                self.is_error_status = true;
                self.status_msg = format!("파일 스캔 오류: {}", e);
            }
        }
    }

    fn open_smc_file(&mut self, path: PathBuf, auto_extract: bool) {
        let resolved = resolve_base_smc_path(&path);
        self.tab = AppTab::Viewer;
        self.opened_smc_path = Some(resolved);
        self.opened_index = None;
        self.selected_entries.clear();
        self.active_preview = None;
        self.password_modal_error = None;
        self.pending_auto_extract = auto_extract;
        self.try_load_index();
    }

    fn try_load_index(&mut self) {
        let Some(ref path) = self.opened_smc_path.clone() else {
            return;
        };
        let pw_opt = if self.viewer_password.is_empty() {
            None
        } else {
            Some(self.viewer_password.as_str())
        };

        match read_any_archive_index(path, pw_opt) {
            Ok(index) => {
                self.needs_password_modal = false;
                self.password_modal_error = None;
                for f in &index.files {
                    self.selected_entries.insert(f.rel_path.clone());
                }
                self.is_error_status = false;
                let vol_note = if index.volume_count > 1 {
                    format!(" · 분할 볼륨 {}개", index.volume_count)
                } else {
                    String::new()
                };
                self.status_msg = format!(
                    "📂 '{}' [{}] 로드 완료 · 파일 {}개 (원본 {} → 압축 {}){} · 더블클릭으로 즉시 미리보기/실행!",
                    path.file_name().unwrap_or_default().to_string_lossy(),
                    index.format.label(),
                    index.files.len(),
                    format_bytes(index.total_original_size),
                    format_bytes(index.total_compressed_size),
                    vol_note
                );
                let smart_dest = smart_extract_dir(path, &index);
                self.opened_index = Some(index);

                if self.pending_auto_extract {
                    self.pending_auto_extract = false;
                    self.start_unpacking(smart_dest, false);
                }
            }
            Err(e) => {
                let msg = format!("{:#}", e);
                if msg.contains("PASSWORD_REQUIRED") {
                    self.needs_password_modal = true;
                    self.password_modal_error = None;
                    self.is_error_status = false;
                    self.status_msg =
                        "🔒 암호화된 아카이브입니다. 비밀번호를 입력해 주세요.".to_string();
                } else if !self.viewer_password.is_empty() {
                    self.needs_password_modal = true;
                    self.password_modal_error = Some(msg.clone());
                    self.is_error_status = true;
                    self.status_msg = format!("아카이브 잠금 해제 실패: {}", msg);
                } else {
                    self.needs_password_modal = false;
                    self.is_error_status = true;
                    self.status_msg = format!("❌ 아카이브 읽기 실패: {}", msg);
                }
            }
        }
    }

    /// Opens the built-in quick preview modal using bounded-memory extraction (never OOMs on huge files)
    fn open_entry_preview(&mut self, ctx: &egui::Context, entry: &FileEntry) {
        let Some(ref smc_path) = self.opened_smc_path else {
            return;
        };
        let pw_opt = if self.viewer_password.is_empty() {
            None
        } else {
            Some(self.viewer_password.as_str())
        };

        let is_img = is_previewable_image(&entry.rel_path) && entry.original_size <= 32 * 1024 * 1024;
        let max_preview_cap = if is_img {
            32 * 1024 * 1024
        } else {
            128 * 1024
        };

        match extract_any_preview_bytes(smc_path, entry, pw_opt, max_preview_cap) {
            Ok(bytes) => {
                if is_img {
                    if let Ok(dyn_img) = image::load_from_memory(&bytes) {
                        let rgba = dyn_img.to_rgba8();
                        let width = rgba.width();
                        let height = rgba.height();
                        let color_image = ColorImage::from_rgba_unmultiplied(
                            [width as usize, height as usize],
                            rgba.as_flat_samples().as_slice(),
                        );
                        let texture = ctx.load_texture(
                            format!("preview_{}", entry.rel_path),
                            color_image,
                            TextureOptions::LINEAR,
                        );
                        self.active_preview = Some(ActivePreview {
                            entry: entry.clone(),
                            payload: PreviewPayload::Image {
                                texture,
                                width,
                                height,
                            },
                        });
                        self.is_error_status = false;
                        self.status_msg = format!(
                            "🖼 이미지 미리보기 열림: {} ({}x{})",
                            entry.rel_path, width, height
                        );
                        return;
                    }
                }

                // Check UTF-8, UTF-16 LE BOM, or Korean CP949 (EUC-KR) text
                let total_exceeds = entry.original_size > 128 * 1024;
                if let Some((text_str, slice_trunc, encoding_label)) =
                    decode_text_preview_with_encoding(&bytes, 128 * 1024)
                {
                    let line_count = text_str.lines().count();
                    self.active_preview = Some(ActivePreview {
                        entry: entry.clone(),
                        payload: PreviewPayload::Text {
                            content: text_str,
                            line_count,
                            truncated: slice_trunc || total_exceeds,
                            encoding_label,
                        },
                    });
                    self.is_error_status = false;
                    self.status_msg = format!(
                        "📄 텍스트/코드 미리보기 열림 ({}): {}",
                        encoding_label, entry.rel_path
                    );
                    return;
                }

                // Fallback: Hex + ASCII Inspector preview for binary files
                let dump = format_hex_dump(&bytes, 4096);
                self.active_preview = Some(ActivePreview {
                    entry: entry.clone(),
                    payload: PreviewPayload::HexDump {
                        dump,
                        total_bytes: entry.original_size,
                    },
                });
                self.is_error_status = false;
                self.status_msg = format!("🔍 바이너리 헥스 미리보기 열림: {}", entry.rel_path);
            }
            Err(e) => {
                self.is_error_status = true;
                self.status_msg = format!("미리보기 추출 실패: {}", e);
            }
        }
    }

    /// Extracts a single file to %TEMP% (on a background thread if large) and launches it in Windows
    fn execute_entry_in_os(&mut self, entry: &FileEntry) {
        let Some(ref smc_path) = self.opened_smc_path else {
            return;
        };
        if self.is_working {
            return;
        }

        let is_7z = self
            .opened_index
            .as_ref()
            .map(|idx| idx.format == ArchiveFormat::SevenZ)
            .unwrap_or(false);

        // Small .smc/.zip files (<= 8 MB) extract in <10ms; larger files or solid .7z use background worker so UI never freezes
        if !is_7z && entry.original_size <= 8 * 1024 * 1024 {
            let pw_opt = if self.viewer_password.is_empty() {
                None
            } else {
                Some(self.viewer_password.as_str())
            };
            match extract_any_to_temp_file(smc_path, entry, pw_opt) {
                Ok(temp_file) => {
                    let _ = Command::new("explorer.exe").arg(&temp_file).spawn();
                    self.is_error_status = false;
                    self.status_msg = format!(
                        "🚀 즉시 실행됨: {} (임시 경로: {})",
                        entry.rel_path,
                        temp_file.display()
                    );
                }
                Err(e) => {
                    self.is_error_status = true;
                    self.status_msg = format!("파일 즉시 실행 실패: {}", e);
                }
            }
        } else {
            let smc_clone = smc_path.clone();
            let entry_clone = entry.clone();
            let pw_opt = if self.viewer_password.is_empty() {
                None
            } else {
                Some(self.viewer_password.clone())
            };

            self.progress = ProgressTracker::new();
            self.progress
                .total_bytes
                .store(entry.original_size, Ordering::Relaxed);
            self.progress.total_files.store(1, Ordering::Relaxed);
            self.progress.set_current(entry.rel_path.clone());

            let (tx, rx) = mpsc::channel();
            self.worker_rx = Some(rx);
            self.is_working = true;
            self.work_title = format!("🚀 임시 추출 후 실행 준비 중... ({})", entry.rel_path);

            thread::spawn(move || {
                let res = extract_any_to_temp_file(&smc_clone, &entry_clone, pw_opt.as_deref())
                    .map_err(|e| format!("{:#}", e));
                let _ = tx.send(WorkerResult::InstantOpenFinished(
                    entry_clone.rel_path,
                    res,
                ));
            });
        }
    }

    fn start_packing(&mut self, output_path: PathBuf) {
        if self.input_roots.is_empty() || self.is_working {
            return;
        }
        let inputs = self.input_roots.clone();
        let out_fmt = if output_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.eq_ignore_ascii_case("zip"))
            .unwrap_or(false)
        {
            OutputFormat::Zip
        } else {
            self.output_format
        };

        let config = PackConfig {
            mode: self.comp_mode,
            smart_bypass: self.smart_bypass,
            filter_dev_dirs: self.filter_dev_dirs,
            custom_excludes: self.parse_excludes(),
            password: if self.pack_password.is_empty() {
                None
            } else {
                Some(self.pack_password.clone())
            },
            split_size_bytes: if out_fmt == OutputFormat::Smc {
                self.split_preset.to_bytes(self.custom_split_mb)
            } else {
                None
            },
        };

        self.progress = ProgressTracker::new();
        let progress_clone = Arc::clone(&self.progress);
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.is_working = true;
        self.work_title = format!(
            "⚡ .{} 아카이브 압축 중... ({})",
            out_fmt.ext(),
            output_path.file_name().unwrap_or_default().to_string_lossy()
        );

        thread::spawn(move || {
            let res = match out_fmt {
                OutputFormat::Smc => pack_archive(&inputs, &output_path, &config, progress_clone),
                OutputFormat::Zip => {
                    pack_zip_archive(&inputs, &output_path, &config, progress_clone)
                }
            }
            .map_err(|e| format!("{:#}", e));
            let _ = tx.send(WorkerResult::PackFinished(output_path, res));
        });
    }

    fn start_unpacking(&mut self, dest_dir: PathBuf, only_selected: bool) {
        let Some(ref smc_path) = self.opened_smc_path else {
            return;
        };
        if self.is_working {
            return;
        }

        let smc_clone = smc_path.clone();
        let pw_opt = if self.viewer_password.is_empty() {
            None
        } else {
            Some(self.viewer_password.clone())
        };
        let sel_opt = if only_selected {
            Some(self.selected_entries.clone())
        } else {
            None
        };

        self.progress = ProgressTracker::new();
        let progress_clone = Arc::clone(&self.progress);
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.is_working = true;
        self.work_title = format!(
            "📂 병렬 압축 해제 중... ({})",
            dest_dir.display()
        );

        thread::spawn(move || {
            let res = unpack_any_archive(
                &smc_clone,
                &dest_dir,
                pw_opt.as_deref(),
                sel_opt.as_ref(),
                progress_clone,
            )
            .map_err(|e| format!("{:#}", e));
            let _ = tx.send(WorkerResult::UnpackFinished(dest_dir, res));
        });
    }

    fn start_verifying(&mut self) {
        let Some(ref smc_path) = self.opened_smc_path else {
            return;
        };
        if self.is_working {
            return;
        }

        let smc_clone = smc_path.clone();
        let pw_opt = if self.viewer_password.is_empty() {
            None
        } else {
            Some(self.viewer_password.clone())
        };

        self.progress = ProgressTracker::new();
        let progress_clone = Arc::clone(&self.progress);
        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.is_working = true;
        self.work_title = format!(
            "🛡 무결성 및 CRC32 검증 중... ({})",
            smc_clone.file_name().unwrap_or_default().to_string_lossy()
        );

        thread::spawn(move || {
            let res = verify_any_archive(&smc_clone, pw_opt.as_deref(), progress_clone)
                .map_err(|e| format!("{:#}", e));
            let _ = tx.send(WorkerResult::VerifyFinished(smc_clone, res));
        });
    }

    fn create_sample_and_benchmark(&mut self) {
        if self.is_working {
            return;
        }
        let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let sample_dir = base_dir.join("smc_sample_data");
        let _ = fs::create_dir_all(sample_dir.join("src"));
        let _ = fs::create_dir_all(sample_dir.join("media"));
        let _ = fs::create_dir_all(sample_dir.join("empty_cache_dir"));
        let _ = fs::create_dir_all(sample_dir.join("node_modules/dummy_pkg"));

        let repeated_log = "2026-10-18 INFO [SMC-Engine] Multi-core Zstd/LZ4 parallel block compression active! Double-click this file inside the archive to preview it instantly.\n".repeat(75_000);
        let _ = fs::write(sample_dir.join("src/server_log.txt"), &repeated_log);

        let repeated_json = r#"{"id":1024,"service":"smc-archiver","status":"fast","features":["custom-icon","instant-preview","split-volumes","zstd","lz4","aes256","zip","7z"]}
"#.repeat(50_000);
        let _ = fs::write(sample_dir.join("src/dataset.json"), &repeated_json);

        if let Ok(png_bytes) = generate_sample_png(320, 180) {
            let _ = fs::write(sample_dir.join("media/preview_banner.png"), png_bytes);
        }

        let dummy_media: Vec<u8> = (0..8_000_000u32)
            .map(|i| ((i.wrapping_mul(1664525).wrapping_add(1013904223)) >> 24) as u8)
            .collect();
        let _ = fs::write(sample_dir.join("media/sample_video.mp4"), &dummy_media);

        let _ = fs::write(
            sample_dir.join("node_modules/dummy_pkg/index.js"),
            "console.log('should be filtered out when dev filter is enabled');",
        );

        self.output_format = OutputFormat::Smc;
        self.filter_dev_dirs = true;
        self.input_roots.clear();
        self.input_roots.push(sample_dir);
        self.refresh_staged_files();

        let out_smc = base_dir.join("sample_benchmark.smc");
        self.start_packing(out_smc);
    }
}

impl eframe::App for SmcGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(ref rx) = self.worker_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_working = false;
                self.worker_rx = None;
                match result {
                    WorkerResult::PackFinished(out_path, Ok(stats)) => {
                        let ratio = if stats.total_original_bytes > 0 {
                            (stats.total_compressed_bytes as f64
                                / stats.total_original_bytes as f64)
                                * 100.0
                        } else {
                            100.0
                        };
                        let vol_info = if stats.volume_count > 1 {
                            format!(" · 분할 볼륨 {}개(.smc + .s01..)", stats.volume_count)
                        } else {
                            String::new()
                        };
                        self.is_error_status = false;
                        self.status_msg = format!(
                            "✅ 압축 완료! '{}'{} · {:.2}초 소요 ({:.1} MB/s) · 압축비 {:.1}%",
                            out_path.display(),
                            vol_info,
                            stats.elapsed_secs,
                            stats.throughput_mb_s(),
                            ratio
                        );
                        let parent_dir = out_path.parent().map(Path::to_path_buf);
                        self.last_stats = Some(("압축 완료".to_string(), stats, parent_dir));
                        self.viewer_password = self.pack_password.clone();
                        self.open_smc_file(out_path, false);
                    }
                    WorkerResult::PackFinished(_, Err(err)) => {
                        self.is_error_status = true;
                        self.status_msg = format!("❌ 압축 실패: {}", err);
                    }
                    WorkerResult::UnpackFinished(dest_dir, Ok(stats)) => {
                        self.is_error_status = false;
                        self.status_msg = format!(
                            "✅ 압축 해제 완료! '{}' · 파일 {}개 · {:.2}초 소요 ({:.1} MB/s)",
                            dest_dir.display(),
                            stats.file_count,
                            stats.elapsed_secs,
                            stats.throughput_mb_s()
                        );
                        self.last_stats =
                            Some(("압축 해제 완료".to_string(), stats, Some(dest_dir)));
                    }
                    WorkerResult::UnpackFinished(_, Err(err)) => {
                        self.is_error_status = true;
                        self.status_msg = format!("❌ 압축 해제 실패: {}", err);
                    }
                    WorkerResult::VerifyFinished(arc_path, Ok(stats)) => {
                        self.is_error_status = false;
                        self.status_msg = format!(
                            "🛡 무결성 검증 완벽 통과! '{}' · 파일 {}개 ({}) 모든 체크섬/암호 태그 이상 없음 · {:.2}초 ({:.1} MB/s)",
                            arc_path.file_name().unwrap_or_default().to_string_lossy(),
                            stats.file_count,
                            format_bytes(stats.total_original_bytes),
                            stats.elapsed_secs,
                            stats.throughput_mb_s()
                        );
                        self.last_stats = Some(("무결성 검증 통과".to_string(), stats, None));
                    }
                    WorkerResult::VerifyFinished(_, Err(err)) => {
                        self.is_error_status = true;
                        self.status_msg = format!("❌ 무결성 검증 실패 (손상 감지): {}", err);
                    }
                    WorkerResult::InstantOpenFinished(rel_path, Ok(temp_file)) => {
                        let _ = Command::new("explorer.exe").arg(&temp_file).spawn();
                        self.is_error_status = false;
                        self.status_msg = format!(
                            "🚀 즉시 실행됨: {} (임시 경로: {})",
                            rel_path,
                            temp_file.display()
                        );
                    }
                    WorkerResult::InstantOpenFinished(_, Err(err)) => {
                        self.is_error_status = true;
                        self.status_msg = format!("❌ 파일 즉시 실행 실패: {}", err);
                    }
                }
            }
        }

        if self.is_working {
            ctx.request_repaint();
        }

        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if !dropped.is_empty() && !self.is_working {
            let paths: Vec<PathBuf> = dropped.into_iter().filter_map(|d| d.path).collect();
            if paths.len() == 1 && is_supported_archive_path(&paths[0]) {
                self.viewer_password.clear();
                self.open_smc_file(paths[0].clone(), false);
            } else if !paths.is_empty() {
                self.tab = AppTab::Packer;
                for p in paths {
                    if !self.input_roots.contains(&p) {
                        self.input_roots.push(p);
                    }
                }
                self.refresh_staged_files();
            }
        }

        egui::TopBottomPanel::top("top_header").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(
                    RichText::new("⚡ SMC Archiver")
                        .size(22.0)
                        .strong()
                        .color(Color32::from_rgb(88, 166, 255)),
                );
                ui.label(
                    RichText::new("v1.2 · .smc / .zip / .7z 통합 · 더블클릭 미리보기/실행 · 무결성 검증")
                        .size(12.5)
                        .color(Color32::GRAY),
                );
                ui.separator();

                ui.selectable_value(
                    &mut self.tab,
                    AppTab::Packer,
                    RichText::new("📦 새 압축 만들기 (.smc / .zip)")
                        .size(15.0)
                        .strong(),
                );
                ui.selectable_value(
                    &mut self.tab,
                    AppTab::Viewer,
                    RichText::new("📂 아카이브 열기 (.smc / .zip / .7z)")
                        .size(15.0)
                        .strong(),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(
                            RichText::new("🧪 원클릭 샘플 속도 테스트")
                                .color(Color32::from_rgb(120, 230, 160)),
                        )
                        .on_hover_text("샘플 로그/JSON/PNG 이미지/영상/빈 폴더/node_modules를 자동 생성하고 초고속 .smc 압축을 즉시 테스트합니다.")
                        .clicked()
                    {
                        self.create_sample_and_benchmark();
                    }
                });
            });
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("bottom_status").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let color = if self.is_error_status {
                    Color32::from_rgb(255, 110, 110)
                } else {
                    Color32::from_rgb(160, 220, 255)
                };
                ui.label(RichText::new(&self.status_msg).color(color));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.explorer_registered {
                        if ui.button("연동 해제").clicked() {
                            match unregister_explorer_integration() {
                                Ok(_) => {
                                    self.explorer_registered = false;
                                    self.is_error_status = false;
                                    self.status_msg =
                                        "Windows 탐색기 우클릭 및 .smc 파일 연결이 해제되었습니다."
                                            .to_string();
                                }
                                Err(e) => {
                                    self.is_error_status = true;
                                    self.status_msg = format!("연동 해제 오류: {}", e);
                                }
                            }
                        }
                        if ui
                            .button("🔄 아이콘/연동 갱신")
                            .on_hover_text("전용 아이콘 및 탐색기 우클릭 메뉴를 최신 상태로 다시 적용합니다.")
                            .clicked()
                        {
                            let _ = register_explorer_integration();
                            self.status_msg =
                                "✅ 전용 .smc 아이콘 및 탐색기 연동이 갱신되었습니다!".to_string();
                        }
                        ui.label(
                            RichText::new("✅ 탐색기 & 전용 아이콘 연동됨")
                                .color(Color32::from_rgb(110, 230, 140)),
                        );
                    } else if ui
                        .button(
                            RichText::new("🔗 Windows 탐색기 & 전용 아이콘 등록 (.smc 더블클릭/우클릭)")
                                .strong(),
                        )
                        .clicked()
                    {
                        match register_explorer_integration() {
                            Ok(_) => {
                                self.explorer_registered = true;
                                self.is_error_status = false;
                                self.status_msg = "✅ 등록 완료! 이제 .smc 파일에 전용 아이콘이 표시되며 더블클릭 열기 및 우클릭 압축이 가능합니다.".to_string();
                            }
                            Err(e) => {
                                self.is_error_status = true;
                                self.status_msg = format!("탐색기 연동 등록 실패: {}", e);
                            }
                        }
                    }
                });
            });
            ui.add_space(4.0);
        });

        if let Some((ref title, ref stats, ref folder_opt)) = self.last_stats.clone() {
            egui::TopBottomPanel::bottom("stats_banner").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let ratio = if stats.total_original_bytes > 0 {
                        (stats.total_compressed_bytes as f64 / stats.total_original_bytes as f64)
                            * 100.0
                    } else {
                        100.0
                    };
                    ui.label(
                        RichText::new(format!("🏆 최근 작업 [{}]:", title))
                            .strong()
                            .color(Color32::from_rgb(255, 215, 100)),
                    );
                    ui.label(format!(
                        "속도 {:.1} MB/s ({:.2}초, {}스레드)  |  원본 {} → 아카이브 {} ({:.1}%)  |  볼륨 {}개  |  스마트패스 {}개  |  개발폴더 제외 {}개",
                        stats.throughput_mb_s(),
                        stats.elapsed_secs,
                        stats.threads_used,
                        format_bytes(stats.total_original_bytes),
                        format_bytes(stats.total_compressed_bytes),
                        ratio,
                        stats.volume_count,
                        stats.smart_bypassed_count,
                        stats.excluded_dev_count
                    ));
                    if let Some(ref dir) = folder_opt {
                        if ui.small_button("📂 결과 폴더 열기").clicked() {
                            let _ = Command::new("explorer.exe").arg(dir).spawn();
                        }
                    }
                    if ui.small_button("닫기").clicked() {
                        self.last_stats = None;
                    }
                });
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            AppTab::Packer => self.render_packer_tab(ui),
            AppTab::Viewer => self.render_viewer_tab(ctx, ui),
        });

        self.render_preview_modal(ctx);

        if self.is_working {
            egui::Window::new(&self.work_title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(460.0);
                    let done_b = self.progress.processed_bytes.load(Ordering::Relaxed);
                    let total_b = self.progress.total_bytes.load(Ordering::Relaxed);
                    let done_f = self.progress.processed_files.load(Ordering::Relaxed);
                    let total_f = self.progress.total_files.load(Ordering::Relaxed);

                    let frac = if total_b > 0 {
                        (done_b as f32 / total_b as f32).clamp(0.0, 1.0)
                    } else if total_f > 0 {
                        (done_f as f32 / total_f as f32).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };

                    ui.add_space(6.0);
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .show_percentage()
                            .animate(true),
                    );
                    ui.add_space(6.0);
                    ui.label(format!(
                        "진행 용량: {} / {}   (파일: {} / {}개)",
                        format_bytes(done_b),
                        format_bytes(total_b),
                        done_f,
                        total_f
                    ));
                    ui.label(
                        RichText::new(format!("처리 중: {}", self.progress.get_current()))
                            .size(12.0)
                            .color(Color32::GRAY),
                    );
                    ui.add_space(8.0);
                    if ui.button("⏹ 작업 취소").clicked() {
                        self.progress.is_cancelled.store(true, Ordering::Relaxed);
                    }
                });
        }

        if self.needs_password_modal {
            egui::Window::new("🔒 암호화된 아카이브 잠금 해제")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(380.0);
                    ui.label("이 아카이브(.smc / .zip / .7z)는 비밀번호로 암호화되어 있습니다.");
                    ui.label("열람 및 압축 해제를 위해 비밀번호를 입력해 주세요:");
                    if let Some(ref err_msg) = self.password_modal_error {
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(format!("⚠️ {}", err_msg))
                                .color(Color32::from_rgb(255, 110, 110))
                                .strong(),
                        );
                    }
                    ui.add_space(6.0);
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.viewer_password)
                            .password(true)
                            .hint_text("비밀번호 입력..."),
                    );
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.try_load_index();
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("🔓 확인 및 잠금 해제").clicked() {
                            self.try_load_index();
                        }
                        if ui.button("취소").clicked() {
                            self.needs_password_modal = false;
                            self.password_modal_error = None;
                        }
                    });
                });
        }
    }
}

impl SmcGuiApp {
    fn render_packer_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("➕ 파일 추가").size(14.0))
                .clicked()
            {
                if let Some(files) = rfd::FileDialog::new().pick_files() {
                    for f in files {
                        if !self.input_roots.contains(&f) {
                            self.input_roots.push(f);
                        }
                    }
                    self.refresh_staged_files();
                }
            }
            if ui
                .button(RichText::new("📁 폴더 추가").size(14.0))
                .clicked()
            {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    if !self.input_roots.contains(&folder) {
                        self.input_roots.push(folder);
                    }
                    self.refresh_staged_files();
                }
            }
            if ui.button("🔄 목록 새로고침").clicked() {
                self.refresh_staged_files();
            }
            if ui.button("🗑 목록 비우기").clicked() {
                self.input_roots.clear();
                self.staged_files.clear();
                self.staged_empty_dirs_count = 0;
                self.staged_total_bytes = 0;
                self.staged_smart_count = 0;
                self.staged_excluded_count = 0;
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let can_pack = (!self.staged_files.is_empty() || self.staged_empty_dirs_count > 0)
                    && !self.is_working;
                let btn_label = match self.output_format {
                    OutputFormat::Smc => "⚡ 지금 .smc로 초고속 압축하기",
                    OutputFormat::Zip => "📦 지금 표준 .zip으로 압축하기",
                };
                ui.add_enabled_ui(can_pack, |ui| {
                    if ui
                        .button(
                            RichText::new(btn_label)
                                .size(16.0)
                                .strong()
                                .color(Color32::from_rgb(255, 230, 120)),
                        )
                        .clicked()
                    {
                        let fmt = self.output_format;
                        let default_name = if let Some(first) = self.input_roots.first() {
                            default_output_archive_path(first, fmt)
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| format!("archive.{}", fmt.ext()))
                        } else {
                            format!("archive.{}", fmt.ext())
                        };

                        let dialog = match fmt {
                            OutputFormat::Smc => {
                                rfd::FileDialog::new().add_filter("SMC Archive (.smc)", &["smc"])
                            }
                            OutputFormat::Zip => {
                                rfd::FileDialog::new().add_filter("ZIP Archive (.zip)", &["zip"])
                            }
                        };
                        if let Some(out_path) = dialog.set_file_name(&default_name).save_file() {
                            self.start_packing(out_path);
                        }
                    }
                });
            });
        });

        ui.separator();

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("출력 포맷:").strong());
                egui::ComboBox::from_id_salt("output_fmt_combo")
                    .selected_text(self.output_format.label())
                    .width(245.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.output_format,
                            OutputFormat::Smc,
                            OutputFormat::Smc.label(),
                        );
                        ui.selectable_value(
                            &mut self.output_format,
                            OutputFormat::Zip,
                            OutputFormat::Zip.label(),
                        );
                    });

                ui.separator();
                ui.label(RichText::new("압축 엔진:").strong());
                egui::ComboBox::from_id_salt("comp_mode_combo")
                    .selected_text(self.comp_mode.label())
                    .width(245.0)
                    .show_ui(ui, |ui| {
                        for m in [
                            CompressionMode::SmartAuto,
                            CompressionMode::Lz4Fast,
                            CompressionMode::ZstdBalanced,
                            CompressionMode::ZstdMax,
                            CompressionMode::StoreOnly,
                        ] {
                            ui.selectable_value(&mut self.comp_mode, m, m.label());
                        }
                    });

                ui.separator();
                ui.add_enabled_ui(self.output_format == OutputFormat::Smc, |ui| {
                    ui.label(RichText::new("📦 분할 압축:").strong())
                        .on_hover_text(".smc 전용 기능입니다 (.zip 선택 시 단일 파일로 생성됨)");
                    egui::ComboBox::from_id_salt("split_preset_combo")
                        .selected_text(if self.output_format == OutputFormat::Smc {
                            self.split_preset.label()
                        } else {
                            "단일 파일 (.zip)"
                        })
                        .width(180.0)
                        .show_ui(ui, |ui| {
                            for sp in [
                                SplitPreset::None,
                                SplitPreset::Mb5,
                                SplitPreset::Mb10,
                                SplitPreset::Mb50,
                                SplitPreset::Mb100,
                                SplitPreset::Mb500,
                                SplitPreset::Gb1,
                                SplitPreset::Gb2,
                                SplitPreset::Gb4,
                                SplitPreset::Custom,
                            ] {
                                ui.selectable_value(&mut self.split_preset, sp, sp.label());
                            }
                        });

                    if self.output_format == OutputFormat::Smc
                        && self.split_preset == SplitPreset::Custom
                    {
                        ui.add(
                            egui::DragValue::new(&mut self.custom_split_mb)
                                .range(1..=65536)
                                .suffix(" MB"),
                        );
                    }
                });
            });

            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .checkbox(
                        &mut self.smart_bypass,
                        "⚡ 스마트 고속 아카이빙 (영상/이미지는 연산 생략)",
                    )
                    .changed()
                {
                    self.refresh_staged_files();
                }

                ui.separator();
                if ui
                    .checkbox(&mut self.filter_dev_dirs, "🧹 개발 캐시 폴더 제외 (선택)")
                    .on_hover_text("체크 시에만 node_modules, .git, target 등 개발 캐시 폴더를 건너뜁니다. 일반 폴더/게임/실행파일 압축 시에는 체크 해제를 권장합니다 (기본값: 해제).")
                    .changed()
                {
                    self.refresh_staged_files();
                }

                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.exclude_text)
                        .desired_width(230.0)
                        .hint_text("node_modules, .git, target ..."),
                );
                if resp.changed() && self.filter_dev_dirs {
                    self.refresh_staged_files();
                }

                ui.separator();
                ui.label("🔒 비밀번호:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.pack_password)
                        .password(!self.show_pack_password)
                        .desired_width(130.0)
                        .hint_text("선택 사항 (AES-256)"),
                );
                ui.checkbox(&mut self.show_pack_password, "표시");
            });
        });

        ui.add_space(6.0);

        ui.horizontal(|ui| {
            let split_desc = if self.output_format == OutputFormat::Smc {
                if let Some(sb) = self.split_preset.to_bytes(self.custom_split_mb) {
                    format!("  |  📦 볼륨당 최대 {} (.smc, .s01, .s02...)", format_bytes(sb))
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            let empty_desc = if self.staged_empty_dirs_count > 0 {
                format!("  |  📁 빈 폴더 보존: {}개", self.staged_empty_dirs_count)
            } else {
                String::new()
            };
            ui.label(
                RichText::new(format!(
                    "총 파일: {}개  |  원본 합계: {}  |  ⚡ 스마트패스: {}개{}  |  🧹 제외된 항목: {}개{}",
                    self.staged_files.len(),
                    format_bytes(self.staged_total_bytes),
                    self.staged_smart_count,
                    empty_desc,
                    self.staged_excluded_count,
                    split_desc
                ))
                .strong(),
            );
        });
        ui.add_space(4.0);

        if self.staged_files.is_empty() && self.staged_empty_dirs_count == 0 {
            egui::Frame::canvas(ui.style()).show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(70.0);
                    ui.heading("📥 여기에 파일/폴더(압축 생성) 또는 .smc/.zip/.7z(열기)를 드롭하세요");
                    ui.add_space(8.0);
                    ui.label("또는 상단의 [➕ 파일 추가] / [📁 폴더 추가] / [🧪 원클릭 샘플 속도 테스트] 버튼을 눌러보세요.");
                    ui.add_space(70.0);
                });
            });
        } else {
            egui::Frame::canvas(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [460.0, 20.0],
                        egui::Label::new(RichText::new("파일 상대 경로").strong()),
                    );
                    ui.add_sized(
                        [150.0, 20.0],
                        egui::Label::new(RichText::new("예정 처리 방식").strong()),
                    );
                    ui.add_sized(
                        [120.0, 20.0],
                        egui::Label::new(RichText::new("원본 크기").strong()),
                    );
                });
                ui.separator();

                let row_height = 22.0;
                let total_rows = self.staged_files.len();
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show_rows(ui, row_height, total_rows, |ui, row_range| {
                        for i in row_range {
                            let item = &self.staged_files[i];
                            ui.horizontal(|ui| {
                                ui.add_sized(
                                    [460.0, row_height],
                                    egui::Label::new(&item.rel_path).truncate(),
                                );
                                let (badge_txt, badge_col) = if item.will_smart_bypass
                                    || self.comp_mode == CompressionMode::StoreOnly
                                {
                                    ("STORE (스마트패스)", Color32::from_rgb(120, 230, 160))
                                } else if self.output_format == OutputFormat::Zip {
                                    ("DEFLATE (.zip)", Color32::from_rgb(255, 195, 110))
                                } else if self.comp_mode == CompressionMode::Lz4Fast {
                                    ("LZ4 멀티코어", Color32::from_rgb(100, 200, 255))
                                } else {
                                    ("ZSTD 멀티코어", Color32::from_rgb(190, 150, 255))
                                };
                                ui.add_sized(
                                    [150.0, row_height],
                                    egui::Label::new(RichText::new(badge_txt).color(badge_col)),
                                );
                                ui.add_sized(
                                    [120.0, row_height],
                                    egui::Label::new(format_bytes(item.size)),
                                );
                            });
                        }
                    });
            });
        }
    }

    fn render_viewer_tab(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("📂 압축 파일 열기 (.smc / .zip / .7z)...").size(14.0))
                .clicked()
            {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter(
                        "지원 압축 파일 (.smc, .zip, .7z, .s01, .001)",
                        &["smc", "s01", "zip", "7z", "001"],
                    )
                    .pick_file()
                {
                    self.viewer_password.clear();
                    self.open_smc_file(path, false);
                }
            }

            if let Some(ref p) = self.opened_smc_path {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "열린 파일: {}",
                            p.file_name().unwrap_or_default().to_string_lossy()
                        ))
                        .strong()
                        .color(Color32::from_rgb(140, 200, 255)),
                    )
                    .truncate(),
                )
                .on_hover_text(p.display().to_string());
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let has_archive = self.opened_index.is_some() && !self.is_working;
                ui.add_enabled_ui(has_archive, |ui| {
                    if ui
                        .button(
                            RichText::new("📂 폴더 지정해 풀기")
                                .size(14.5)
                                .strong()
                                .color(Color32::from_rgb(130, 240, 160)),
                        )
                        .clicked()
                    {
                        if let Some(dest) = rfd::FileDialog::new().pick_folder() {
                            self.start_unpacking(dest, false);
                        }
                    }

                    if ui
                        .button(
                            RichText::new(format!(
                                "☑️ 선택만 풀기 ({}개)",
                                self.selected_entries.len()
                            ))
                            .size(13.5),
                        )
                        .clicked()
                    {
                        if let Some(dest) = rfd::FileDialog::new().pick_folder() {
                            self.start_unpacking(dest, true);
                        }
                    }

                    if ui
                        .button(
                            RichText::new("⚡ 스마트 즉시 풀기")
                                .color(Color32::from_rgb(255, 225, 120)),
                        )
                        .on_hover_text(
                            "알아서 풀기: 단일 루트 폴더 아카이브는 이중 폴더(폴더/폴더) 없이 깔끔하게 풀고, 낱개 파일이 흩어진 아카이브는 자동으로 새 폴더에 안전하게 풉니다.",
                        )
                        .clicked()
                    {
                        if let (Some(ref smc_p), Some(ref idx)) =
                            (&self.opened_smc_path, &self.opened_index)
                        {
                            let dest = smart_extract_dir(smc_p, idx);
                            self.start_unpacking(dest, false);
                        }
                    }

                    if ui
                        .button(
                            RichText::new("🛡 무결성 검사")
                                .color(Color32::from_rgb(135, 210, 255)),
                        )
                        .on_hover_text(
                            "디스크에 파일을 쓰지 않고 모든 청크/블록 압축 해제, AES 인증 태그, CRC32 체크섬을 고속 검증합니다.",
                        )
                        .clicked()
                    {
                        self.start_verifying();
                    }
                });
            });
        });

        ui.separator();

        let Some(index) = self.opened_index.clone() else {
            egui::Frame::canvas(ui.style()).show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    ui.heading("📂 .smc / .zip / .7z 압축 파일을 열거나 이 창으로 드래그하세요");
                    ui.add_space(8.0);
                    ui.label("내부 파일을 더블클릭하면 전체 압축 해제 없이 즉시 미리보기 및 실행이 가능합니다 (레거시 한글 CP949 파일명 자동 복원 포함).");
                    ui.add_space(80.0);
                });
            });
            return;
        };

        let ratio = if index.total_original_size > 0 {
            (index.total_compressed_size as f64 / index.total_original_size as f64) * 100.0
        } else {
            100.0
        };
        let saved = index
            .total_original_size
            .saturating_sub(index.total_compressed_size);

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!("[{}]", index.format.label()))
                        .color(Color32::from_rgb(130, 210, 255))
                        .strong(),
                );
                ui.separator();
                ui.label(
                    RichText::new(format!("총 파일: {}개", index.files.len()))
                        .strong()
                        .size(14.0),
                );
                if !index.empty_dirs.is_empty() {
                    ui.label(
                        RichText::new(format!("(+빈 폴더 {}개)", index.empty_dirs.len()))
                            .color(Color32::GRAY),
                    );
                }
                ui.separator();
                ui.label(format!(
                    "원본: {}  →  압축: {} ({:.1}%, {} 절약)",
                    format_bytes(index.total_original_size),
                    format_bytes(index.total_compressed_size),
                    ratio,
                    format_bytes(saved)
                ));
                ui.separator();
                if index.volume_count > 1 {
                    ui.label(
                        RichText::new(format!("📦 분할 압축 ({}개 볼륨)", index.volume_count))
                            .color(Color32::from_rgb(100, 210, 255))
                            .strong(),
                    );
                } else {
                    ui.label(RichText::new("📦 단일 볼륨").color(Color32::GRAY));
                }
                ui.separator();
                ui.label(if index.encrypted {
                    RichText::new("🔒 AES 암호화됨").color(Color32::from_rgb(255, 200, 110))
                } else {
                    RichText::new("🔓 암호화 없음").color(Color32::GRAY)
                });
            });
        });

        ui.add_space(4.0);

        let all_paths: Vec<String> = index.files.iter().map(|f| f.rel_path.clone()).collect();
        ui.horizontal(|ui| {
            ui.label("🔍 검색:");
            ui.add(
                egui::TextEdit::singleline(&mut self.search_query)
                    .desired_width(220.0)
                    .hint_text("파일명 또는 확장자 필터..."),
            );
            if ui.button("전체 선택").clicked() {
                for p in &all_paths {
                    self.selected_entries.insert(p.clone());
                }
            }
            if ui.button("선택 해제").clicked() {
                self.selected_entries.clear();
            }
            ui.separator();
            ui.label(
                RichText::new("💡 팁: 파일 행을 더블클릭하거나 우측 [👁 미리보기] / [🚀 실행] 버튼을 눌러보세요!")
                    .color(Color32::from_rgb(255, 220, 120))
                    .size(12.5),
            );
        });

        ui.add_space(4.0);

        let query_lower = self.search_query.to_lowercase();
        let filtered: Vec<&FileEntry> = index
            .files
            .iter()
            .filter(|f| {
                query_lower.is_empty() || f.rel_path.to_lowercase().contains(&query_lower)
            })
            .collect();

        let mut preview_target: Option<FileEntry> = None;
        let mut execute_target: Option<FileEntry> = None;

        egui::Frame::canvas(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add_sized([36.0, 20.0], egui::Label::new(RichText::new("선택").strong()));
                ui.add_sized(
                    [310.0, 20.0],
                    egui::Label::new(RichText::new("파일 경로 (더블클릭: 즉시 미리보기/실행)").strong()),
                );
                ui.add_sized([120.0, 20.0], egui::Label::new(RichText::new("알고리즘").strong()));
                ui.add_sized([90.0, 20.0], egui::Label::new(RichText::new("원본 크기").strong()));
                ui.add_sized([90.0, 20.0], egui::Label::new(RichText::new("압축 크기").strong()));
                ui.add_sized([60.0, 20.0], egui::Label::new(RichText::new("압축비").strong()));
                ui.add_sized(
                    [150.0, 20.0],
                    egui::Label::new(RichText::new("즉시 동작").strong()),
                );
            });
            ui.separator();

            let row_height = 24.0;
            ScrollArea::vertical()
                .auto_shrink([false, false])
                .show_rows(ui, row_height, filtered.len(), |ui, row_range| {
                    for i in row_range {
                        let entry = filtered[i];
                        let mut is_sel = self.selected_entries.contains(&entry.rel_path);
                        ui.horizontal(|ui| {
                            if ui
                                .add_sized(
                                    [36.0, row_height],
                                    egui::Checkbox::without_text(&mut is_sel),
                                )
                                .changed()
                            {
                                if is_sel {
                                    self.selected_entries.insert(entry.rel_path.clone());
                                } else {
                                    self.selected_entries.remove(&entry.rel_path);
                                }
                            }

                            let path_resp = ui
                                .add_sized(
                                    [310.0, row_height],
                                    egui::SelectableLabel::new(false, &entry.rel_path),
                                )
                                .on_hover_text(format!(
                                    "{}\nCRC32: {:08X}\n더블클릭하면 즉시 미리보기/실행합니다.",
                                    entry.rel_path, entry.crc32
                                ));

                            if path_resp.double_clicked() {
                                if is_likely_direct_os_launch(&entry.rel_path) {
                                    execute_target = Some(entry.clone());
                                } else {
                                    preview_target = Some(entry.clone());
                                }
                            }

                            let method = entry.primary_method();
                            let m_color = match method {
                                ChunkMethod::Store => Color32::from_rgb(120, 230, 160),
                                ChunkMethod::Lz4 => Color32::from_rgb(100, 200, 255),
                                ChunkMethod::Zstd => Color32::from_rgb(190, 150, 255),
                                ChunkMethod::Deflate => Color32::from_rgb(255, 195, 110),
                                ChunkMethod::Lzma2 => Color32::from_rgb(255, 150, 195),
                                ChunkMethod::Other => Color32::LIGHT_GRAY,
                            };
                            ui.add_sized(
                                [120.0, row_height],
                                egui::Label::new(RichText::new(method.badge()).color(m_color)),
                            );
                            ui.add_sized(
                                [90.0, row_height],
                                egui::Label::new(format_bytes(entry.original_size)),
                            );
                            ui.add_sized(
                                [90.0, row_height],
                                egui::Label::new(format_bytes(entry.compressed_size)),
                            );
                            ui.add_sized(
                                [60.0, row_height],
                                egui::Label::new(format!("{:.1}%", entry.ratio_percent())),
                            );

                            if ui
                                .small_button("👁 미리보기")
                                .on_hover_text("내장 뷰어로 텍스트/코드/이미지/헥스 내용을 즉시 확인합니다.")
                                .clicked()
                            {
                                preview_target = Some(entry.clone());
                            }
                            if ui
                                .small_button("🚀 실행")
                                .on_hover_text("이 파일 하나만 임시 추출하여 Windows 기본 프로그램으로 즉시 실행합니다.")
                                .clicked()
                            {
                                execute_target = Some(entry.clone());
                            }
                        });
                    }
                });
        });

        if let Some(entry) = preview_target {
            self.open_entry_preview(ctx, &entry);
        }
        if let Some(entry) = execute_target {
            self.execute_entry_in_os(&entry);
        }
    }

    fn render_preview_modal(&mut self, ctx: &egui::Context) {
        let Some(ref preview) = self.active_preview else {
            return;
        };
        let entry_clone = preview.entry.clone();
        let mut close_modal = false;
        let mut launch_external = false;

        let mut is_open = true;
        egui::Window::new(format!("👁 아카이브 내부 미리보기 — {}", entry_clone.rel_path))
            .open(&mut is_open)
            .resizable(true)
            .default_size([680.0, 480.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "원본 크기: {}  |  압축 크기: {} ({:.1}%)  |  알고리즘: {}  |  CRC32: {:08X}",
                            format_bytes(entry_clone.original_size),
                            format_bytes(entry_clone.compressed_size),
                            entry_clone.ratio_percent(),
                            entry_clone.primary_method().badge(),
                            entry_clone.crc32
                        ))
                        .color(Color32::from_rgb(160, 210, 255)),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("닫기").clicked() {
                            close_modal = true;
                        }
                        if ui
                            .button(
                                RichText::new("🚀 외부 기본 프로그램으로 열기")
                                    .strong()
                                    .color(Color32::from_rgb(130, 240, 160)),
                            )
                            .clicked()
                        {
                            launch_external = true;
                        }
                        if let PreviewPayload::Text { ref content, .. } = preview.payload {
                            if ui.button("📋 텍스트 복사").clicked() {
                                ui.output_mut(|o| o.copied_text = content.clone());
                            }
                        }
                    });
                });
                ui.separator();

                match &preview.payload {
                    PreviewPayload::Text {
                        content,
                        line_count,
                        truncated,
                        encoding_label,
                    } => {
                        ui.label(
                            RichText::new(format!(
                                "텍스트/코드 뷰어 ({} · {}줄{})",
                                encoding_label,
                                line_count,
                                if *truncated {
                                    ", 앞부분 128KB 미리보기 표시 중"
                                } else {
                                    ""
                                }
                            ))
                            .size(12.0)
                            .color(Color32::GRAY),
                        );
                        ScrollArea::both()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let mut read_only = content.as_str();
                                ui.add(
                                    egui::TextEdit::multiline(&mut read_only)
                                        .font(egui::TextStyle::Monospace)
                                        .desired_width(f32::INFINITY),
                                );
                            });
                    }
                    PreviewPayload::Image {
                        texture,
                        width,
                        height,
                    } => {
                        ui.label(
                            RichText::new(format!("해상도: {} x {} px", width, height))
                                .size(12.5)
                                .color(Color32::GRAY),
                        );
                        ScrollArea::both()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let avail = ui.available_size();
                                let scale = (avail.x / (*width as f32))
                                    .min(avail.y / (*height as f32))
                                    .min(1.0)
                                    .max(0.1);
                                let size =
                                    egui::vec2(*width as f32 * scale, *height as f32 * scale);
                                ui.image((texture.id(), size));
                            });
                    }
                    PreviewPayload::HexDump { dump, total_bytes } => {
                        ui.label(
                            RichText::new(format!(
                                "바이너리 파일 헥스(Hex) 미리보기 (전체 {} 중 앞부분 4KB 표시)",
                                format_bytes(*total_bytes)
                            ))
                            .size(12.0)
                            .color(Color32::GRAY),
                        );
                        ScrollArea::both()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let mut read_only = dump.as_str();
                                ui.add(
                                    egui::TextEdit::multiline(&mut read_only)
                                        .font(egui::TextStyle::Monospace)
                                        .desired_width(f32::INFINITY),
                                );
                            });
                    }
                }
            });

        if !is_open || close_modal {
            self.active_preview = None;
        }
        if launch_external {
            self.execute_entry_in_os(&entry_clone);
        }
    }
}

fn is_likely_direct_os_launch(rel_path: &str) -> bool {
    Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "mp4" | "mkv" | "avi" | "mov" | "mp3" | "wav" | "pdf" | "docx" | "xlsx" | "pptx" | "exe" | "msi"
            )
        })
        .unwrap_or(false)
}

/// Safely decodes UTF-8, UTF-16 LE BOM, or Korean CP949 (EUC-KR) text
pub fn decode_text_preview(bytes: &[u8], max_bytes: usize) -> Option<(String, bool)> {
    decode_text_preview_with_encoding(bytes, max_bytes).map(|(s, trunc, _)| (s, trunc))
}

pub fn decode_text_preview_with_encoding(
    bytes: &[u8],
    max_bytes: usize,
) -> Option<(String, bool, &'static str)> {
    if bytes.is_empty() {
        return Some((String::new(), false, "UTF-8"));
    }

    // 1. Check UTF-16 LE BOM (FF FE)
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let body = &bytes[2..];
        let truncated = body.len() > max_bytes;
        let limit = (body.len().min(max_bytes) / 2) * 2;
        let u16_words: Vec<u16> = body[..limit]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&u16_words) {
            return Some((s, truncated, "UTF-16 LE"));
        }
    }

    // 2. Strip UTF-8 BOM (EF BB BF) if present
    let body = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    };

    let truncated = body.len() > max_bytes;
    let slice = if truncated { &body[..max_bytes] } else { body };

    // Reject binary files that contain NUL bytes
    if slice.contains(&0) {
        return None;
    }

    match std::str::from_utf8(slice) {
        Ok(s) => Some((s.to_string(), truncated, "UTF-8")),
        Err(e) => {
            if truncated && e.error_len().is_none() && e.valid_up_to() > 0 {
                let valid_slice = &slice[..e.valid_up_to()];
                if let Ok(s) = std::str::from_utf8(valid_slice) {
                    return Some((s.to_string(), true, "UTF-8"));
                }
            }
            // 3. Fallback: Try Korean CP949 (ANSI/EUC-KR) via Windows MultiByteToWideChar
            if let Some(cp949_str) = try_decode_cp949(slice) {
                return Some((cp949_str, truncated, "CP949/EUC-KR"));
            }
            None
        }
    }
}

/// Uses Windows native CodePage 949 (Unified Hangul Code / EUC-KR) to decode legacy Korean text files
fn try_decode_cp949(slice: &[u8]) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn MultiByteToWideChar(
                CodePage: u32,
                dwFlags: u32,
                lpMultiByteStr: *const u8,
                cbMultiByte: i32,
                lpWideCharStr: *mut u16,
                cchWideChar: i32,
            ) -> i32;
        }
        const CP_949: u32 = 949;
        const MB_ERR_INVALID_CHARS: u32 = 0x00000008;

        // If truncated at max_bytes, trim at most 1 trailing lead byte if needed
        for trim in 0..=1 {
            if slice.len() <= trim {
                break;
            }
            let sub = &slice[..slice.len() - trim];
            unsafe {
                let needed = MultiByteToWideChar(
                    CP_949,
                    MB_ERR_INVALID_CHARS,
                    sub.as_ptr(),
                    sub.len() as i32,
                    std::ptr::null_mut(),
                    0,
                );
                if needed > 0 {
                    let mut wide = vec![0u16; needed as usize];
                    let written = MultiByteToWideChar(
                        CP_949,
                        MB_ERR_INVALID_CHARS,
                        sub.as_ptr(),
                        sub.len() as i32,
                        wide.as_mut_ptr(),
                        needed,
                    );
                    if written > 0 {
                        if let Ok(s) = String::from_utf16(&wide[..written as usize]) {
                            return Some(s);
                        }
                    }
                }
            }
        }
    }
    None
}

fn format_hex_dump(bytes: &[u8], limit: usize) -> String {
    let slice = &bytes[..bytes.len().min(limit)];
    let mut out = String::new();
    for (row_idx, chunk) in slice.chunks(16).enumerate() {
        out.push_str(&format!("{:08X}  ", row_idx * 16));
        for i in 0..16 {
            if i < chunk.len() {
                out.push_str(&format!("{:02X} ", chunk[i]));
            } else {
                out.push_str("   ");
            }
            if i == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for &b in chunk {
            if (0x20..=0x7E).contains(&b) {
                out.push(b as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}

/// Generates a colorful sample PNG image in memory for testing the built-in image previewer
fn generate_sample_png(width: u32, height: u32) -> Result<Vec<u8>, image::ImageError> {
    let mut img = image::RgbaImage::new(width, height);
    for (x, y, pixel) in img.enumerate_pixels_mut() {
        let r = ((x * 255) / width) as u8;
        let g = ((y * 255) / height) as u8;
        let b = 210u8;
        *pixel = image::Rgba([r, g, b, 255]);
    }
    let mut buf = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut buf);
    img.write_to(&mut cursor, image::ImageFormat::Png)?;
    Ok(buf)
}

fn default_output_archive_path(input: &Path, fmt: OutputFormat) -> PathBuf {
    let base_name = if input.is_dir() {
        input.file_name()
    } else {
        input.file_stem().or_else(|| input.file_name())
    }
    .and_then(|s| s.to_str())
    .unwrap_or("archive");
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{}.{}", base_name, fmt.ext()))
}

/// Loads Windows Malgun Gothic (맑은 고딕) so Korean UI renders cleanly
fn setup_korean_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let font_candidates = [
        r"C:\Windows\Fonts\malgun.ttf",
        r"C:\Windows\Fonts\NanumGothic.ttf",
        r"C:\Windows\Fonts\gulim.ttc",
    ];

    for path in font_candidates {
        if let Ok(bytes) = fs::read(path) {
            fonts
                .font_data
                .insert("korean_font".to_owned(), FontData::from_owned(bytes).into());
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .insert(0, "korean_font".to_owned());
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .push("korean_font".to_owned());
            break;
        }
    }
    ctx.set_fonts(fonts);
}

fn setup_visual_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_rounding = egui::Rounding::same(8.0);
    visuals.widgets.noninteractive.rounding = egui::Rounding::same(6.0);
    visuals.widgets.inactive.rounding = egui::Rounding::same(6.0);
    visuals.widgets.hovered.rounding = egui::Rounding::same(6.0);
    visuals.widgets.active.rounding = egui::Rounding::same(6.0);
    ctx.set_visuals(visuals);
}
