use crate::crypto::{
    decrypt_block, derive_key, derive_key_versioned, encrypt_block, generate_salt, INDEX_BLOCK_ID,
};
use crate::format::{
    is_already_compressed_ext, resolve_base_smc_path, should_exclude_path, volume_path_for,
    ArchiveFormat, ArchiveIndex, ChunkMeta, ChunkMethod, CompressionMode, FileEntry, CHUNK_SIZE,
    FLAG_ENCRYPTED, FLAG_KDF_V2, FLAG_SPLIT_VOLUME, HEADER_SIZE, MAX_CHUNK_UNCOMPRESSED_SIZE,
    MAX_INDEX_COMPRESSED_SIZE, MAX_INDEX_UNCOMPRESSED_SIZE, SMC_FOOTER_MAGIC, SMC_MAGIC,
};
use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};
use walkdir::WalkDir;

/// Shared progress tracker updated by worker threads and read by the GUI
pub struct ProgressTracker {
    pub total_bytes: AtomicU64,
    pub processed_bytes: AtomicU64,
    pub total_files: AtomicUsize,
    pub processed_files: AtomicUsize,
    pub smart_bypassed_files: AtomicUsize,
    pub excluded_dev_items: AtomicUsize,
    pub current_item: Mutex<String>,
    pub is_cancelled: AtomicBool,
}

impl ProgressTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            total_bytes: AtomicU64::new(0),
            processed_bytes: AtomicU64::new(0),
            total_files: AtomicUsize::new(0),
            processed_files: AtomicUsize::new(0),
            smart_bypassed_files: AtomicUsize::new(0),
            excluded_dev_items: AtomicUsize::new(0),
            current_item: Mutex::new(String::new()),
            is_cancelled: AtomicBool::new(false),
        })
    }

    pub fn set_current(&self, text: impl Into<String>) {
        if let Ok(mut guard) = self.current_item.lock() {
            *guard = text.into();
        }
    }

    pub fn get_current(&self) -> String {
        self.current_item
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

/// Configuration for creating a .smc archive
#[derive(Debug, Clone)]
pub struct PackConfig {
    pub mode: CompressionMode,
    pub smart_bypass: bool,
    pub filter_dev_dirs: bool,
    pub custom_excludes: Vec<String>,
    pub password: Option<String>,
    /// Optional split-volume size in bytes (None = single .smc file)
    pub split_size_bytes: Option<u64>,
}

/// Result summary after packing or unpacking
#[derive(Debug, Clone)]
pub struct OperationStats {
    pub elapsed_secs: f64,
    pub total_original_bytes: u64,
    pub total_compressed_bytes: u64,
    pub file_count: usize,
    pub smart_bypassed_count: usize,
    pub excluded_dev_count: usize,
    pub threads_used: usize,
    pub volume_count: usize,
}

impl OperationStats {
    pub fn throughput_mb_s(&self) -> f64 {
        let secs = self.elapsed_secs.max(0.001);
        (self.total_original_bytes as f64 / (1024.0 * 1024.0)) / secs
    }
}

/// Multi-volume sequential writer that splits output across `.smc`, `.s01`, `.s02`, ...
struct MultiVolumeWriter {
    base_smc: PathBuf,
    split_limit: Option<u64>,
    current_vol_index: usize,
    current_vol_written: u64,
    writer: BufWriter<File>,
}

impl MultiVolumeWriter {
    fn new(base_smc: &Path, split_limit: Option<u64>) -> Result<Self> {
        if let Some(parent) = base_smc.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        cleanup_volumes(base_smc, false);

        let first_file = File::create(base_smc)
            .with_context(|| format!("출력 파일 생성 실패: {}", base_smc.display()))?;
        Ok(Self {
            base_smc: base_smc.to_path_buf(),
            split_limit: split_limit.map(|s| s.max(64 * 1024)), // minimum 64 KB per volume
            current_vol_index: 0,
            current_vol_written: 0,
            writer: BufWriter::with_capacity(4 * 1024 * 1024, first_file),
        })
    }

    fn write_all_bytes(&mut self, mut data: &[u8]) -> Result<()> {
        if let Some(limit) = self.split_limit {
            while !data.is_empty() {
                let remaining_in_vol = limit.saturating_sub(self.current_vol_written);
                if remaining_in_vol == 0 {
                    self.rotate_volume()?;
                    continue;
                }
                let to_write = (data.len() as u64).min(remaining_in_vol) as usize;
                self.writer.write_all(&data[..to_write])?;
                self.current_vol_written += to_write as u64;
                data = &data[to_write..];
            }
            Ok(())
        } else {
            self.writer.write_all(data)?;
            self.current_vol_written += data.len() as u64;
            Ok(())
        }
    }

    fn rotate_volume(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.current_vol_index += 1;
        let next_path = volume_path_for(&self.base_smc, self.current_vol_index);
        let next_file = File::create(&next_path)
            .with_context(|| format!("분할 볼륨 파일 생성 실패: {}", next_path.display()))?;
        self.writer = BufWriter::with_capacity(4 * 1024 * 1024, next_file);
        self.current_vol_written = 0;
        Ok(())
    }

    fn finalize_and_write_header(&mut self, header: &[u8; HEADER_SIZE]) -> Result<usize> {
        self.writer.flush()?;
        let total_volumes = self.current_vol_index + 1;

        let mut vol0 = OpenOptions::new()
            .write(true)
            .open(&self.base_smc)
            .context("헤더 기록을 위해 메인 .smc 파일을 열 수 없습니다.")?;
        vol0.seek(SeekFrom::Start(0))?;
        vol0.write_all(header)?;
        vol0.flush()?;

        Ok(total_volumes)
    }
}

/// Removes `.s01`, `.s02`, ... and optionally the base `.smc` file (used on cancel/error cleanup)
fn cleanup_volumes(base_smc: &Path, include_base: bool) {
    if include_base && base_smc.exists() {
        let _ = fs::remove_file(base_smc);
    }
    for idx in 1..=99_999 {
        let vp = volume_path_for(base_smc, idx);
        if vp.exists() {
            let _ = fs::remove_file(vp);
        } else {
            break;
        }
    }
}

/// Thread-safe multi-volume reader that maps logical archive offsets across `.smc`, `.s01`, `.s02`, ...
pub struct MultiVolumeReader {
    volumes: Vec<(PathBuf, u64, u64)>, // (path, logical_start, logical_end)
}

impl MultiVolumeReader {
    pub fn open(smc_or_part_path: &Path) -> Result<Self> {
        let base_smc = resolve_base_smc_path(smc_or_part_path);
        if !base_smc.exists() {
            bail!(
                "기본 .smc 아카이브 파일을 찾을 수 없습니다: {}",
                base_smc.display()
            );
        }

        let mut volumes = Vec::new();
        let mut logical_cursor = 0u64;

        let vol0_len = fs::metadata(&base_smc)?.len();
        volumes.push((base_smc.clone(), 0, vol0_len));
        logical_cursor += vol0_len;

        for idx in 1..=99_999 {
            let vp = volume_path_for(&base_smc, idx);
            if vp.exists() {
                let len = fs::metadata(&vp)?.len();
                volumes.push((vp, logical_cursor, logical_cursor + len));
                logical_cursor += len;
            } else {
                break;
            }
        }

        Ok(Self { volumes })
    }

    pub fn volume_count(&self) -> usize {
        self.volumes.len()
    }

    pub fn total_size(&self) -> u64 {
        self.volumes.last().map(|v| v.2).unwrap_or(0)
    }

    /// Reads exact `buf.len()` bytes starting at `logical_offset`, seamlessly spanning volume boundaries
    /// using O(log N) binary search across volume intervals.
    pub fn read_exact_at(&self, mut logical_offset: u64, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            let vol_idx = self
                .volumes
                .partition_point(|(_, _, end)| *end <= logical_offset);
            let vol = self.volumes.get(vol_idx).ok_or_else(|| {
                anyhow!(
                    "아카이브 오프셋 범위 초과 또는 분할 볼륨(.s01 등) 누락 (요청 오프셋: {}, 전체 크기: {})",
                    logical_offset,
                    self.total_size()
                )
            })?;

            let offset_in_vol = logical_offset - vol.1;
            let avail_in_vol = (vol.2 - logical_offset) as usize;
            let to_read = buf.len().min(avail_in_vol);

            let mut f = File::open(&vol.0)
                .with_context(|| format!("볼륨 파일을 열 수 없습니다: {}", vol.0.display()))?;
            f.seek(SeekFrom::Start(offset_in_vol))?;
            f.read_exact(&mut buf[..to_read])?;

            logical_offset += to_read as u64;
            buf = &mut buf[to_read..];
        }
        Ok(())
    }
}

/// Candidate input file discovered on disk before packing
#[derive(Debug, Clone)]
pub struct InputFileItem {
    pub abs_path: PathBuf,
    pub rel_path: String,
    pub size: u64,
    pub modified_unix: i64,
    pub will_smart_bypass: bool,
}

/// Fast path key normalization without expensive per-file kernel syscalls
pub(crate) fn fast_norm_key(p: &Path) -> String {
    p.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn mark_parent_prefixes(rel_path: &str, non_empty_dirs: &mut HashSet<String>) {
    for (idx, b) in rel_path.bytes().enumerate() {
        if b == b'/' && idx > 0 {
            let prefix = &rel_path[..idx];
            if !non_empty_dirs.contains(prefix) {
                non_empty_dirs.insert(prefix.to_string());
            }
        }
    }
}

/// Scans input files and directories, preserving empty directories, applying optional dev-folder filtering,
/// and disambiguating duplicate relative file paths.
pub fn collect_input_items(
    inputs: &[PathBuf],
    filter_dev_dirs: bool,
    exclude_list: &[String],
    smart_bypass: bool,
) -> Result<(Vec<InputFileItem>, Vec<String>, usize)> {
    let mut items = Vec::new();
    let mut visited_dirs = Vec::new();
    let mut seen_dir_rels = HashSet::new();
    let mut excluded_count = 0usize;
    let mut seen_rel_paths = HashSet::new();
    let mut seen_abs_keys = HashSet::new();

    for input in inputs {
        if !input.exists() {
            continue;
        }
        let parent_base = input.parent().unwrap_or_else(|| Path::new(""));

        if input.is_file() {
            if !seen_abs_keys.insert(fast_norm_key(input)) {
                continue;
            }
            let rel = input
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| input.clone());
            if filter_dev_dirs && should_exclude_path(&rel, exclude_list) {
                excluded_count += 1;
                continue;
            }
            let meta = fs::metadata(input)?;
            let rel_str = disambiguate_rel_path(&normalize_rel_path(&rel), &mut seen_rel_paths);
            let modified_unix = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            items.push(InputFileItem {
                abs_path: input.clone(),
                rel_path: rel_str,
                size: meta.len(),
                modified_unix,
                will_smart_bypass: smart_bypass && is_already_compressed_ext(input),
            });
        } else if input.is_dir() {
            let mut walker = WalkDir::new(input).follow_links(false).into_iter();
            while let Some(entry_res) = walker.next() {
                let entry = match entry_res {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let path = entry.path();
                let rel = path.strip_prefix(parent_base).unwrap_or(path);

                if filter_dev_dirs && should_exclude_path(rel, exclude_list) {
                    excluded_count += 1;
                    if entry.file_type().is_dir() {
                        walker.skip_current_dir();
                    }
                    continue;
                }

                if entry.file_type().is_dir() {
                    let dir_rel = normalize_rel_path(rel);
                    if !dir_rel.is_empty() && seen_dir_rels.insert(dir_rel.clone()) {
                        visited_dirs.push(dir_rel);
                    }
                } else if entry.file_type().is_file() {
                    if !seen_abs_keys.insert(fast_norm_key(path)) {
                        continue;
                    }
                    let meta = match entry.metadata() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let rel_str =
                        disambiguate_rel_path(&normalize_rel_path(rel), &mut seen_rel_paths);
                    let modified_unix = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    items.push(InputFileItem {
                        abs_path: path.to_path_buf(),
                        rel_path: rel_str,
                        size: meta.len(),
                        modified_unix,
                        will_smart_bypass: smart_bypass && is_already_compressed_ext(path),
                    });
                }
            }
        }
    }

    let mut non_empty_dirs = HashSet::new();
    for item in &items {
        mark_parent_prefixes(&item.rel_path, &mut non_empty_dirs);
    }
    for dir in &visited_dirs {
        mark_parent_prefixes(dir, &mut non_empty_dirs);
    }
    let empty_dirs: Vec<String> = visited_dirs
        .into_iter()
        .filter(|d| !non_empty_dirs.contains(d))
        .collect();

    Ok((items, empty_dirs, excluded_count))
}

/// Convenience wrapper returning discovered input files and excluded count
pub fn collect_input_files(
    inputs: &[PathBuf],
    filter_dev_dirs: bool,
    exclude_list: &[String],
    smart_bypass: bool,
) -> Result<(Vec<InputFileItem>, usize)> {
    let (items, _empty_dirs, excluded) =
        collect_input_items(inputs, filter_dev_dirs, exclude_list, smart_bypass)?;
    Ok((items, excluded))
}

/// Ensures two different files with the same relative name (e.g. from different folders) never overwrite or drop each other
fn disambiguate_rel_path(candidate: &str, seen: &mut HashSet<String>) -> String {
    if seen.insert(candidate.to_string()) {
        return candidate.to_string();
    }
    let path = Path::new(candidate);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = path.extension().and_then(|e| e.to_str());
    let parent = path
        .parent()
        .and_then(|p| p.to_str())
        .filter(|p| !p.is_empty());

    for counter in 2..=9999 {
        let new_name = match ext {
            Some(e) => format!("{} ({}).{}", stem, counter, e),
            None => format!("{} ({})", stem, counter),
        };
        let full = match parent {
            Some(p) => format!("{}/{}", p.replace('\\', "/"), new_name),
            None => new_name,
        };
        if seen.insert(full.clone()) {
            return full;
        }
    }
    candidate.to_string()
}

fn normalize_rel_path(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Compresses a single chunk in memory according to mode & smart bypass
fn compress_chunk_bytes(
    raw: &[u8],
    mode: CompressionMode,
    force_store: bool,
) -> Result<(Vec<u8>, ChunkMethod)> {
    if force_store || mode == CompressionMode::StoreOnly || raw.len() < 64 {
        return Ok((raw.to_vec(), ChunkMethod::Store));
    }

    match mode {
        CompressionMode::SmartAuto => {
            let compressed = zstd::bulk::compress(raw, 1).context("Zstd 고속 압축 실패")?;
            if compressed.len() >= (raw.len() * 98) / 100 {
                Ok((raw.to_vec(), ChunkMethod::Store))
            } else {
                Ok((compressed, ChunkMethod::Zstd))
            }
        }
        CompressionMode::Lz4Fast => {
            let compressed = lz4_flex::compress_prepend_size(raw);
            if compressed.len() >= (raw.len() * 98) / 100 {
                Ok((raw.to_vec(), ChunkMethod::Store))
            } else {
                Ok((compressed, ChunkMethod::Lz4))
            }
        }
        CompressionMode::ZstdBalanced => {
            let compressed = zstd::bulk::compress(raw, 3).context("Zstd 밸런스 압축 실패")?;
            if compressed.len() >= (raw.len() * 99) / 100 {
                Ok((raw.to_vec(), ChunkMethod::Store))
            } else {
                Ok((compressed, ChunkMethod::Zstd))
            }
        }
        CompressionMode::ZstdMax => {
            let compressed = zstd::bulk::compress(raw, 9).context("Zstd 고압축 실패")?;
            if compressed.len() >= (raw.len() * 99) / 100 {
                Ok((raw.to_vec(), ChunkMethod::Store))
            } else {
                Ok((compressed, ChunkMethod::Zstd))
            }
        }
        CompressionMode::StoreOnly => Ok((raw.to_vec(), ChunkMethod::Store)),
    }
}

/// Decompresses a single chunk in memory
fn decompress_chunk_bytes(
    data: &[u8],
    method: ChunkMethod,
    uncompressed_size: usize,
) -> Result<Vec<u8>> {
    match method {
        ChunkMethod::Store => Ok(data.to_vec()),
        ChunkMethod::Lz4 => lz4_flex::decompress_size_prepended(data)
            .map_err(|e| anyhow!("LZ4 블록 압축 해제 실패: {}", e)),
        ChunkMethod::Zstd => zstd::bulk::decompress(data, uncompressed_size)
            .map_err(|e| anyhow!("Zstd 블록 압축 해제 실패: {}", e)),
        other => bail!("SMC 컨테이너에서 지원하지 않는 청크 압축 방식입니다: {:?}", other),
    }
}

/// Packs input files/folders into a .smc archive (single or multi-volume split) using all CPU cores.
/// Automatically cleans up partial output files if cancelled or an error occurs.
pub fn pack_archive(
    inputs: &[PathBuf],
    output_smc: &Path,
    config: &PackConfig,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    match pack_archive_inner(inputs, output_smc, config, progress) {
        Ok(stats) => Ok(stats),
        Err(e) => {
            cleanup_volumes(output_smc, true);
            Err(e)
        }
    }
}

fn pack_archive_inner(
    inputs: &[PathBuf],
    output_smc: &Path,
    config: &PackConfig,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    let start_time = Instant::now();

    let (mut files, empty_dirs, excluded_dev_count) = collect_input_items(
        inputs,
        config.filter_dev_dirs,
        &config.custom_excludes,
        config.smart_bypass,
    )?;

    // Prevent self-inclusion bug if output_smc (or its split volumes) is inside one of the input folders
    let out_stem = output_smc
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let out_parent_key = output_smc.parent().map(fast_norm_key).unwrap_or_default();

    files.retain(|item| {
        let item_parent_key = item.abs_path.parent().map(fast_norm_key).unwrap_or_default();
        if out_parent_key == item_parent_key {
            let item_stem = item
                .abs_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if item_stem == out_stem {
                if let Some(ext) = item.abs_path.extension().and_then(|e| e.to_str()) {
                    let lower_ext = ext.to_ascii_lowercase();
                    if lower_ext == "smc"
                        || (lower_ext.starts_with('s')
                            && lower_ext.len() >= 3
                            && lower_ext[1..].chars().all(|c| c.is_ascii_digit()))
                    {
                        return false;
                    }
                }
            }
        }
        true
    });

    if files.is_empty() && empty_dirs.is_empty() {
        bail!("압축할 파일이나 폴더가 없습니다. (모든 항목이 제외되었거나 대상이 비어 있습니다)");
    }

    let total_bytes: u64 = files.iter().map(|f| f.size).sum();
    let smart_bypassed_count = files.iter().filter(|f| f.will_smart_bypass).count();

    progress.total_bytes.store(total_bytes, Ordering::Relaxed);
    progress.total_files.store(files.len(), Ordering::Relaxed);
    progress
        .smart_bypassed_files
        .store(smart_bypassed_count, Ordering::Relaxed);
    progress
        .excluded_dev_items
        .store(excluded_dev_count, Ordering::Relaxed);

    let encrypted = config
        .password
        .as_ref()
        .map(|p| !p.is_empty())
        .unwrap_or(false);
    let salt = if encrypted { generate_salt() } else { [0u8; 16] };
    let derived_key = if let Some(ref pw) = config.password {
        if !pw.is_empty() {
            Some(derive_key(pw, &salt))
        } else {
            None
        }
    } else {
        None
    };

    let mut vol_writer = MultiVolumeWriter::new(output_smc, config.split_size_bytes)?;

    // Write placeholder 32-byte header in Volume 0
    vol_writer.write_all_bytes(&[0u8; HEADER_SIZE])?;
    let mut current_offset = HEADER_SIZE as u64;
    let mut global_chunk_id = 0u64;

    const BATCH_BYTES_LIMIT: u64 = 128 * 1024 * 1024;
    let mut file_entries = Vec::with_capacity(files.len());

    let mut idx = 0;
    while idx < files.len() {
        if progress.is_cancelled.load(Ordering::Relaxed) {
            bail!("사용자에 의해 압축 작업이 취소되었습니다.");
        }

        let single_file_chunks = (files[idx].size as usize) > CHUNK_SIZE * 2;
        if single_file_chunks {
            let item = &files[idx];
            progress.set_current(format!("대용량 병렬 처리 중: {}", item.rel_path));

            let mut f = File::open(&item.abs_path)
                .with_context(|| format!("파일 열기 실패: {}", item.abs_path.display()))?;
            let mut hasher = crc32fast::Hasher::new();
            let mut chunks_meta = Vec::new();
            let mut file_comp_size = 0u64;

            let num_threads = rayon::current_num_threads().max(4);
            let sub_batch_count = num_threads * 2;

            loop {
                if progress.is_cancelled.load(Ordering::Relaxed) {
                    bail!("사용자에 의해 압축 작업이 취소되었습니다.");
                }

                let mut raw_chunks: Vec<(u64, Vec<u8>)> = Vec::with_capacity(sub_batch_count);
                for _ in 0..sub_batch_count {
                    let mut buf = vec![0u8; CHUNK_SIZE];
                    let n = read_up_to(&mut f, &mut buf)?;
                    if n == 0 {
                        break;
                    }
                    buf.truncate(n);
                    hasher.update(&buf);
                    let cid = global_chunk_id;
                    global_chunk_id += 1;
                    raw_chunks.push((cid, buf));
                }

                if raw_chunks.is_empty() {
                    break;
                }

                let processed_chunks: Result<Vec<(u64, usize, Vec<u8>, ChunkMethod)>> = raw_chunks
                    .into_par_iter()
                    .map(|(cid, raw_buf)| {
                        let orig_len = raw_buf.len();
                        let (mut comp_bytes, method) =
                            compress_chunk_bytes(&raw_buf, config.mode, item.will_smart_bypass)?;
                        if let Some(ref key) = derived_key {
                            comp_bytes = encrypt_block(&comp_bytes, key, &salt, cid)?;
                        }
                        progress
                            .processed_bytes
                            .fetch_add(orig_len as u64, Ordering::Relaxed);
                        Ok((cid, orig_len, comp_bytes, method))
                    })
                    .collect();

                for (cid, orig_len, comp_bytes, method) in processed_chunks? {
                    let comp_len = comp_bytes.len() as u64;
                    vol_writer.write_all_bytes(&comp_bytes)?;
                    chunks_meta.push(ChunkMeta {
                        chunk_id: cid,
                        offset: current_offset,
                        compressed_size: comp_len,
                        uncompressed_size: orig_len as u64,
                        method,
                    });
                    current_offset += comp_len;
                    file_comp_size += comp_len;
                }
            }

            let crc32 = hasher.finalize();
            progress.processed_files.fetch_add(1, Ordering::Relaxed);

            file_entries.push(FileEntry {
                rel_path: item.rel_path.clone(),
                original_size: item.size,
                compressed_size: file_comp_size,
                crc32,
                modified_unix: item.modified_unix,
                smart_bypassed: item.will_smart_bypass,
                chunks: chunks_meta,
            });
            idx += 1;
        } else {
            let mut batch_end = idx;
            let mut batch_bytes = 0u64;
            while batch_end < files.len()
                && (files[batch_end].size as usize) <= CHUNK_SIZE * 2
                && (batch_bytes + files[batch_end].size <= BATCH_BYTES_LIMIT || batch_end == idx)
            {
                batch_bytes += files[batch_end].size;
                batch_end += 1;
            }

            let batch_slice = &files[idx..batch_end];
            let base_chunk_id = global_chunk_id;
            global_chunk_id += batch_slice.len() as u64;

            let batch_results: Result<Vec<(FileEntry, Vec<u8>, ChunkMethod)>> = batch_slice
                .par_iter()
                .enumerate()
                .map(|(i, item)| {
                    if progress.is_cancelled.load(Ordering::Relaxed) {
                        bail!("사용자에 의해 압축 작업이 취소되었습니다.");
                    }
                    progress.set_current(item.rel_path.clone());
                    let raw = fs::read(&item.abs_path)
                        .with_context(|| format!("파일 읽기 실패: {}", item.abs_path.display()))?;
                    let orig_len = raw.len() as u64;
                    let crc32 = crc32fast::hash(&raw);

                    let cid = base_chunk_id + i as u64;
                    let (mut comp_bytes, method) =
                        compress_chunk_bytes(&raw, config.mode, item.will_smart_bypass)?;
                    if let Some(ref key) = derived_key {
                        comp_bytes = encrypt_block(&comp_bytes, key, &salt, cid)?;
                    }

                    progress.processed_bytes.fetch_add(orig_len, Ordering::Relaxed);
                    progress.processed_files.fetch_add(1, Ordering::Relaxed);

                    let entry = FileEntry {
                        rel_path: item.rel_path.clone(),
                        original_size: orig_len,
                        compressed_size: comp_bytes.len() as u64,
                        crc32,
                        modified_unix: item.modified_unix,
                        smart_bypassed: item.will_smart_bypass,
                        chunks: vec![ChunkMeta {
                            chunk_id: cid,
                            offset: 0,
                            compressed_size: comp_bytes.len() as u64,
                            uncompressed_size: orig_len,
                            method,
                        }],
                    };
                    Ok((entry, comp_bytes, method))
                })
                .collect();

            for (mut entry, comp_bytes, _method) in batch_results? {
                if !entry.chunks.is_empty() {
                    entry.chunks[0].offset = current_offset;
                }
                vol_writer.write_all_bytes(&comp_bytes)?;
                current_offset += comp_bytes.len() as u64;
                file_entries.push(entry);
            }

            idx = batch_end;
        }
    }

    let total_compressed_size: u64 = file_entries.iter().map(|f| f.compressed_size).sum();
    let split_size_bytes = config.split_size_bytes.unwrap_or(0);
    let estimated_vols = if split_size_bytes > 0 {
        ((current_offset + 4096) / split_size_bytes).max(1) as usize
    } else {
        1
    };

    let mut archive_index = ArchiveIndex {
        version: 2,
        created_unix: Utc::now().timestamp(),
        mode_used: config.mode,
        encrypted,
        total_original_size: total_bytes,
        total_compressed_size,
        volume_count: estimated_vols,
        split_size_bytes,
        files: file_entries,
        empty_dirs,
        format: ArchiveFormat::Smc,
    };

    let index_offset = current_offset;
    let temp_json = serde_json::to_vec(&archive_index)?;
    let temp_comp = zstd::bulk::compress(&temp_json, 3)?;
    let total_archive_len = index_offset + 16 + temp_comp.len() as u64 + 32;
    archive_index.volume_count = if split_size_bytes > 0 {
        ((total_archive_len + split_size_bytes - 1) / split_size_bytes).max(1) as usize
    } else {
        1
    };

    let index_json = serde_json::to_vec(&archive_index)?;
    let index_uncompressed_len = index_json.len() as u64;
    let mut index_compressed = zstd::bulk::compress(&index_json, 3)?;
    if let Some(ref key) = derived_key {
        index_compressed = encrypt_block(&index_compressed, key, &salt, INDEX_BLOCK_ID)?;
    }
    let index_compressed_len = index_compressed.len() as u64;

    vol_writer.write_all_bytes(&index_compressed_len.to_le_bytes())?;
    vol_writer.write_all_bytes(&index_uncompressed_len.to_le_bytes())?;
    vol_writer.write_all_bytes(&index_compressed)?;
    vol_writer.write_all_bytes(SMC_FOOTER_MAGIC)?;

    let mut flags: u32 = 0;
    if encrypted {
        flags |= FLAG_ENCRYPTED | FLAG_KDF_V2;
    }
    if split_size_bytes > 0 {
        flags |= FLAG_SPLIT_VOLUME;
    }

    let mut header = [0u8; HEADER_SIZE];
    header[0..4].copy_from_slice(SMC_MAGIC);
    header[4..8].copy_from_slice(&flags.to_le_bytes());
    header[8..24].copy_from_slice(&salt);
    header[24..32].copy_from_slice(&index_offset.to_le_bytes());

    let actual_volumes = vol_writer.finalize_and_write_header(&header)?;

    Ok(OperationStats {
        elapsed_secs: start_time.elapsed().as_secs_f64(),
        total_original_bytes: total_bytes,
        total_compressed_bytes: total_compressed_size,
        file_count: archive_index.files.len(),
        smart_bypassed_count,
        excluded_dev_count,
        threads_used: rayon::current_num_threads(),
        volume_count: actual_volumes,
    })
}

fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Restores a file's original modification timestamp on disk
pub(crate) fn restore_file_mtime(path: &Path, modified_unix: i64) {
    if modified_unix > 0 {
        let mtime = UNIX_EPOCH + Duration::from_secs(modified_unix as u64);
        if let Ok(f) = OpenOptions::new().write(true).open(path) {
            let _ = f.set_modified(mtime);
        }
    }
}

/// Header info parsed from the first 32 bytes of a .smc file
#[derive(Debug, Clone)]
pub struct SmcHeaderInfo {
    pub encrypted: bool,
    pub split_volume: bool,
    pub kdf_v2: bool,
    pub salt: [u8; 16],
    pub index_offset: u64,
}

/// Reads and validates the 32-byte header of a .smc file (or resolves from .s01)
pub fn read_smc_header(smc_path: &Path) -> Result<SmcHeaderInfo> {
    let base_smc = resolve_base_smc_path(smc_path);
    let mut f = File::open(&base_smc)
        .with_context(|| format!(".smc 파일을 열 수 없습니다: {}", base_smc.display()))?;
    let mut header = [0u8; HEADER_SIZE];
    f.read_exact(&mut header)
        .context("유효한 .smc 파일이 아닙니다 (헤더 길이 부족)")?;

    if &header[0..4] != SMC_MAGIC {
        bail!("유효한 .smc 포맷이 아닙니다 (SMC 매직 시그니처 불일치)");
    }

    let flags = u32::from_le_bytes(header[4..8].try_into().unwrap());
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&header[8..24]);
    let index_offset = u64::from_le_bytes(header[24..32].try_into().unwrap());

    Ok(SmcHeaderInfo {
        encrypted: (flags & FLAG_ENCRYPTED) != 0,
        split_volume: (flags & FLAG_SPLIT_VOLUME) != 0,
        kdf_v2: (flags & FLAG_KDF_V2) != 0,
        salt,
        index_offset,
    })
}

/// Validates bounds, reads, optionally decrypts, and decompresses a single .smc chunk safely (prevents OOM on corrupt files)
fn read_and_decode_chunk(
    reader: &MultiVolumeReader,
    chunk: &ChunkMeta,
    derived_key: Option<&[u8; 32]>,
    salt: &[u8; 16],
) -> Result<Vec<u8>> {
    let total_size = reader.total_size();
    let end_offset = chunk
        .offset
        .checked_add(chunk.compressed_size)
        .ok_or_else(|| anyhow!("손상된 아카이브 청크입니다 (오프셋 오버플로우)"))?;
    if chunk.offset < HEADER_SIZE as u64 || end_offset > total_size {
        bail!(
            "손상된 청크 범위입니다 (오프셋 {}..{}, 전체 크기 {} · 분할 볼륨 누락 여부 확인)",
            chunk.offset,
            end_offset,
            total_size
        );
    }
    if chunk.uncompressed_size as usize > MAX_CHUNK_UNCOMPRESSED_SIZE {
        bail!(
            "비정상적인 청크 원본 크기({})가 감지되어 메모리 보호를 위해 차단했습니다.",
            chunk.uncompressed_size
        );
    }
    if chunk.compressed_size as usize > MAX_CHUNK_UNCOMPRESSED_SIZE + 65536 {
        bail!(
            "비정상적인 청크 압축 크기({})가 감지되어 메모리 보호를 위해 차단했습니다.",
            chunk.compressed_size
        );
    }

    let mut buf = vec![0u8; chunk.compressed_size as usize];
    reader.read_exact_at(chunk.offset, &mut buf)?;
    if let Some(key) = derived_key {
        buf = decrypt_block(&buf, key, salt, chunk.chunk_id)?;
    }
    let raw = decompress_chunk_bytes(&buf, chunk.method, chunk.uncompressed_size as usize)?;
    if raw.len() as u64 != chunk.uncompressed_size {
        bail!(
            "청크 압축 해제 크기 불일치 (예상 {} B, 실제 {} B)",
            chunk.uncompressed_size,
            raw.len()
        );
    }
    Ok(raw)
}

/// Reads the Footer Index Table from a .smc archive (supports both single and split-volume archives, with OOM bounds checks)
pub fn read_archive_index(smc_path: &Path, password: Option<&str>) -> Result<ArchiveIndex> {
    let header = read_smc_header(smc_path)?;
    if header.encrypted && password.map(|p| p.is_empty()).unwrap_or(true) {
        bail!("PASSWORD_REQUIRED");
    }

    let reader = MultiVolumeReader::open(smc_path)?;
    let total_size = reader.total_size();
    if header.index_offset < HEADER_SIZE as u64 || header.index_offset.saturating_add(20) > total_size
    {
        bail!(
            "손상된 .smc 헤더이거나 분할 볼륨(.s01 등)이 누락되었습니다 (인덱스 오프셋: {}, 아카이브 크기: {}).",
            header.index_offset,
            total_size
        );
    }

    let mut cursor = header.index_offset;

    let mut len_buf = [0u8; 16];
    reader.read_exact_at(cursor, &mut len_buf).context(
        "인덱스 헤더를 읽을 수 없습니다 (분할 압축 볼륨이 모두 같은 폴더에 있는지 확인해 주세요).",
    )?;
    cursor += 16;

    let comp_len_u64 = u64::from_le_bytes(len_buf[0..8].try_into().unwrap());
    let uncomp_len_u64 = u64::from_le_bytes(len_buf[8..16].try_into().unwrap());

    if comp_len_u64 > MAX_INDEX_COMPRESSED_SIZE
        || cursor
            .checked_add(comp_len_u64)
            .and_then(|c| c.checked_add(4))
            .map(|end| end > total_size)
            .unwrap_or(true)
    {
        bail!(
            "손상된 .smc 인덱스 길이({})이거나 분할 볼륨이 누락되었습니다.",
            comp_len_u64
        );
    }
    if uncomp_len_u64 > MAX_INDEX_UNCOMPRESSED_SIZE as u64 {
        bail!(
            "비정상적인 인덱스 원본 크기({})가 감지되어 메모리 보호를 위해 차단했습니다.",
            uncomp_len_u64
        );
    }

    let comp_len = comp_len_u64 as usize;
    let uncomp_len = uncomp_len_u64 as usize;

    let mut payload = vec![0u8; comp_len];
    reader
        .read_exact_at(cursor, &mut payload)
        .context("인덱스 데이터를 읽을 수 없습니다.")?;
    cursor += comp_len_u64;

    let mut footer_magic = [0u8; 4];
    reader
        .read_exact_at(cursor, &mut footer_magic)
        .context("푸터 시그니처를 읽을 수 없습니다.")?;
    if &footer_magic != SMC_FOOTER_MAGIC {
        bail!("아카이브 끝 시그니처(SMCE)가 일치하지 않습니다. 파일이 손상되었거나 볼륨이 누락되었습니다.");
    }

    if header.encrypted {
        let pw = password.unwrap_or("");
        let key = derive_key_versioned(pw, &header.salt, header.kdf_v2);
        payload = decrypt_block(&payload, &key, &header.salt, INDEX_BLOCK_ID)?;
    }

    let index_json =
        zstd::bulk::decompress(&payload, uncomp_len).context("인덱스 테이블 압축 해제 실패")?;
    let mut index: ArchiveIndex =
        serde_json::from_slice(&index_json).context("인덱스 메타데이터 파싱 실패")?;
    index.volume_count = reader.volume_count();
    index.format = ArchiveFormat::Smc;

    Ok(index)
}

/// Extracts up to `max_bytes` from a `FileEntry` in memory for instant previewing without OOM on huge files!
pub fn extract_entry_preview_bytes(
    smc_path: &Path,
    entry: &FileEntry,
    password: Option<&str>,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if entry.chunks.len() <= 1 && (entry.original_size as usize) <= max_bytes {
        return extract_entry_to_bytes(smc_path, entry, password);
    }

    let header = read_smc_header(smc_path)?;
    let reader = MultiVolumeReader::open(smc_path)?;
    let derived_key = if header.encrypted {
        let pw = password.unwrap_or("");
        Some(derive_key_versioned(pw, &header.salt, header.kdf_v2))
    } else {
        None
    };

    let mut out = Vec::with_capacity(max_bytes.min(entry.original_size as usize));
    for chunk in &entry.chunks {
        if out.len() >= max_bytes {
            break;
        }
        let part = read_and_decode_chunk(&reader, chunk, derived_key.as_ref(), &header.salt)?;
        out.extend_from_slice(&part);
    }

    Ok(out)
}

/// Instantly extracts a single `FileEntry` into memory
pub fn extract_entry_to_bytes(
    smc_path: &Path,
    entry: &FileEntry,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    let header = read_smc_header(smc_path)?;
    let reader = MultiVolumeReader::open(smc_path)?;
    let derived_key = if header.encrypted {
        let pw = password.unwrap_or("");
        Some(derive_key_versioned(pw, &header.salt, header.kdf_v2))
    } else {
        None
    };

    if entry.chunks.is_empty() || entry.original_size == 0 {
        return Ok(Vec::new());
    }

    let chunk_vecs: Result<Vec<Vec<u8>>> = entry
        .chunks
        .par_iter()
        .map(|chunk| read_and_decode_chunk(&reader, chunk, derived_key.as_ref(), &header.salt))
        .collect();

    let cap = (entry.original_size as usize).min(MAX_CHUNK_UNCOMPRESSED_SIZE * 4);
    let mut full_raw = Vec::with_capacity(cap);
    for part in chunk_vecs? {
        full_raw.extend_from_slice(&part);
    }

    let crc = crc32fast::hash(&full_raw);
    if crc != entry.crc32 {
        bail!(
            "무결성 검증(CRC32) 실패: {} (예상 {:08X}, 실제 {:08X})",
            entry.rel_path,
            entry.crc32,
            crc
        );
    }

    Ok(full_raw)
}

/// Streams a single `FileEntry` to a temporary file on disk in bounded memory batches (safe even for 10GB+ files)
pub fn extract_entry_to_temp_file(
    smc_path: &Path,
    entry: &FileEntry,
    password: Option<&str>,
) -> Result<PathBuf> {
    let header = read_smc_header(smc_path)?;
    let reader = MultiVolumeReader::open(smc_path)?;
    let derived_key = if header.encrypted {
        let pw = password.unwrap_or("");
        Some(derive_key_versioned(pw, &header.salt, header.kdf_v2))
    } else {
        None
    };

    let archive_hash = crc32fast::hash(smc_path.to_string_lossy().as_bytes());
    let temp_root = std::env::temp_dir()
        .join("smc_instant_open")
        .join(format!("{:08X}", archive_hash));
    let out_path = sanitize_join(&temp_root, &entry.rel_path)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut out_file = BufWriter::with_capacity(4 * 1024 * 1024, File::create(&out_path)?);
    let mut hasher = crc32fast::Hasher::new();
    let batch_size = (rayon::current_num_threads() * 2).max(4);

    for chunk_group in entry.chunks.chunks(batch_size) {
        let decompressed_group: Result<Vec<Vec<u8>>> = chunk_group
            .par_iter()
            .map(|chunk| read_and_decode_chunk(&reader, chunk, derived_key.as_ref(), &header.salt))
            .collect();

        for raw in decompressed_group? {
            hasher.update(&raw);
            out_file.write_all(&raw)?;
        }
    }
    out_file.flush()?;
    drop(out_file);

    let crc = hasher.finalize();
    if entry.original_size > 0 && crc != entry.crc32 {
        let _ = fs::remove_file(&out_path);
        bail!(
            "무결성 검증(CRC32) 실패: {} (예상 {:08X}, 실제 {:08X})",
            entry.rel_path,
            entry.crc32,
            crc
        );
    }

    restore_file_mtime(&out_path, entry.modified_unix);
    Ok(out_path)
}

/// Extracts files (and preserved empty directories) from a .smc archive in parallel across all CPU cores
pub fn unpack_archive(
    smc_path: &Path,
    dest_dir: &Path,
    password: Option<&str>,
    selected_files: Option<&HashSet<String>>,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    let start_time = Instant::now();
    let header = read_smc_header(smc_path)?;
    let index = read_archive_index(smc_path, password)?;
    let reader = Arc::new(MultiVolumeReader::open(smc_path)?);

    let derived_key = if header.encrypted {
        let pw = password.unwrap_or("");
        Some(derive_key_versioned(pw, &header.salt, header.kdf_v2))
    } else {
        None
    };

    let target_entries: Vec<&FileEntry> = index
        .files
        .iter()
        .filter(|e| {
            selected_files
                .map(|set| set.contains(&e.rel_path))
                .unwrap_or(true)
        })
        .collect();

    if target_entries.is_empty() && (selected_files.is_some() || index.empty_dirs.is_empty()) {
        bail!("압축 해제할 파일이 선택되지 않았습니다.");
    }

    let total_orig: u64 = target_entries.iter().map(|e| e.original_size).sum();
    let total_comp: u64 = target_entries.iter().map(|e| e.compressed_size).sum();
    let smart_bypassed_count = target_entries.iter().filter(|e| e.smart_bypassed).count();

    progress.total_bytes.store(total_orig, Ordering::Relaxed);
    progress
        .total_files
        .store(target_entries.len(), Ordering::Relaxed);
    progress
        .smart_bypassed_files
        .store(smart_bypassed_count, Ordering::Relaxed);

    fs::create_dir_all(dest_dir)?;

    // Recreate preserved empty directories when performing full archive extraction
    if selected_files.is_none() {
        for empty_dir in &index.empty_dirs {
            let dir_path = sanitize_join(dest_dir, empty_dir)?;
            fs::create_dir_all(&dir_path)?;
        }
    }

    let (single_chunk_entries, multi_chunk_entries): (Vec<&FileEntry>, Vec<&FileEntry>) =
        target_entries
            .into_iter()
            .partition(|e| e.chunks.len() <= 1);

    // 1. Extract single-chunk files in parallel across all CPU cores
    single_chunk_entries
        .par_iter()
        .try_for_each(|entry| -> Result<()> {
            if progress.is_cancelled.load(Ordering::Relaxed) {
                bail!("사용자에 의해 압축 해제가 취소되었습니다.");
            }
            progress.set_current(entry.rel_path.clone());

            let out_path = sanitize_join(dest_dir, &entry.rel_path)?;
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            if entry.chunks.is_empty() || entry.original_size == 0 {
                File::create(&out_path)?;
                restore_file_mtime(&out_path, entry.modified_unix);
                progress.processed_files.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }

            let chunk = &entry.chunks[0];
            let raw = read_and_decode_chunk(&reader, chunk, derived_key.as_ref(), &header.salt)?;
            let crc = crc32fast::hash(&raw);
            if crc != entry.crc32 {
                bail!(
                    "무결성 검증(CRC32) 실패: {} (예상 {:08X}, 실제 {:08X})",
                    entry.rel_path,
                    entry.crc32,
                    crc
                );
            }

            fs::write(&out_path, &raw)?;
            restore_file_mtime(&out_path, entry.modified_unix);
            progress
                .processed_bytes
                .fetch_add(entry.original_size, Ordering::Relaxed);
            progress.processed_files.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })?;

    // 2. Extract multi-chunk large files with parallel chunk decompression
    let batch_size = (rayon::current_num_threads() * 2).max(4);
    for entry in multi_chunk_entries {
        if progress.is_cancelled.load(Ordering::Relaxed) {
            bail!("사용자에 의해 압축 해제가 취소되었습니다.");
        }
        progress.set_current(format!("대용량 병렬 해제 중: {}", entry.rel_path));

        let out_path = sanitize_join(dest_dir, &entry.rel_path)?;
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out_file = BufWriter::with_capacity(8 * 1024 * 1024, File::create(&out_path)?);
        let mut hasher = crc32fast::Hasher::new();

        for chunk_group in entry.chunks.chunks(batch_size) {
            if progress.is_cancelled.load(Ordering::Relaxed) {
                bail!("사용자에 의해 압축 해제가 취소되었습니다.");
            }
            let decompressed_group: Result<Vec<Vec<u8>>> = chunk_group
                .par_iter()
                .map(|chunk| {
                    let raw =
                        read_and_decode_chunk(&reader, chunk, derived_key.as_ref(), &header.salt)?;
                    progress
                        .processed_bytes
                        .fetch_add(raw.len() as u64, Ordering::Relaxed);
                    Ok(raw)
                })
                .collect();

            for raw in decompressed_group? {
                hasher.update(&raw);
                out_file.write_all(&raw)?;
            }
        }
        out_file.flush()?;
        drop(out_file);

        let crc = hasher.finalize();
        if crc != entry.crc32 {
            let _ = fs::remove_file(&out_path);
            bail!(
                "무결성 검증(CRC32) 실패: {} (예상 {:08X}, 실제 {:08X})",
                entry.rel_path,
                entry.crc32,
                crc
            );
        }
        restore_file_mtime(&out_path, entry.modified_unix);
        progress.processed_files.fetch_add(1, Ordering::Relaxed);
    }

    Ok(OperationStats {
        elapsed_secs: start_time.elapsed().as_secs_f64(),
        total_original_bytes: total_orig,
        total_compressed_bytes: total_comp,
        file_count: progress.processed_files.load(Ordering::Relaxed),
        smart_bypassed_count,
        excluded_dev_count: 0,
        threads_used: rayon::current_num_threads(),
        volume_count: reader.volume_count(),
    })
}

/// Verifies every chunk, AES-GCM tag (if encrypted), and CRC32 checksum inside a .smc archive in parallel without writing to disk
pub fn verify_smc_archive(
    smc_path: &Path,
    password: Option<&str>,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    let start_time = Instant::now();
    let header = read_smc_header(smc_path)?;
    let index = read_archive_index(smc_path, password)?;
    let reader = Arc::new(MultiVolumeReader::open(smc_path)?);

    let derived_key = if header.encrypted {
        let pw = password.unwrap_or("");
        Some(derive_key_versioned(pw, &header.salt, header.kdf_v2))
    } else {
        None
    };

    for empty_dir in &index.empty_dirs {
        let _ = sanitize_join(Path::new("."), empty_dir)?;
    }

    let total_orig: u64 = index.files.iter().map(|e| e.original_size).sum();
    let total_comp: u64 = index.files.iter().map(|e| e.compressed_size).sum();
    let smart_bypassed_count = index.files.iter().filter(|e| e.smart_bypassed).count();

    progress.total_bytes.store(total_orig, Ordering::Relaxed);
    progress
        .total_files
        .store(index.files.len(), Ordering::Relaxed);
    progress
        .smart_bypassed_files
        .store(smart_bypassed_count, Ordering::Relaxed);

    let (single_chunk_entries, multi_chunk_entries): (Vec<&FileEntry>, Vec<&FileEntry>) =
        index.files.iter().partition(|e| e.chunks.len() <= 1);

    single_chunk_entries
        .par_iter()
        .try_for_each(|entry| -> Result<()> {
            if progress.is_cancelled.load(Ordering::Relaxed) {
                bail!("사용자에 의해 무결성 검사가 취소되었습니다.");
            }
            let _ = sanitize_join(Path::new("."), &entry.rel_path)?;
            progress.set_current(format!("무결성 검증 중: {}", entry.rel_path));

            if entry.chunks.is_empty() || entry.original_size == 0 {
                progress.processed_files.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }

            let raw = read_and_decode_chunk(
                &reader,
                &entry.chunks[0],
                derived_key.as_ref(),
                &header.salt,
            )?;
            let crc = crc32fast::hash(&raw);
            if crc != entry.crc32 {
                bail!(
                    "무결성 검증(CRC32) 실패: {} (예상 {:08X}, 실제 {:08X})",
                    entry.rel_path,
                    entry.crc32,
                    crc
                );
            }
            progress
                .processed_bytes
                .fetch_add(entry.original_size, Ordering::Relaxed);
            progress.processed_files.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })?;

    let batch_size = (rayon::current_num_threads() * 2).max(4);
    for entry in multi_chunk_entries {
        if progress.is_cancelled.load(Ordering::Relaxed) {
            bail!("사용자에 의해 무결성 검사가 취소되었습니다.");
        }
        let _ = sanitize_join(Path::new("."), &entry.rel_path)?;
        progress.set_current(format!("대용량 무결성 검증 중: {}", entry.rel_path));

        let mut hasher = crc32fast::Hasher::new();
        for chunk_group in entry.chunks.chunks(batch_size) {
            if progress.is_cancelled.load(Ordering::Relaxed) {
                bail!("사용자에 의해 무결성 검사가 취소되었습니다.");
            }
            let decompressed_group: Result<Vec<Vec<u8>>> = chunk_group
                .par_iter()
                .map(|chunk| {
                    let raw =
                        read_and_decode_chunk(&reader, chunk, derived_key.as_ref(), &header.salt)?;
                    progress
                        .processed_bytes
                        .fetch_add(raw.len() as u64, Ordering::Relaxed);
                    Ok(raw)
                })
                .collect();

            for raw in decompressed_group? {
                hasher.update(&raw);
            }
        }
        let crc = hasher.finalize();
        if crc != entry.crc32 {
            bail!(
                "무결성 검증(CRC32) 실패: {} (예상 {:08X}, 실제 {:08X})",
                entry.rel_path,
                entry.crc32,
                crc
            );
        }
        progress.processed_files.fetch_add(1, Ordering::Relaxed);
    }

    Ok(OperationStats {
        elapsed_secs: start_time.elapsed().as_secs_f64(),
        total_original_bytes: total_orig,
        total_compressed_bytes: total_comp,
        file_count: progress.processed_files.load(Ordering::Relaxed),
        smart_bypassed_count,
        excluded_dev_count: 0,
        threads_used: rayon::current_num_threads(),
        volume_count: reader.volume_count(),
    })
}

/// Automatically cleans up stale temporary preview/instant-open directories older than 12 hours
pub fn cleanup_stale_temp_files() {
    let temp_base = std::env::temp_dir().join("smc_instant_open");
    let Ok(entries) = fs::read_dir(&temp_base) else {
        return;
    };
    let cutoff = Duration::from_secs(12 * 3600);
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_stale = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|mtime| now.duration_since(mtime).ok())
            .map(|age| age > cutoff)
            .unwrap_or(false);
        if is_stale {
            if path.is_dir() {
                let _ = fs::remove_dir_all(&path);
            } else {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

/// Prevents Zip-Slip path traversal, drive-letter injection, and NTFS ADS injection when joining relative archive paths
pub(crate) fn sanitize_join(base: &Path, rel: &str) -> Result<PathBuf> {
    let mut out = base.to_path_buf();
    for part in rel.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains(':') || part.contains('\0') {
            bail!(
                "보안 경고: 안전하지 않은 아카이브 상대 경로가 차단되었습니다: {}",
                rel
            );
        }
        out.push(part);
    }
    Ok(out)
}
