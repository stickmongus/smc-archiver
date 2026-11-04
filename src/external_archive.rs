use crate::archiver::{
    collect_input_items, extract_entry_preview_bytes, extract_entry_to_temp_file, fast_norm_key,
    read_archive_index, restore_file_mtime, sanitize_join, unpack_archive, verify_smc_archive,
    OperationStats, PackConfig, ProgressTracker,
};
use crate::format::{
    is_already_compressed_ext, resolve_base_smc_path, ArchiveFormat, ArchiveIndex, ChunkMeta,
    ChunkMethod, CompressionMode, FileEntry, SMC_MAGIC,
};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{Datelike, NaiveDate, TimeZone, Timelike, Utc};
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, ZipArchive, ZipWriter};

const SEVEN_Z_MAGIC: &[u8; 6] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Checks whether a file path has an extension recognized as an openable archive (.smc, .s01.., .zip, .7z, .7z.001..)
pub fn is_supported_archive_path(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let lower = ext.to_ascii_lowercase();
    if matches!(lower.as_str(), "smc" | "zip" | "7z") {
        return true;
    }
    if lower.starts_with('s') && lower.len() >= 3 && lower[1..].chars().all(|c| c.is_ascii_digit())
    {
        return true;
    }
    if lower.len() >= 3 && lower.chars().all(|c| c.is_ascii_digit()) {
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            if stem.to_ascii_lowercase().ends_with(".7z") {
                return true;
            }
        }
    }
    false
}

/// Detects the container format (.smc, .zip, .7z) using header magic signatures and fallback extensions
pub fn detect_archive_format(path: &Path) -> Result<ArchiveFormat> {
    let base = resolve_base_smc_path(path);
    let mut f = File::open(&base)
        .with_context(|| format!("아카이브 파일을 열 수 없습니다: {}", base.display()))?;
    let mut magic = [0u8; 8];
    let n = f.read(&mut magic).unwrap_or(0);

    if n >= 4 && &magic[0..4] == SMC_MAGIC {
        return Ok(ArchiveFormat::Smc);
    }
    if n >= 6 && &magic[0..6] == SEVEN_Z_MAGIC {
        return Ok(ArchiveFormat::SevenZ);
    }
    if n >= 4
        && (&magic[0..4] == b"PK\x03\x04"
            || &magic[0..4] == b"PK\x05\x06"
            || &magic[0..4] == b"PK\x07\x08")
    {
        return Ok(ArchiveFormat::Zip);
    }

    if let Some(ext) = base.extension().and_then(|e| e.to_str()) {
        let lower = ext.to_ascii_lowercase();
        match lower.as_str() {
            "smc" => return Ok(ArchiveFormat::Smc),
            "zip" => return Ok(ArchiveFormat::Zip),
            "7z" => return Ok(ArchiveFormat::SevenZ),
            _ if lower.chars().all(|c| c.is_ascii_digit()) => {
                if base
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_ascii_lowercase().ends_with(".7z"))
                    .unwrap_or(false)
                {
                    return Ok(ArchiveFormat::SevenZ);
                }
            }
            _ => {}
        }
    }

    bail!(
        "지원하지 않는 아카이브 포맷이거나 헤더가 손상되었습니다: {}",
        base.display()
    )
}

/// Decodes raw archive entry bytes, prioritizing valid UTF-8 and falling back to Korean CP949 (EUC-KR) on Windows
pub fn decode_archive_filename(raw: &[u8]) -> String {
    let decoded = if let Ok(s) = std::str::from_utf8(raw) {
        s.to_string()
    } else if let Some(cp949) = try_decode_cp949(raw) {
        cp949
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };

    decoded
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string()
}

fn try_decode_cp949(raw: &[u8]) -> Option<String> {
    if raw.is_empty() {
        return Some(String::new());
    }
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

        unsafe {
            let needed = MultiByteToWideChar(
                CP_949,
                MB_ERR_INVALID_CHARS,
                raw.as_ptr(),
                raw.len() as i32,
                std::ptr::null_mut(),
                0,
            );
            if needed > 0 {
                let mut wide = vec![0u16; needed as usize];
                let written = MultiByteToWideChar(
                    CP_949,
                    MB_ERR_INVALID_CHARS,
                    raw.as_ptr(),
                    raw.len() as i32,
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
    None
}

/// Computes the Smart Extract ("알아서 풀기") target directory so single-root archives never double-nest (`foo/foo`),
/// loose-file archives always wrap into a clean subfolder, and existing folders on disk are never silently overwritten.
pub fn smart_extract_dir(archive_path: &Path, index: &ArchiveIndex) -> PathBuf {
    let resolved = resolve_base_smc_path(archive_path);
    let parent = resolved.parent().unwrap_or_else(|| Path::new("."));
    let stem = clean_archive_stem(&resolved);

    let mut top_components: HashSet<String> = HashSet::new();
    let mut has_root_loose_file = false;

    for f in &index.files {
        let mut parts = f
            .rel_path
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".");
        if let Some(first) = parts.next() {
            if parts.next().is_none() {
                has_root_loose_file = true;
            }
            top_components.insert(first.to_string());
        }
    }
    for d in &index.empty_dirs {
        if let Some(first) = d
            .split(['/', '\\'])
            .find(|s| !s.is_empty() && *s != ".")
        {
            top_components.insert(first.to_string());
        }
    }

    if !has_root_loose_file && top_components.len() == 1 {
        let single_root = top_components.into_iter().next().unwrap();
        let target_in_parent = parent.join(&single_root);
        if !target_in_parent.exists() {
            return parent.to_path_buf();
        }
    }

    disambiguate_dir(parent, &stem)
}

fn clean_archive_stem(path: &Path) -> String {
    let raw_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("extracted");
    // Handle `.7z.001` where file_stem() is `archive.7z`
    if raw_stem.len() > 3 && raw_stem.to_ascii_lowercase().ends_with(".7z") {
        raw_stem[..raw_stem.len() - 3].to_string()
    } else {
        raw_stem.to_string()
    }
}

fn disambiguate_dir(parent: &Path, base_name: &str) -> PathBuf {
    let first = parent.join(base_name);
    if !first.exists() {
        return first;
    }
    for idx in 2..=9999 {
        let candidate = parent.join(format!("{} ({})", base_name, idx));
        if !candidate.exists() {
            return candidate;
        }
    }
    first
}

/// Multi-part `Read + Seek` stream supporting both single `.7z` files and split `.7z.001`, `.7z.002`, ... volumes
struct MultiPartFileReader {
    volumes: Vec<(PathBuf, u64, u64)>,
    total_size: u64,
    pos: u64,
    active_vol: Option<(usize, File, u64)>,
}

impl MultiPartFileReader {
    fn open(path: &Path) -> Result<Self> {
        let base = resolve_base_smc_path(path);
        if !base.exists() {
            bail!("아카이브 파일을 찾을 수 없습니다: {}", base.display());
        }

        let mut volumes = Vec::new();
        let mut cursor = 0u64;

        let is_numbered_split = base
            .extension()
            .and_then(|e| e.to_str())
            .map(|ext| ext.len() >= 3 && ext.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false);

        if is_numbered_split {
            let ext = base.extension().and_then(|e| e.to_str()).unwrap_or("001");
            let width = ext.len();
            let stem = base
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("archive.7z");
            let parent = base.parent().unwrap_or_else(|| Path::new("."));

            for idx in 1..=99_999 {
                let part = parent.join(format!("{}.{:0width$}", stem, idx, width = width));
                if part.exists() {
                    let len = fs::metadata(&part)?.len();
                    volumes.push((part, cursor, cursor + len));
                    cursor += len;
                } else {
                    break;
                }
            }
        }

        if volumes.is_empty() {
            let len = fs::metadata(&base)?.len();
            volumes.push((base, 0, len));
            cursor = len;
        }

        Ok(Self {
            volumes,
            total_size: cursor,
            pos: 0,
            active_vol: None,
        })
    }

    fn volume_count(&self) -> usize {
        self.volumes.len()
    }
}

impl Read for MultiPartFileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.total_size || buf.is_empty() {
            return Ok(0);
        }

        let vol_idx = self
            .volumes
            .partition_point(|(_, _, end)| *end <= self.pos);
        let Some((vpath, vstart, vend)) = self.volumes.get(vol_idx) else {
            return Ok(0);
        };
        let vpath = vpath.clone();
        let vstart = *vstart;
        let vend = *vend;
        let needed_off = self.pos - vstart;

        let need_reopen = self
            .active_vol
            .as_ref()
            .map(|(idx, _, _)| *idx != vol_idx)
            .unwrap_or(true);
        if need_reopen {
            let mut f = File::open(&vpath)?;
            if needed_off > 0 {
                f.seek(SeekFrom::Start(needed_off))?;
            }
            self.active_vol = Some((vol_idx, f, needed_off));
        }

        let (_, ref mut file, ref mut cur_off) = self.active_vol.as_mut().unwrap();
        if *cur_off != needed_off {
            file.seek(SeekFrom::Start(needed_off))?;
            *cur_off = needed_off;
        }

        let max_to_read = (vend - self.pos).min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..max_to_read])?;
        *cur_off += n as u64;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for MultiPartFileReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let next: i128 = match pos {
            SeekFrom::Start(off) => off as i128,
            SeekFrom::Current(delta) => self.pos as i128 + delta as i128,
            SeekFrom::End(delta) => self.total_size as i128 + delta as i128,
        };
        if next < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "음수 오프셋으로 탐색할 수 없습니다.",
            ));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
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

// ============================================================================
// Unified Dispatchers (.smc / .zip / .7z)
// ============================================================================

pub fn read_any_archive_index(path: &Path, password: Option<&str>) -> Result<ArchiveIndex> {
    match detect_archive_format(path)? {
        ArchiveFormat::Smc => read_archive_index(path, password),
        ArchiveFormat::Zip => read_zip_index(path, password),
        ArchiveFormat::SevenZ => read_7z_index(path, password),
    }
}

pub fn extract_any_preview_bytes(
    path: &Path,
    entry: &FileEntry,
    password: Option<&str>,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    match detect_archive_format(path)? {
        ArchiveFormat::Smc => extract_entry_preview_bytes(path, entry, password, max_bytes),
        ArchiveFormat::Zip => extract_zip_preview_bytes(path, entry, password, max_bytes),
        ArchiveFormat::SevenZ => extract_7z_preview_bytes(path, entry, password, max_bytes),
    }
}

pub fn extract_any_to_temp_file(
    path: &Path,
    entry: &FileEntry,
    password: Option<&str>,
) -> Result<PathBuf> {
    match detect_archive_format(path)? {
        ArchiveFormat::Smc => extract_entry_to_temp_file(path, entry, password),
        ArchiveFormat::Zip => extract_zip_to_temp_file(path, entry, password),
        ArchiveFormat::SevenZ => extract_7z_to_temp_file(path, entry, password),
    }
}

pub fn unpack_any_archive(
    path: &Path,
    dest_dir: &Path,
    password: Option<&str>,
    selected_files: Option<&HashSet<String>>,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    match detect_archive_format(path)? {
        ArchiveFormat::Smc => unpack_archive(path, dest_dir, password, selected_files, progress),
        ArchiveFormat::Zip => unpack_zip(path, dest_dir, password, selected_files, progress),
        ArchiveFormat::SevenZ => unpack_7z(path, dest_dir, password, selected_files, progress),
    }
}

pub fn verify_any_archive(
    path: &Path,
    password: Option<&str>,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    match detect_archive_format(path)? {
        ArchiveFormat::Smc => verify_smc_archive(path, password, progress),
        ArchiveFormat::Zip => verify_zip(path, password, progress),
        ArchiveFormat::SevenZ => verify_7z(path, password, progress),
    }
}

// ============================================================================
// .ZIP Implementation (Read, Preview, Instant Open, Parallel Unpack, Verify, Create)
// ============================================================================

fn map_zip_method(m: CompressionMethod) -> ChunkMethod {
    match m {
        CompressionMethod::Stored => ChunkMethod::Store,
        CompressionMethod::Deflated | CompressionMethod::Deflate64 => ChunkMethod::Deflate,
        CompressionMethod::Zstd => ChunkMethod::Zstd,
        CompressionMethod::Lzma | CompressionMethod::Xz => ChunkMethod::Lzma2,
        _ => ChunkMethod::Other,
    }
}

fn zip_datetime_to_unix(dt: Option<zip::DateTime>) -> i64 {
    let Some(dt) = dt else {
        return 0;
    };
    NaiveDate::from_ymd_opt(dt.year() as i32, dt.month() as u32, dt.day() as u32)
        .and_then(|d| d.and_hms_opt(dt.hour() as u32, dt.minute() as u32, dt.second() as u32))
        .map(|naive| naive.and_utc().timestamp())
        .unwrap_or(0)
}

fn unix_to_zip_datetime(unix_secs: i64) -> Option<zip::DateTime> {
    if unix_secs <= 0 {
        return None;
    }
    let dt = Utc.timestamp_opt(unix_secs, 0).single()?;
    zip::DateTime::from_date_and_time(
        (dt.year().clamp(1980, 2107)) as u16,
        dt.month() as u8,
        dt.day() as u8,
        dt.hour() as u8,
        dt.minute() as u8,
        (dt.second().min(58)) as u8,
    )
    .ok()
}

fn map_zip_err(e: zip::result::ZipError) -> anyhow::Error {
    match e {
        zip::result::ZipError::InvalidPassword => {
            anyhow!("비밀번호가 올바르지 않습니다 (ZIP 암호 인증 실패).")
        }
        zip::result::ZipError::UnsupportedArchive(msg) => {
            anyhow!("지원하지 않는 ZIP 기능입니다: {}", msg)
        }
        other => anyhow!("ZIP 처리 오류: {}", other),
    }
}

fn read_zip_index(zip_path: &Path, password: Option<&str>) -> Result<ArchiveIndex> {
    let file = File::open(zip_path)
        .with_context(|| format!(".zip 파일을 열 수 없습니다: {}", zip_path.display()))?;
    let archive_mtime = file
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut archive = ZipArchive::new(BufReader::new(file)).map_err(map_zip_err)?;
    let mut files = Vec::new();
    let mut visited_dirs = Vec::new();
    let mut seen_dirs = HashSet::new();
    let mut any_encrypted = false;
    let mut first_encrypted_idx: Option<usize> = None;

    for i in 0..archive.len() {
        let zentry = archive.by_index_data(i).map_err(map_zip_err)?;
        let raw_name = zentry.name_raw().to_vec();
        let is_dir = zentry.is_dir();
        let is_enc = zentry.encrypted();
        let orig_size = zentry.size();
        let comp_size = zentry.compressed_size();
        let crc = zentry.crc32();
        let method = map_zip_method(zentry.compression());
        let mod_unix = zip_datetime_to_unix(zentry.last_modified());
        let header_start = zentry.header_start();

        if is_enc {
            any_encrypted = true;
            if first_encrypted_idx.is_none() {
                first_encrypted_idx = Some(i);
            }
        }

        let decoded = decode_archive_filename(&raw_name);
        let trimmed = decoded.trim_end_matches('/').to_string();
        if trimmed.is_empty() {
            continue;
        }

        if is_dir {
            if seen_dirs.insert(trimmed.clone()) {
                visited_dirs.push(trimmed);
            }
        } else {
            let smart_bypassed = method == ChunkMethod::Store && orig_size > 0;
            files.push(FileEntry {
                rel_path: trimmed,
                original_size: orig_size,
                compressed_size: comp_size,
                crc32: crc,
                modified_unix: mod_unix,
                smart_bypassed,
                chunks: vec![ChunkMeta {
                    chunk_id: i as u64,
                    offset: header_start,
                    compressed_size: comp_size,
                    uncompressed_size: orig_size,
                    method,
                }],
            });
        }
    }

    if any_encrypted {
        let Some(pw) = password.filter(|p| !p.is_empty()) else {
            bail!("PASSWORD_REQUIRED");
        };
        if let Some(enc_idx) = first_encrypted_idx {
            let mut zf = archive
                .by_index_decrypt(enc_idx, pw.as_bytes())
                .map_err(map_zip_err)?;
            let mut probe = [0u8; 64];
            let _ = zf.read(&mut probe).map_err(|e| {
                anyhow!(
                    "비밀번호가 올바르지 않거나 암호화된 ZIP 스트림을 읽을 수 없습니다: {}",
                    e
                )
            })?;
        }
    }

    let mut non_empty_dirs = HashSet::new();
    for f in &files {
        mark_parent_prefixes(&f.rel_path, &mut non_empty_dirs);
    }
    for d in &visited_dirs {
        mark_parent_prefixes(d, &mut non_empty_dirs);
    }
    let empty_dirs: Vec<String> = visited_dirs
        .into_iter()
        .filter(|d| !non_empty_dirs.contains(d))
        .collect();

    let total_original_size: u64 = files.iter().map(|f| f.original_size).sum();
    let total_compressed_size: u64 = files.iter().map(|f| f.compressed_size).sum();

    Ok(ArchiveIndex {
        version: 1,
        created_unix: archive_mtime,
        mode_used: CompressionMode::ZstdBalanced,
        encrypted: any_encrypted,
        total_original_size,
        total_compressed_size,
        volume_count: 1,
        split_size_bytes: 0,
        files,
        empty_dirs,
        format: ArchiveFormat::Zip,
    })
}

fn open_zip_entry<'a, R: Read + Seek>(
    archive: &'a mut ZipArchive<R>,
    zip_idx: usize,
    password: Option<&str>,
) -> Result<zip::read::ZipFile<'a, R>> {
    let is_enc = archive
        .by_index_data(zip_idx)
        .map_err(map_zip_err)?
        .encrypted();
    if is_enc {
        let pw = password
            .filter(|p| !p.is_empty())
            .ok_or_else(|| anyhow!("PASSWORD_REQUIRED"))?;
        archive
            .by_index_decrypt(zip_idx, pw.as_bytes())
            .map_err(map_zip_err)
    } else {
        archive.by_index(zip_idx).map_err(map_zip_err)
    }
}

fn extract_zip_preview_bytes(
    zip_path: &Path,
    entry: &FileEntry,
    password: Option<&str>,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let zip_idx = entry
        .chunks
        .first()
        .map(|c| c.chunk_id as usize)
        .ok_or_else(|| anyhow!("ZIP 엔트리 인덱스가 없습니다."))?;
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(BufReader::new(file)).map_err(map_zip_err)?;
    let zf = open_zip_entry(&mut archive, zip_idx, password)?;

    let mut out = Vec::with_capacity(max_bytes.min(entry.original_size as usize));
    zf.take(max_bytes as u64)
        .read_to_end(&mut out)
        .map_err(|e| anyhow!("ZIP 미리보기 데이터 읽기 실패 (비밀번호 또는 손상 확인): {}", e))?;
    Ok(out)
}

fn extract_zip_to_temp_file(
    zip_path: &Path,
    entry: &FileEntry,
    password: Option<&str>,
) -> Result<PathBuf> {
    let zip_idx = entry
        .chunks
        .first()
        .map(|c| c.chunk_id as usize)
        .ok_or_else(|| anyhow!("ZIP 엔트리 인덱스가 없습니다."))?;
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(BufReader::new(file)).map_err(map_zip_err)?;
    let mut zf = open_zip_entry(&mut archive, zip_idx, password)?;

    let archive_hash = crc32fast::hash(zip_path.to_string_lossy().as_bytes());
    let temp_root = std::env::temp_dir()
        .join("smc_instant_open")
        .join(format!("zip_{:08X}", archive_hash));
    let out_path = sanitize_join(&temp_root, &entry.rel_path)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut out_file = BufWriter::with_capacity(2 * 1024 * 1024, File::create(&out_path)?);
    if let Err(e) = std::io::copy(&mut zf, &mut out_file) {
        drop(out_file);
        let _ = fs::remove_file(&out_path);
        bail!("ZIP 파일 추출 실패 (비밀번호 또는 손상 확인): {}", e);
    }
    out_file.flush()?;
    drop(out_file);

    restore_file_mtime(&out_path, entry.modified_unix);
    Ok(out_path)
}

fn unpack_zip(
    zip_path: &Path,
    dest_dir: &Path,
    password: Option<&str>,
    selected_files: Option<&HashSet<String>>,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    let start_time = Instant::now();
    let index = read_zip_index(zip_path, password)?;

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
    if selected_files.is_none() {
        for empty_dir in &index.empty_dirs {
            let dir_path = sanitize_join(dest_dir, empty_dir)?;
            fs::create_dir_all(&dir_path)?;
        }
    }

    // Parallel multi-core ZIP extraction: each Rayon worker thread reuses one ZipArchive handle!
    target_entries.par_iter().try_for_each_init(
        || -> Option<ZipArchive<BufReader<File>>> {
            let f = File::open(zip_path).ok()?;
            ZipArchive::new(BufReader::new(f)).ok()
        },
        |tl_archive, entry| -> Result<()> {
            if progress.is_cancelled.load(Ordering::Relaxed) {
                bail!("사용자에 의해 압축 해제가 취소되었습니다.");
            }
            let archive = tl_archive
                .as_mut()
                .ok_or_else(|| anyhow!("워커 스레드에서 ZIP 파일을 열 수 없습니다."))?;

            progress.set_current(entry.rel_path.clone());
            let out_path = sanitize_join(dest_dir, &entry.rel_path)?;
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let zip_idx = entry.chunks.first().map(|c| c.chunk_id as usize).unwrap_or(0);
            let mut zf = open_zip_entry(archive, zip_idx, password)?;
            let mut out_file = BufWriter::with_capacity(512 * 1024, File::create(&out_path)?);
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                if progress.is_cancelled.load(Ordering::Relaxed) {
                    drop(out_file);
                    let _ = fs::remove_file(&out_path);
                    bail!("사용자에 의해 압축 해제가 취소되었습니다.");
                }
                let n = match zf.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        drop(out_file);
                        let _ = fs::remove_file(&out_path);
                        bail!(
                            "ZIP 압축 해제 실패 ({}) — 비밀번호 불일치 또는 데이터 손상: {}",
                            entry.rel_path,
                            e
                        );
                    }
                };
                if n == 0 {
                    break;
                }
                out_file.write_all(&buf[..n])?;
                progress
                    .processed_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
            out_file.flush()?;
            drop(out_file);

            restore_file_mtime(&out_path, entry.modified_unix);
            progress.processed_files.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
    )?;

    Ok(OperationStats {
        elapsed_secs: start_time.elapsed().as_secs_f64(),
        total_original_bytes: total_orig,
        total_compressed_bytes: total_comp,
        file_count: progress.processed_files.load(Ordering::Relaxed),
        smart_bypassed_count,
        excluded_dev_count: 0,
        threads_used: rayon::current_num_threads(),
        volume_count: 1,
    })
}

fn verify_zip(
    zip_path: &Path,
    password: Option<&str>,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    let start_time = Instant::now();
    let index = read_zip_index(zip_path, password)?;

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

    index.files.par_iter().try_for_each_init(
        || -> Option<ZipArchive<BufReader<File>>> {
            let f = File::open(zip_path).ok()?;
            ZipArchive::new(BufReader::new(f)).ok()
        },
        |tl_archive, entry| -> Result<()> {
            if progress.is_cancelled.load(Ordering::Relaxed) {
                bail!("사용자에 의해 무결성 검사가 취소되었습니다.");
            }
            let _ = sanitize_join(Path::new("."), &entry.rel_path)?;
            let archive = tl_archive
                .as_mut()
                .ok_or_else(|| anyhow!("워커 스레드에서 ZIP 파일을 열 수 없습니다."))?;

            progress.set_current(format!("ZIP 무결성 검증 중: {}", entry.rel_path));
            let zip_idx = entry.chunks.first().map(|c| c.chunk_id as usize).unwrap_or(0);
            let mut zf = open_zip_entry(archive, zip_idx, password)?;
            let mut buf = vec![0u8; 256 * 1024];
            // Note: ZipFile automatically verifies CRC32 / AES HMAC-SHA1 upon reaching EOF!
            loop {
                if progress.is_cancelled.load(Ordering::Relaxed) {
                    bail!("사용자에 의해 무결성 검사가 취소되었습니다.");
                }
                let n = zf.read(&mut buf).map_err(|e| {
                    anyhow!("ZIP 무결성 오류 ({}): {}", entry.rel_path, e)
                })?;
                if n == 0 {
                    break;
                }
                progress
                    .processed_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
            progress.processed_files.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
    )?;

    Ok(OperationStats {
        elapsed_secs: start_time.elapsed().as_secs_f64(),
        total_original_bytes: total_orig,
        total_compressed_bytes: total_comp,
        file_count: progress.processed_files.load(Ordering::Relaxed),
        smart_bypassed_count,
        excluded_dev_count: 0,
        threads_used: rayon::current_num_threads(),
        volume_count: 1,
    })
}

/// Creates a standard compatible `.zip` archive (with Smart Bypass, empty directory preservation, ZIP64, and optional AES-256 encryption)
pub fn pack_zip_archive(
    inputs: &[PathBuf],
    output_zip: &Path,
    config: &PackConfig,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    match pack_zip_inner(inputs, output_zip, config, progress) {
        Ok(stats) => Ok(stats),
        Err(e) => {
            if output_zip.exists() {
                let _ = fs::remove_file(output_zip);
            }
            Err(e)
        }
    }
}

fn pack_zip_inner(
    inputs: &[PathBuf],
    output_zip: &Path,
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

    // Prevent self-inclusion if output_zip is inside an input directory
    let out_key = fast_norm_key(output_zip);
    files.retain(|item| fast_norm_key(&item.abs_path) != out_key);

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

    if let Some(parent) = output_zip.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let out_file = File::create(output_zip)
        .with_context(|| format!("출력 ZIP 파일 생성 실패: {}", output_zip.display()))?;
    let mut zip = ZipWriter::new(BufWriter::with_capacity(4 * 1024 * 1024, out_file));

    let pw_opt = config.password.as_deref().filter(|p| !p.is_empty());

    let dir_opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for empty_dir in &empty_dirs {
        let dir_name = format!("{}/", empty_dir.trim_end_matches('/'));
        zip.add_directory(dir_name, dir_opts).map_err(map_zip_err)?;
    }

    let mut copy_buf = vec![0u8; 1024 * 1024];
    for item in &files {
        if progress.is_cancelled.load(Ordering::Relaxed) {
            bail!("사용자에 의해 ZIP 압축이 취소되었습니다.");
        }
        progress.set_current(item.rel_path.clone());

        let use_store = item.will_smart_bypass
            || config.mode == CompressionMode::StoreOnly
            || is_already_compressed_ext(&item.abs_path);

        let (method, level) = if use_store {
            (CompressionMethod::Stored, None)
        } else {
            let lvl = match config.mode {
                CompressionMode::SmartAuto | CompressionMode::Lz4Fast => Some(1),
                CompressionMode::ZstdBalanced => Some(6),
                CompressionMode::ZstdMax => Some(9),
                CompressionMode::StoreOnly => None,
            };
            (CompressionMethod::Deflated, lvl)
        };

        let mut opts = SimpleFileOptions::default()
            .compression_method(method)
            .compression_level(level)
            .large_file(item.size >= 0xFFFF_FFFF);
        if let Some(dt) = unix_to_zip_datetime(item.modified_unix) {
            opts = opts.last_modified_time(dt);
        }

        if let Some(pw) = pw_opt {
            let enc_opts = opts.with_aes_encryption(AesMode::Aes256, pw);
            zip.start_file(&item.rel_path, enc_opts)
                .map_err(map_zip_err)?;
        } else {
            zip.start_file(&item.rel_path, opts).map_err(map_zip_err)?;
        }

        let mut src = File::open(&item.abs_path)
            .with_context(|| format!("원본 파일 열기 실패: {}", item.abs_path.display()))?;
        loop {
            if progress.is_cancelled.load(Ordering::Relaxed) {
                bail!("사용자에 의해 ZIP 압축이 취소되었습니다.");
            }
            let n = src.read(&mut copy_buf)?;
            if n == 0 {
                break;
            }
            zip.write_all(&copy_buf[..n])?;
            progress
                .processed_bytes
                .fetch_add(n as u64, Ordering::Relaxed);
        }
        progress.processed_files.fetch_add(1, Ordering::Relaxed);
    }

    let mut finished_writer = zip.finish().map_err(map_zip_err)?;
    finished_writer.flush()?;
    drop(finished_writer);

    let comp_bytes = fs::metadata(output_zip).map(|m| m.len()).unwrap_or(0);

    Ok(OperationStats {
        elapsed_secs: start_time.elapsed().as_secs_f64(),
        total_original_bytes: total_bytes,
        total_compressed_bytes: comp_bytes,
        file_count: files.len(),
        smart_bypassed_count,
        excluded_dev_count,
        threads_used: 1,
        volume_count: 1,
    })
}

// ============================================================================
// .7Z Implementation (Single & Split .7z.001, Encrypted Headers/Blocks, Preview, Unpack, Verify)
// ============================================================================

fn map_7z_err(e: sevenz_rust2::Error) -> anyhow::Error {
    match e {
        sevenz_rust2::Error::PasswordRequired => anyhow!("PASSWORD_REQUIRED"),
        sevenz_rust2::Error::MaybeBadPassword(_) => {
            anyhow!("비밀번호가 올바르지 않거나 암호화된 7z 블록이 손상되었습니다.")
        }
        sevenz_rust2::Error::ChecksumVerificationFailed | sevenz_rust2::Error::NextHeaderCrcMismatch => {
            anyhow!("7z 무결성 검증(CRC) 실패: 비밀번호 불일치 또는 파일 손상입니다.")
        }
        other => anyhow!("7z 처리 오류: {}", other),
    }
}

fn map_7z_block_method(archive: &sevenz_rust2::Archive) -> ChunkMethod {
    for block in &archive.blocks {
        for coder in &block.coders {
            let id = coder.encoder_method_id();
            if id == sevenz_rust2::EncoderMethod::ID_LZMA2
                || id == sevenz_rust2::EncoderMethod::ID_LZMA
            {
                return ChunkMethod::Lzma2;
            }
            if id == sevenz_rust2::EncoderMethod::ID_ZSTD {
                return ChunkMethod::Zstd;
            }
            if id == sevenz_rust2::EncoderMethod::ID_LZ4 {
                return ChunkMethod::Lz4;
            }
            if id == sevenz_rust2::EncoderMethod::ID_DEFLATE
                || id == sevenz_rust2::EncoderMethod::ID_DEFLATE64
            {
                return ChunkMethod::Deflate;
            }
            if id == sevenz_rust2::EncoderMethod::ID_COPY {
                return ChunkMethod::Store;
            }
        }
    }
    ChunkMethod::Lzma2
}

fn is_7z_content_encrypted(archive: &sevenz_rust2::Archive) -> bool {
    archive.blocks.iter().any(|b| {
        b.coders
            .iter()
            .any(|c| c.encoder_method_id() == sevenz_rust2::EncoderMethod::ID_AES256_SHA256)
    })
}

fn nt_time_to_unix(has_mtime: bool, nt: sevenz_rust2::NtTime) -> i64 {
    if !has_mtime {
        return 0;
    }
    let st: SystemTime = nt.into();
    st.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn open_7z_archive_meta(
    path: &Path,
    password: Option<&str>,
) -> Result<(sevenz_rust2::Archive, sevenz_rust2::Password, MultiPartFileReader, bool)> {
    let mut source = MultiPartFileReader::open(path)?;
    let pw_str = password.unwrap_or("");
    let pw = if pw_str.is_empty() {
        sevenz_rust2::Password::empty()
    } else {
        sevenz_rust2::Password::from(pw_str)
    };

    let archive = match sevenz_rust2::Archive::read(&mut source, &pw) {
        Ok(a) => a,
        Err(sevenz_rust2::Error::PasswordRequired) => bail!("PASSWORD_REQUIRED"),
        Err(sevenz_rust2::Error::MaybeBadPassword(_))
        | Err(sevenz_rust2::Error::NextHeaderCrcMismatch)
        | Err(sevenz_rust2::Error::ChecksumVerificationFailed)
            if !pw_str.is_empty() =>
        {
            bail!("비밀번호가 올바르지 않습니다 (7z 헤더 복호화 실패).")
        }
        Err(e) => return Err(map_7z_err(e)),
    };

    let content_enc = is_7z_content_encrypted(&archive) || !pw_str.is_empty();
    if is_7z_content_encrypted(&archive) && pw_str.is_empty() {
        bail!("PASSWORD_REQUIRED");
    }

    Ok((archive, pw, source, content_enc))
}

fn read_7z_index(path: &Path, password: Option<&str>) -> Result<ArchiveIndex> {
    let (archive, pw, mut source, encrypted) = open_7z_archive_meta(path, password)?;
    let vol_count = source.volume_count();
    let total_packed_bytes: u64 = archive.pack_sizes().iter().sum();

    // If blocks are AES-encrypted (with unencrypted header), probe 1 byte from the first non-empty block to catch wrong passwords immediately
    if is_7z_content_encrypted(&archive) && !archive.blocks.is_empty() {
        let threads = (rayon::current_num_threads() as u32).clamp(1, 16);
        let bdec = sevenz_rust2::BlockDecoder::new(threads, 0, &archive, &pw, &mut source);
        bdec.for_each_entries(&mut |_entry, reader| {
            let mut probe = [0u8; 32];
            let _ = reader.read(&mut probe)?;
            Ok(false)
        })
        .map_err(map_7z_err)?;
    }

    let primary_method = map_7z_block_method(&archive);
    let mut files = Vec::new();
    let mut visited_dirs = Vec::new();
    let mut seen_dirs = HashSet::new();

    for (idx, f) in archive.files.iter().enumerate() {
        if f.is_anti_item() {
            continue;
        }
        let norm = f
            .name()
            .replace('\\', "/")
            .trim_matches('/')
            .to_string();
        if norm.is_empty() {
            continue;
        }

        if f.is_directory() {
            if seen_dirs.insert(norm.clone()) {
                visited_dirs.push(norm);
            }
        } else {
            let orig_size = f.size();
            let comp_size = if f.compressed_size > 0 {
                f.compressed_size
            } else {
                orig_size
            };
            let mod_unix = nt_time_to_unix(f.has_last_modified_date, f.last_modified_date());
            files.push(FileEntry {
                rel_path: norm,
                original_size: orig_size,
                compressed_size: comp_size,
                crc32: f.crc as u32,
                modified_unix: mod_unix,
                smart_bypassed: primary_method == ChunkMethod::Store && orig_size > 0,
                chunks: vec![ChunkMeta {
                    chunk_id: idx as u64,
                    offset: 0,
                    compressed_size: comp_size,
                    uncompressed_size: orig_size,
                    method: primary_method,
                }],
            });
        }
    }

    let mut non_empty_dirs = HashSet::new();
    for f in &files {
        mark_parent_prefixes(&f.rel_path, &mut non_empty_dirs);
    }
    for d in &visited_dirs {
        mark_parent_prefixes(d, &mut non_empty_dirs);
    }
    let empty_dirs: Vec<String> = visited_dirs
        .into_iter()
        .filter(|d| !non_empty_dirs.contains(d))
        .collect();

    let total_original_size: u64 = files.iter().map(|f| f.original_size).sum();
    let base_resolved = resolve_base_smc_path(path);
    let created_unix = fs::metadata(&base_resolved)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(ArchiveIndex {
        version: 1,
        created_unix,
        mode_used: CompressionMode::ZstdMax,
        encrypted,
        total_original_size,
        total_compressed_size: total_packed_bytes,
        volume_count: vol_count,
        split_size_bytes: 0,
        files,
        empty_dirs,
        format: ArchiveFormat::SevenZ,
    })
}

fn find_7z_block_for_file(
    archive: &sevenz_rust2::Archive,
    pw: &sevenz_rust2::Password,
    source: &mut MultiPartFileReader,
    target_ptr: *const sevenz_rust2::ArchiveEntry,
) -> Option<usize> {
    for block_idx in 0..archive.blocks.len() {
        let dec = sevenz_rust2::BlockDecoder::new(1, block_idx, archive, pw, source);
        if dec
            .entries()
            .iter()
            .any(|e| std::ptr::eq(e as *const _, target_ptr))
        {
            return Some(block_idx);
        }
    }
    None
}

fn extract_7z_preview_bytes(
    path: &Path,
    entry: &FileEntry,
    password: Option<&str>,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if entry.original_size == 0 {
        return Ok(Vec::new());
    }
    let file_idx = entry
        .chunks
        .first()
        .map(|c| c.chunk_id as usize)
        .ok_or_else(|| anyhow!("7z 엔트리 인덱스가 없습니다."))?;

    let (archive, pw, mut source, _) = open_7z_archive_meta(path, password)?;
    let target_file = archive
        .files
        .get(file_idx)
        .ok_or_else(|| anyhow!("7z 엔트리를 찾을 수 없습니다."))?;
    if !target_file.has_stream() {
        return Ok(Vec::new());
    }

    let target_ptr = target_file as *const sevenz_rust2::ArchiveEntry;
    let Some(block_idx) = find_7z_block_for_file(&archive, &pw, &mut source, target_ptr) else {
        return Ok(Vec::new());
    };

    let threads = (rayon::current_num_threads() as u32).clamp(1, 16);
    let bdec = sevenz_rust2::BlockDecoder::new(threads, block_idx, &archive, &pw, &mut source);
    let mut out = Vec::with_capacity(max_bytes.min(entry.original_size as usize));

    bdec.for_each_entries(&mut |ae, reader| {
        if std::ptr::eq(ae as *const _, target_ptr) {
            reader.take(max_bytes as u64).read_to_end(&mut out)?;
            Ok(false)
        } else {
            std::io::copy(reader, &mut std::io::sink())?;
            Ok(true)
        }
    })
    .map_err(map_7z_err)?;

    Ok(out)
}

fn extract_7z_to_temp_file(
    path: &Path,
    entry: &FileEntry,
    password: Option<&str>,
) -> Result<PathBuf> {
    let archive_hash = crc32fast::hash(path.to_string_lossy().as_bytes());
    let temp_root = std::env::temp_dir()
        .join("smc_instant_open")
        .join(format!("7z_{:08X}", archive_hash));
    let out_path = sanitize_join(&temp_root, &entry.rel_path)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }

    if entry.original_size == 0 {
        File::create(&out_path)?;
        restore_file_mtime(&out_path, entry.modified_unix);
        return Ok(out_path);
    }

    let file_idx = entry
        .chunks
        .first()
        .map(|c| c.chunk_id as usize)
        .ok_or_else(|| anyhow!("7z 엔트리 인덱스가 없습니다."))?;
    let (archive, pw, mut source, _) = open_7z_archive_meta(path, password)?;
    let target_file = archive
        .files
        .get(file_idx)
        .ok_or_else(|| anyhow!("7z 엔트리를 찾을 수 없습니다."))?;
    if !target_file.has_stream() {
        File::create(&out_path)?;
        restore_file_mtime(&out_path, entry.modified_unix);
        return Ok(out_path);
    }

    let target_ptr = target_file as *const sevenz_rust2::ArchiveEntry;
    let Some(block_idx) = find_7z_block_for_file(&archive, &pw, &mut source, target_ptr) else {
        File::create(&out_path)?;
        return Ok(out_path);
    };

    let threads = (rayon::current_num_threads() as u32).clamp(1, 16);
    let bdec = sevenz_rust2::BlockDecoder::new(threads, block_idx, &archive, &pw, &mut source);
    let mut written_ok = false;

    let res = bdec.for_each_entries(&mut |ae, reader| {
        if std::ptr::eq(ae as *const _, target_ptr) {
            let mut out_f = BufWriter::with_capacity(2 * 1024 * 1024, File::create(&out_path)?);
            std::io::copy(reader, &mut out_f)?;
            out_f.flush()?;
            written_ok = true;
            Ok(false)
        } else {
            std::io::copy(reader, &mut std::io::sink())?;
            Ok(true)
        }
    });

    if let Err(e) = res {
        let _ = fs::remove_file(&out_path);
        return Err(map_7z_err(e));
    }
    if !written_ok {
        bail!("7z 아카이브에서 대상 스트림을 추출하지 못했습니다.");
    }

    restore_file_mtime(&out_path, entry.modified_unix);
    Ok(out_path)
}

fn unpack_7z(
    path: &Path,
    dest_dir: &Path,
    password: Option<&str>,
    selected_files: Option<&HashSet<String>>,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    let start_time = Instant::now();
    let index = read_7z_index(path, password)?;
    let (archive, pw, source, _) = open_7z_archive_meta(path, password)?;
    let vol_count = source.volume_count();
    drop(source);

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
    let total_comp = index.total_compressed_size;
    progress.total_bytes.store(total_orig, Ordering::Relaxed);
    progress
        .total_files
        .store(target_entries.len(), Ordering::Relaxed);

    fs::create_dir_all(dest_dir)?;
    if selected_files.is_none() {
        for empty_dir in &index.empty_dirs {
            let dir_path = sanitize_join(dest_dir, empty_dir)?;
            fs::create_dir_all(&dir_path)?;
        }
    }

    // 1. Create any 0-byte / empty-stream selected files up front
    for f in &archive.files {
        if f.is_directory() || f.is_anti_item() || (f.has_stream() && f.size() > 0) {
            continue;
        }
        let norm = f.name().replace('\\', "/").trim_matches('/').to_string();
        if norm.is_empty() {
            continue;
        }
        if let Some(sel) = selected_files {
            if !sel.contains(&norm) {
                continue;
            }
        }
        let out_path = sanitize_join(dest_dir, &norm)?;
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        File::create(&out_path)?;
        restore_file_mtime(
            &out_path,
            nt_time_to_unix(f.has_last_modified_date, f.last_modified_date()),
        );
        progress.processed_files.fetch_add(1, Ordering::Relaxed);
    }

    // 2. Decode non-empty 7z blocks in parallel across CPU cores!
    let block_count = archive.blocks.len();
    let threads_per_block = if block_count <= 1 {
        (rayon::current_num_threads() as u32).clamp(1, 32)
    } else {
        1
    };

    (0..block_count)
        .into_par_iter()
        .try_for_each(|block_idx| -> Result<()> {
            if progress.is_cancelled.load(Ordering::Relaxed) {
                bail!("사용자에 의해 압축 해제가 취소되었습니다.");
            }
            let mut local_source = MultiPartFileReader::open(path)?;
            let probe_dec =
                sevenz_rust2::BlockDecoder::new(1, block_idx, &archive, &pw, &mut local_source);

            // Skip blocks that contain zero selected files
            if let Some(sel) = selected_files {
                let any_needed = probe_dec.entries().iter().any(|ae| {
                    !ae.is_directory()
                        && !ae.is_anti_item()
                        && sel.contains(ae.name().replace('\\', "/").trim_matches('/'))
                });
                if !any_needed {
                    return Ok(());
                }
            }

            let bdec = sevenz_rust2::BlockDecoder::new(
                threads_per_block,
                block_idx,
                &archive,
                &pw,
                &mut local_source,
            );
            let mut cancel_err: Option<anyhow::Error> = None;

            let res = bdec.for_each_entries(&mut |ae, reader| {
                if progress.is_cancelled.load(Ordering::Relaxed) {
                    cancel_err = Some(anyhow!("사용자에 의해 압축 해제가 취소되었습니다."));
                    return Ok(false);
                }
                if ae.is_directory() || ae.is_anti_item() || !ae.has_stream() || ae.size() == 0 {
                    return Ok(true);
                }
                let norm = ae.name().replace('\\', "/").trim_matches('/').to_string();
                let wanted = selected_files.map(|s| s.contains(&norm)).unwrap_or(true);
                if !wanted {
                    std::io::copy(reader, &mut std::io::sink())?;
                    return Ok(true);
                }

                progress.set_current(norm.clone());
                let out_path = match sanitize_join(dest_dir, &norm) {
                    Ok(p) => p,
                    Err(e) => {
                        cancel_err = Some(e);
                        return Ok(false);
                    }
                };
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                let mut out_file = BufWriter::with_capacity(512 * 1024, File::create(&out_path)?);
                let mut buf = vec![0u8; 256 * 1024];
                loop {
                    if progress.is_cancelled.load(Ordering::Relaxed) {
                        drop(out_file);
                        let _ = fs::remove_file(&out_path);
                        cancel_err = Some(anyhow!("사용자에 의해 압축 해제가 취소되었습니다."));
                        return Ok(false);
                    }
                    let n = match reader.read(&mut buf) {
                        Ok(n) => n,
                        Err(e) => {
                            drop(out_file);
                            let _ = fs::remove_file(&out_path);
                            return Err(sevenz_rust2::Error::from(e));
                        }
                    };
                    if n == 0 {
                        break;
                    }
                    out_file.write_all(&buf[..n])?;
                    progress
                        .processed_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                out_file.flush()?;
                drop(out_file);

                restore_file_mtime(
                    &out_path,
                    nt_time_to_unix(ae.has_last_modified_date, ae.last_modified_date()),
                );
                progress.processed_files.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            });

            if let Some(err) = cancel_err {
                return Err(err);
            }
            res.map_err(map_7z_err)?;
            Ok(())
        })?;

    Ok(OperationStats {
        elapsed_secs: start_time.elapsed().as_secs_f64(),
        total_original_bytes: total_orig,
        total_compressed_bytes: total_comp,
        file_count: progress.processed_files.load(Ordering::Relaxed),
        smart_bypassed_count: 0,
        excluded_dev_count: 0,
        threads_used: rayon::current_num_threads(),
        volume_count: vol_count,
    })
}

fn verify_7z(
    path: &Path,
    password: Option<&str>,
    progress: Arc<ProgressTracker>,
) -> Result<OperationStats> {
    let start_time = Instant::now();
    let index = read_7z_index(path, password)?;
    let (archive, pw, source, _) = open_7z_archive_meta(path, password)?;
    let vol_count = source.volume_count();
    drop(source);

    for empty_dir in &index.empty_dirs {
        let _ = sanitize_join(Path::new("."), empty_dir)?;
    }
    for f in &index.files {
        let _ = sanitize_join(Path::new("."), &f.rel_path)?;
    }

    let total_orig = index.total_original_size;
    let total_comp = index.total_compressed_size;
    progress.total_bytes.store(total_orig, Ordering::Relaxed);
    progress
        .total_files
        .store(index.files.len(), Ordering::Relaxed);

    // Count 0-byte files immediately
    let zero_files = index
        .files
        .iter()
        .filter(|f| f.original_size == 0)
        .count();
    progress
        .processed_files
        .fetch_add(zero_files, Ordering::Relaxed);

    let block_count = archive.blocks.len();
    let threads_per_block = if block_count <= 1 {
        (rayon::current_num_threads() as u32).clamp(1, 32)
    } else {
        1
    };

    (0..block_count)
        .into_par_iter()
        .try_for_each(|block_idx| -> Result<()> {
            if progress.is_cancelled.load(Ordering::Relaxed) {
                bail!("사용자에 의해 무결성 검사가 취소되었습니다.");
            }
            let mut local_source = MultiPartFileReader::open(path)?;
            let bdec = sevenz_rust2::BlockDecoder::new(
                threads_per_block,
                block_idx,
                &archive,
                &pw,
                &mut local_source,
            );
            let mut cancel_err: Option<anyhow::Error> = None;

            let res = bdec.for_each_entries(&mut |ae, reader| {
                if progress.is_cancelled.load(Ordering::Relaxed) {
                    cancel_err = Some(anyhow!("사용자에 의해 무결성 검사가 취소되었습니다."));
                    return Ok(false);
                }
                if ae.is_directory() || ae.is_anti_item() || !ae.has_stream() || ae.size() == 0 {
                    return Ok(true);
                }
                progress.set_current(format!("7z 무결성 검증 중: {}", ae.name()));
                let mut buf = vec![0u8; 256 * 1024];
                // BlockDecoder wraps each entry in Crc32VerifyingReader, automatically verifying CRC32 at EOF!
                loop {
                    if progress.is_cancelled.load(Ordering::Relaxed) {
                        cancel_err = Some(anyhow!("사용자에 의해 무결성 검사가 취소되었습니다."));
                        return Ok(false);
                    }
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    progress
                        .processed_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                progress.processed_files.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            });

            if let Some(err) = cancel_err {
                return Err(err);
            }
            res.map_err(map_7z_err)?;
            Ok(())
        })?;

    Ok(OperationStats {
        elapsed_secs: start_time.elapsed().as_secs_f64(),
        total_original_bytes: total_orig,
        total_compressed_bytes: total_comp,
        file_count: progress.processed_files.load(Ordering::Relaxed),
        smart_bypassed_count: 0,
        excluded_dev_count: 0,
        threads_used: rayon::current_num_threads(),
        volume_count: vol_count,
    })
}
