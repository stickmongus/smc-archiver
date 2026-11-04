use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Magic bytes at the start of every .smc file: "SMC\x01"
pub const SMC_MAGIC: &[u8; 4] = b"SMC\x01";

/// Magic bytes at the very end of every .smc file: "SMCE"
pub const SMC_FOOTER_MAGIC: &[u8; 4] = b"SMCE";

/// Fixed header size:
/// - 4 bytes: Magic ("SMC\x01")
/// - 4 bytes: Flags (bit 0 = encrypted, bit 1 = split volume, bit 2 = KDF v2 600k iterations)
/// - 16 bytes: Salt for AES-256-GCM key derivation
/// - 8 bytes: Footer Index offset (u64 LE)
pub const HEADER_SIZE: usize = 32;

/// Default parallel chunk size: 4 MB per chunk so large files use all CPU cores
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Maximum allowed uncompressed size for a single .smc chunk (guards against corrupted headers / OOM)
pub const MAX_CHUNK_UNCOMPRESSED_SIZE: usize = 64 * 1024 * 1024;

/// Maximum allowed compressed/uncompressed Footer Index size (guards against corrupted headers / OOM)
pub const MAX_INDEX_COMPRESSED_SIZE: u64 = 256 * 1024 * 1024;
pub const MAX_INDEX_UNCOMPRESSED_SIZE: usize = 512 * 1024 * 1024;

pub const FLAG_ENCRYPTED: u32 = 1 << 0;
pub const FLAG_SPLIT_VOLUME: u32 = 1 << 1;
pub const FLAG_KDF_V2: u32 = 1 << 2;

/// Archive container format opened in the Viewer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ArchiveFormat {
    #[default]
    Smc,
    Zip,
    SevenZ,
}

impl ArchiveFormat {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Smc => ".smc 전용 초고속 컨테이너",
            Self::Zip => ".zip 표준 호환 아카이브",
            Self::SevenZ => ".7z 고압축 아카이브",
        }
    }
}

/// Target archive format when creating a new archive in the Packer tab
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Smc,
    Zip,
}

impl OutputFormat {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Smc => "⚡ .smc (멀티코어 초고속 · 분할 · AES-256)",
            Self::Zip => "📦 .zip (표준 범용 호환 포맷)",
        }
    }

    pub fn ext(&self) -> &'static str {
        match self {
            Self::Smc => "smc",
            Self::Zip => "zip",
        }
    }
}

/// User-selectable compression mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionMode {
    /// Smart mode: uses Store for media/already-compressed files, Zstd level 1 or LZ4 for others
    SmartAuto,
    /// Ultra-fast LZ4 multi-core compression
    Lz4Fast,
    /// Zstandard balanced multi-core compression (level 3)
    ZstdBalanced,
    /// Zstandard high compression (level 9)
    ZstdMax,
    /// Store only (0 compression overhead, pure parallel archiving)
    StoreOnly,
}

impl CompressionMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SmartAuto => "⚡ 스마트 초고속 (자동 최적화 · 추천)",
            Self::Lz4Fast => "🚀 LZ4 극한 속도 (수 GB/s급 초고속)",
            Self::ZstdBalanced => "⚖️ Zstd 밸런스 (고속 + 고압축률)",
            Self::ZstdMax => "💎 Zstd 고압축 (용량 최소화)",
            Self::StoreOnly => "📦 Store 무압축 묶기 (디스크 최고 속도)",
        }
    }
}

/// Split-volume preset options for multi-volume archiving (.smc, .s01, .s02, ...)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitPreset {
    None,
    Mb5,
    Mb10,
    Mb50,
    Mb100,
    Mb500,
    Gb1,
    Gb2,
    Gb4,
    Custom,
}

impl SplitPreset {
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "분할 안 함 (단일 파일)",
            Self::Mb5 => "5 MB 분할 (테스트/소형 첨부)",
            Self::Mb10 => "10 MB 분할 (이메일 첨부용)",
            Self::Mb50 => "50 MB 분할",
            Self::Mb100 => "100 MB 분할",
            Self::Mb500 => "500 MB 분할",
            Self::Gb1 => "1 GB 분할",
            Self::Gb2 => "2 GB 분할 (메신저/업로드용)",
            Self::Gb4 => "4 GB 분할 (FAT32 호환)",
            Self::Custom => "직접 입력 (MB)",
        }
    }

    pub fn to_bytes(&self, custom_mb: u64) -> Option<u64> {
        const MB: u64 = 1024 * 1024;
        const GB: u64 = 1024 * MB;
        match self {
            Self::None => None,
            Self::Mb5 => Some(5 * MB),
            Self::Mb10 => Some(10 * MB),
            Self::Mb50 => Some(50 * MB),
            Self::Mb100 => Some(100 * MB),
            Self::Mb500 => Some(500 * MB),
            Self::Gb1 => Some(GB),
            Self::Gb2 => Some(2 * GB),
            Self::Gb4 => Some(4 * GB),
            Self::Custom => {
                let clamped = custom_mb.max(1);
                Some(clamped * MB)
            }
        }
    }
}

/// Returns the path for volume `vol_index` (0 = `archive.smc`, 1 = `archive.s01`, 2 = `archive.s02`, ...)
pub fn volume_path_for(base_smc: &Path, vol_index: usize) -> PathBuf {
    if vol_index == 0 {
        return base_smc.to_path_buf();
    }
    let stem = base_smc
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("archive");
    let parent = base_smc.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{}.s{:02}", stem, vol_index))
}

/// If the user opens a split volume part like `archive.s01` or `archive.7z.002`, resolves the master volume path
pub fn resolve_base_smc_path(path: &Path) -> PathBuf {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let lower = ext.to_ascii_lowercase();
        // 1. .s01, .s02, ... -> .smc
        if lower.starts_with('s')
            && lower.len() >= 3
            && lower[1..].chars().all(|c| c.is_ascii_digit())
        {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("archive");
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            let candidate = parent.join(format!("{}.smc", stem));
            if candidate.exists() {
                return candidate;
            }
        }
        // 2. .7z.002, .7z.003, ... -> .7z.001
        if lower.len() >= 3 && lower.chars().all(|c| c.is_ascii_digit()) {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if stem.to_ascii_lowercase().ends_with(".7z") {
                let parent = path.parent().unwrap_or_else(|| Path::new("."));
                let width = lower.len();
                let candidate = parent.join(format!("{}.{:0width$}", stem, 1, width = width));
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    path.to_path_buf()
}

/// Actual method used for an individual chunk or external archive entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkMethod {
    Store,
    Lz4,
    Zstd,
    Deflate,
    Lzma2,
    #[serde(other)]
    Other,
}

impl ChunkMethod {
    pub fn badge(&self) -> &'static str {
        match self {
            Self::Store => "STORE (스마트패스)",
            Self::Lz4 => "LZ4",
            Self::Zstd => "ZSTD",
            Self::Deflate => "DEFLATE",
            Self::Lzma2 => "LZMA2",
            Self::Other => "ARCHIVE",
        }
    }
}

/// Metadata for a single parallel chunk of a file inside the .smc container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMeta {
    pub chunk_id: u64,
    pub offset: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub method: ChunkMethod,
}

/// Metadata for a single file stored inside an archive
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path inside the archive (normalized with '/')
    pub rel_path: String,
    /// Original uncompressed size in bytes
    pub original_size: u64,
    /// Total compressed size across all chunks
    pub compressed_size: u64,
    /// CRC32 checksum of the original file
    pub crc32: u32,
    /// Last modified timestamp (Unix seconds)
    pub modified_unix: i64,
    /// Whether this file was bypassed via Smart High-Speed Archiving
    pub smart_bypassed: bool,
    /// Ordered list of chunks comprising this file
    pub chunks: Vec<ChunkMeta>,
}

impl FileEntry {
    pub fn primary_method(&self) -> ChunkMethod {
        if self.smart_bypassed {
            return ChunkMethod::Store;
        }
        self.chunks
            .first()
            .map(|c| c.method)
            .unwrap_or(ChunkMethod::Store)
    }

    pub fn ratio_percent(&self) -> f64 {
        if self.original_size == 0 {
            100.0
        } else {
            (self.compressed_size as f64 / self.original_size as f64) * 100.0
        }
    }
}

/// Footer index stored at the end of a .smc archive (also used in-memory for .zip / .7z viewing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveIndex {
    pub version: u32,
    pub created_unix: i64,
    pub mode_used: CompressionMode,
    pub encrypted: bool,
    pub total_original_size: u64,
    pub total_compressed_size: u64,
    #[serde(default = "default_vol_count")]
    pub volume_count: usize,
    #[serde(default)]
    pub split_size_bytes: u64,
    pub files: Vec<FileEntry>,
    /// Empty directories preserved inside the archive (v1.2+, backward-compatible via serde default)
    #[serde(default)]
    pub empty_dirs: Vec<String>,
    /// Runtime-only container format tag
    #[serde(skip)]
    pub format: ArchiveFormat,
}

fn default_vol_count() -> usize {
    1
}

/// Extensions that are already compressed (video, image, audio, archives, modern office docs).
const ALREADY_COMPRESSED_EXTS: &[&str] = &[
    // Video
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpeg", "mpg", "ts",
    // Image
    "jpg", "jpeg", "png", "gif", "webp", "avif", "heic", "heif", "jxl",
    // Audio
    "mp3", "aac", "ogg", "flac", "m4a", "opus", "wma",
    // Archives & Disk Images
    "zip", "7z", "rar", "gz", "tgz", "bz2", "xz", "zst", "lz4", "smc", "cab", "iso", "dmg",
    // Documents & Packages (internally ZIP/compressed)
    "pdf", "docx", "xlsx", "pptx", "odt", "epub", "apk", "aab", "ipa", "jar", "whl", "nupkg",
    // Web fonts
    "woff", "woff2",
];

/// Default development/cache directories to skip when dev filter is explicitly enabled.
/// Note: "bin", "dist", and "build" are intentionally NOT excluded by default so portable apps/games never lose binaries!
pub const DEFAULT_DEV_EXCLUDES: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".idea",
    ".vscode",
    ".gradle",
    "obj",
];

/// Checks if a file path has an already-compressed extension suitable for Smart Bypass
pub fn is_already_compressed_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| {
            let lower = ext.to_ascii_lowercase();
            ALREADY_COMPRESSED_EXTS.contains(&lower.as_str())
        })
        .unwrap_or(false)
}

/// Checks if a relative path has an image extension supported by the built-in image previewer
pub fn is_previewable_image(rel_path: &str) -> bool {
    Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "ico"
            )
        })
        .unwrap_or(false)
}

/// Checks if any component of the relative path matches the excluded dev folder names
pub fn should_exclude_path(rel_path: &Path, exclude_list: &[String]) -> bool {
    for comp in rel_path.components() {
        if let std::path::Component::Normal(os_str) = comp {
            if let Some(name) = os_str.to_str() {
                if name == "Thumbs.db" || name == ".DS_Store" {
                    return true;
                }
                if exclude_list
                    .iter()
                    .any(|ex| ex.eq_ignore_ascii_case(name))
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Helper to format byte sizes into human-readable strings (KB, MB, GB)
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}
