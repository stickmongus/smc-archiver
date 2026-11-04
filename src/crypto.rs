use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

/// Legacy PBKDF2-HMAC-SHA256 iterations (v1.1 archives without FLAG_KDF_V2)
pub const PBKDF2_ITERATIONS_V1: u32 = 60_000;

/// Strengthened OWASP-standard PBKDF2-HMAC-SHA256 iterations (v1.2+ archives with FLAG_KDF_V2)
pub const PBKDF2_ITERATIONS_V2: u32 = 600_000;

/// Special block ID reserved for encrypting the Footer Index Table
pub const INDEX_BLOCK_ID: u64 = u64::MAX;

struct CachedDerivedKey {
    lookup_tag: [u8; 32],
    key: [u8; 32],
}

impl Drop for CachedDerivedKey {
    fn drop(&mut self) {
        for b in &mut self.lookup_tag {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        for b in &mut self.key {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

static KEY_CACHE: Mutex<Option<CachedDerivedKey>> = Mutex::new(None);

/// Generates a random 16-byte salt
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn compute_lookup_tag(password: &str, salt: &[u8; 16], iterations: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SMC_KDF_CACHE_V1");
    hasher.update(salt);
    hasher.update(iterations.to_le_bytes());
    hasher.update((password.len() as u64).to_le_bytes());
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

/// Derives a 32-byte (256-bit) key using v1 (60k) or v2 (600k) PBKDF2 iterations,
/// caching the most recently unlocked archive key in memory so repeated previews take 0ms.
pub fn derive_key_versioned(password: &str, salt: &[u8; 16], use_kdf_v2: bool) -> [u8; 32] {
    let iterations = if use_kdf_v2 {
        PBKDF2_ITERATIONS_V2
    } else {
        PBKDF2_ITERATIONS_V1
    };
    let tag = compute_lookup_tag(password, salt, iterations);

    if let Ok(guard) = KEY_CACHE.lock() {
        if let Some(ref cached) = *guard {
            if cached.lookup_tag == tag {
                return cached.key;
            }
        }
    }

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);

    if let Ok(mut guard) = KEY_CACHE.lock() {
        *guard = Some(CachedDerivedKey {
            lookup_tag: tag,
            key,
        });
    }

    key
}

/// Default key derivation for newly created v1.2+ archives (uses 600,000 iterations)
pub fn derive_key(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    derive_key_versioned(password, salt, true)
}

/// Clears any cached encryption key from memory
pub fn clear_key_cache() {
    if let Ok(mut guard) = KEY_CACHE.lock() {
        *guard = None;
    }
}

/// Builds a unique 12-byte (96-bit) nonce for each chunk/block within an archive
fn build_nonce(salt: &[u8; 16], block_id: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&salt[0..4]);
    nonce[4..12].copy_from_slice(&block_id.to_le_bytes());
    nonce
}

/// Encrypts a byte slice with AES-256-GCM using the derived key, salt, and unique block_id
pub fn encrypt_block(
    data: &[u8],
    key_bytes: &[u8; 32],
    salt: &[u8; 16],
    block_id: u64,
) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = build_nonce(salt, block_id);
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .encrypt(nonce, data)
        .map_err(|_| anyhow!("AES-256-GCM 암호화 중 오류가 발생했습니다."))
}

/// Decrypts a byte slice with AES-256-GCM using the derived key, salt, and unique block_id
pub fn decrypt_block(
    data: &[u8],
    key_bytes: &[u8; 32],
    salt: &[u8; 16],
    block_id: u64,
) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = build_nonce(salt, block_id);
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, data)
        .map_err(|_| anyhow!("비밀번호가 올바르지 않거나 아카이브 데이터가 손상되었습니다 (AES-256-GCM 인증 실패)."))
}
