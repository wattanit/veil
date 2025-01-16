use std::num::NonZeroU32;

use anyhow::Context;
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, PasswordHash,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};

use crate::error::VeilError;

// Constants for Argon2id configuration
const MEMORY_COST_KB: u32 = 64 * 1024; // 64MB
const TIME_COST: u32 = 3;
const PARALLELISM: u32 = 4;
const SALT_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 24;
const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks for streaming

pub struct CryptoManager {
    cipher: XChaCha20Poly1305,
}

#[derive(Debug, Clone)]
pub struct FileNonce {
    pub file_id: u64,
    pub chunk_counter: u64,
    pub random: [u8; 8],
}

impl CryptoManager {
    /// Create a new CryptoManager with a derived key from password
    pub fn new(password: &str, salt: &[u8]) -> anyhow::Result<Self> {
        let key = Self::derive_key(password, salt)?;
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        Ok(Self { cipher })
    }

    /// Derive an encryption key using Argon2id
    fn derive_key(password: &str, salt: &[u8]) -> anyhow::Result<[u8; KEY_LENGTH]> {
        let salt = SaltString::encode_b64(salt)
            .map_err(|e| anyhow::anyhow!("Failed to encode salt: {}", e))?;

        let params = Params::new(
            MEMORY_COST_KB,
            TIME_COST,
            PARALLELISM,
            Some(KEY_LENGTH as usize),
        )
        .map_err(|e| VeilError::Encryption(e.to_string()))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| VeilError::Encryption(e.to_string()))?;

        let mut key = [0u8; KEY_LENGTH];
        key.copy_from_slice(password_hash.hash.unwrap().as_bytes());
        Ok(key)
    }

    /// Generate a new random salt
    pub fn generate_salt() -> [u8; SALT_LENGTH] {
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Generate a new file nonce
    pub fn generate_file_nonce(file_id: u64) -> FileNonce {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        FileNonce {
            file_id,
            chunk_counter: 0,
            random,
        }
    }

    /// Convert FileNonce to XNonce for encryption
    fn file_nonce_to_xnonce(nonce: &FileNonce) -> XNonce {
        let mut bytes = [0u8; NONCE_LENGTH];
        bytes[0..8].copy_from_slice(&nonce.file_id.to_le_bytes());
        bytes[8..16].copy_from_slice(&nonce.chunk_counter.to_le_bytes());
        bytes[16..24].copy_from_slice(&nonce.random);
        XNonce::from(bytes)
    }

    /// Encrypt a chunk of data
    pub fn encrypt_chunk(&self, data: &[u8], nonce: &FileNonce) -> anyhow::Result<Vec<u8>> {
        let xnonce = Self::file_nonce_to_xnonce(nonce);
        self.cipher
            .encrypt(&xnonce, data)
            .map_err(|e| VeilError::Encryption(e.to_string()).into())
    }

    /// Decrypt a chunk of data
    pub fn decrypt_chunk(&self, encrypted_data: &[u8], nonce: &FileNonce) -> anyhow::Result<Vec<u8>> {
        let xnonce = Self::file_nonce_to_xnonce(nonce);
        self.cipher
            .decrypt(&xnonce, encrypted_data)
            .map_err(|e| VeilError::Encryption(e.to_string()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let password = "test_password";
        let salt = CryptoManager::generate_salt();
        
        let key1 = CryptoManager::derive_key(password, &salt).unwrap();
        let key2 = CryptoManager::derive_key(password, &salt).unwrap();
        
        assert_eq!(key1, key2, "Same password and salt should derive same key");
    }

    #[test]
    fn test_encryption_decryption() {
        let password = "test_password";
        let salt = CryptoManager::generate_salt();
        let crypto = CryptoManager::new(password, &salt).unwrap();
        
        let data = b"Hello, World!";
        let nonce = CryptoManager::generate_file_nonce(1);
        
        let encrypted = crypto.encrypt_chunk(data, &nonce).unwrap();
        let decrypted = crypto.decrypt_chunk(&encrypted, &nonce).unwrap();
        
        assert_eq!(data.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let nonce1 = CryptoManager::generate_file_nonce(1);
        let nonce2 = CryptoManager::generate_file_nonce(1);
        
        assert_ne!(nonce1.random, nonce2.random, "Random parts should be different");
    }

    #[test]
    fn test_invalid_decryption() {
        let password = "test_password";
        let salt = CryptoManager::generate_salt();
        let crypto = CryptoManager::new(password, &salt).unwrap();
        
        let data = b"Hello, World!";
        let nonce = CryptoManager::generate_file_nonce(1);
        
        let mut encrypted = crypto.encrypt_chunk(data, &nonce).unwrap();
        // Tamper with the encrypted data
        if let Some(byte) = encrypted.get_mut(0) {
            *byte ^= 1;
        }
        
        assert!(crypto.decrypt_chunk(&encrypted, &nonce).is_err());
    }
} 