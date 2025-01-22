use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::crypto::{self, CryptoManager, FileNonce};
use crate::error::VeilError;

#[derive(Serialize, Deserialize)]
pub struct MetadataHeader {
    version: u8,
    created_at: u64,
    salt: [u8; 16],
    nonce_counter: u64,
    repo_id: [u8; 8],
}

#[derive(Serialize, Deserialize)]
pub struct FileEntry {
    id: u64,                 // Unique identifier
    original_path: String,   // Original file path
    size: u64,              // File size
    modified_time: u64,      // Modification timestamp
    content_hash: [u8; 32],  // Hash of the content (for integrity/identification)
    nonce: FileNonce,        // Nonce used for the file encryption
}

pub struct MetadataDB {
    db: sled::Db,
    crypto: CryptoManager,
    header: MetadataHeader,
}

impl MetadataDB {
    pub fn new(path: PathBuf, password: &str) -> Result<Self, VeilError> {
        let db = sled::open(path)?;
        
        // First try to load existing header
        if let Some(encrypted_header) = db.get("header")? {
            // First, get the salt from the encrypted header
            // The salt should be stored in plaintext at the start of the header
            // This is safe because salt doesn't need to be secret
            let salt: [u8; 16] = encrypted_header.get(..16)
                .ok_or(VeilError::InvalidHeader)?
                .try_into()
                .map_err(|_| VeilError::InvalidHeader)?;
            
            // Create crypto manager with the correct salt
            let crypto = CryptoManager::new(password, &salt)?;
            
            let nonce = FileNonce {
                file_id: 0,
                chunk_counter: 0,
                random: [0; 8], // Header uses a fixed nonce
            };
            
            // Decrypt the rest of the header (after the salt)
            let header_bytes = crypto.decrypt_chunk(&encrypted_header[16..], &nonce)?;
            let header: MetadataHeader = bincode::deserialize(&header_bytes)?;
            
            // Verify that the salt in the header matches the one we used
            if header.salt != salt {
                return Err(VeilError::InvalidHeader);
            }
            
            Ok(Self { db, crypto, header })
        } else {
            // Create new header with new salt
            let salt = CryptoManager::generate_salt();
            let crypto = CryptoManager::new(password, &salt)?;
            
            let header = MetadataHeader {
                version: 1,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs(),
                salt,
                nonce_counter: 0,
                repo_id: rand::random(),
            };
            
            let header_bytes = bincode::serialize(&header)?;
            let nonce = FileNonce {
                file_id: 0,
                chunk_counter: 0,
                random: [0; 8],
            };
            
            // Store the salt in plaintext at the start of the encrypted header
            let mut encrypted_header = salt.to_vec();
            encrypted_header.extend(crypto.encrypt_chunk(&header_bytes, &nonce)?);
            
            db.insert("header", encrypted_header)?;
            
            Ok(Self { db, crypto, header })
        }
    }

    pub fn insert_file(&mut self, entry: FileEntry) -> Result<(), VeilError> {
        let entry_bytes = bincode::serialize(&entry)?;
        let nonce = CryptoManager::generate_file_nonce(entry.id);
        let encrypted_entry = self.crypto.encrypt_chunk(&entry_bytes, &nonce)?;
        self.db.insert(entry.id.to_string(), encrypted_entry)?;
        Ok(())
    }

    pub fn get_file(&self, id: u64) -> Result<Option<FileEntry>, VeilError> {
        if let Some(encrypted_entry) = self.db.get(id.to_string())? {
            let nonce = CryptoManager::generate_file_nonce(id);
            let entry_bytes = self.crypto.decrypt_chunk(&encrypted_entry, &nonce)?;
            Ok(Some(bincode::deserialize(&entry_bytes)?))
        } else {
            Ok(None)
        }
    }
}
