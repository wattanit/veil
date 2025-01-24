use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::crypto::{self, CryptoManager, FileNonce};
use crate::error::VeilError;

#[derive(Serialize, Deserialize, Debug)]
pub struct MetadataHeader {
    version: u8,
    created_at: u64,
    salt: [u8; 16],
    nonce_counter: u64,
    repo_id: [u8; 8],
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
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
        // Store the file entry itself
        let entry_bytes = bincode::serialize(&entry)?;
        let nonce = CryptoManager::generate_file_nonce(entry.id);
        
        // Store nonce alongside encrypted data
        let nonce_bytes = bincode::serialize(&nonce)?;
        let encrypted_entry = self.crypto.encrypt_chunk(&entry_bytes, &nonce)?;
        
        let mut full_entry = nonce_bytes;
        full_entry.extend(encrypted_entry);
        
        self.db.insert(format!("file:{}", entry.id).as_bytes(), full_entry)?;

        // Store path-to-id mapping for browsing
        let path_key = format!("path:{}", entry.original_path);
        self.db.insert(path_key.as_bytes(), entry.id.to_string().as_bytes())?;

        // Store directory entries for browsing
        let mut current_path = PathBuf::from(&entry.original_path);
        while let Some(parent) = current_path.parent() {
            if parent.to_string_lossy().is_empty() {
                break;
            }
            
            let dir_key = format!("dir:{}", parent.to_string_lossy());
            let entry_name = current_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            
            // Append to existing directory entries or create new
            if let Some(existing) = self.db.get(dir_key.as_bytes())? {
                let mut entries = String::from_utf8(existing.to_vec())
                    .map_err(|_| VeilError::InvalidMetadata)?;
                if !entries.contains(&entry_name) {
                    entries.push('\n');
                    entries.push_str(&entry_name);
                    self.db.insert(dir_key.as_bytes(), entries.as_bytes())?;
                }
            } else {
                self.db.insert(dir_key.as_bytes(), entry_name.as_bytes())?;
            }
            
            current_path = parent.to_path_buf();
        }
        
        Ok(())
    }

    pub fn get_file(&self, id: u64) -> Result<Option<FileEntry>, VeilError> {
        if let Some(encrypted_entry) = self.db.get(format!("file:{}", id).as_bytes())? {
            // First get the nonce that was used during encryption (first 24 bytes)
            let nonce_bytes = encrypted_entry.get(..24)
                .ok_or(VeilError::InvalidMetadata)?;
            let nonce: FileNonce = bincode::deserialize(nonce_bytes)?;
            
            // Decrypt the rest using the stored nonce
            let entry_bytes = self.crypto.decrypt_chunk(&encrypted_entry[24..], &nonce)?;
            Ok(Some(bincode::deserialize(&entry_bytes)?))
        } else {
            Ok(None)
        }
    }

    pub fn list_directory(&self, path: &str) -> Result<Vec<String>, VeilError> {
        let dir_key = format!("dir:{}", path);
        if let Some(entries) = self.db.get(dir_key.as_bytes())? {
            let entries_str = String::from_utf8(entries.to_vec())
                .map_err(|_| VeilError::InvalidMetadata)?;
            Ok(entries_str.split('\n').map(String::from).collect())
        } else {
            Ok(Vec::new())
        }
    }

    pub fn get_file_by_path(&self, path: &str) -> Result<Option<FileEntry>, VeilError> {
        let path_key = format!("path:{}", path);
        if let Some(id_bytes) = self.db.get(path_key.as_bytes())? {
            let id = String::from_utf8(id_bytes.to_vec())
                .map_err(|_| VeilError::InvalidMetadata)?
                .parse::<u64>()
                .map_err(|_| VeilError::InvalidMetadata)?;
            self.get_file(id)
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_metadata_db_new() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        
        // Test creating a new MetadataDB
        let db = MetadataDB::new(path.clone(), "test_password");
        assert!(db.is_ok());
        
        // Clean up the temporary directory
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_insert_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        let entry = FileEntry {
            id: 1,
            original_path: String::from("test/file.txt"),
            size: 1234,
            modified_time: 1620000000,
            content_hash: [0; 32],
            nonce: FileNonce {
                file_id: 1,
                chunk_counter: 0,
                random: [0; 8],
            },
        };

        // Test inserting a file
        let result = db.insert_file(entry);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        let entry = FileEntry {
            id: 2,
            original_path: String::from("test/file2.txt"),
            size: 5678,
            modified_time: 1620000001,
            content_hash: [0; 32],
            nonce: FileNonce {
                file_id: 2,
                chunk_counter: 0,
                random: [0; 8],
            },
        };

        db.insert_file(entry.clone()).unwrap();
        let retrieved = db.get_file(2).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, entry.id);
    }

    #[test]
    fn test_list_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        let entry = FileEntry {
            id: 3,
            original_path: String::from("test/dir/file3.txt"),
            size: 91011,
            modified_time: 1620000002,
            content_hash: [0; 32],
            nonce: FileNonce {
                file_id: 3,
                chunk_counter: 0,
                random: [0; 8],
            },
        };

        db.insert_file(entry.clone()).unwrap();
        let entries = db.list_directory("test/dir").unwrap();
        assert!(entries.contains(&String::from("file3.txt")));
    }

    #[test]
    fn test_get_file_by_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        let entry = FileEntry {
            id: 4,
            original_path: String::from("test/file4.txt"),
            size: 1213,
            modified_time: 1620000003,
            content_hash: [0; 32],
            nonce: FileNonce {
                file_id: 4,
                chunk_counter: 0,
                random: [0; 8],
            },
        };

        db.insert_file(entry.clone()).unwrap();
        let retrieved = db.get_file_by_path("test/file4.txt").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, entry.id);
    }

    // Clean up the temporary directory after all tests
    #[test]
    fn cleanup() {
        let dir = tempdir().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
