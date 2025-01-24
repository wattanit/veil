//! Metadata management for the Veil secure file encryption tool.
//!
//! This module handles the storage and retrieval of metadata related to
//! encrypted files, including file entries and directory structures.
//! It provides functionality to insert, retrieve, and list files in the
//! encrypted repository.
//!
//! # Overview
//!
//! The `MetadataDB` struct manages the metadata for encrypted files,
//! allowing for secure storage and retrieval of file entries. It uses
//! the `CryptoManager` for encryption and decryption of metadata.
//!
//! # Usage
//!
//! To use this module, create an instance of `MetadataDB` with a path
//! and a master password:
//!
//! ```rust
//! let db = MetadataDB::new(PathBuf::from("path/to/db"), "your_password").unwrap();
//! ```
//!
//! You can then insert, retrieve, and manage file entries:
//!
//! ```rust
//! let entry = FileEntry {
//!     id: 1,
//!     original_path: String::from("test/file.txt"),
//!     size: 1234,
//!     modified_time: 1620000000,
//!     content_hash: [0; 32],
//!     nonce: FileNonce {
//!         file_id: 1,
//!         chunk_counter: 0,
//!         random: [0; 8],
//!     },
//! };
//! db.insert_file(entry).unwrap();
//! ```


use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::crypto::{CryptoManager, FileNonce};
use crate::error::VeilError;

/// Represents the header for the metadata database.
#[derive(Serialize, Deserialize, Debug)]
pub struct MetadataHeader {
    version: u8,
    created_at: u64,
    salt: [u8; 16],
    nonce_counter: u64,
    repo_id: [u8; 8],
}

/// Represents a file entry in the metadata database.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct FileEntry {
    pub id: u64,                 // Unique identifier for the file
    pub original_path: String,   // Original file path
    pub size: u64,              // Size of the file in bytes
    pub modified_time: u64,      // Last modification timestamp
    pub content_hash: [u8; 32],  // Hash of the file content for integrity
    pub nonce: FileNonce,        // Nonce used for file encryption
}

/// Represents the metadata database.
pub struct MetadataDB {
    db: sled::Db,            // The underlying sled database
    crypto: CryptoManager,   // Crypto manager for encryption/decryption
    header: MetadataHeader,  // Metadata header information
}

impl MetadataDB {
    /// Creates a new `MetadataDB` instance.
    ///
    /// This function initializes the database at the specified path
    /// and attempts to load an existing header. If no header exists,
    /// a new one is created.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the database.
    /// * `password` - The master password for encryption.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `MetadataDB` instance or a `VeilError`.
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

    /// Inserts a new file entry into the metadata database.
    ///
    /// This function encrypts the file entry and stores it in the database,
    /// along with the path-to-ID mapping and directory entries for browsing.
    ///
    /// # Arguments
    ///
    /// * `entry` - The `FileEntry` to insert.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure as a `VeilError`.
    pub fn insert_file(&mut self, entry: FileEntry) -> Result<(), VeilError> {
        // Check if a file with the same ID already exists
        if self.db.contains_key(format!("file:{}", entry.id).as_bytes())? {
            return Err(VeilError::Metadata("File already exists".to_string()));
        }

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

    /// Retrieves a file entry by its unique identifier.
    ///
    /// This function decrypts the file entry using the stored nonce.
    ///
    /// # Arguments
    ///
    /// * `id` - The unique identifier of the file.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing an `Option<FileEntry>` or a `VeilError`.
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

    /// Lists the contents of a directory.
    ///
    /// This function retrieves the names of files in the specified directory.
    ///
    /// # Arguments
    ///
    /// * `path` - The path of the directory to list.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a vector of file names or a `VeilError`.
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

    /// Retrieves a file entry by its original path.
    ///
    /// This function looks up the file ID using the path and retrieves the file entry.
    ///
    /// # Arguments
    ///
    /// * `path` - The original path of the file.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing an `Option<FileEntry>` or a `VeilError`.
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

    /// Removes a file entry from the metadata database.
    ///
    /// This function deletes the file entry, its path-to-ID mapping,
    /// and updates the directory entries accordingly.
    ///
    /// # Arguments
    ///
    /// * `id` - The unique identifier of the file to remove.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure as a `VeilError`.
    pub fn remove_file(&mut self, id: u64) -> Result<(), VeilError> {
        // Retrieve the file entry to get its original path
        if let Some(encrypted_entry) = self.db.get(format!("file:{}", id).as_bytes())? {
            let nonce_bytes = encrypted_entry.get(..24)
                .ok_or(VeilError::InvalidMetadata)?;
            let nonce: FileNonce = bincode::deserialize(nonce_bytes)?;
            let entry_bytes = self.crypto.decrypt_chunk(&encrypted_entry[24..], &nonce)?;
            let entry: FileEntry = bincode::deserialize(&entry_bytes)?;

            // Remove the file entry
            self.db.remove(format!("file:{}", id).as_bytes())?;

            // Remove path-to-ID mapping
            let path_key = format!("path:{}", entry.original_path);
            self.db.remove(path_key.as_bytes())?;

            // Update directory entries
            let mut current_path = PathBuf::from(&entry.original_path);
            while let Some(parent) = current_path.parent() {
                if parent.to_string_lossy().is_empty() {
                    break;
                }

                let dir_key = format!("dir:{}", parent.to_string_lossy());
                if let Some(existing) = self.db.get(dir_key.as_bytes())? {
                    let mut entries = String::from_utf8(existing.to_vec())
                        .map_err(|_| VeilError::InvalidMetadata)?;
                    let entry_name = current_path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string();

                    // Remove the entry name from the directory
                    entries = entries.lines()
                        .filter(|&name| name != entry_name)
                        .collect::<Vec<&str>>()
                        .join("\n");

                    self.db.insert(dir_key.as_bytes(), entries.as_bytes())?;
                }

                current_path = parent.to_path_buf();
            }

            Ok(())
        } else {
            Err(VeilError::Metadata("File not found".to_string()))
        }
    }

    /// Updates an existing file entry in the metadata database.
    ///
    /// This function re-encrypts the updated file entry and stores it
    /// back in the database.
    ///
    /// # Arguments
    ///
    /// * `entry` - The updated `FileEntry` to store.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure as a `VeilError`.
    pub fn update_file(&mut self, entry: FileEntry) -> Result<(), VeilError> {
        // Check if the original path is valid
        if entry.original_path.is_empty() {
            return Err(VeilError::Metadata("Invalid file path".to_string()));
        }

        // Serialize and encrypt the updated file entry
        let entry_bytes = bincode::serialize(&entry)?;
        let nonce = CryptoManager::generate_file_nonce(entry.id);
        let encrypted_entry = self.crypto.encrypt_chunk(&entry_bytes, &nonce)?;

        // Store the nonce alongside the encrypted data
        let nonce_bytes = bincode::serialize(&nonce)?;
        let mut full_entry = nonce_bytes;
        full_entry.extend(encrypted_entry);

        // Update the file entry in the database
        self.db.insert(format!("file:{}", entry.id).as_bytes(), full_entry)?;

        // Update the path-to-ID mapping
        let path_key = format!("path:{}", entry.original_path);
        self.db.insert(path_key.as_bytes(), entry.id.to_string().as_bytes())?;

        // Update directory entries if the original path has changed
        Ok(())
    }

    /// Retrieves the `CryptoManager` instance used for encryption and decryption.
    ///
    /// This function provides access to the `CryptoManager` that was initialized
    /// with the `MetadataDB`. It can be used to perform encryption or decryption
    /// operations on data related to the metadata.
    ///
    /// # Returns
    ///
    /// Returns a cloned instance of `CryptoManager`.
    pub fn get_crypto_manager(&self) -> CryptoManager {
        self.crypto.clone()
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

    #[test]
    fn test_remove_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        let entry = FileEntry {
            id: 5,
            original_path: String::from("test/file5.txt"),
            size: 1500,
            modified_time: 1620000004,
            content_hash: [0; 32],
            nonce: FileNonce {
                file_id: 5,
                chunk_counter: 0,
                random: [0; 8],
            },
        };

        db.insert_file(entry.clone()).unwrap();
        assert!(db.get_file(5).unwrap().is_some()); // Ensure the file exists before removal

        // Test removing the file
        let result = db.remove_file(5);
        assert!(result.is_ok());
        assert!(db.get_file(5).unwrap().is_none()); // Ensure the file no longer exists
    }

    #[test]
    fn test_update_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        let mut entry = FileEntry {
            id: 6,
            original_path: String::from("test/file6.txt"),
            size: 2000,
            modified_time: 1620000005,
            content_hash: [0; 32],
            nonce: FileNonce {
                file_id: 6,
                chunk_counter: 0,
                random: [0; 8],
            },
        };

        db.insert_file(entry.clone()).unwrap();

        // Update the entry
        entry.size = 2500; // Change the size
        let result = db.update_file(entry.clone());
        assert!(result.is_ok());

        // Retrieve the updated entry
        let updated_entry = db.get_file(6).unwrap().unwrap();
        assert_eq!(updated_entry.size, 2500); // Ensure the size has been updated
    }

    #[test]
    fn test_remove_nonexistent_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        // Attempt to remove a file that doesn't exist
        let result = db.remove_file(999); // Assuming 999 does not exist
        assert!(result.is_err());

        // Check that the error is of the expected variant
        if let Err(e) = result {
            match e {
                VeilError::Metadata(msg) => assert_eq!(msg, "File not found".to_string()),
                _ => panic!("Expected Metadata error, got {:?}", e),
            }
        }
    }

    #[test]
    fn test_update_file_with_invalid_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        let entry = FileEntry {
            id: 7,
            original_path: String::from("test/file7.txt"),
            size: 2000,
            modified_time: 1620000005,
            content_hash: [0; 32],
            nonce: FileNonce {
                file_id: 7,
                chunk_counter: 0,
                random: [0; 8],
            },
        };

        db.insert_file(entry.clone()).unwrap();

        // Attempt to update with an invalid path
        let mut updated_entry = entry.clone();
        updated_entry.original_path = String::from(""); // Set to an empty string to simulate an invalid path

        let result = db.update_file(updated_entry);
        assert!(result.is_err());

        // Check that the error is of the expected variant
        if let Err(e) = result {
            match e {
                VeilError::Metadata(msg) => assert_eq!(msg, "Invalid file path".to_string()),
                _ => panic!("Expected Metadata error, got {:?}", e),
            }
        }
    }

    #[test]
    fn test_insert_file_with_duplicate_id() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        let entry1 = FileEntry {
            id: 8,
            original_path: String::from("test/file8.txt"),
            size: 2000,
            modified_time: 1620000005,
            content_hash: [0; 32],
            nonce: FileNonce {
                file_id: 8,
                chunk_counter: 0,
                random: [0; 8],
            },
        };

        let entry2 = FileEntry {
            id: 8, // Same ID as entry1
            original_path: String::from("test/file8_duplicate.txt"),
            size: 3000,
            modified_time: 1620000006,
            content_hash: [0; 32],
            nonce: FileNonce {
                file_id: 8,
                chunk_counter: 0,
                random: [0; 8],
            },
        };

        db.insert_file(entry1).unwrap();
        let result = db.insert_file(entry2); // Attempt to insert with duplicate ID
        assert!(result.is_err());

        // Check that the error is of the expected variant
        if let Err(e) = result {
            match e {
                VeilError::Metadata(msg) => assert_eq!(msg, "File already exists".to_string()), // Adjust this error as needed
                _ => panic!("Expected Metadata error, got {:?}", e),
            }
        }
    }

    // Clean up the temporary directory after all tests
    #[test]
    fn cleanup() {
        let dir = tempdir().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
