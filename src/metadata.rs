//! Metadata management for the Veil secure file encryption tool.
//!
//! This module provides functionality for managing encrypted file metadata,
//! including file entries, virtual paths, and directory structures. It uses
//! an encrypted sled database to store metadata securely.
//!
//! # Overview
//!
//! The metadata system consists of three main components:
//! - `MetadataHeader`: Contains repository-wide information
//! - `FileEntry`: Represents individual encrypted file metadata
//! - `MetadataDB`: Manages the encrypted metadata database
//!
//! # Usage
//!
//! To create or open a metadata database:
//!
//! ```rust
//! use std::path::PathBuf;
//! let db = MetadataDB::new(PathBuf::from("path/to/db"), "password")?;
//! ```
//!
//! To add a new file:
//!
//! ```rust
//! db.insert_file("source/path.txt", "virtual/path.txt")?;
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::crypto::{CryptoManager, FileNonce};
use crate::error::VeilError;

/// Represents the header for the metadata database.
/// 
/// The header contains repository-wide information including:
/// - Version number for format compatibility
/// - Creation timestamp
/// - Cryptographic salt
/// - Nonce counter for unique nonce generation
/// - Repository identifier
#[derive(Serialize, Deserialize, Debug)]
pub struct MetadataHeader {
    version: u8,
    created_at: u64,
    salt: [u8; 16],
    nonce_counter: u64,
    repo_id: [u8; 8],
}

/// Represents a file entry in the metadata database.
/// 
/// Each entry contains all necessary information about an encrypted file:
/// - Unique identifier
/// - Virtual and source paths
/// - File size and modification time
/// - Content hash for integrity verification
/// - Encryption nonce
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct FileEntry {
    pub id: u64,                 // Unique identifier for the file
    pub virtual_path: String,    // Path in our virtual filesystem
    pub source_path: String,     // Original source path (for reference only)
    pub size: u64,              // Size of the file in bytes
    pub modified_time: u64,      // Last modification timestamp
    pub content_hash: [u8; 32],  // Hash of the file content for integrity
    pub nonce: FileNonce,        // Nonce used for file encryption
}

/// Manages the encrypted metadata database.
/// 
/// The MetadataDB provides a secure interface for storing and retrieving
/// file metadata, managing virtual paths, and maintaining directory structures.
pub struct MetadataDB {
    db: sled::Db,            // The underlying sled database
    crypto: CryptoManager,   // Crypto manager for encryption/decryption
    header: MetadataHeader,  // Metadata header information
}

impl MetadataDB {

    /// Creates a new or opens an existing metadata database.
    ///
    /// This function will either initialize a new metadata database with the given
    /// password or open an existing one. For existing databases, the password must
    /// match the one used during creation.
    ///
    /// # Arguments
    ///
    /// * `path` - The path where the metadata database should be stored
    /// * `password` - The password used for encryption/decryption
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
    /// This function creates a new file entry and updates all necessary indexes
    /// including virtual path mappings and directory structures.
    ///
    /// # Arguments
    ///
    /// * `source_path` - The original path of the file being encrypted
    /// * `virtual_path` - The virtual path where the file will appear in the repository
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or a `VeilError`.
    pub fn insert_file(&mut self, source_path: &str, virtual_path: &str, file_id: u64) -> Result<(), VeilError> {
        // Check if a file with the same virtual path already exists
        if self.db.contains_key(format!("vpath:{}", virtual_path).as_bytes())? {
            return Err(VeilError::Metadata("File already exists".to_string()));
        }

        let entry = FileEntry {
            id: file_id,  // Use the provided file_id instead of generating a new one
            virtual_path: virtual_path.to_string(),
            source_path: source_path.to_string(), // Keep original path for reference
            size: std::fs::metadata(source_path)?.len(),
            modified_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs(),
            content_hash: [0; 32],
            nonce: CryptoManager::generate_file_nonce(file_id),  // Use the same file_id for nonce
        };

        // Store the file entry itself
        let entry_bytes = bincode::serialize(&entry)?;
        let nonce = CryptoManager::generate_file_nonce(entry.id);
        
        let nonce_bytes = bincode::serialize(&nonce)?;
        let encrypted_entry = self.crypto.encrypt_chunk(&entry_bytes, &nonce)?;
        
        let mut full_entry = nonce_bytes;
        full_entry.extend(encrypted_entry);
        
        self.db.insert(format!("file:{}", entry.id).as_bytes(), full_entry)?;

        // Store virtual path mapping
        let path_key = format!("vpath:{}", entry.virtual_path);
        self.db.insert(path_key.as_bytes(), entry.id.to_string().as_bytes())?;

        // Store directory entries for virtual path browsing
        let mut current_path = PathBuf::from(&entry.virtual_path);
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
    /// # Arguments
    ///
    /// * `id` - The unique identifier of the file entry
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

    /// Lists all entries in a virtual directory.
    ///
    /// # Arguments
    ///
    /// * `path` - The virtual path of the directory to list
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a vector of entry names or a `VeilError`.
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

    /// Retrieves a file entry by its virtual path.
    ///
    /// # Arguments
    ///
    /// * `path` - The virtual path of the file
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing an `Option<FileEntry>` or a `VeilError`.
    pub fn get_file_by_path(&self, path: &str) -> Result<Option<FileEntry>, VeilError> {
        let path_key = format!("vpath:{}", path);
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

    /// Removes a file entry and all associated metadata.
    ///
    /// This function removes the file entry and updates all necessary indexes
    /// including virtual path mappings and directory structures.
    ///
    /// # Arguments
    ///
    /// * `id` - The unique identifier of the file to remove
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or a `VeilError`.
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
            let path_key = format!("vpath:{}", entry.virtual_path);
            self.db.remove(path_key.as_bytes())?;

            // Update directory entries
            let mut current_path = PathBuf::from(&entry.virtual_path);
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

    /// Updates an existing file entry with new metadata.
    ///
    /// # Arguments
    ///
    /// * `entry` - The updated file entry
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or a `VeilError`.
    pub fn update_file(&mut self, entry: FileEntry) -> Result<(), VeilError> {
        // Check if the virtual path is valid
        if entry.virtual_path.is_empty() {
            return Err(VeilError::Metadata("Invalid virtual path".to_string()));
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

        // Update the virtual path mapping
        let path_key = format!("vpath:{}", entry.virtual_path);
        self.db.insert(path_key.as_bytes(), entry.id.to_string().as_bytes())?;

        // Update directory entries if the virtual path has changed
        // (You may want to implement additional logic here if needed)

        Ok(())
    }

    /// Returns a clone of the crypto manager used by this database.
    ///
    /// This allows other components to use the same encryption settings
    /// when working with file contents.
    pub fn get_crypto_manager(&self) -> CryptoManager {
        self.crypto.clone()
    }

    /// Generates the next available unique identifier for file entries.
    ///
    /// This is an internal helper method that manages the ID counter
    /// in the database.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the next available ID or a `VeilError`.
    fn generate_next_id(&mut self) -> Result<u64, VeilError> {
        let counter_key = "id_counter";
        let next_id = match self.db.get(counter_key)? {
            Some(bytes) => {
                let current: u64 = String::from_utf8(bytes.to_vec())
                    .map_err(|_| VeilError::InvalidMetadata)?
                    .parse()
                    .map_err(|_| VeilError::InvalidMetadata)?;
                current + 1
            }
            None => 1,
        };
        
        self.db.insert(counter_key, next_id.to_string().as_bytes())?;
        Ok(next_id)
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

        // Create the source directory and file for testing
        let source_dir = dir.path().join("test");
        fs::create_dir_all(&source_dir).unwrap(); // Ensure the directory exists
        let source_path = source_dir.join("file.txt");
        fs::write(&source_path, "This is a test file.").unwrap(); // Write the dummy file

        // Define the virtual path
        let virtual_path = "virtual/file.txt";

        // Test inserting a file
        let result = db.insert_file(source_path.to_string_lossy().as_ref(), virtual_path, 1);
        assert!(result.is_ok());

        // Verify that the file entry was added
        let retrieved_entry = db.get_file_by_path(virtual_path).unwrap();
        assert!(retrieved_entry.is_some());
        assert_eq!(retrieved_entry.unwrap().virtual_path, virtual_path);

        // Clean up the dummy file
        fs::remove_file(&source_path).unwrap();
    }

    #[test]
    fn test_get_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        // Create the source directory and file for testing
        let source_dir = dir.path().join("test");
        fs::create_dir_all(&source_dir).unwrap(); // Ensure the directory exists
        let source_path = source_dir.join("file.txt");
        fs::write(&source_path, "This is a test file.").unwrap(); // Write the dummy file

        // Define the virtual path
        let virtual_path = "virtual/file.txt";

        // Insert the file into the database
        db.insert_file(source_path.to_string_lossy().as_ref(), virtual_path, 1).unwrap();

        // Retrieve the file by its virtual path
        let retrieved_entry = db.get_file_by_path(virtual_path).unwrap();
        assert!(retrieved_entry.is_some());

        let entry = retrieved_entry.unwrap(); // Store the unwrapped value in a variable
        assert_eq!(entry.virtual_path, virtual_path);
        assert_eq!(entry.source_path, source_path.to_string_lossy());

        // Clean up the dummy file
        fs::remove_file(&source_path).unwrap();
    }

    #[test]
    fn test_list_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        // Create a nested directory structure for testing
        let base_dir = dir.path().join("test");
        fs::create_dir_all(&base_dir).unwrap(); // Ensure the base directory exists

        // Create files in nested directories
        let file1_path = base_dir.join("dir1").join("file1.txt");
        let file2_path = base_dir.join("dir1").join("file2.txt");
        let file3_path = base_dir.join("dir2").join("file3.txt");
        fs::create_dir_all(file1_path.parent().unwrap()).unwrap(); // Create parent directory for file1
        fs::write(&file1_path, "Content of file 1").unwrap();
        fs::write(&file2_path, "Content of file 2").unwrap();
        fs::create_dir_all(file3_path.parent().unwrap()).unwrap(); // Create parent directory for file3
        fs::write(&file3_path, "Content of file 3").unwrap();

        // Insert files into the database
        db.insert_file(file1_path.to_string_lossy().as_ref(), "virtual/dir1/file1.txt", 1).unwrap();
        db.insert_file(file2_path.to_string_lossy().as_ref(), "virtual/dir1/file2.txt", 2).unwrap();
        db.insert_file(file3_path.to_string_lossy().as_ref(), "virtual/dir2/file3.txt", 3).unwrap();

        // List the contents of the first directory
        let entries = db.list_directory("virtual/dir1").unwrap();
        assert!(entries.contains(&String::from("file1.txt")));
        assert!(entries.contains(&String::from("file2.txt")));

        // List the contents of the second directory
        let entries = db.list_directory("virtual/dir2").unwrap();
        assert!(entries.contains(&String::from("file3.txt")));
    }

    #[test]
    fn test_get_file_by_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        // Create the source directory and file for testing
        let source_dir = dir.path().join("test");
        fs::create_dir_all(&source_dir).unwrap(); // Ensure the directory exists
        let source_path = source_dir.join("file.txt");
        fs::write(&source_path, "This is a test file.").unwrap(); // Write the dummy file

        // Define the virtual path
        let virtual_path = "virtual/file.txt";

        // Insert the file into the database
        db.insert_file(source_path.to_string_lossy().as_ref(), virtual_path, 1).unwrap();

        // Retrieve the file by its virtual path
        let retrieved_entry = db.get_file_by_path(virtual_path).unwrap();
        assert!(retrieved_entry.is_some());

        let entry = retrieved_entry.unwrap(); // Store the unwrapped value in a variable
        assert_eq!(entry.virtual_path, virtual_path);
        assert_eq!(entry.source_path, source_path.to_string_lossy());

        // Clean up the dummy file
        fs::remove_file(&source_path).unwrap();
    }

    #[test]
    fn test_remove_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        // Create the source directory and file for testing
        let source_dir = dir.path().join("test");
        fs::create_dir_all(&source_dir).unwrap(); // Ensure the directory exists
        let source_path = source_dir.join("file.txt");
        fs::write(&source_path, "This is a test file.").unwrap(); // Write the dummy file

        // Define the virtual path
        let virtual_path = "virtual/file.txt";

        // Insert the file into the database
        db.insert_file(source_path.to_string_lossy().as_ref(), virtual_path, 1).unwrap();

        // Ensure the file exists before removal
        let retrieved_entry = db.get_file_by_path(virtual_path).unwrap();
        assert!(retrieved_entry.is_some());

        // Test removing the file
        let result = db.remove_file(retrieved_entry.unwrap().id);
        assert!(result.is_ok());

        // Ensure the file no longer exists
        let retrieved_after_removal = db.get_file_by_path(virtual_path).unwrap();
        assert!(retrieved_after_removal.is_none()); // Should be None after removal
    }

    #[test]
    fn test_update_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        // Create the source directory and file for testing
        let source_dir = dir.path().join("test");
        fs::create_dir_all(&source_dir).unwrap(); // Ensure the directory exists
        let source_path = source_dir.join("file.txt");
        fs::write(&source_path, "This is a test file.").unwrap(); // Write the dummy file

        // Define the virtual path
        let virtual_path = "virtual/file.txt";

        // Insert the file into the database
        db.insert_file(source_path.to_string_lossy().as_ref(), virtual_path, 1).unwrap();

        // Retrieve the file entry to update
        let mut entry = db.get_file_by_path(virtual_path).unwrap().unwrap();

        // Update the entry's size and virtual path
        entry.size += 100; // Change the size
        entry.virtual_path = "virtual/updated_file.txt".to_string(); // Update the virtual path

        // Update the file entry in the database
        let result = db.update_file(entry.clone());
        assert!(result.is_ok());

        // Retrieve the updated entry
        let updated_entry = db.get_file_by_path("virtual/updated_file.txt").unwrap();
        assert!(updated_entry.is_some());
        assert_eq!(updated_entry.unwrap().size, entry.size); // Ensure the size has been updated

        // Clean up the dummy file
        fs::remove_file(&source_path).unwrap();
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

        // Create the source directory and file for testing
        let source_dir = dir.path().join("test");
        fs::create_dir_all(&source_dir).unwrap(); // Ensure the directory exists
        let source_path = source_dir.join("file.txt");
        fs::write(&source_path, "This is a test file.").unwrap(); // Write the dummy file

        // Define the virtual path
        let virtual_path = "virtual/file.txt";

        // Insert the file into the database
        db.insert_file(source_path.to_string_lossy().as_ref(), virtual_path, 1).unwrap();

        // Retrieve the file entry to update
        let mut entry = db.get_file_by_path(virtual_path).unwrap().unwrap();

        // Attempt to update with an invalid path
        entry.virtual_path = String::from(""); // Set to an empty string to simulate an invalid path

        let result = db.update_file(entry.clone());
        assert!(result.is_err());

        // Check that the error is of the expected variant
        if let Err(e) = result {
            match e {
                VeilError::Metadata(msg) => assert_eq!(msg, "Invalid virtual path".to_string()),
                _ => panic!("Expected Metadata error, got {:?}", e),
            }
        }

        // Clean up the dummy file
        fs::remove_file(&source_path).unwrap();
    }

    #[test]
    fn test_insert_file_with_existing_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_db");
        let mut db = MetadataDB::new(path.clone(), "test_password").unwrap();

        // Create the source directory and file for testing
        let source_dir = dir.path().join("test");
        fs::create_dir_all(&source_dir).unwrap(); // Ensure the directory exists
        let source_path = source_dir.join("file.txt");
        fs::write(&source_path, "This is a test file.").unwrap(); // Write the dummy file

        // Define the virtual path
        let virtual_path = "virtual/file.txt";

        // Insert the file into the database
        db.insert_file(source_path.to_string_lossy().as_ref(), virtual_path, 1).unwrap();

        // Attempt to insert another file with the same virtual path
        let duplicate_source_path = source_dir.join("file_duplicate.txt");
        fs::write(&duplicate_source_path, "This is a duplicate file.").unwrap(); // Write the dummy duplicate file

        let result = db.insert_file(duplicate_source_path.to_string_lossy().as_ref(), virtual_path, 2);
        assert!(result.is_err());

        // Check that the error is of the expected variant
        if let Err(e) = result {
            match e {
                VeilError::Metadata(msg) => assert_eq!(msg, "File already exists".to_string()), // Adjust this error as needed
                _ => panic!("Expected Metadata error, got {:?}", e),
            }
        }

        // Clean up the dummy files
        fs::remove_file(&source_path).unwrap();
        fs::remove_file(&duplicate_source_path).unwrap();
    }

    // Clean up the temporary directory after all tests
    #[test]
    fn cleanup() {
        let dir = tempdir().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
