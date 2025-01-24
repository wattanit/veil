//! File system operations for the Veil secure file encryption tool.
//!
//! This module provides functionality for encrypting and decrypting files,
//! as well as managing the reading and writing of encrypted data. It includes
//! the `EncryptedFileWriter` and `EncryptedFileReader` structs for handling
//! the encryption and decryption processes, respectively.
//!
//! # Overview
//!
//! The `EncryptedFileWriter` struct is responsible for writing encrypted data
//! to a file, while the `EncryptedFileReader` struct is used to read and
//! decrypt data from an encrypted file. Both structs utilize the `CryptoManager`
//! for encryption and decryption operations.
//!
//! # Usage
//!
//! To encrypt a file, use the `encrypt_file` function:
//!
//! ```rust
//! let source_path = "path/to/source.txt";
//! let dest_path = "path/to/encrypted.enc";
//! let crypto = CryptoManager::new("your_password", &CryptoManager::generate_salt()).unwrap();
//! encrypt_file(source_path, dest_path, crypto, 1).unwrap();
//! ```
//!
//! To decrypt a file, use the `decrypt_file` function:
//!
//! ```rust
//! let source_path = "path/to/encrypted.enc";
//! let dest_path = "path/to/decrypted.txt";
//! let crypto = CryptoManager::new("your_password", &CryptoManager::generate_salt()).unwrap();
//! decrypt_file(source_path, dest_path, crypto, 1).unwrap();
//! ```

use std::io::{self, Read, Write, Seek, SeekFrom};
use std::fs::{self, File};
use std::path::Path;

use anyhow::Context;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::crypto::{CryptoManager, FileNonce};
use crate::error::VeilError;

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
const VERSION: u8 = 1;

/// File format structure:
/// ```text
/// [Version byte]        (1 byte)
/// [Random nonce]        (8 bytes)
/// For each chunk:
///   [Encrypted length]  (4 bytes, little-endian u32)
///   [Original length]   (4 bytes, little-endian u32)
///   [Encrypted data]    (encrypted_length bytes)
/// ```
/// 
/// The encrypted data in each chunk is larger than the original data
/// due to the encryption overhead. The exact size difference depends
/// on the encryption algorithm used.
pub struct EncryptedFileWriter<W: Write + Seek> {
    writer: W,
    crypto: CryptoManager,
    nonce: FileNonce,
    current_chunk: Vec<u8>,
}

/// Reader for files written by `EncryptedFileWriter`.
/// Handles the file format:
/// ```text
/// Header:
///   - Version byte     (1 byte, must match VERSION constant)
///   - Random nonce     (8 bytes, used for all chunks)
/// 
/// Chunks:
///   - Encrypted length (4 bytes) - size of encrypted data
///   - Original length  (4 bytes) - size of decrypted data
///   - Encrypted data   (variable size)
/// ```
pub struct EncryptedFileReader<R: Read + Seek> {
    reader: R,
    crypto: CryptoManager,
    nonce: FileNonce,
    file_size: u64,
    current_position: u64,
}

impl<W: Write + Seek> EncryptedFileWriter<W> {
    /// Creates a new `EncryptedFileWriter` instance.
    ///
    /// This function initializes the writer with the specified writer,
    /// crypto manager, and file ID. It writes the version byte and generates
    /// a random nonce for encryption.
    ///
    /// # Arguments
    ///
    /// * `writer` - The writer to which encrypted data will be written.
    /// * `crypto` - The `CryptoManager` instance for encryption.
    /// * `file_id` - The unique identifier for the file.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `EncryptedFileWriter` instance or an `io::Error`.
    pub fn new(mut writer: W, crypto: CryptoManager, file_id: u64) -> io::Result<Self> {
        // Write version byte
        writer.write_all(&[VERSION])?;
        
        // Generate and write nonce
        let nonce = CryptoManager::generate_file_nonce(file_id);
        writer.write_all(&nonce.random)?;  // Write the random part
        
        Ok(Self {
            writer,
            crypto,
            nonce,  // Use the same nonce we just wrote
            current_chunk: Vec::with_capacity(CHUNK_SIZE),
        })
    }

    /// Writes a buffer of data to the encrypted file.
    ///
    /// This function encrypts the data and writes it in chunks to the file.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer containing the data to write.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the number of bytes written or an `io::Error`.
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written = 0;
        let mut remaining = buf;

        while !remaining.is_empty() {
            let space_in_chunk = CHUNK_SIZE - self.current_chunk.len();
            let bytes_to_write = remaining.len().min(space_in_chunk);
            
            self.current_chunk.extend_from_slice(&remaining[..bytes_to_write]);
            
            if self.current_chunk.len() == CHUNK_SIZE {
                self.flush_chunk()?;
            }
            
            remaining = &remaining[bytes_to_write..];
            bytes_written += bytes_to_write;
        }

        Ok(bytes_written)
    }

    /// Flushes the current chunk of data to the file.
    ///
    /// This function encrypts the current chunk and writes it to the file,
    /// including the encrypted length and original length.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure as an `io::Error`.
    fn flush_chunk(&mut self) -> io::Result<()> {
        if self.current_chunk.is_empty() {
            return Ok(());
        }

        let encrypted = self.crypto
            .encrypt_chunk(&self.current_chunk, &self.nonce)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let enc_len = encrypted.len() as u32;
        let orig_len = self.current_chunk.len() as u32;

        self.writer.write_u32::<LittleEndian>(enc_len)?;
        self.writer.write_u32::<LittleEndian>(orig_len)?;
        self.writer.write_all(&encrypted)?;

        self.nonce.chunk_counter += 1;
        self.current_chunk.clear();

        Ok(())
    }

    /// Finalizes the writing process and flushes any remaining data.
    ///
    /// This function ensures that all data is written to the file and flushes
    /// the writer.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure as an `io::Error`.
    pub fn finish(mut self) -> io::Result<()> {
        // Flush any remaining data
        self.flush_chunk()?;
        self.writer.flush()
    }
}

impl<R: Read + Seek> EncryptedFileReader<R> {
    /// Creates a new `EncryptedFileReader` instance.
    ///
    /// This function initializes the reader with the specified reader,
    /// crypto manager, file ID, and file size. It reads the version byte
    /// and nonce from the file.
    ///
    /// # Arguments
    ///
    /// * `reader` - The reader from which encrypted data will be read.
    /// * `crypto` - The `CryptoManager` instance for decryption.
    /// * `file_id` - The unique identifier for the file.
    /// * `file_size` - The total size of the encrypted file.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `EncryptedFileReader` instance or an `io::Error`.
    pub fn new(
        mut reader: R,
        crypto: CryptoManager, 
        file_id: u64,
        file_size: u64
    ) -> io::Result<Self> {
        // Read version byte
        let mut version = [0u8; 1];
        reader.read_exact(&mut version)?;
        if version[0] != VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid version"));
        }
        
        // Read nonce (exactly 8 bytes)
        let mut random = [0u8; 8];
        reader.read_exact(&mut random)?;
        
        let nonce = FileNonce {
            file_id,
            chunk_counter: 0,
            random,
        };
        
        // Calculate remaining file size (total - version byte - nonce bytes)
        let data_start = reader.stream_position()?;
        
        Ok(Self {
            reader,
            crypto,
            nonce,
            file_size: file_size - data_start,
            current_position: 0,
        })
    }

    /// Reads decrypted data from the encrypted file into the provided buffer.
    ///
    /// This function decrypts the next chunk of data and fills the buffer
    /// with the decrypted content.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to fill with decrypted data.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the number of bytes read or an `io::Error`.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.current_position >= self.file_size {
            return Ok(0);
        }

        let enc_len = self.reader.read_u32::<LittleEndian>()?;
        let orig_len = self.reader.read_u32::<LittleEndian>()?;

        let mut encrypted = vec![0u8; enc_len as usize];
        self.reader.read_exact(&mut encrypted)?;

        let decrypted = self.crypto
            .decrypt_chunk(&encrypted, &self.nonce)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        if decrypted.len() != orig_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Decrypted data length mismatch"
            ));
        }

        let bytes_to_copy = buf.len().min(decrypted.len());
        buf[..bytes_to_copy].copy_from_slice(&decrypted[..bytes_to_copy]);

        self.current_position += (8 + enc_len) as u64;
        
        if bytes_to_copy == decrypted.len() {
            self.nonce.chunk_counter += 1;
        }

        Ok(bytes_to_copy)
    }
}

/// Encrypts a file to a new location, preserving the original.
pub fn encrypt_file<P: AsRef<Path>>(
    source_path: P,
    dest_path: P,
    crypto: CryptoManager,
    file_id: u64,
) -> anyhow::Result<()> {
    let source_file = File::open(&source_path)
        .context("Failed to open source file")?;
    let mut dest_file = File::create(&dest_path)
        .context("Failed to create destination file")?;

    let mut writer = EncryptedFileWriter::new(dest_file, crypto, file_id)?;
    let mut buffer = vec![0u8; CHUNK_SIZE];

    let mut reader = io::BufReader::new(source_file);
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        writer.write(&buffer[..bytes_read])?;
    }

    writer.finish()?;
    Ok(())
}

/// Decrypts a file to a new location, preserving the encrypted file.
pub fn decrypt_file<P: AsRef<Path>>(
    source_path: P,
    dest_path: P,
    crypto: CryptoManager,
    file_id: u64,
) -> anyhow::Result<()> {
    let source_file = File::open(&source_path)
        .context("Failed to open encrypted file")?;
    let mut dest_file = File::create(&dest_path)
        .context("Failed to create destination file")?;

    let file_size = source_file.metadata()?.len();
    let mut reader = EncryptedFileReader::new(source_file, crypto, file_id, file_size)?;
    let mut writer = io::BufWriter::new(dest_file);
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        writer.write_all(&buffer[..bytes_read])?;
    }

    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_decrypt_stream() -> anyhow::Result<()> {
        let password = "test_password";
        let salt = CryptoManager::generate_salt();
        let crypto = CryptoManager::new(password, &salt)?;

        let test_data = b"Hello, this is test data!".repeat(1000);
        let temp_dir = tempdir()?;
        
        let encrypted_path = temp_dir.path().join("test.enc");
        let decrypted_path = temp_dir.path().join("test.dec");

        // Write test data to a temporary file
        let source_path = temp_dir.path().join("test.txt");
        fs::write(&source_path, &test_data)?;

        // Encrypt
        encrypt_file(&source_path, &encrypted_path, crypto.clone(), 1)?;

        // Decrypt
        decrypt_file(&encrypted_path, &decrypted_path, crypto, 1)?;

        // Verify
        let decrypted_data = fs::read(decrypted_path)?;
        assert_eq!(&test_data[..], &decrypted_data[..]);

        Ok(())
    }
} 