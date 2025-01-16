# Veil - Secure File Encryption Tool

## Project Name

"Veil" was chosen as the project name for its characteristics:

- Short and memorable
- Suggests the security/privacy aspect
- Unlikely to conflict with existing tools
- Works well as a verb (veil/unveil)
- Easy to type for CLI usage

## 1. Overview

A cross-platform file encryption tool written in Rust that provides secure file encryption with browsable metadata and temporary decryption capabilities. The tool focuses on simplicity, security, and performance while maintaining a clear upgrade path for future enhancements.

## 2. Core Requirements

### 2.1 Functional Requirements

- Initialize encrypted repositories with a single master password
- Encrypt files and folders while preserving directory structure
- Browse encrypted contents without decryption
- Temporary decryption to a secure location
- Streaming support for large files
- Command-line interface
- Version control for data formats
- Auto-cleanup of decrypted files

### 2.2 Security Requirements

- XChaCha20-Poly1305 for file encryption
- Argon2id for key derivation
- Secure nonce management
- No storage of plain-text passwords
- Secure handling of temporary files
- Memory safety (leveraging Rust's guarantees)

### 2.3 Performance Requirements

- Constant memory usage regardless of file size
- Efficient handling of large files through streaming
- Quick metadata operations without full decryption
- Minimal overhead for small files

## 3. Architecture

### 3.1 Repository Structure

```
.veil/
├── .version           # Plain text version identifier
├── .metadata.db       # Encrypted metadata database
└── contents/          # Encrypted file contents
    ├── [hash1].enc
    ├── [hash2].enc
    └── ...
```

### 3.2 Temporary Decryption Structure

```
~/.cache/veil/
└── [session_id]/
    └── unlocked/
        └── [original folder structure]
```

### 3.3 Metadata Database Schema

```rust
struct MetadataHeader {
    version: u8,
    created_at: u64,
    salt: [u8; 16],
    nonce_counter: u64,
    repo_id: [u8; 8],
}

struct FileEntry {
    id: u64,
    original_path: String,
    size: u64,
    modified_time: u64,
    content_hash: [u8; 32],
    nonce: FileNonce,
}

struct FileNonce {
    file_id: u64,
    chunk_counter: u64,
    random: [u8; 8],
}
```

### 3.4 Encrypted File Format

```
[Version: 1 byte]
[Nonce: 24 bytes]
[Encrypted data chunks...]
    [Chunk length: 4 bytes]
    [Chunk nonce: 24 bytes]
    [Encrypted chunk data]
    [Auth tag: 16 bytes]
[Final auth tag: 16 bytes]
```

## 4. Core Components

### 4.1 Encryption Layer

- Key derivation using Argon2id
  - Memory: 64MB
  - Iterations: 3
  - Parallelism: 4
- XChaCha20-Poly1305 for encryption
- Hybrid nonce generation scheme
- Streaming encryption/decryption support

### 4.2 Metadata Management

- Encrypted sled database
- In-memory caching for browsing
- Version-aware serialization
- Atomic updates

### 4.3 Temporary File Handler

- Secure temporary directory creation
- Automatic cleanup on process exit
- Timeout-based cleanup for orphaned files
- Read-only by default

## 5. Command Line Interface

### 5.1 Core Commands

```bash
# Repository management
veil init <path>
veil status
veil clean

# File operations
veil add <source_path> [target_path]
veil ls [path]
veil find <pattern>
veil unlock <path> [--writable] [--timeout <minutes>]

# Information
veil version
veil help
```

### 5.2 Command Options

```bash
Global options:
  --verbose    Enable verbose output
  --quiet      Suppress non-error output

unlock options:
  --writable   Allow modifications to decrypted files
  --timeout    Auto-clean after specified minutes
```

## 6. Error Handling

### 6.1 Recovery Scenarios

- Interrupted encryption/decryption
- Corrupted metadata database
- Missing encrypted files
- Session cleanup failures

### 6.2 Error Categories

- User errors (wrong password, paths)
- System errors (permissions, disk space)
- Crypto errors (corrupted data)
- Internal errors (version mismatch)

## 7. Future Considerations

### 7.1 Potential Extensions

- Multiple password support
- Compression before encryption
- Network storage backend support
- GUI interface

### 7.2 Version Migration

- Version number in all serialized structures
- Migration functions for each version bump
- Backward compatibility requirements

## 8. Development Guidelines

### 8.1 Code Organization

```rust
src/
├── main.rs           # CLI entry point
├── crypto/           # Encryption implementation
├── metadata/         # Database handling
├── fs/              # File system operations
├── cli/             # Command processing
└── error.rs         # Error types and handling
```

### 8.2 Testing Requirements

- Unit tests for all components
- Integration tests for CLI
- Fuzz testing for crypto operations
- Cross-platform testing
- Performance benchmarks

### 8.3 Security Considerations

- Regular dependency audits
- Constant-time operations
- Secure memory wiping
- No debug logs of sensitive data
