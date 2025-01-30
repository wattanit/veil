# Veil - Secure File Encryption Tool

Veil is a secure file encryption tool that provides users with the ability to encrypt and decrypt files to protect sensitive information. It employs modern cryptographic algorithms, including XChaCha20-Poly1305 for encryption and Argon2id for password hashing, ensuring that data remains secure during storage and transmission.

The tool features a command-line interface for ease of use and supports functionalities such as streaming encryption and metadata management. Veil is designed for users who need a reliable solution for safeguarding their files against unauthorized access.

## Basic Usage

The Veil command-line tool provides secure file encryption with an easy-to-use interface. Here are the main commands:

### Initialize a Repository

```bash
# Create a new encrypted repository
veil init /path/to/repo
```

### Adding Files

```bash
# Add a single file
veil add document.pdf

# Add with a custom path in the repository
veil add document.pdf /documents/2024/

# Add an entire directory
veil add /path/to/directory
```

### Managing Files

```bash
# List files in the repository
veil ls                    # List root directory
veil ls /documents/        # List specific directory

# Remove files
veil remove document.pdf   # Remove a single file
veil remove /documents/    # Remove a directory
```

### Working with Files

```bash
# Temporarily decrypt files for viewing
veil unlock document.pdf
veil unlock /documents/    # Unlock entire directory

# Clean up decrypted files
veil clean
```

### Global Options

```bash
# Available with all commands:
--verbose    # Show detailed operation information
--quiet      # Show only errors
```

### Security Notes

- All files are encrypted using XChaCha20-Poly1305
- Repository is secured with a master password
- Unlocked files are automatically tracked for cleanup
- Use `veil clean` to ensure sensitive data is removed

For more detailed information about specific commands, use:
```bash
veil help
veil help <command>
```

---
## Development Plan

### TODO
- [X] Implement the crypto module with XChaCha20-Poly1305 and Argon2id
- [X] Implement the streaming encryption/decryption in the fs module
- [X] Build the metadata database handling
- [X] Implement the filesystem operations
- [X] Complete the CLI command implementations

---
#### TASK: Implement the crypto module with XChaCha20-Poly1305 and Argon2id
- [X] Implement CryptoManager
- [X] Implement utility functions
- [X] Add unit test to crypto module
- [X] Add documentation

#### TASK: Implement the streaming encryption/decryption in the fs module
- [X] Implement encrypt_file
- [X] Implement decrypt_file
- [X] Add unit test to fs module
- [X] Add documentation

#### TASK: Build the metadata database handling
- [X] Add the metadata encryption layer
- [X] Add methods to remove and update metadata/files entries
- [X] Add unit test to the metadata encryption layer
- [X] Add documentation

#### TASK: Complete the CLI command implementations
- [X] Implement `veil init` command
- [X] Implement `veil add` command
- [X] Implement `veil ls` command
- [X] Implement `veil unlock` command
- [X] Implement `veil clean` command
- [X] Implement `veil remove` command

---
### BACKLOG
- [ ] Implement secure memory wiping for sensitive data (Deferred)
- [ ] Add more comprehensive tests including fuzz testing (Deferred)
- [ ] Implement file search within the virtual directory (Deferred)