# Veil - Secure File Encryption Tool

Veil is a secure file encryption tool that provides users with the ability to encrypt and decrypt files to protect sensitive information. It employs modern cryptographic algorithms, including XChaCha20-Poly1305 for encryption and Argon2id for password hashing, ensuring that data remains secure during storage and transmission.

The tool features a command-line interface for ease of use and supports functionalities such as streaming encryption and metadata management. Veil is designed for users who need a reliable solution for safeguarding their files against unauthorized access.

---
## Development Plan

### TODO
- [X] Implement the crypto module with XChaCha20-Poly1305 and Argon2id
- [X] Implement the streaming encryption/decryption in the fs module
- [X] Build the metadata database handling
- [X] Implement the filesystem operations
- [ ] Complete the CLI command implementations

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
- [ ] Implement `veil add` command
- [ ] Implement `veil ls` command
- [ ] Implement `veil unlock` command
- [ ] Implement `veil clean` command

---
### BACKLOG
- [ ] Implement secure memory wiping for sensitive data (Deferred)
- [ ] Add more comprehensive tests including fuzz testing (Deferred)