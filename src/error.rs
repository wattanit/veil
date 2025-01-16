use thiserror::Error;

#[derive(Error, Debug)]
pub enum VeilError {
    #[error("Repository error: {0}")]
    Repository(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u8, actual: u8 },
} 