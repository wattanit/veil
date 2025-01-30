use thiserror::Error;

#[allow(dead_code)]
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

    #[error("Invalid file version: found {0}, expected {1}")]
    InvalidVersion(u8, u8),

    #[error("Metadata error: {0}")]
    Metadata(String),

    #[error("Sled database error: {0}")]
    Sled(#[from] sled::Error),

    #[error("Bincode serialization error: {0}")]
    Bincode(#[from] bincode::Error),

    #[error("System time error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),

    #[error("Invalid header")]
    InvalidHeader,

    #[error("Invalid metadata")]
    InvalidMetadata,
}

impl From<anyhow::Error> for VeilError {
    fn from(err: anyhow::Error) -> Self {
        VeilError::Encryption(err.to_string())
    }
} 