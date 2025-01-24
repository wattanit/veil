use clap::{Parser, Subcommand};

use std::path::{PathBuf, Path};
use std::fs;
use crate::metadata::{MetadataDB, FileEntry};
use crate::crypto::{CryptoManager, FileNonce};
use crate::fs::encrypt_file;

const VEIL_VERSION: &str = "0.1.0";
const PASSWORD_MIN_LENGTH: usize = 8;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]

pub struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Suppress non-error output
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new encrypted repository
    Init {
        /// Path to create the repository
        path: std::path::PathBuf,
    },
    /// Show repository status
    Status,
    /// Clean up temporary files
    Clean,
    /// Add files or directories to the repository
    Add {
        /// Source path to encrypt
        source_path: std::path::PathBuf,
        /// Optional target path in the repository
        target_path: Option<std::path::PathBuf>,
    },
    /// List contents of the repository
    Ls {
        /// Optional path within the repository
        path: Option<std::path::PathBuf>,
    },
    /// Find files matching a pattern
    Find {
        /// Pattern to search for
        pattern: String,
    },
    /// Temporarily decrypt files
    Unlock {
        /// Path to decrypt
        path: std::path::PathBuf,
        /// Allow modifications to decrypted files
        #[arg(long)]
        writable: bool,
        /// Auto-clean after specified minutes
        #[arg(long)]
        timeout: Option<u32>,
    },
}

impl Cli {
    pub fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            Commands::Init { path } => self.handle_init(path),
            Commands::Status => self.handle_status(),
            Commands::Clean => self.handle_clean(),
            Commands::Add { source_path, target_path } => self.handle_add(source_path, target_path),
            Commands::Ls { path } => self.handle_ls(path),
            Commands::Find { pattern } => self.handle_find(pattern),
            Commands::Unlock { path, writable, timeout } => self.handle_unlock(path, writable, timeout),
        }
    }

    fn handle_init(&self, path: &PathBuf) -> anyhow::Result<()> {
        if !self.quiet {
            println!("Initializing Veil Repository at {:?}", path);
        }
        
        // Create repository structure
        let repo_path = path.join(".veil");
        std::fs::create_dir_all(&repo_path)?;
        std::fs::create_dir_all(repo_path.join("contents"))?;
        
        // Write version file
        std::fs::write(
            repo_path.join(".version"),
            format!("VEIL_VERSION={}", VEIL_VERSION),
        )?;
        
        // Initialize metadata DB with a new password
        let password = rpassword::prompt_password("Enter master password: ")?;
        let verify = rpassword::prompt_password("Verify password: ")?;
        
        if password != verify {
            anyhow::bail!("Passwords do not match");
        }
        
        if password.len() < PASSWORD_MIN_LENGTH {
            anyhow::bail!("Password must be at least {} characters", PASSWORD_MIN_LENGTH);
        }
        
        let _db = crate::metadata::MetadataDB::new(
            repo_path.join(".metadata.db"),
            &password
        )?;
        
        if self.verbose {
            println!("Created repository structure");
            println!("Initialized metadata database");
        }
        
        Ok(())
    }

    fn handle_status(&self) -> anyhow::Result<()> {
        // Implementation for status command
        println!("Showing repository status");
        Ok(())
    }

    fn handle_clean(&self) -> anyhow::Result<()> {
        // Implementation for clean command
        println!("Cleaning temporary files");
        Ok(())
    }

    fn handle_add(&self, source_path: &PathBuf, target_path: &Option<PathBuf>) -> anyhow::Result<()> {
        // Get repository root and verify it exists
        let repo_root = self.find_repository_root()?;
        let repo_path = repo_root.join(".veil");
        
        if !self.quiet {
            println!("Adding {:?} to repository", source_path);
        }

        // Get password for metadata DB
        let password = rpassword::prompt_password("Enter repository password: ")?;
        
        // Open metadata DB
        let mut db = MetadataDB::new(repo_path.join(".metadata.db"), &password)?;
        
        // Determine target path within repository
        let relative_target = match target_path {
            Some(target) => target.clone(),
            None => source_path.to_path_buf(),
        };
        
        // Process the source path (handles both files and directories)
        self.add_path(&source_path, &relative_target, &repo_path, &mut db)?;
        
        if self.verbose {
            println!("Successfully added {:?} to repository", source_path);
        }
        
        Ok(())
    }

    fn add_path(
        &self,
        source: &Path,
        target: &Path,
        repo_path: &Path,
        db: &mut MetadataDB
    ) -> anyhow::Result<()> {
        if source.is_dir() {
            self.add_directory(source, target, repo_path, db)
        } else {
            self.add_file(source, target, repo_path, db)
        }
    }

    fn add_file(
        &self,
        source: &Path,
        target: &Path,
        repo_path: &Path,
        db: &mut MetadataDB
    ) -> anyhow::Result<()> {
        if self.verbose {
            println!("Processing file: {:?}", source);
        }

        // Generate a unique ID for the file
        let file_id = rand::random::<u64>();
        
        // Calculate content hash
        let mut hasher = blake3::Hasher::new();
        let mut file = fs::File::open(source)?;
        std::io::copy(&mut file, &mut hasher)?;
        let content_hash = hasher.finalize().into();

        // Create file entry
        let metadata = fs::metadata(source)?;
        let entry = FileEntry {
            id: file_id,
            original_path: target.to_string_lossy().into_owned(),
            size: metadata.len(),
            modified_time: metadata
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            content_hash,
            nonce: FileNonce {
                file_id,
                chunk_counter: 0,
                random: [0; 8], // Will be generated during encryption
            },
        };

        // Encrypt the file
        let dest_path = repo_path.join("contents").join(format!("{}.enc", file_id));
        encrypt_file(
            source,
            &dest_path,
            db.get_crypto_manager(),
            file_id,
        )?;

        // Add to metadata DB
        db.insert_file(entry)?;

        Ok(())
    }

    fn add_directory(
        &self,
        source: &Path,
        target: &Path,
        repo_path: &Path,
        db: &mut MetadataDB
    ) -> anyhow::Result<()> {
        if self.verbose {
            println!("Processing directory: {:?}", source);
        }

        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let source_path = entry.path();
            let relative_path = target.join(
                entry.file_name()
            );
            
            self.add_path(&source_path, &relative_path, repo_path, db)?;
        }

        Ok(())
    }

    fn find_repository_root(&self) -> anyhow::Result<PathBuf> {
        let mut current = std::env::current_dir()?;
        
        loop {
            if current.join(".veil").is_dir() {
                return Ok(current);
            }
            
            if !current.pop() {
                anyhow::bail!("Not in a Veil repository");
            }
        }
    }

    fn handle_ls(&self, path: &Option<PathBuf>) -> anyhow::Result<()> {
        // Implementation for ls command
        println!("Listing contents");
        Ok(())
    }

    fn handle_find(&self, pattern: &str) -> anyhow::Result<()> {
        // Implementation for find command
        println!("Finding files matching: {}", pattern);
        Ok(())
    }

    fn handle_unlock(&self, path: &PathBuf, writable: &bool, timeout: &Option<u32>) -> anyhow::Result<()> {
        // Implementation for unlock command
        println!("Unlocking {:?}", path);
        Ok(())
    }
} 