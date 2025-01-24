use clap::{Parser, Subcommand};

use std::path::PathBuf;

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
        // Implementation for add command
        println!("Adding {:?} to repository", source_path);
        Ok(())
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