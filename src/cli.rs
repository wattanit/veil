use clap::{Parser, Subcommand};

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
    pub fn run(self) -> anyhow::Result<()> {
        match self.command {
            Commands::Init { path } => {
                println!("Initializing repository at {:?}", path);
                Ok(())
            }
            Commands::Status => {
                println!("Showing repository status");
                Ok(())
            }
            Commands::Clean => {
                println!("Cleaning temporary files");
                Ok(())
            }
            Commands::Add { source_path, target_path } => {
                println!("Adding {:?} to repository", source_path);
                Ok(())
            }
            Commands::Ls { path } => {
                println!("Listing contents");
                Ok(())
            }
            Commands::Find { pattern } => {
                println!("Finding files matching: {}", pattern);
                Ok(())
            }
            Commands::Unlock { path, writable, timeout } => {
                println!("Unlocking {:?}", path);
                Ok(())
            }
        }
    }
} 