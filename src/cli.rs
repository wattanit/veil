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
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress non-error output
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
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
        
        // Get source filename
        let source_filename = source_path.file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid source filename"))?;
        
        // Determine target path within repository
        let relative_target = match target_path {
            Some(target) => {
                if target.as_os_str() == "/" || target.as_os_str() == "." {
                    // Use source filename for root directory with exactly one leading slash
                    let filename = source_filename.to_string_lossy();
                    let path = if filename.starts_with('/') {
                        filename.to_string()
                    } else {
                        format!("/{}", filename)
                    };
                    PathBuf::from(path)
                } else {
                    let mut target_owned = target.clone();
                    if self.verbose {
                        println!("Initial target path: {:?}", target_owned);
                    }

                    let trimmed_target = target_owned.strip_prefix("/").unwrap_or(&target_owned);
                    target_owned = trimmed_target.to_path_buf();
                    
                    if target_owned.file_name().is_none() || target_owned.to_string_lossy().ends_with('/') {
                        // If target is a directory (ends with separator or has no filename component)
                        // strip any trailing slashes but preserve the path
                        let mut path_str = target_owned.to_string_lossy().to_string();
                        if path_str.ends_with('/') {
                            if self.verbose {
                                println!("Removing trailing slash from: {:?}", path_str);
                            }
                            path_str.pop(); // Remove just the '/' character
                            target_owned = PathBuf::from(path_str);
                        }
                        
                        if self.verbose {
                            println!("Adding source filename: {:?} to path: {:?}", source_filename, target_owned);
                        }
                        target_owned = PathBuf::from(format!("/{}", target_owned.display()));
                        target_owned.push(source_filename);
                        target_owned
                    } else {
                        PathBuf::from(format!("/{}", target_owned.display()))
                        // target_owned
                    }
                }
            },
            None => {
                // No target path means root directory, ensuring a leading slash
                PathBuf::from(format!("/{}", source_filename.to_string_lossy()))
            }
        };
        
        if self.verbose {
            println!("Target path in repository: {:?}", relative_target.to_string_lossy());
        }
        
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

        // Encrypt the file
        let dest_path = repo_path.join("contents").join(format!("{}.enc", target.file_name().unwrap().to_string_lossy()));
        encrypt_file(
            source,
            &dest_path,
            db.get_crypto_manager(),
            rand::random::<u64>(), // Generate a random file ID for encryption
        )?;

        // Convert the target path to a string, ensuring consistent path separators
        // and exactly one leading slash for root directory files
        let virtual_path = target.to_string_lossy()
            .trim_start_matches('/')  // Remove any leading slashes
            .to_string();
        
        // Always add exactly one leading slash
        let virtual_path = format!("/{}", virtual_path);

        if self.verbose {
            println!("Creating virtual path: {}", virtual_path);
        }

        // Add to metadata DB using the source and target paths
        db.insert_file(source.to_string_lossy().as_ref(), &virtual_path)?;

        if self.verbose {
            println!("Successfully added {:?} to repository", source);
            println!("Virtual path: {}", virtual_path);
        }

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
        // Get repository root and verify it exists
        let repo_root = self.find_repository_root()?;
        let repo_path = repo_root.join(".veil");
        
        // Get password for metadata DB
        let password = rpassword::prompt_password("Enter repository password: ")?;
        
        // Open metadata DB
        let db = MetadataDB::new(repo_path.join(".metadata.db"), &password)?;
        
        // Determine which path to list
        let list_path = match path {
            Some(p) => {
                // Handle special cases for root directory
                if p.as_os_str() == "/" || p.as_os_str() == "." {
                    String::from("/")  // Use "/" for root directory
                } else {
                    // Ensure path starts with a slash
                    format!("/{}", p.to_string_lossy().trim_start_matches('/'))
                }
            },
            None => String::from("/"), // Root directory
        };
        
        if self.verbose {
            println!("Listing directory: {}", list_path);
        }
        
        // Get directory contents
        let entries = db.list_directory(&list_path)?;
        
        if entries.is_empty() {
            if !self.quiet {
                println!("Directory is empty");
            }
            return Ok(());
        }
        
        // Sort entries for consistent output
        let mut entries = entries;
        entries.sort();
        
        // Print entries
        for entry in entries {
            let full_path = if list_path == "/" {
                format!("/{}", entry)
            } else {
                format!("{}/{}", list_path, entry)
            };
            
            // Try to get file details
            match db.get_file_by_path(&full_path)? {
                Some(file_entry) => {
                    // It's a file - print details
                    if !self.quiet {
                        println!("{:>10} {}",
                            bytesize::to_string(file_entry.size, true),
                            entry
                        );
                    } else {
                        println!("{}", entry);
                    }
                }
                None => {
                    // It's a directory
                    if !self.quiet {
                        println!("{:>10} {}/", "", entry);
                    } else {
                        println!("{}/", entry);
                    }
                }
            }
        }
        
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