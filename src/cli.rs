//! Command-line interface for the Veil secure file encryption tool.
//!
//! This module provides the command-line interface functionality, handling user
//! commands and their execution. It includes the `Cli` struct which parses and
//! processes command-line arguments, and implements various commands like init,
//! add, unlock, etc.
//!
//! # Overview
//!
//! The CLI module uses clap for argument parsing and provides the following
//! main commands:
//!
//! - `init`: Initialize a new encrypted repository
//! - `status`: Show repository status
//! - `clean`: Clean up temporary files
//! - `add`: Add files or directories to the repository
//! - `ls`: List contents of the repository
//! - `find`: Find files matching a pattern
//! - `unlock`: Temporarily decrypt files
//!
//! # Usage
//!
//! ```bash
//! # Initialize a new repository
//! veil init /path/to/repo
//!
//! # Add files to the repository
//! veil add source_file.txt [target_path]
//!
//! # List repository contents
//! veil ls [path]
//!
//! # Unlock (decrypt) files
//! veil unlock path/to/file [--writable] [--timeout <minutes>]
//! ```

use clap::{Parser, Subcommand};

use std::path::{PathBuf, Path};
use std::fs;
use crate::metadata::{MetadataDB, FileEntry};
use crate::crypto::{CryptoManager, FileNonce};
use crate::fs::encrypt_file;
use std::io::{BufRead, BufReader, Write};
use std::collections::HashSet;

const VEIL_VERSION: &str = "0.1.0";
const PASSWORD_MIN_LENGTH: usize = 8;

/// Command-line interface parser and executor.
///
/// This struct represents the command-line interface for Veil, handling
/// argument parsing and command execution. It uses clap for defining the
/// CLI structure and provides methods for executing each command.
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
    /// Executes the command specified in the CLI arguments.
    ///
    /// This is the main entry point for command execution. It delegates to
    /// specific handler methods based on the command provided.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the command execution.
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

    /// Initializes a new encrypted repository.
    ///
    /// Creates the repository structure and initializes the metadata database
    /// with a new master password.
    ///
    /// # Arguments
    ///
    /// * `path` - The path where the repository should be created
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the initialization.
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

    /// Shows the current status of the repository.
    ///
    /// Displays information about the repository state, including any
    /// unlocked files or pending operations.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the status check.
    fn handle_status(&self) -> anyhow::Result<()> {
        // Implementation for status command
        println!("Showing repository status");
        Ok(())
    }

    /// Cleans up temporary files and unlocked content.
    ///
    /// Removes decrypted files and cleans up any temporary files created
    /// during repository operations.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the cleanup operation.
    fn handle_clean(&self) -> anyhow::Result<()> {
        let repo_root = self.find_repository_root()?;
        let cache_file = repo_root.join(".unlocked_files");
        
        if !cache_file.exists() {
            if !self.quiet {
                println!("No unlocked files found");
            }
            return Ok(());
        }

        let (cleaned_count, failed_count) = self.clean_unlocked_files(&cache_file)?;
        self.cleanup_empty_dirs()?;

        // Remove the cache file itself
        if let Err(e) = std::fs::remove_file(&cache_file) {
            if self.verbose {
                eprintln!("Failed to remove cache file: {}", e);
            }
        }

        if !self.quiet {
            println!("Cleaned {} files", cleaned_count);
            if failed_count > 0 {
                println!("Failed to clean {} files", failed_count);
            }
        }

        Ok(())
    }

    /// Cleans up unlocked files from the cache.
    ///
    /// Removes decrypted files listed in the cache and updates the cache.
    ///
    /// # Arguments
    ///
    /// * `cache_file` - Path to the unlocked files cache
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the count of cleaned and failed files.
    fn clean_unlocked_files(&self, cache_file: &Path) -> anyhow::Result<(usize, usize)> {
        let mut cleaned_count = 0;
        let mut failed_count = 0;

        if let Ok(file) = std::fs::File::open(cache_file) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(path) = line {
                    let path = PathBuf::from(path);
                    if path.exists() {
                        match std::fs::remove_file(&path) {
                            Ok(_) => {
                                if self.verbose {
                                    println!("Removed {:?}", path);
                                }
                                cleaned_count += 1;
                            }
                            Err(e) => {
                                if self.verbose {
                                    eprintln!("Failed to remove {:?}: {}", path, e);
                                }
                                failed_count += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok((cleaned_count, failed_count))
    }

    /// Cleans up empty directories after file removal.
    ///
    /// Removes empty directories that may remain after cleaning up
    /// unlocked files.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the cleanup operation.
    fn cleanup_empty_dirs(&self) -> anyhow::Result<()> {
        let current_dir = std::env::current_dir()?;
        let mut dirs_to_check = HashSet::new();

        // Collect all parent directories
        for entry in walkdir::WalkDir::new(&current_dir)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| e.file_type().is_dir()) {
                if let Ok(entry) = entry {
                    dirs_to_check.insert(entry.path().to_path_buf());
                }
            }

        // Try to remove empty directories, starting from deepest
        let mut dirs: Vec<_> = dirs_to_check.into_iter().collect();
        dirs.sort_by(|a, b| b.components().count().cmp(&a.components().count()));

        for dir in dirs {
            if dir.exists() && dir.read_dir()?.next().is_none() {
                if let Err(e) = std::fs::remove_dir(&dir) {
                    if self.verbose {
                        eprintln!("Failed to remove empty directory {:?}: {}", dir, e);
                    }
                } else if self.verbose {
                    println!("Removed empty directory {:?}", dir);
                }
            }
        }

        Ok(())
    }

    /// Adds a file to the unlocked files cache.
    ///
    /// Records temporarily decrypted files for later cleanup.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the unlocked file
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the cache update.
    fn add_to_unlocked_cache(&self, path: &Path) -> anyhow::Result<()> {
        let repo_root = self.find_repository_root()?;
        let cache_file = repo_root.join(".unlocked_files");
        
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(cache_file)?;

        writeln!(file, "{}", path.display())?;
        Ok(())
    }

    /// Adds files or directories to the repository.
    ///
    /// Encrypts and stores files in the repository, preserving directory
    /// structure and maintaining metadata.
    ///
    /// # Arguments
    ///
    /// * `source_path` - Path to the file or directory to add
    /// * `target_path` - Optional target path within the repository
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the add operation.
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

        // Generate a file ID once
        let file_id = rand::random::<u64>();

        // Encrypt the file with the generated file_id
        let dest_path = repo_path.join("contents").join(format!("{}.enc", file_id));
        encrypt_file(
            source,
            &dest_path,
            db.get_crypto_manager(),
            file_id,  // Use the generated file_id
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

        // Add to metadata DB using the source and target paths, including the file_id
        db.insert_file(source.to_string_lossy().as_ref(), &virtual_path, file_id)?;

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

    /// Finds the root directory of the current repository.
    ///
    /// Searches up the directory tree for a .veil directory to identify
    /// the repository root.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the path to the repository root or an error
    /// if not in a repository.
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

    /// Lists contents of the repository.
    ///
    /// Displays files and directories stored in the repository, optionally
    /// filtered by path.
    ///
    /// # Arguments
    ///
    /// * `path` - Optional path within the repository to list
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the list operation.
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

    /// Finds files matching a pattern.
    ///
    /// Searches the repository for files matching the specified pattern.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The pattern to search for
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the find operation.
    fn handle_find(&self, pattern: &str) -> anyhow::Result<()> {
        // Implementation for find command
        println!("Finding files matching: {}", pattern);
        Ok(())
    }

    /// Temporarily decrypts files for access.
    ///
    /// Decrypts specified files to a temporary location with optional
    /// write permissions and automatic cleanup.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file or directory to unlock
    /// * `writable` - Whether to allow modifications to decrypted files
    /// * `timeout` - Optional duration after which files are automatically cleaned up
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure of the unlock operation.
    fn handle_unlock(&self, path: &PathBuf, writable: &bool, timeout: &Option<u32>) -> anyhow::Result<()> {
        // Get repository root and verify it exists
        let repo_root = self.find_repository_root()?;
        let repo_path = repo_root.join(".veil");
        
        if !self.quiet {
            println!("Unlocking {:?}", path);
        }

        // Get password for metadata DB
        let password = rpassword::prompt_password("Enter repository password: ")?;
        
        // Open metadata DB
        let db = MetadataDB::new(repo_path.join(".metadata.db"), &password)?;
        
        // Normalize the path to ensure it has a leading slash
        let virtual_path = if path.starts_with("/") {
            path.to_string_lossy().to_string()
        } else {
            format!("/{}", path.to_string_lossy())
        };

        // Use current working directory for unlocked files
        let unlocked_dir = std::env::current_dir()?;

        // Check if path exists as a file first
        if let Some(file_entry) = db.get_file_by_path(&virtual_path)? {
            // It's a file - decrypt it
            self.unlock_single_file(&file_entry, &repo_path, &unlocked_dir, &db, writable, self.verbose)?;
        } else {
            // Check if it's a directory
            let entries = db.list_directory(&virtual_path)?;
            if entries.is_empty() {
                anyhow::bail!("Path not found: {}", virtual_path);
            }

            // It's a directory - decrypt all files in it
            for entry in entries {
                let full_path = if virtual_path == "/" {
                    format!("/{}", entry)
                } else {
                    format!("{}/{}", virtual_path, entry)
                };

                if let Some(file_entry) = db.get_file_by_path(&full_path)? {
                    self.unlock_single_file(&file_entry, &repo_path, &unlocked_dir, &db, writable, self.verbose)?;
                }
            }
        }

        if !self.quiet {
            println!("Files decrypted to current directory");
            if *writable {
                println!("Files are writable - changes will NOT be automatically encrypted");
            }
        }

        Ok(())
    }

    fn unlock_single_file(
        &self,
        file_entry: &FileEntry,
        repo_path: &Path,
        unlocked_dir: &Path,
        db: &MetadataDB,
        writable: &bool,
        verbose: bool,
    ) -> anyhow::Result<()> {
        // Create parent directories for the target file
        let target_path = unlocked_dir.join(
            file_entry.virtual_path.strip_prefix("/").unwrap_or(&file_entry.virtual_path)
        );
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Construct source path for encrypted file using file_id
        let source_path = repo_path
            .join("contents")
            .join(format!("{}.enc", file_entry.id));

        if verbose {
            println!("Virtual path: {}", file_entry.virtual_path);
            println!("Looking for encrypted file at: {}", source_path.display());
        }

        // Decrypt file using the crypto manager
        let crypto = db.get_crypto_manager();
        crate::fs::decrypt_file(
            &source_path,
            &target_path,
            crypto,
            file_entry.id,
        )?;

        // Set file permissions based on writable flag
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if *writable { 0o600 } else { 0o400 };
            std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(mode))?;
        }

        // Add the newly unlocked file to the cache
        self.add_to_unlocked_cache(&target_path)?;

        Ok(())
    }
} 