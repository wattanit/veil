use clap::Parser;

mod cli;
mod crypto;
mod error;
mod fs;
mod metadata;

fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse CLI commands and run
    let cli = cli::Cli::parse();
    cli.run()
} 