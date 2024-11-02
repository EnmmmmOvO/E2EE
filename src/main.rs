use std::error::Error;
use std::path::Path;
use clap::{Parser, Subcommand};
use dotenv::from_path;

#[derive(Parser)]
#[command(name = "App")]
#[command(about = "An application with server and client modes", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server,
    Client,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    
    match &cli.command {
        Commands::Server => {
            from_path(Path::new("./src/server/.env")).expect("Failed to load .env file");
            server::start()?
        }
        Commands::Client => {
            from_path(Path::new("./src/client/.env")).expect("Failed to load .env file");
            client::start()?
        }
    };
    Ok(())
}