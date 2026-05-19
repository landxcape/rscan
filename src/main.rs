mod cli;
mod scanner;

use clap::Parser;

#[tokio::main]
async fn main() {
    let config = cli::Cli::parse();

    if let Err(e) = scanner::run_scan(config).await {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}
