use anyhow::Result;
use clap::{Parser, Subcommand};

mod did;

#[derive(Parser)]
struct DIDKit {
    #[command(subcommand)]
    command: DIDKitCmd,
}
#[derive(Subcommand)]
pub enum DIDKitCmd {
    /// Subcommand for DID operations
    #[clap(subcommand)]
    Did(did::DidCmd),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let opt = DIDKit::parse();
    match opt.command {
        DIDKitCmd::Did(args) => did::cli(args).await.unwrap(),
    }
    Ok(())
}
