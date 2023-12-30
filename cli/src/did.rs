use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use didkit::{DIDCreate, DID_METHODS};

#[derive(Subcommand)]
pub enum DidCmd {
    /// Create new DID Document.
    Create(DidCreateArgs),
}

#[derive(Args)]
pub struct DidCreateArgs {
    /// DID method name for DID create operation
    ///
    /// More info: https://identity.foundation/did-registration/#method
    method: String,
    #[clap(short, long)]
    /// Secret for DID create operation
    ///
    /// More info: https://identity.foundation/did-registration/#secret
    secret: Option<String>,
    #[clap(short, long)]
    /// Options for DID create operation
    ///
    /// More info: https://identity.foundation/did-registration/#options
    options: Option<String>,
}

pub async fn cli(cmd: DidCmd) -> Result<()> {
    match cmd {
        DidCmd::Create(a) => create(a).await?,
    };
    Ok(())
}

pub async fn create(args: DidCreateArgs) -> Result<()> {
    let method = DID_METHODS
        .get(&args.method)
        .ok_or(anyhow!("Unable to get DID method"))?;

    let tx = method
        .create(DIDCreate {
            options: args.options,
        })
        .context("DID Create failed")?;

    println!("{}", serde_json::to_string_pretty(&tx).unwrap());
    Ok(())
}
