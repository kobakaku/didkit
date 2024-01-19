use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use didkit::{DIDCreate, DID_METHODS};

use crate::{metadata_properties_to_value, read_jwk_file_opt, MetadataProperty};

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
    /// JWK file for default verification method
    #[clap(short, long)]
    verification_key: Option<PathBuf>,
    /// JWK file for DID Update operations
    #[clap(short, long)]
    update_key: Option<PathBuf>,
    /// JWK file for DID Recovery and/or Deactivate operations
    #[clap(short, long)]
    recovery_key: Option<PathBuf>,
    #[clap(short, long)]
    /// Options for DID create operation
    ///
    /// More info: https://identity.foundation/did-registration/#options
    options: Vec<MetadataProperty>,
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
    let update_key =
        read_jwk_file_opt(&args.update_key).context("Read update key for DID Create")?;
    let verification_key = read_jwk_file_opt(&args.verification_key)
        .context("Read verification key for DID Create")?;
    let recovery_key =
        read_jwk_file_opt(&args.recovery_key).context("Read recovery key for DID Create")?;
    let options =
        metadata_properties_to_value(args.options).context("Parse options for DID Create")?;
    let options = serde_json::from_value(options).context("Unable to convert options")?;

    let tx = method
        .create(DIDCreate {
            options: options,
            update_key,
            recovery_key,
            verification_key,
        })
        .context("DID Create failed")?;

    println!("{}", serde_json::to_string_pretty(&tx).unwrap());
    Ok(())
}
