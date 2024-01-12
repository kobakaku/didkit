use std::{path::PathBuf, str::FromStr};

use anyhow::{anyhow, Context, Error, Result};
use clap::{Args, Subcommand};
use didkit::{DIDCreate, DID_METHODS};
use serde_json::Value;

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
    // #[clap(short, long)]
    #[clap(short = 'o', name = "name=value")]
    /// Options for DID create operation
    ///
    /// More info: https://identity.foundation/did-registration/#options
    options: Vec<MetadataProperty>,
}

#[derive(Clone)]
/// Subset of [DID Metadata Structure][metadata] that is just a string property name and string value.
/// [metadata]: https://w3c.github.io/did-core/#metadata-structure
pub struct MetadataProperty {
    pub name: String,
    pub value: Value,
}

impl FromStr for MetadataProperty {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, '=');
        let name = parts.next().unwrap_or_default().to_string();
        if let Some(value) = parts.next() {
            Ok(Self {
                name,
                value: Value::String(value.to_string()),
            })
        } else {
            Ok(Self {
                name,
                value: Value::Bool(true),
            })
        }
    }
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

    let options =
        metadata_properties_to_value(args.options).context("Parse options for DID Create")?;
    let options = serde_json::from_value(options).context("Unable to convert options")?;

    let tx = method
        .create(DIDCreate {
            options: options,
            update_key: None,
            recovery_key: None,
            verification_key: None,
        })
        .context("DID Create failed")?;

    println!("{}", serde_json::to_string_pretty(&tx).unwrap());
    Ok(())
}

fn metadata_properties_to_value(meta_props: Vec<MetadataProperty>) -> Result<Value, Error> {
    use serde_json::map::Entry;
    let mut map = serde_json::Map::new();
    for prop in meta_props {
        let value = serde_json::to_value(prop.value)?;
        match map.entry(prop.name) {
            Entry::Vacant(entry) => {
                entry.insert(value);
            }
            Entry::Occupied(mut entry) => {
                match entry.get_mut() {
                    Value::Null => {
                        entry.insert(value);
                    }
                    Value::Array(ref mut array) => {
                        array.push(value);
                    }
                    _ => {
                        let old_value = entry.get_mut().take();
                        entry.insert(Value::Array(vec![old_value, value]));
                    }
                };
            }
        };
    }
    Ok(Value::Object(map))
}
