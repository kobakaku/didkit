use std::str::FromStr;

use anyhow::{Error, Result};
use clap::{Parser, Subcommand};
use didkit::ssi::ssi_dids::did_resolve::Metadata;
use serde_json::Value;

mod did;
mod key;

#[derive(Parser)]
struct DIDKit {
    #[command(subcommand)]
    command: DIDKitCmd,
}
#[derive(Subcommand)]
pub enum DIDKitCmd {
    /// Subcommand for keypair operations
    #[clap(subcommand)]
    Key(key::KeyCmd),
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
        DIDKitCmd::Key(args) => key::cli(args).await.unwrap(),
    }
    Ok(())
}

#[derive(Clone)]
/// Subset of [DID Metadata Structure][metadata] that is just a string property name and string value.
/// [metadata]: https://w3c.github.io/did-core/#metadata-structure
pub struct MetadataProperty {
    pub name: String,
    pub value: Metadata,
}

impl FromStr for MetadataProperty {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, '=');
        let name = parts.next().unwrap_or_default().to_string();
        if let Some(value) = parts.next() {
            Ok(Self {
                name,
                value: Metadata::String(value.to_string()),
            })
        } else {
            Ok(Self {
                name,
                value: Metadata::Boolean(true),
            })
        }
    }
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
