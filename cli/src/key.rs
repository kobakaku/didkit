use anyhow::Result;
use clap::Subcommand;

use didkit::JWK;

#[derive(Subcommand)]
pub enum KeyCmd {
    /// Generate and output a keypair in JWK format
    #[clap(subcommand)]
    Generate(KeyGenerateCmd),
}

#[derive(Subcommand)]
pub enum KeyGenerateCmd {
    /*/ /// Generate and output a Ed25519 keypair in JWK format
    Ed25519, */
    /// Generate and output a K-256 keypair in JWK format
    Secp256k1,
    /* /// Generate and output a P-256 keypair in JWK format
    Secp256r1, */
}

pub async fn cli(cmd: KeyCmd) -> Result<()> {
    match cmd {
        KeyCmd::Generate(cmd_generate) => generate(cmd_generate).await?,
    };
    Ok(())
}

pub async fn generate(cmd: KeyGenerateCmd) -> Result<()> {
    let jwk = match cmd {
        // KeyGenerateCmd::Ed25519 => JWK::generate_secp256k1().unwrap(),
        KeyGenerateCmd::Secp256k1 => JWK::generate_secp256k1().unwrap(),
        // KeyGenerateCmd::Secp256r1 => JWK::generate_secp256k1().unwrap(),
    };
    let jwk_str = serde_json::to_string(&jwk).unwrap();
    println!("{jwk_str}");
    Ok(())
}
