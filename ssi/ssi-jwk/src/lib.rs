use anyhow::Error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct JWK {
    #[serde(flatten)]
    pub params: Params,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Params {
    EC(String),
}

impl JWK {
    pub fn generate_secp256k1() -> Result<JWK, Error> {
        Ok(JWK {
            params: Params::EC("jwk".to_string()),
        })
    }
}
