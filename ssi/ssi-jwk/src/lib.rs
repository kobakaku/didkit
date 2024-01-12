use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct JWK {
    #[serde(flatten)]
    pub params: String,
}
