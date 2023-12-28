use serde_json::Value;
use ssi_dids::{DIDCreate, DIDMethod, DIDMethodError, DIDMethodTransaction};

/// did:web Method
///
/// [Specification](https://w3c-ccg.github.io/did-method-web/)
pub struct DIDWeb;

impl DIDMethod for DIDWeb {
    fn name(&self) -> &'static str {
        "web"
    }
    fn create(&self, _create: DIDCreate) -> Result<DIDMethodTransaction, DIDMethodError> {
        Ok(DIDMethodTransaction {
            did_method: "did:web".to_string(),
            value: Value::Null,
        })
    }
}
