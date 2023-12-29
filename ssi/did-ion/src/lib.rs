use serde_json::Value;
use ssi_dids::{DIDCreate, DIDMethod, DIDMethodError, DIDMethodTransaction};

/// did:ion Method
pub struct DIDIon;

impl DIDMethod for DIDIon {
    fn name(&self) -> &'static str {
        "ion"
    }
    fn create(&self, _create: DIDCreate) -> Result<DIDMethodTransaction, DIDMethodError> {
        Ok(DIDMethodTransaction {
            did_method: "did:ion".to_string(),
            value: Value::Null,
        })
    }
}
