use serde_json::Value;
use ssi_dids::{DIDCreate, DIDMethod, DIDMethodError, DIDMethodTransaction};

/// did:ion Method
pub struct DIDIon;

impl DIDMethod for DIDIon {
    fn name(&self) -> &'static str {
        "ion"
    }
    fn create(&self, create: DIDCreate) -> Result<DIDMethodTransaction, DIDMethodError> {
        let DIDCreate {
            options,
            update_key: _,
            recovery_key: _,
            verification_key: _,
        } = create;
        if let Some(opt) = options.keys().next() {
            return Err(DIDMethodError::OptionNotSupported {
                operation: "create",
                option: opt.clone(),
            });
        }
        Ok(DIDMethodTransaction {
            did_method: "did:ion".to_string(),
            value: Value::Null,
        })
    }
}
