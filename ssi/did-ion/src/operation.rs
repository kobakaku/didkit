use serde::{Deserialize, Serialize};

use crate::{delta::Delta, suffix_data::SuffixData};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum Operation {
    Create(CreateOperation),
    // Update(UpdateOperation),
    // Recover(RecoverOperation),
    // Deactivate(DeactivateOperation),
}

/// Sidetree DID Create operation
///
/// ### References
/// - [Sidetree §11.1 Create](https://identity.foundation/sidetree/spec/v1.0.0/#create)
/// - [Sidetree REST API §1.2.1 Create](https://identity.foundation/sidetree/api/#create)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOperation {
    pub delta: Delta,
    pub suffix_data: SuffixData,
}
