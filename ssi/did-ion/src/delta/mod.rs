use serde::{Deserialize, Serialize};

use self::patches::DIDStatePatch;

pub mod patches;

/// Create/Update/Recover Delta Object
///
/// ### References
/// - [Sidetree §11.1 Create - Create Operation Delta Object][codo]
/// - [Sidetree §11.2 Update - Update Operation Delta Object][uodo]
/// - [Sidetree §11.3 Recover - Recover Operation Delta Object][rodo]
///
/// [codo]: https://identity.foundation/sidetree/spec/v1.0.0/#create-delta-object
/// [uodo]: https://identity.foundation/sidetree/spec/v1.0.0/#update-delta-object
/// [rodo]: https://identity.foundation/sidetree/spec/v1.0.0/#recover-delta-object
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delta {
    /// DID state patches to apply.
    pub patches: Vec<DIDStatePatch>,

    /// Update commitment generated as part of a Sidetree Create or Update operation.
    pub update_commitment: String,
}
