use serde::{Deserialize, Serialize};

/// [Create Operation Suffix Data Object][data]
///
/// [data]: https://identity.foundation/sidetree/spec/v1.0.0/#create-suffix-data-object
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuffixData {
    /// Implementation-defined type property
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,

    /// Delta Hash
    ///
    /// [Hash](Sidetree::hash) of canonicalized [Create Operation Delta Object](Delta).
    pub delta_hash: String,

    /// [Recovery commitment](https://identity.foundation/sidetree/spec/v1.0.0/#recovery-commitment)
    ///
    /// Generated in step 2 of the [Create](https://identity.foundation/sidetree/spec/v1.0.0/#create) process.
    pub recovery_commitment: String,

    /// Anchor Origin
    ///
    /// Implementation-defined identifier for most recent anchor for the DID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_origin: Option<String>,
}
