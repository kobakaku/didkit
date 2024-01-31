use anyhow::{ensure, Context, Error, Result};
use json_patch::Patch;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryFrom;

use ssi_dids::{ServiceEndpoint, VerificationRelationship};
use ssi_jwk::JWK;

use crate::error::{PublicKeyJwkFromJWKError, SidetreeError};

const MULTIHASH_SHA2_256_PREFIX: &[u8] = &[0x12];
const MULTIHASH_SHA2_256_SIZE: &[u8] = &[0x20];

// use crate::DIDION;

/// Parameters for a Sidetree client implementation
///
/// This trait consistest of the subset of parameters defined in [Sidetree §5. Default Parameters][default-params] that are needed to implemented a Sidetree client, that is a client to the [Sidetree REST API][sidetree-rest].
///
/// [default-params]: https://identity.foundation/sidetree/spec/v1.0.0/#default-parameters
/// [sidetree-rest]: https://identity.foundation/sidetree/api/
pub trait Sidetree {
    /// Method name for Sidetree-based DID
    ///
    /// Mentioned in [Sidetree §9. DID URI Composition](https://identity.foundation/sidetree/spec/v1.0.0/#did-uri-composition)
    const METHOD: &'static str;

    /// [Public Key Commitment Scheme (Sidetree §6.2.1)][pkcs]
    ///
    /// [pkcs]: https://identity.foundation/sidetree/spec/v1.0.0/#public-key-commitment-scheme
    fn commitment_scheme(pkjwk: &PublicKeyJwk) -> Result<String> {
        let canonicalized_public_key =
            Self::json_canonicalization_scheme(&pkjwk).context("Canonicalize JWK")?;
        // Note: hash_algorithm called here instead of reveal_value, since the underlying hash is
        // used, not the encoded/prefixed one.
        let reveal_value = Self::hash_algorithm(canonicalized_public_key.as_bytes());
        let commitment = Self::hash(&reveal_value);
        Ok(commitment)
    }

    /// [`JSON_CANONICALIZATION_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#json-canonicalization-scheme)
    fn json_canonicalization_scheme<T: Serialize>(value: &T) -> Result<String, SidetreeError> {
        serde_jcs::to_string(value).map_err(SidetreeError::JCS)
    }

    /// Hash and encode data
    ///
    /// [Sidetree §6.1 Hashing Process](https://identity.foundation/sidetree/spec/#hashing-process)
    fn hash(data: &[u8]) -> String {
        let hash = Self::hash_protocol(data);
        /*
        ensure!(
            hash.len() <= Self::MAX_OPERATION_HASH_LENGTH,
            "Hash is too long"
        );
        */
        Self::data_encoding_scheme(&hash)
    }

    /// [`DATA_ENCODING_SCHEME`](https://identity.foundation/sidetree/spec/v1.0.0/#data-encoding-scheme)
    fn data_encoding_scheme(data: &[u8]) -> String {
        base64::encode_config(data, base64::URL_SAFE_NO_PAD)
    }

    /// [`HASH_PROTOCOL`](https://identity.foundation/sidetree/spec/v1.0.0/#hash-protocol)
    ///
    /// This should be implemented using [hash_algorithm].
    ///
    /// Default implementation calls [hash_protocol_algorithm] and returns the concatenation of the
    /// prefix and hash.
    ///
    /// This function must correspond with [hash_algorithm]. To ensure that correspondence,
    /// implementers may want to override [hash_protocol_algorithm] instead of this function.
    ///
    /// [hash_algorithm]: Self::hash_algorithm
    /// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
    fn hash_protocol(data: &[u8]) -> Vec<u8> {
        let (prefix, hash) = Self::hash_protocol_algorithm(data);
        [prefix, hash].concat()
    }

    /// [`HASH_ALGORITHM`](https://identity.foundation/sidetree/spec/v1.0.0/#hash-algorithm)
    ///
    /// Default implementation calls [hash_protocol_algorithm] and returns the hash, discarding the
    /// prefix.
    ///
    /// This function must correspond with [hash_protocol]. To ensure that correspondence,
    /// implementers may want to override [hash_protocol_algorithm] instead of this function.
    ///
    /// [hash_protocol]: Self::hash_protocol
    /// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
    fn hash_algorithm(data: &[u8]) -> Vec<u8> {
        let (_prefix, hash) = Self::hash_protocol_algorithm(data);
        hash
    }

    /// Combination of [hash_protocol] and [hash_algorithm]
    ///
    /// Returns multihash prefix and hash.
    ///
    /// Default implementation: SHA-256 (`sha2-256`)
    ///
    /// [hash_protocol] and [hash_algorithm] must correspond, and their default implementations
    /// call this function ([hash_protocol_algorithm]). Implementers are therefore encouraged to
    /// overwrite this function ([hash_protocol_algorithm]) rather than those ([hash_protocol] and
    /// [hash_algorithm]).
    ///
    /// [hash_protocol]: Self::hash_protocol
    /// [hash_algorithm]: Self::hash_algorithm
    /// [hash_protocol_algorithm]: Self::hash_protocol_algorithm
    fn hash_protocol_algorithm(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize().to_vec();
        (
            [MULTIHASH_SHA2_256_PREFIX, MULTIHASH_SHA2_256_SIZE].concat(),
            hash,
        )
    }

    /// Create a Sidetree-based DID using existing keys
    ///
    /// This function creates a Sidetree-based DID using existing public keys for
    /// the update key and recovery key and respective
    /// [commitments][].
    ///
    /// Sidetree specifies in ([§11.1 Create][create]) that creating a Sidetree DID involves
    /// generating a Update keypair and Recovery keypair. That is implemented in [Self::create].
    ///
    /// **Note**: The Sidetree specification ([§6.2.1 Public Key Commitment
    /// Scheme][pkcs]) recommends not reusing public keys across different commitment invocations, and
    /// requires not using public key JWK payloads across commitment invocations.
    ///
    /// [commitments]: https://identity.foundation/sidetree/spec/v1.0.0/#commitment
    /// [create]: https://identity.foundation/sidetree/spec/v1.0.0/#create
    /// [pkcs]: https://identity.foundation/sidetree/spec/v1.0.0/#public-key-commitment-scheme
    fn create_existing(
        update_pk: &PublicKeyJwk,
        recovery_pk: &PublicKeyJwk,
        patches: Vec<DIDStatePatch>,
    ) -> Result<Operation> {
        ensure!(
            update_pk != recovery_pk,
            "Update and recovery public key JWK payload must be different."
        );

        let update_commitment =
            Self::commitment_scheme(update_pk).context("Generate update commitment")?;

        let delta = Delta {
            patches,
            update_commitment,
        };
        let delta_string = Self::json_canonicalization_scheme(&delta)
            .context("Canonicalize Create Operation Delta Object")?;
        let delta_hash = Self::hash(delta_string.as_bytes());

        let recovery_commitment =
            Self::commitment_scheme(recovery_pk).context("Generate recovery commitment")?;

        let suffix_data = SuffixData {
            r#type: None,
            delta_hash,
            recovery_commitment,
            anchor_origin: None,
        };

        let create_operation = CreateOperation { delta, suffix_data };

        Ok(Operation::Create(create_operation))
    }
}

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

/// Public Key JWK (JSON Web Key)
///
/// Wraps [ssi_jwk::JWK]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyJwk {
    jwk: Value,
}

impl TryFrom<JWK> for PublicKeyJwk {
    type Error = PublicKeyJwkFromJWKError;
    fn try_from(jwk: JWK) -> Result<Self, Self::Error> {
        let jwk_value = serde_json::to_value(jwk).map_err(PublicKeyJwkFromJWKError::ToValue)?;
        // if jwk_value.get("d").is_some() {
        //     return Err(PublicKeyJwkFromJWKError::PrivateKeyParameters);
        // };
        Ok(Self { jwk: jwk_value })
    }
}

/// Public key as JWK or Multibase
///
/// Property of a public key / verification method containing public key data,
/// as part of a [PublicKeyEntry][].
///
/// per [Sidetree §12.1.1 `add-public-keys`: Step 4][apk].
///
/// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicKey {
    /// [`publicKeyJwk`](https://www.w3.org/TR/did-core/#dfn-publickeyjwk) as defined in DID Core.
    ///
    /// JSON Web Key (JWK) is specified in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
    PublicKeyJwk(PublicKeyJwk),

    /// [`publicKeyMultibase`](https://www.w3.org/TR/did-core/#dfn-publickeymultibase) as defined in DID Core.
    ///
    /// Maximum length may be set in [Sidetree::MAX_PKMB_LENGTH].
    PublicKeyMultibase(String),
}

/// Public Key Entry
///
/// Used by the [`add-public-keys`](DIDStatePatch::AddPublicKeys) and
/// [`replace`](DIDStatePatch::Replace) DID state patch actions.
///
/// Specified in [Sidetree §12.1.1 `add-public-keys`][apk].
///
/// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEntry {
    /// `id` property
    ///
    /// Maximum length: 50 in Base64url
    pub id: String,

    /// Verification method type
    pub r#type: String,

    /// Verification method controller (DID)
    ///
    /// Maximum length may be set in [Sidetree::MAX_CONTROLLER_LENGTH].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,

    /// `publicKeyJwk` or `publicKeyMultibase` property
    #[serde(flatten)]
    pub public_key: PublicKey,

    /// Verification relationships
    ///
    /// Defined in [DID Core](https://www.w3.org/TR/did-core/#verification-relationships).
    ///
    /// Corresponds to [`proofPurpose`](https://www.w3.org/TR/did-core/#verification-relationships) in VC Data Model.
    pub purposes: Vec<VerificationRelationship>,
}

/// Verification method type for Create operation
///
/// This is used when converting JWK to [verification method map][vmm] for the Create operation.
///
/// Reference: [Sidetree §12.1.1 `add-public-keys`][apk] Step 3.2
///
/// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
/// [vmm]: https://www.w3.org/TR/did-core/#verification-methods
pub const VERIFICATION_METHOD_TYPE: &str = "JsonWebSignature2020";

impl TryFrom<JWK> for PublicKeyEntry {
    type Error = Error;

    fn try_from(jwk: JWK) -> Result<Self, Self::Error> {
        let public_key_jwk = PublicKeyJwk::try_from(jwk.to_public()).context("Convert key")?;
        let public_key = PublicKey::PublicKeyJwk(public_key_jwk);
        Ok(PublicKeyEntry {
            id: "TODO".to_string(),
            r#type: VERIFICATION_METHOD_TYPE.to_string(),
            controller: None,
            public_key,
            purposes: vec![
                VerificationRelationship::Authentication,
                VerificationRelationship::AssertionMethod,
                VerificationRelationship::KeyAgreement,
                VerificationRelationship::CapabilityInvocation,
                VerificationRelationship::CapabilityDelegation,
            ],
        })
    }
}

/// Service Endpoint Entry
///
/// Used by the [`add-services`](DIDStatePatch::AddServices) and
/// [`replace`](DIDStatePatch::Replace) DID state patch actions.
///
/// Specified in [Sidetree §12.1.3 `add-services`][as].
///
/// [as]: https://identity.foundation/sidetree/spec/v1.0.0/#add-services
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEndpointEntry {
    /// `id` property
    ///
    /// Maximum length: 50 in Base64Url
    pub id: String,

    /// Service type
    ///
    /// Maximum length: 30 in Base64Url
    pub r#type: String,

    /// Service endpoint URL or object
    pub service_endpoint: ServiceEndpoint,
}

/// DID PKI metadata state
///
/// Used by the [`replace`](DIDStatePatch::Replace) DID state patch.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentState {
    /// Public key entries

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<PublicKeyEntry>>,

    /// Services
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<ServiceEndpointEntry>>,
}

/// [DID State Patch][dsp] using a [Sidetree Standard Patch action][spa]
///
/// [dsp]: https://identity.foundation/sidetree/spec/v1.0.0/#did-state-patches
/// [spa]: https://identity.foundation/sidetree/spec/v1.0.0/#standard-patch-actions
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
#[serde(rename_all = "kebab-case")]
pub enum DIDStatePatch {
    /// [`add-public-keys`][apk] Patch Action
    ///
    /// [apk]: https://identity.foundation/sidetree/spec/v1.0.0/#add-public-keys
    AddPublicKeys {
        /// Keys to add or over overwrite
        #[serde(rename = "publicKeys")]
        public_keys: Vec<PublicKeyEntry>,
    },

    /// [`remove-public-keys`][rpk] Patch Action
    ///
    /// [rpk]: https://identity.foundation/sidetree/spec/v1.0.0/#remove-public-keys
    RemovePublicKeys {
        /// IDs of keys to remove
        ids: Vec<String>,
    },

    /// [`add-services`][as] Patch Action
    ///
    /// [as]: https://identity.foundation/sidetree/spec/v1.0.0/#add-services
    AddServices {
        /// Service entries to add
        services: Vec<ServiceEndpointEntry>,
    },

    /// [`remove-services`][rs] Patch Action
    ///
    /// [rs]: https://identity.foundation/sidetree/spec/v1.0.0/#remove-services
    RemoveServices {
        /// IDs of service endpoints to remove
        ids: Vec<String>,
    },

    /// [`replace`][r] Patch Action
    ///
    /// [r]: https://identity.foundation/sidetree/spec/v1.0.0/#replace
    Replace {
        /// Reset DID state
        document: DocumentState,
    },

    /// [`ietf-json-patch`][ijp] Patch Action
    ///
    /// [ijp]: https://identity.foundation/sidetree/spec/v1.0.0/#ietf-json-patch
    ///
    IetfJsonPatch {
        /// JSON Patches according to [RFC 6902](https://datatracker.ietf.org/doc/html/rfc6902).
        patches: Patch,
    },
}
