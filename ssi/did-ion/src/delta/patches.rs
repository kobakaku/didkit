use std::convert::TryFrom;

use anyhow::{Context, Error};
use json_patch::Patch;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_dids::{ServiceEndpoint, VerificationRelationship};
use ssi_jwk::JWK;

use crate::error::PublicKeyJwkFromJWKError;

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
