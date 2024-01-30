use anyhow::{ensure, Context, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryFrom;

use ssi_jwk::JWK;

use crate::error::PublicKeyJwkFromJWKError;

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
        patches: Vec<String>,
    ) -> Result<Operation> {
        ensure!(
            update_pk != recovery_pk,
            "Update and recovery public key JWK payload must be different."
        );

        let create_operation = CreateOperation {
            suffix_data: Value::Null,
            delta: Value::Null,
        };

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
    pub suffix_data: Value,
    pub delta: Value,
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

    /// `publicKeyJwk` or `publicKeyMultibase` property
    #[serde(flatten)]
    pub public_key: PublicKey,
}

impl TryFrom<JWK> for PublicKeyEntry {
    type Error = Error;

    fn try_from(jwk: JWK) -> Result<Self, Self::Error> {
        let public_key_jwk = PublicKeyJwk::try_from(jwk.to_public()).context("Convert key")?;
        let public_key = PublicKey::PublicKeyJwk(public_key_jwk);
        Ok(PublicKeyEntry {
            id: "TODO".to_string(),
            r#type: "TODO".to_string(),
            public_key,
        })
    }
}
