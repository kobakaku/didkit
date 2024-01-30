use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryFrom;
use thiserror::Error as ThisError;

use ssi_jwk::JWK;

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
    fn create_existing(update_pk: &PublicKeyJwk, recovery_pk: &PublicKeyJwk) -> Result<Operation> {
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
#[derive(PartialEq)]
pub struct PublicKeyJwk {
    jwk: Value,
}

/// Error resulting from [converting JWK to PublicKeyJwk][PublicKeyJwk::try_from]
#[derive(ThisError, Debug)]
pub enum PublicKeyJwkFromJWKError {
    /// Unable to convert JWK to [Value]
    #[error("Unable to convert JWK to Value")]
    ToValue(#[from] serde_json::Error),
    /// Public Key JWK must not contain private key parameters (e.g. "d")
    #[error("Public Key JWK must not contain private key parameters")]
    PrivateKeyParameters,
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
