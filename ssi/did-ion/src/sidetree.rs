use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{convert::TryFrom, marker::PhantomData};
use thiserror::Error as ThisError;

use ssi_dids::{
    did_resolve::HTTPDIDResolver, DIDCreate, DIDMethod, DIDMethodError, DIDMethodTransaction,
};
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

/// DID Resolver using ION/Sidetree REST API
pub struct HTTPSidetreeDIDResolver<S: Sidetree> {
    pub http_did_resolver: HTTPDIDResolver,
    pub _marker: PhantomData<S>,
}

impl<S: Sidetree> HTTPSidetreeDIDResolver<S> {
    pub fn new(sidetree_api_url: &str) -> Self {
        let identifiers_url = format!("{sidetree_api_url}identifiers/");
        Self {
            http_did_resolver: HTTPDIDResolver::new(&identifiers_url),
            _marker: PhantomData,
        }
    }
}

/// Sidetree DID Method client implementation
pub struct SidetreeClient<S: Sidetree> {
    pub resolver: Option<HTTPSidetreeDIDResolver<S>>,
    pub endpoint: Option<String>,
}

impl<S: Sidetree> SidetreeClient<S> {
    pub fn new(api_url_opt: Option<String>) -> Self {
        let resolver_opt = api_url_opt
            .as_ref()
            .map(|url| HTTPSidetreeDIDResolver::new(url));
        Self {
            endpoint: api_url_opt,
            resolver: resolver_opt,
        }
    }
}

impl<S: Sidetree + Send + Sync> DIDMethod for SidetreeClient<S> {
    fn name(&self) -> &'static str {
        "ion"
    }
    fn create(&self, create: DIDCreate) -> Result<DIDMethodTransaction, DIDMethodError> {
        let DIDCreate {
            options,
            update_key,
            recovery_key,
            verification_key: _,
        } = create;
        if let Some(opt) = options.keys().next() {
            return Err(DIDMethodError::OptionNotSupported {
                operation: "create",
                option: opt.clone(),
            });
        }
        let (update_pk, recovery_pk) =
            new_did_state(update_key, recovery_key).context("Prepare keys for DID creation")?;
        let operation = S::create_existing(&update_pk, &recovery_pk /*,patches*/)
            .context("Construct Create operation")?;
        let tx =
            Self::operation_to_transaction(operation).context("Construct create transaction")?;

        Ok(tx)
    }
}

impl<S: Sidetree> SidetreeClient<S> {
    fn operation_to_transaction(op: Operation) -> Result<DIDMethodTransaction> {
        let value = serde_json::to_value(op).context("Convert operation to value")?;
        Ok(DIDMethodTransaction {
            did_method: S::METHOD.to_string(),
            value: serde_json::json!({ "sidetreeOperation": value }),
        })
    }
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

fn new_did_state(
    update_key: Option<JWK>,
    recovery_key: Option<JWK>,
    // verification_key: Option<JWK>,
) -> Result<(PublicKeyJwk, PublicKeyJwk /* , Vec<DIDStatePatch>*/)> {
    let update_key = update_key.ok_or_else(|| anyhow!("Missing required update key"))?;
    let recovery_key = recovery_key.ok_or_else(|| anyhow!("Missing required recovery key"))?;
    // TODO: validate jwk
    let update_pk = PublicKeyJwk::try_from(update_key).context("Convert update key")?;
    let recovery_pk = PublicKeyJwk::try_from(recovery_key).context("Convert recovery key")?;
    Ok((update_pk, recovery_pk /* , patches*/))
}
