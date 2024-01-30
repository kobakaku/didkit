use anyhow::{anyhow, Context, Result};
use std::{convert::TryFrom, marker::PhantomData};

use ssi_dids::{
    did_resolve::HTTPDIDResolver, DIDCreate, DIDMethod, DIDMethodError, DIDMethodTransaction,
};
use ssi_jwk::JWK;

use crate::sidetree::{Operation, PublicKeyJwk, Sidetree};

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
