//! # Decentralized Identifiers (DIDs)
//!
//! As specified by [Decentralized Identifiers (DIDs) v1.0 - Core architecture, data model, and representations][did-core].
//!
//! [did-core]: https://www.w3.org/TR/did-core/
//!

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;

/// DID Create Operation
///
/// <https://identity.foundation/did-registration/#create>
pub struct DIDCreate {
    pub options: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDMethodTransaction {
    /// DID method name
    pub did_method: String,

    /// Method-specific transaction data
    // #[serde(flatten)]
    pub value: Value,
}

/// An error having to do with a [DIDMethod].
#[derive(Error, Debug)]
pub enum DIDMethodError {
    #[error("Not implemented for DID method: {0}")]
    NotImplemented(&'static str),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// An implementation of a [DID method](https://www.w3.org/TR/did-core/#dfn-did-methods).
pub trait DIDMethod: Sync + Send {
    /// Get the DID method's name.
    ///
    /// `method-name` in [DID Syntax](https://w3c.github.io/did-core/#did-syntax).
    fn name(&self) -> &'static str;

    /// Create a DID
    fn create(&self, _create: DIDCreate) -> Result<DIDMethodTransaction, DIDMethodError> {
        Err(DIDMethodError::NotImplemented("Create operation"))
    }
}

/// A collection of DID methods
#[derive(Default)]
pub struct DIDMethods<'a> {
    pub methods: HashMap<&'a str, Box<dyn DIDMethod>>,
}

impl<'a> DIDMethods<'a> {
    /// Add a DID method to the set. Returns the previous one set for the given method name, if any.
    pub fn insert(&mut self, method: Box<dyn DIDMethod>) -> Option<Box<dyn DIDMethod>> {
        let name = method.name();
        self.methods.insert(name, method)
    }

    /// Get a DID method from the set.
    pub fn get(&self, method_name: &str) -> Option<&Box<dyn DIDMethod>> {
        self.methods.get(method_name)
    }
}
