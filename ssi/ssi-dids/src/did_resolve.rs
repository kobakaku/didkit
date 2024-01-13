use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// [Metadata structure](https://www.w3.org/TR/did-core/#metadata-structure) "for DID resolution,
/// DID URL dereferencing, and other DID-related processes"
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Metadata {
    /// [String](https://infra.spec.whatwg.org/#string)
    String(String),
    /// A [map](https://infra.spec.whatwg.org/#maps) of properties for a metadata structure.
    Map(HashMap<String, Metadata>),
    /// [List](https://infra.spec.whatwg.org/#list) (array)
    List(Vec<Metadata>),
    /// [Boolean](https://infra.spec.whatwg.org/#boolean)
    Boolean(bool),
    /// [Null](https://infra.spec.whatwg.org/#nulls)
    Null,
}

/// A DID Resolver implementing a client for the [DID Resolution HTTP(S)
/// Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
pub struct HTTPDIDResolver {
    /// HTTP(S) URL for DID resolver HTTP(S) endpoint.
    pub endpoint: String,
}

impl HTTPDIDResolver {
    /// Construct a new HTTP DID Resolver with a given [endpoint][HTTPDIDResolver::endpoint] URL.
    pub fn new(url: &str) -> Self {
        Self {
            endpoint: url.to_string(),
        }
    }
}
