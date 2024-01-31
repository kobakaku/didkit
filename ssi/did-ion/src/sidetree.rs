use anyhow::{ensure, Context, Result};
use serde::Serialize;

use crate::{
    delta::{
        patches::{DIDStatePatch, PublicKeyJwk},
        Delta,
    },
    error::SidetreeError,
    operation::{CreateOperation, Operation},
    suffix_data::SuffixData,
};

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
