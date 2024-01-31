use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum SidetreeError {
    /// Error from [serde_jcs::to_string]
    #[error("Unable to execute JSON Canonicalization Scheme (JCS)")]
    JCS(#[from] serde_json::Error),
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
