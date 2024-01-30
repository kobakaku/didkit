use thiserror::Error as ThisError;

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
