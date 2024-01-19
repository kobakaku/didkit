use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// Missing elliptic curve point in JWK
    #[error("Missing elliptic curve point in JWK")]
    MissingPoint,
}
