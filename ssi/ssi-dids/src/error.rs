use thiserror::Error;

/// Error type for `ssi`.
#[derive(Error, Debug)]
pub enum Error {
    /// Key mismatch
    #[error("Key mismatch")]
    KeyMismatch,
}
