mod client;
mod error;
mod sidetree;

use client::SidetreeClient;
use sidetree::Sidetree;

pub struct ION;

/// did:ion Method
pub type DIDION = SidetreeClient<ION>;

impl Sidetree for ION {
    const METHOD: &'static str = "ion";
}
