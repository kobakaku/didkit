mod client;
mod delta;
mod error;
mod operation;
mod sidetree;
mod suffix_data;

use client::SidetreeClient;
use sidetree::Sidetree;

pub struct ION;

/// did:ion Method
pub type DIDION = SidetreeClient<ION>;

impl Sidetree for ION {
    const METHOD: &'static str = "ion";
}
