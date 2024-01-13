mod sidetree;

use sidetree::{Sidetree, SidetreeClient};

pub struct ION;

/// did:ion Method
pub type DIDION = SidetreeClient<ION>;

impl Sidetree for ION {
    const METHOD: &'static str = "ion";
}
