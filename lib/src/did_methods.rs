use once_cell::sync::Lazy;

use did_ion::DIDIon;
use did_web::DIDWeb;
use ssi::did::DIDMethods;

pub static DID_METHODS: Lazy<DIDMethods<'static>> = Lazy::new(|| {
    let mut methods = DIDMethods::default();
    methods.insert(Box::new(DIDWeb));
    methods.insert(Box::new(DIDIon));
    methods
});
