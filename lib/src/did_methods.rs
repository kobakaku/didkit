#![allow(non_snake_case)]
use std::env::VarError;

use once_cell::sync::Lazy;

use did_ion::DIDION;
use did_web::DIDWEB;
use ssi::ssi_dids::DIDMethods;

pub static DID_METHODS: Lazy<DIDMethods<'static>> = Lazy::new(|| {
    let mut methods = DIDMethods::default();

    let DIDION: DIDION = DIDION::new(match std::env::var("DID_ION_API_URL") {
        Ok(string) => Some(string),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(err)) => {
            eprintln!("Unable to parse DID_ION_API_URL: {:?}", err);
            None
        }
    });

    methods.insert(Box::new(DIDWEB));
    methods.insert(Box::new(DIDION));
    methods
});
