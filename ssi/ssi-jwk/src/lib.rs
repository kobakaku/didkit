use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

mod error;
pub use error::Error;
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize)]
#[serde(try_from = "String")]
#[serde(into = "Base64urlUIntString")]
pub struct Base64urlUInt(Vec<u8>);
type Base64urlUIntString = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct JWK {
    #[serde(flatten)]
    pub params: Params,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Params {
    EC(ECParams),
}

#[derive(Debug, Serialize, Deserialize, Zeroize)]
pub struct ECParams {
    // Parameters for Elliptic Curve Public Keys
    #[serde(rename = "crv")]
    pub curve: String,
    #[serde(rename = "x")]
    pub x_coordinate: Base64urlUInt,
    #[serde(rename = "y")]
    pub y_coordinate: Base64urlUInt,

    // Parameters for Elliptic Curve Private Keys
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_private_key: Option<Base64urlUInt>,
}

impl Drop for ECParams {
    fn drop(&mut self) {
        // Zeroize private key
        if let Some(ref mut d) = self.ecc_private_key {
            d.zeroize();
        }
    }
}

impl JWK {
    #[cfg(feature = "secp256k1")]
    pub fn generate_secp256k1() -> Result<JWK, Error> {
        let mut rng = rand::rngs::OsRng {};
        let secret_key = k256::SecretKey::random(&mut rng);
        let sk_bytes = zeroize::Zeroizing::new(secret_key.to_bytes().to_vec());
        let public_key: k256::elliptic_curve::PublicKey<k256::Secp256k1> = secret_key.public_key();
        let mut ec_params = ECParams::try_from(&public_key)?;
        ec_params.ecc_private_key = Some(Base64urlUInt(sk_bytes.to_vec()));
        Ok(JWK {
            params: Params::EC(ec_params),
        })
    }
}

impl TryFrom<String> for Base64urlUInt {
    type Error = base64::DecodeError;
    fn try_from(data: String) -> Result<Self, Self::Error> {
        Ok(Base64urlUInt(base64::decode_config(
            data,
            base64::URL_SAFE,
        )?))
    }
}

impl From<&Base64urlUInt> for String {
    fn from(data: &Base64urlUInt) -> String {
        base64::encode_config(&data.0, base64::URL_SAFE_NO_PAD)
    }
}

impl From<Base64urlUInt> for Base64urlUIntString {
    fn from(data: Base64urlUInt) -> Base64urlUIntString {
        String::from(&data)
    }
}

#[cfg(feature = "secp256k1")]
impl TryFrom<&k256::PublicKey> for ECParams {
    type Error = Error;
    fn try_from(pk: &k256::PublicKey) -> Result<Self, Self::Error> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let ec_points = pk.to_encoded_point(false);
        let x = ec_points.x().ok_or(Error::MissingPoint)?;
        let y = ec_points.y().ok_or(Error::MissingPoint)?;
        Ok(ECParams {
            curve: "secp256k1".to_string(),
            x_coordinate: Base64urlUInt(x.to_vec()),
            y_coordinate: Base64urlUInt(y.to_vec()),
            ecc_private_key: None,
        })
    }
}
