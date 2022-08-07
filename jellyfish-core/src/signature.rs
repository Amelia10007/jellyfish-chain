use std::error::Error;
use std::fmt::{self, Display, Formatter};

use ed25519_dalek::ed25519::signature::Signature as _;
use hex::ToHex;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::byteorder::ByteOrder;

/// Sign to a message by message's creator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(
    #[serde(serialize_with = "serialize_signature")]
    #[serde(deserialize_with = "deserialize_signature")]
    ed25519_dalek::Signature,
);

impl Signature {
    pub(crate) fn as_raw_sign(&self) -> &ed25519_dalek::Signature {
        &self.0
    }

    pub(crate) fn from_raw_sign(sign: ed25519_dalek::Signature) -> Self {
        Self(sign)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl ByteOrder for Signature {
    fn append_bytes(&self, buf: &mut Vec<u8>) {
        buf.extend(self.as_ref());
    }
}

fn serialize_signature<S: Serializer>(
    sign: &ed25519_dalek::Signature,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let hex: String = sign.as_bytes().encode_hex();
    hex.serialize(serializer)
}

fn deserialize_signature<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<ed25519_dalek::Signature, D::Error> {
    let hex = String::deserialize(deserializer)?;
    let bytes = hex::decode(&hex).map_err(D::Error::custom)?;
    let sign = ed25519_dalek::Signature::from_bytes(&bytes).map_err(D::Error::custom)?;
    Ok(sign)
}

#[derive(Debug)]
pub struct SignatureError(ed25519_dalek::ed25519::Error);

impl From<ed25519_dalek::ed25519::Error> for SignatureError {
    fn from(e: ed25519_dalek::ed25519::Error) -> Self {
        Self(e)
    }
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for SignatureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGN_HEX:&'static str = "f980f643a1af9602564fb1da2fd296bc48e546d0958124c2a466756eb35bcf9e145a0b8eea383672d54ea9f10b67011cbb1df7896dd796de1ff326fbc39edd08";
    const SIGN_BYTES: [u8; 64] = [
        249, 128, 246, 67, 161, 175, 150, 2, 86, 79, 177, 218, 47, 210, 150, 188, 72, 229, 70, 208,
        149, 129, 36, 194, 164, 102, 117, 110, 179, 91, 207, 158, 20, 90, 11, 142, 234, 56, 54,
        114, 213, 78, 169, 241, 11, 103, 1, 28, 187, 29, 247, 137, 109, 215, 150, 222, 31, 243, 38,
        251, 195, 158, 221, 8,
    ];

    #[test]
    fn serialize() {
        let sign =
            Signature::from_raw_sign(ed25519_dalek::Signature::from_bytes(&SIGN_BYTES).unwrap());

        let serialized = serde_json::to_string(&sign).unwrap();
        let json = format!(r#""{}""#, SIGN_HEX);

        assert_eq!(serialized, json);
    }

    #[test]
    fn deserialize() {
        let json = format!(r#""{}""#, SIGN_HEX);
        let deserialized = serde_json::from_str::<Signature>(&json).unwrap();

        assert_eq!(deserialized.as_ref(), SIGN_BYTES);
    }

    #[test]
    fn deserialize_fail_invalid_sign() {
        // 256byte sign, but invalid format
        let json = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678";
        let result = serde_json::from_str::<Signature>(json);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_fail_too_short_sign() {
        // 254byte (127 chars) sign
        let json = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567";
        let result = serde_json::from_str::<Signature>(json);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_fail_too_long_sign() {
        // 258byte (129 chars) sign
        let json = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        let result = serde_json::from_str::<Signature>(json);

        assert!(result.is_err());
    }
}
