use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::byteorder::ByteOrder;

/// SHA256 digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Digest(#[serde(with = "hex")] [u8; 32]);

impl Digest {
    /// Returns sha256 digest aganist given message.
    pub fn create<T: AsRef<[u8]> + ?Sized>(msg: &T) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        Self(hasher.finalize().into())
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ByteOrder for Digest {
    fn append_bytes(&self, buf: &mut Vec<u8>) {
        buf.extend(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::byteorder::ByteOrderBuilder;

    use super::*;

    const DIGEST_SOURCE: &'static str = "abc";
    const DIGEST_BYTES: [u8; 32] = [
        186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 176, 3, 97, 163,
        150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173,
    ];
    const DIGEST_HEX: &'static str =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn create() {
        let digest = Digest::create(DIGEST_SOURCE);
        assert_eq!(digest.as_ref(), DIGEST_BYTES);
    }

    #[test]
    fn byte_order() {
        let digest = Digest::create(DIGEST_SOURCE);
        let byte_order = ByteOrderBuilder::new().append(&digest).finalize();

        assert_eq!(byte_order, DIGEST_BYTES);
    }

    #[test]
    fn serialize() {
        let digest = Digest::create(DIGEST_SOURCE);
        let serialized = serde_json::to_string(&digest).unwrap();
        let json = format!(r#""{}""#, DIGEST_HEX);

        assert_eq!(serialized, json);
    }

    #[test]
    fn deserialize() {
        let json = format!(r#""{}""#, DIGEST_HEX);
        let digest = serde_json::from_str::<Digest>(&json).unwrap();

        assert_eq!(digest.as_ref(), DIGEST_BYTES);
    }

    #[test]
    fn deserialize_fail_too_short_digest() {
        let json = "1234567890123456789012345678901"; // Too short (31 bytes)
        let result = serde_json::from_str::<Digest>(&json);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_fail_too_long_digest() {
        let json = "123456789012345678901234567890123"; // Too long (33 bytes)
        let result = serde_json::from_str::<Digest>(&json);

        assert!(result.is_err());
    }
}
