use std::fmt::{self, Display, Formatter};

use ed25519_dalek::{Keypair, PublicKey, Signer, Verifier};
use hex::ToHex;
use rand::{CryptoRng, RngCore};
use serde::de::Error as _;
use serde::Deserializer;
use serde::Serializer;
use serde::{Deserialize, Serialize};

use crate::signature::SignatureError;
use crate::ByteOrder;
use crate::Signature;

/// jellyfish-chain protocol's account.
/// Ledger, miner, and client have own account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    #[serde(serialize_with = "serialize_name")]
    #[serde(deserialize_with = "deserialize_name")]
    name: PublicKey,
}

impl Account {
    /// Returns whether given message and sign was created by the account.
    pub fn verify<T>(&self, msg: &T, sign: &Signature) -> Result<(), SignatureError>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        self.name.verify(msg.as_ref(), sign.as_raw_sign())?;
        Ok(())
    }
}

impl ByteOrder for Account {
    fn append_bytes(&self, buf: &mut Vec<u8>) {
        buf.extend(self.name.as_bytes());
    }
}

fn serialize_name<S: Serializer>(name: &PublicKey, serializer: S) -> Result<S::Ok, S::Error> {
    let hex: String = name.as_bytes().encode_hex();
    hex.serialize(serializer)
}

fn deserialize_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PublicKey, D::Error> {
    let hex = String::deserialize(deserializer)?;
    let bytes = hex::decode(&hex).map_err(D::Error::custom)?;
    PublicKey::from_bytes(&bytes).map_err(D::Error::custom)
}

/// jellyfish-chain protocol's account with secret key.
///
/// DO NOT reveal its secret key.
#[derive(Debug)]
pub struct SecretAccount {
    keypair: Keypair,
}

impl SecretAccount {
    /// Create an account ramdomly.
    pub fn create<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let keypair = Keypair::generate(rng);
        Self { keypair }
    }

    /// Restores an account from the bytes.
    ///
    /// Bytes can be obtained from `SecretAccount::to_bytes()`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccountError> {
        let keypair = Keypair::from_bytes(bytes).map_err(AccountError)?;
        Ok(Self { keypair })
    }

    /// Obtain bytes representation of the account.
    pub fn to_bytes(&self) -> [u8; ed25519_dalek::KEYPAIR_LENGTH] {
        self.keypair.to_bytes()
    }

    pub fn public_key(&self) -> &[u8] {
        self.keypair.public.as_ref()
    }

    pub fn secret_key(&self) -> &[u8] {
        self.keypair.secret.as_ref()
    }

    /// Sign to the given message.
    pub fn sign<T>(&self, msg: &T) -> Signature
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let raw = self.keypair.sign(msg.as_ref());
        Signature::from_raw_sign(raw)
    }

    /// Returns public part of the account.
    pub fn to_public(&self) -> Account {
        Account {
            name: self.keypair.public,
        }
    }
}

#[derive(Debug)]
pub struct AccountError(ed25519_dalek::ed25519::Error);

impl Display for AccountError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for AccountError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[cfg(test)]
mod tests_account {
    use super::*;

    const NAME_BYTES: [u8; 32] = [
        140, 35, 172, 38, 161, 125, 175, 252, 1, 188, 200, 221, 219, 141, 254, 225, 118, 102, 219,
        28, 94, 112, 152, 162, 97, 84, 7, 31, 81, 218, 151, 240,
    ];

    const NAME_HEX: &'static str =
        "8c23ac26a17daffc01bcc8dddb8dfee17666db1c5e7098a26154071f51da97f0";

    #[test]
    fn serialize() {
        let publickey = PublicKey::from_bytes(&NAME_BYTES).unwrap();
        let account = Account { name: publickey };

        let serialized = serde_json::to_string(&account).unwrap();
        let json = format!(r#"{{"name":"{}"}}"#, NAME_HEX);

        assert_eq!(serialized, json);
    }

    #[test]
    fn deserialize() {
        let json = format!(r#"{{ "name": "{}" }}"#, NAME_HEX);

        let deserialized: Account = serde_json::from_str(&json).unwrap();
        let hex = hex::encode(deserialized.name);

        assert_eq!(hex, NAME_HEX);
    }

    #[test]
    fn deserialize_fail_too_short_key() {
        let too_short_name = "1234567890123456789012345678901"; // Too short (31 bytes)
        let json = format!(r#"{{ "name": "{}" }}"#, too_short_name);

        let res = serde_json::from_str::<Account>(&json);

        assert!(res.is_err());
    }

    #[test]
    fn deserialize_fail_too_long_key() {
        let too_long_name = "123456789012345678901234567890123"; // Too long (33 bytes)
        let json = format!(r#"{{ "name": "{}" }}"#, too_long_name);

        let res = serde_json::from_str::<Account>(&json);

        assert!(res.is_err());
    }
}

#[cfg(test)]
mod tests_secret_account {
    use super::*;

    fn create_secret_account() -> SecretAccount {
        SecretAccount::create(&mut rand::rngs::OsRng {})
    }

    #[test]
    fn from_to_bytes() {
        let secret_account = create_secret_account();

        let bytes = secret_account.to_bytes();
        let restored_secret_account = SecretAccount::from_bytes(&bytes).unwrap();

        // Sign to the same message
        let message = "hello";

        let sign1 = secret_account.sign(message);
        let sign2 = restored_secret_account.sign(message);

        assert_eq!(sign1, sign2);
    }

    #[test]
    fn sign() {
        let secret_account = create_secret_account();
        let message = "The altimate answer=42";

        let sign = secret_account.sign(message);

        let account = secret_account.to_public();
        assert!(account.verify(message, &sign).is_ok());
    }

    #[test]
    fn sign_corrupt_message() {
        let secret_account = create_secret_account();
        let message = "The altimate answer=42";

        let sign = secret_account.sign(message);

        let account = secret_account.to_public();
        assert!(account.verify("The altimate answer=43", &sign).is_err());
    }

    #[test]
    fn sign_corrupt_sign() {
        let secret_account = create_secret_account();
        let message = "The altimate answer=42";

        let sign = secret_account.sign("The altimate answer=43");

        let account = secret_account.to_public();
        assert!(account.verify(message, &sign).is_err());
    }
}
