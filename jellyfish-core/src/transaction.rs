use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::signature::SignatureError;
use crate::{Account, SecretAccount, Signature, Timestamp, Verified, Yet};
use crate::{ByteOrder, ByteOrderBuilder};

/// The smallest unit of contract.
/// ### Generic type parameter
/// - `T` transaction content.
/// - `V` verification process marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Transaction<T, V> {
    /// Creator of the transaction
    account: Account,
    /// When this transaction offered
    timestamp: Timestamp,
    /// Transaction content
    content: T,
    /// Sign by offerer
    sign: Signature,
    /// Marker of verification process
    #[serde(skip_serializing)]
    _phantom: PhantomData<fn() -> V>,
}

impl<T, V> Transaction<T, V> {
    pub fn account(&self) -> &Account {
        &self.account
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn content(&self) -> &T {
        &self.content
    }

    pub fn sign(&self) -> &Signature {
        &self.sign
    }
}

/// Module-inner struct, which has save field with Transaction, except verification marker field.
/// This is used to deserialize data into unverified transaction.
#[derive(Deserialize)]
struct TransactionWithoutMarker<T> {
    account: Account,
    timestamp: Timestamp,
    content: T,
    sign: Signature,
}

impl<'de, T> Deserialize<'de> for Transaction<T, Yet>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize into transaction without marker
        let inner = TransactionWithoutMarker::deserialize(deserializer)?;

        // Append 'unverified' marker to deserialized transaction.
        Ok(Transaction {
            account: inner.account,
            timestamp: inner.timestamp,
            content: inner.content,
            sign: inner.sign,
            _phantom: PhantomData,
        })
    }
}

impl<T: ByteOrder> Transaction<T, Yet> {
    /// Verify transaction signature.
    pub fn verify(self) -> Result<Transaction<T, Verified>, TransactionError> {
        let signature_source = build_signature_source(&self.account, self.timestamp, &self.content);

        match self.account.verify(&signature_source, &self.sign) {
            Ok(()) => Ok(Transaction {
                account: self.account,
                timestamp: self.timestamp,
                content: self.content,
                sign: self.sign,
                _phantom: PhantomData,
            }),
            Err(e) => Err(TransactionError::Signature(e)),
        }
    }
}

impl<T: ByteOrder> Transaction<T, Verified> {
    pub fn create(secret_account: &SecretAccount, timestamp: Timestamp, content: T) -> Self {
        let account = secret_account.to_public();
        let signature_source = build_signature_source(&account, timestamp, &content);
        let sign = secret_account.sign(&signature_source);

        Transaction {
            account,
            timestamp,
            content,
            sign,
            _phantom: PhantomData,
        }
    }
}

fn build_signature_source<T: ByteOrder>(
    account: &Account,
    timestamp: Timestamp,
    content: &T,
) -> Vec<u8> {
    ByteOrderBuilder::new()
        .append(account)
        .append(&timestamp)
        .append(content)
        .finalize()
}

#[derive(Debug)]
pub enum TransactionError {
    /// Invalid sign in transaction.
    Signature(SignatureError),
}

impl Display for TransactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TransactionError::Signature(e) => {
                write!(f, "Transaction signature verification failed: {}", e)
            }
        }
    }
}

impl Error for TransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TransactionError::Signature(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretAccount;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ContentStab(Vec<u8>);

    impl ByteOrder for ContentStab {
        fn append_bytes(&self, buf: &mut Vec<u8>) {
            buf.extend(&self.0);
        }
    }

    fn create_account() -> SecretAccount {
        SecretAccount::create(&mut rand_core::OsRng {})
    }

    #[test]
    fn verify() {
        // Create transaction
        let account = create_account();
        let timestamp = Timestamp::now();
        let content = ContentStab(vec![0, 1, 2]);

        let tx = Transaction::create(&account, timestamp, content);

        // Convert transaction to unverified one, but same content.
        let ser = serde_json::to_string(&tx).unwrap();
        let de = serde_json::from_str::<Transaction<ContentStab, Yet>>(&ser).unwrap();

        // Try verification
        let verified = de.verify().unwrap();

        assert_eq!(tx, verified);
    }

    #[test]
    fn verify_corrupt_account() {
        // Create transaction
        let account = create_account();
        let timestamp = Timestamp::now();
        let content = ContentStab(vec![0, 1, 2]);

        let mut tx = Transaction::create(&account, timestamp, content);

        // Cheat account
        tx.account = create_account().to_public();

        // Convert transaction to unverified one, but same content.
        let ser = serde_json::to_string(&tx).unwrap();
        let de = serde_json::from_str::<Transaction<ContentStab, Yet>>(&ser).unwrap();

        // Try verification
        let res = de.verify();

        assert!(matches!(res, Err(TransactionError::Signature(_))));
    }

    #[test]
    fn verify_corrupt_timestamp() {
        // Create transaction
        let account = create_account();
        let timestamp = Timestamp::now();
        let content = ContentStab(vec![0, 1, 2]);

        let mut tx = Transaction::create(&account, timestamp, content);

        // Cheat timestamp
        tx.timestamp = Timestamp::now();

        // Convert transaction to unverified one, but same content.
        let ser = serde_json::to_string(&tx).unwrap();
        let de = serde_json::from_str::<Transaction<ContentStab, Yet>>(&ser).unwrap();

        // Try verification
        let res = de.verify();

        assert!(matches!(res, Err(TransactionError::Signature(_))));
    }

    #[test]
    fn verify_corrupt_content() {
        // Create transaction
        let account = create_account();
        let timestamp = Timestamp::now();
        let content = ContentStab(vec![0, 1, 2]);

        let mut tx = Transaction::create(&account, timestamp, content);

        // Cheat content
        tx.content = ContentStab(vec![42]);

        // Convert transaction to unverified one, but same content.
        let ser = serde_json::to_string(&tx).unwrap();
        let de = serde_json::from_str::<Transaction<ContentStab, Yet>>(&ser).unwrap();

        // Try verification
        let res = de.verify();

        assert!(matches!(res, Err(TransactionError::Signature(_))));
    }

    #[test]
    fn verify_corrupt_sign() {
        // Create transaction
        let account = create_account();
        let timestamp = Timestamp::now();
        let content = ContentStab(vec![0, 1, 2]);

        let mut tx = Transaction::create(&account, timestamp, content);

        // Cheat sign
        tx.sign = account.sign(&[]);

        // Convert transaction to unverified one, but same content.
        let ser = serde_json::to_string(&tx).unwrap();
        let de = serde_json::from_str::<Transaction<ContentStab, Yet>>(&ser).unwrap();

        // Try verification
        let res = de.verify();

        assert!(matches!(res, Err(TransactionError::Signature(_))));
    }
}
