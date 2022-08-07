use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::{byteorder::ByteOrder, Signature};

/// Represents an operation of transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Method {
    /// Add new record.
    Insert,
    /// Modify previously added record.
    Modify,
    /// Remove previously added record.
    Remove,
}

impl ByteOrder for Method {
    fn append_bytes(&self, buf: &mut Vec<u8>) {
        let byte = match self {
            Method::Insert => 0x01,
            Method::Modify => 0x02,
            Method::Remove => 0x04,
        };
        buf.push(byte);
    }
}

/// Specify a transaction in blocks.
/// Used for `Modify` or `Remove` method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionIdentifier {
    /// Which block contains the target transaction.
    pub height: u64,
    /// Target transaction's sign.
    pub sign: Signature,
}

impl TransactionIdentifier {
    /// Creates new transaction identifier.
    pub fn new(block_height: u64, sign: Signature) -> Self {
        Self {
            height: block_height,
            sign,
        }
    }
}

impl ByteOrder for TransactionIdentifier {
    fn append_bytes(&self, buf: &mut Vec<u8>) {
        buf.extend(self.height.to_le_bytes());
        self.sign.append_bytes(buf);
    }
}

/// Content of jellyfish-chain protocol's transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]

pub struct JellyfishTransactionContent {
    /// Operation.
    method: Method,
    /// Record. Used on `Insert` or `Modify` method.
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<String>,
    /// Ientifer of operation's target transaction. Used on `Modify` or `Remove` method.
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<TransactionIdentifier>,
}

impl JellyfishTransactionContent {
    /// Create new transaction content with `Insert` method.
    pub fn insert<'a, T>(record: T) -> Self
    where
        T: Into<Cow<'a, str>>,
    {
        Self {
            method: Method::Insert,
            record: Some(record.into().into_owned()),
            target: None,
        }
    }

    /// Create new transaction content with `Modify` method.
    pub fn modify<'a, T>(record: T, target: TransactionIdentifier) -> Self
    where
        T: Into<Cow<'a, str>>,
    {
        Self {
            method: Method::Modify,
            record: Some(record.into().into_owned()),
            target: Some(target),
        }
    }

    /// Create new transaction content with `Remove` method.
    pub fn remove(target: TransactionIdentifier) -> Self {
        Self {
            method: Method::Remove,
            record: None,
            target: Some(target),
        }
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn record(&self) -> Option<&str> {
        self.record.as_deref()
    }

    pub fn target_transaction(&self) -> Option<&TransactionIdentifier> {
        self.target.as_ref()
    }
}

impl ByteOrder for JellyfishTransactionContent {
    fn append_bytes(&self, buf: &mut Vec<u8>) {
        self.method.append_bytes(buf);
        if let Some(record) = self.record() {
            buf.extend(record.as_bytes());
        }
        if let Some(target) = &self.target {
            target.append_bytes(buf);
        }
    }
}

#[cfg(test)]
mod tests_method {
    use crate::byteorder::ByteOrderBuilder;

    use super::*;

    #[test]
    fn byte_order() {
        assert_eq!(
            ByteOrderBuilder::new().append(&Method::Insert).finalize(),
            &[0x01]
        );
        assert_eq!(
            ByteOrderBuilder::new().append(&Method::Modify).finalize(),
            &[0x02]
        );
        assert_eq!(
            ByteOrderBuilder::new().append(&Method::Remove).finalize(),
            &[0x04]
        );
    }
}

#[cfg(test)]
mod tests_transaction_identifier {
    use super::*;

    const SIGN_JSON: &'static str = "\"f980f643a1af9602564fb1da2fd296bc48e546d0958124c2a466756eb35bcf9e145a0b8eea383672d54ea9f10b67011cbb1df7896dd796de1ff326fbc39edd08\"";

    #[test]
    fn serialize() {
        let block_height = 42;
        let sign = serde_json::from_str(SIGN_JSON).unwrap();
        let id = TransactionIdentifier::new(block_height, sign);

        let serialized = serde_json::to_string(&id).unwrap();
        let json = format!(r#"{{"height":{},"sign":{}}}"#, block_height, SIGN_JSON);

        assert_eq!(serialized, json);
    }

    #[test]
    fn deserialize() {
        let block_height = 42;
        let sign = serde_json::from_str(SIGN_JSON).unwrap();
        let json = format!(r#"{{"height":{},"sign":{}}}"#, block_height, SIGN_JSON);

        let deserialized = serde_json::from_str::<TransactionIdentifier>(&json).unwrap();

        assert_eq!(deserialized.height, block_height);
        assert_eq!(deserialized.sign, sign);
    }
}
