use std::borrow::Cow;

use crate::{byteorder::ByteOrder, Signature};
use serde::{Deserialize, Serialize};

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
    pub block_height: u64,
    /// Target transaction's sign.
    pub sign: Signature,
}

impl ByteOrder for TransactionIdentifier {
    fn append_bytes(&self, buf: &mut Vec<u8>) {
        buf.extend(self.block_height.to_le_bytes());
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
