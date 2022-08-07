use crate::{ByteOrder, ByteOrderBuilder};
use crate::{Timestamp, Transaction};

pub struct Header {
    height: u64,
    timestamp: Timestamp,
    previous_digest: (),
    difficulty: u64,
    markle_root: (),
    nonce: u64,
    digest: (),
}

#[derive(Debug)]
pub struct Block<T, V> {
    transactions: Vec<Transaction<T, V>>,
}
