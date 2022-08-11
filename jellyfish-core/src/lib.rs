pub mod account;
pub mod block;
pub mod difficulty;
pub mod digest;
pub mod jellyfish_transaction;
pub mod signature;
pub mod timestamp;
pub mod transaction;

mod byteorder;
mod verification;

pub use account::{Account, SecretAccount};
use block::Block;
pub use difficulty::Difficulty;
pub use digest::Sha256Digest;
pub use signature::Signature;
pub use timestamp::Timestamp;
use transaction::Transaction;
pub use verification::{Verified, Yet};

use byteorder::{ByteOrder, ByteOrderBuilder};
use jellyfish_transaction::JellyfishTransactionContent;

pub type JellyfishTransaction<VT> = Transaction<JellyfishTransactionContent, VT>;
pub type JellyfishBlock<VB> = Block<JellyfishTransactionContent, VB>;
