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

/// Constant value collection of jellyfish protocol.
pub mod constant {
    use crate::Difficulty;

    /// Minimum difficulty of finding a new block.
    pub const MIN_DIFFICULTY: Difficulty = Difficulty::new(10);
}

pub use account::{Account, SecretAccount};
pub use difficulty::Difficulty;
pub use digest::Digest;
pub use signature::Signature;
pub use timestamp::Timestamp;
pub use transaction::Transaction;
pub use verification::{Verified, Yet};

use byteorder::{ByteOrder, ByteOrderBuilder};
