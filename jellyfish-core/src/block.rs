use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;

use itertools::Itertools;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use serde::{Deserialize, Serialize};

use crate::digest::calculate_digest;
use crate::transaction::{TransactionError, VerifiedTransaction};
use crate::Timestamp;
use crate::{ByteOrder, Difficulty, Sha256Digest, Verified, Yet};

/// Block header. This contains all data of a block, except for transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Block height.
    height: u64,
    /// When the block created.
    timestamp: Timestamp,
    /// Digest of the previous block.
    /// This is used to verify block relationship.
    #[serde(with = "hex")]
    previous_digest: Sha256Digest,
    /// How difficult to find the block based on Proof-of-Work.
    difficulty: Difficulty,
    /// Merkle root of the transactions of the block.
    #[serde(with = "hex")]
    merkle_root: Sha256Digest,
    /// Nonce, which is required to meet with Proof-of-Work condition.
    nonce: u64,
    /// Digest of the header.
    #[serde(with = "hex")]
    digest: Sha256Digest,
}

impl Header {
    /// Create a new block header.
    /// Merkle root is internally calculated by using the givin transactions.
    ///
    /// # Returns
    /// `None` if empty transaction is given, otherwise, `Some(header)`.
    ///
    /// # Caution:
    /// Nonce after [`create()`] is not valid value for meeting with Proof-of-Work condition.
    /// Proof-of-Work must be executed manually by using [`modify_nonce()`] and [`digest()`].
    pub fn create<T>(
        height: u64,
        timestamp: Timestamp,
        previous_digest: Sha256Digest,
        difficulty: Difficulty,
        transactions: &[VerifiedTransaction<T>],
        nonce: u64,
    ) -> Option<Self> {
        let merkle_root = build_merkle_tree(transactions).root()?;

        let mut header = Self {
            height,
            timestamp,
            previous_digest,
            difficulty,
            merkle_root,
            nonce,
            digest: calculate_digest(""), // Temporal value to instantiate
        };

        header.modify_nonce(nonce); // Set nonce and calculate digest

        Some(header)
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn previous_digest(&self) -> &Sha256Digest {
        &self.previous_digest
    }

    pub fn difficulty(&self) -> Difficulty {
        self.difficulty
    }

    pub fn merkle_root(&self) -> &Sha256Digest {
        &self.merkle_root
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// Sets the given nonce, then re-calculates header's digest.
    pub fn modify_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
        // Re-calculate digest
        self.set_digest();
    }

    fn set_digest(&mut self) {
        let byte_order = self.build_byte_order();
        self.digest = calculate_digest(&byte_order);
    }
}

impl ByteOrder for Header {
    fn append_bytes(&self, buf: &mut Vec<u8>) {
        buf.extend(self.height.to_be_bytes());
        self.timestamp.append_bytes(buf);
        buf.extend(&self.previous_digest);
        self.difficulty.append_bytes(buf);
        buf.extend(&self.merkle_root);
        buf.extend(self.nonce.to_le_bytes());
    }
}

/// Block.
/// # Generic type parameters
/// - `T` Transaction content.
/// - `V` Verification process marker of block integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block<T, V> {
    header: Header,
    transactions: Vec<VerifiedTransaction<T>>,
    _phantom: PhantomData<fn() -> V>,
}

impl<T, V> Block<T, V> {
    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn transactions(&self) -> &[VerifiedTransaction<T>] {
        &self.transactions
    }
}

impl<T> Block<T, Yet> {
    /// Create new block without executing Proof-of-Work.
    ///
    /// # Caution:
    /// After creating a block, proof-of-Work must be executed manually by using [`header_mut()`] and modifying nonce.
    pub fn create(header: Header, transactions: Vec<VerifiedTransaction<T>>) -> Block<T, Yet> {
        Block {
            header,
            transactions,
            _phantom: PhantomData,
        }
    }

    /// Returns mutable reference to the header.
    ///
    /// This method is designed to execute Proof-of-Work via [`Header::modify_nonce()`].
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

impl<T> Block<T, Yet> {
    /// Verify integrity of the block.
    /// # Parameters
    /// - `previous_digest_judge` Given a header of verification-target block, returns `true` if the previous digest is meet with blockchain.
    /// # Returns
    /// `Ok(block)` if verification succeeded, otherwise, `Err(err)`.
    ///
    /// # Caution
    /// No verification is checked for transactions' contents (['Transaction::content()']).
    /// Contents' integrity must be checked manually based on each protocol.
    pub fn verify_block<F>(self, previous_digest_judge: F) -> Result<Block<T, Verified>, BlockError>
    where
        F: FnOnce(&Header) -> bool,
    {
        // Build merkle root of transactions
        let merkle_root = match build_merkle_tree(&self.transactions).root() {
            Some(root) => root,
            None => return Err(BlockError::Empty),
        };

        // Merkle root matching
        if &merkle_root != self.header.merkle_root() {
            return Err(BlockError::Merkle);
        }

        if !self.header.difficulty().verify_digest(self.header.digest()) {
            return Err(BlockError::Difficulty);
        }

        if self.header.digest() != &calculate_digest(&self.header().build_byte_order()) {
            return Err(BlockError::Digest);
        }

        if !previous_digest_judge(&self.header) {
            return Err(BlockError::PreviousDigest);
        }

        let block = Block {
            header: self.header,
            transactions: self.transactions,
            _phantom: PhantomData,
        };

        Ok(block)
    }
}

/// An error occurred during creating or verifying a block.
#[derive(Debug)]
pub enum BlockError {
    /// Transaction verification failed.
    Transaction(TransactionError),
    /// No transaction in block.
    Empty,
    /// Header's digest does not match.
    Digest,
    /// Previous digest does not match.
    PreviousDigest,
    /// Header's markle root does not match with that from block's transactions.
    Merkle,
    /// Block digest does not satisfy difficulty.
    Difficulty,
}

impl Display for BlockError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use BlockError::*;

        match self {
            Transaction(e) => write!(f, "Transaction verification failed: {}", e),
            Empty => write!(f, "No transaction in block."),
            Digest => write!(f, "Header's digest does not match."),
            PreviousDigest => write!(f, "Previous digest does not match."),
            Merkle => write!(
                f,
                "Header's markle root does not match with that from block's transactions."
            ),
            Difficulty => write!(f, "Block digest does not satisfy difficulty."),
        }
    }
}

impl std::error::Error for BlockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use BlockError::*;

        match self {
            Transaction(e) => Some(e),
            Empty | Digest | PreviousDigest | Merkle | Difficulty => None,
        }
    }
}

/// Build merkle tree from given transactions.
fn build_merkle_tree<T>(transactions: &[VerifiedTransaction<T>]) -> MerkleTree<Sha256> {
    let digests = transactions
        .iter()
        .map(|tx| tx.sign().as_ref())
        .map(calculate_digest)
        // Digest is always 32bytes, so the below unwrap() always succeeds.
        .map(|digest| digest.as_ref().try_into().unwrap())
        .collect_vec();

    MerkleTree::from_leaves(&digests)
}

#[cfg(test)]
mod tests_stab {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Stab(pub &'static str);

    impl crate::byteorder::ByteOrder for Stab {
        fn append_bytes(&self, buf: &mut Vec<u8>) {
            buf.extend(self.0.as_bytes())
        }
    }
}

#[cfg(test)]
mod tests_header {
    use crate::SecretAccount;

    use super::tests_stab::*;
    use super::*;

    #[test]
    fn create_empty_transaction() {
        let height = 42;
        let timestamp = Timestamp::now();
        let previous_digest = [0; 32];
        let difficulty = Difficulty::new(1);
        let transactions: Vec<VerifiedTransaction<Stab>> = vec![];
        let nonce = 0;

        let option = Header::create(
            height,
            timestamp,
            previous_digest,
            difficulty,
            &transactions,
            nonce,
        );

        assert!(option.is_none());
    }

    #[test]
    fn modify_nonce() {
        let height = 42;
        let timestamp = Timestamp::now();
        let previous_digest = [0; 32];
        let difficulty = Difficulty::new(1);
        let transactions = {
            let secret_account = SecretAccount::create(&mut rand_core::OsRng {});
            let content = Stab("hello");
            let tx = VerifiedTransaction::create(&secret_account, timestamp, content);
            vec![tx]
        };
        let nonce = 0;

        let mut header = Header::create(
            height,
            timestamp,
            previous_digest,
            difficulty,
            &transactions,
            nonce,
        )
        .unwrap();

        let digest1 = header.digest().clone();

        // Modify nonce, then digest is re-calculated.
        // Thus, digest should change.
        header.modify_nonce(header.nonce() + 1);
        let digest2 = header.digest();

        assert_ne!(&digest1, digest2);
    }

    #[test]
    fn byte_order() {
        // Create header
        let height = 42;
        let timestamp = Timestamp::now();
        let previous_digest = [0; 32];
        let difficulty = Difficulty::new(1);
        let transactions = {
            let secret_account = SecretAccount::create(&mut rand_core::OsRng {});
            let content = Stab("hello");
            let tx = VerifiedTransaction::create(&secret_account, timestamp, content);
            vec![tx]
        };
        let nonce = 0;

        let header = Header::create(
            height,
            timestamp,
            previous_digest,
            difficulty,
            &transactions,
            nonce,
        )
        .unwrap();

        let digest_org = header.build_byte_order();
        // Digest is not affected by header's digest
        {
            let mut h = header.clone();
            h.digest = calculate_digest("cheat header digest");
            assert_eq!(digest_org, h.build_byte_order());
        }
        // Digest is affected by header's content, except for its digest
        {
            let mut h = header.clone();
            h.height = header.height + 1;
            assert_ne!(digest_org, h.build_byte_order());
        }
        {
            let mut h = header.clone();
            h.timestamp = Timestamp::now();
            assert_ne!(digest_org, h.build_byte_order());
        }
        {
            let mut h = header.clone();
            h.previous_digest = [1; 32];
            assert_ne!(digest_org, h.build_byte_order());
        }
        {
            let mut h = header.clone();
            h.difficulty = Difficulty::new(42);
            assert_ne!(digest_org, h.build_byte_order());
        }
        {
            let mut h = header.clone();
            h.merkle_root = [2; 32];
            assert_ne!(digest_org, h.build_byte_order());
        }
        {
            let mut h = header.clone();
            h.nonce = header.nonce + 1;
            assert_ne!(digest_org, h.build_byte_order());
        }
    }
}

#[cfg(test)]
mod tests_block {
    use crate::SecretAccount;

    use super::tests_stab::*;
    use super::*;

    fn stab_block() -> Block<Stab, Yet> {
        let transactions = {
            let secret_account = SecretAccount::create(&mut rand_core::OsRng {});
            let timestamp = Timestamp::now();
            let content = Stab("hello");
            let tx = VerifiedTransaction::create(&secret_account, timestamp, content);
            vec![tx]
        };
        let header = {
            let height = 42;
            let timestamp = Timestamp::now();
            let previous_digest = [0; 32];
            let difficulty = Difficulty::new(1);
            let nonce = 0;

            Header::create(
                height,
                timestamp,
                previous_digest,
                difficulty,
                &transactions,
                nonce,
            )
            .unwrap()
        };

        Block::create(header, transactions)
    }

    #[test]
    fn verify_block_fail_empty_transaction() {
        let mut block = stab_block();

        // Cheat transactions
        block.transactions.clear();

        let result = block.verify_block(|_header| true);
        assert!(matches!(result, Err(BlockError::Empty)));
    }

    #[test]
    fn verify_block() {
        let mut block = stab_block();

        // Proof-of-Work process
        // Find valid digest, with changing nonce.
        loop {
            let h = block.header();
            if h.difficulty().verify_digest(h.digest()) {
                break;
            } else {
                let nonce = h.nonce();
                block.header_mut().modify_nonce(nonce + 1);
            }
        }

        // Verification should succeed because valid digest has found.
        let block = block.verify_block(|_header| true).unwrap();

        // Proof-of-Work check
        let h = block.header();
        assert!(h.difficulty().verify_digest(h.digest()));
    }

    #[test]
    fn verify_block_fail_merkle_root() {
        let mut block = stab_block();

        // Proof-of-Work process
        // Find valid digest, with changing nonce.
        loop {
            let h = block.header();
            if h.difficulty().verify_digest(h.digest()) {
                break;
            } else {
                let nonce = h.nonce();
                block.header_mut().modify_nonce(nonce + 1);
            }
        }

        // Cheat transactions
        let tx = block.transactions()[0].clone();
        block.transactions.push(tx);

        let result = block.verify_block(|_header| true);
        assert!(result.is_err());
    }

    #[test]
    fn verify_block_fail_difficulty() {
        let mut block = stab_block();

        // Proof-of-Work process
        // Find valid digest, with changing nonce.
        loop {
            let h = block.header();
            if h.difficulty().verify_digest(h.digest()) {
                break;
            } else {
                let nonce = h.nonce();
                block.header_mut().modify_nonce(nonce + 1);
            }
        }

        // Cheat difficulty
        block.header.difficulty = Difficulty::new(u64::MAX);

        let result = block.verify_block(|_header| true);
        assert!(result.is_err());
    }

    #[test]
    fn verify_block_fail_digest() {
        let mut block = stab_block();

        // Proof-of-Work process
        // Find valid digest, with changing nonce.
        loop {
            let h = block.header();
            if h.difficulty().verify_digest(h.digest()) {
                // Cheat digest after nonce was found
                block.header.digest = [255; 32];

                break;
            } else {
                let nonce = h.nonce();
                block.header_mut().modify_nonce(nonce + 1);
            }
        }

        let result = block.verify_block(|_header| true);
        assert!(result.is_err());
    }

    #[test]
    fn verify_block_fail_previous_digest() {
        let mut block = stab_block();

        // Proof-of-Work process
        // Find valid digest, with changing nonce.
        loop {
            let h = block.header();
            if h.difficulty().verify_digest(h.digest()) {
                break;
            } else {
                let nonce = h.nonce();
                block.header_mut().modify_nonce(nonce + 1);
            }
        }

        // Give previous digest judge, which alway fails
        let result = block.verify_block(|_| false);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod tests_function {
    use crate::SecretAccount;

    use super::tests_stab::*;
    use super::*;

    #[test]
    fn build_merkle_tree() {
        let secret_account = SecretAccount::create(&mut rand_core::OsRng {});
        let timestamp = Timestamp::now();
        let content = Stab("hello");
        let tx = VerifiedTransaction::create(&secret_account, timestamp, content);

        let expected_merkle_root = calculate_digest(tx.sign());

        let tree = super::build_merkle_tree(&vec![tx]);
        let merkle_root = tree.root().unwrap();

        assert_eq!(merkle_root, expected_merkle_root);
    }

    #[test]
    fn build_merkle_tree_empty() {
        let tree = super::build_merkle_tree::<Stab>(&[]);
        assert!(tree.root().is_none());
    }
}
