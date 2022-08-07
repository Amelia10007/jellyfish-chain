use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;

use itertools::Itertools;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use serde::{Deserialize, Serialize};

use crate::digest::calculate_digest;
use crate::transaction::TransactionError;
use crate::{ByteOrder, Difficulty, Sha256Digest, Verified, Yet};
use crate::{Timestamp, Transaction};

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
    /// Proof-of-Work process must be executed manually by using [`modify_nonce()`] and [`digest()`].
    pub fn create<T, VT>(
        height: u64,
        timestamp: Timestamp,
        previous_digest: Sha256Digest,
        difficulty: Difficulty,
        transactions: &[Transaction<T, VT>],
        nonce: u64,
    ) -> Option<Self>
    where
        T: ByteOrder,
    {
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
/// - `VT` Verification process marker of transactions.
/// - `VB` Verification process marker of block integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block<T, VT, VB> {
    header: Header,
    transactions: Vec<Transaction<T, VT>>,
    _phantom: PhantomData<fn() -> VB>,
}

impl<T, VT, VB> Block<T, VT, VB> {
    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn transactions(&self) -> &[Transaction<T, VT>] {
        &self.transactions
    }
}

impl<T, VT> Block<T, VT, Yet> {
    /// Create new block without executing Proof-of-Work.
    /// # Returns
    /// `Err(err)` if empty transaction is given, otherwise, `Ok(block)`.
    ///
    /// # Caution:
    /// Nonce after [`create()`] is not valid value for meeting with Proof-of-Work condition.
    /// Proof-of-Work process must be executed manually by using [`header_mut()`] and modifying nonce.
    pub fn create(
        height: u64,
        timestamp: Timestamp,
        previous_digest: Sha256Digest,
        difficulty: Difficulty,
        transactions: Vec<Transaction<T, VT>>,
    ) -> Result<Block<T, VT, Yet>, BlockError>
    where
        T: ByteOrder,
    {
        let nonce = 0;
        let header = Header::create(
            height,
            timestamp,
            previous_digest,
            difficulty,
            &transactions,
            nonce,
        )
        .ok_or(BlockError::Empty)?;
        let block = Block {
            header,
            transactions,
            _phantom: PhantomData,
        };
        Ok(block)
    }

    /// Returns mutable reference to the header.
    ///
    /// This method is designed to execute Proof-of-Work process via [`Header::modify_nonce()`].
    pub fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }
}

impl<T, VB> Block<T, Yet, VB>
where
    T: ByteOrder,
{
    /// Verify all sign of transactions in the block.
    pub fn verify_transactions(self) -> Result<Block<T, Verified, VB>, BlockError> {
        let result = self
            .transactions
            .into_iter()
            .map(Transaction::verify)
            .collect::<Result<Vec<_>, TransactionError>>();
        match result {
            Ok(transactions) => {
                let block = Block {
                    header: self.header,
                    transactions,
                    _phantom: PhantomData,
                };
                Ok(block)
            }
            Err(e) => Err(BlockError::Transaction(e)),
        }
    }
}

impl<T, VT> Block<T, VT, Yet> {
    /// Verify integrity of the block.
    /// # Parameters
    /// - `previous_digest_judge` Given a header of verification-target block, returns `true` if the previous digest is meet with blockchain.
    /// # Returns
    /// `Ok(block)` if verification succeeded, otherwise, `Err(err)`.
    ///
    /// # Caution
    /// No verification is checked for transactions' contents (['Transaction::content()']).
    /// Contents' integrity must be checked manually based on each protocol.
    pub fn verify_block<F>(
        self,
        previous_digest_judge: F,
    ) -> Result<Block<T, VT, Verified>, BlockError>
    where
        F: FnOnce(&Header) -> bool,
    {
        let merkle_root = match build_merkle_tree(&self.transactions).root() {
            Some(root) => root,
            None => return Err(BlockError::Empty),
        };

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
fn build_merkle_tree<T, VT>(transactions: &[Transaction<T, VT>]) -> MerkleTree<Sha256> {
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
        let transactions: Vec<Transaction<Stab, Verified>> = vec![];
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
            let tx = Transaction::create(&secret_account, timestamp, content);
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
}

#[cfg(test)]
mod tests_block {
    use crate::SecretAccount;

    use super::tests_stab::*;
    use super::*;

    fn stab_transactions() -> Vec<Transaction<Stab, Verified>> {
        let secret_account = SecretAccount::create(&mut rand_core::OsRng {});
        let timestamp = Timestamp::now();
        let content = Stab("hello");
        let tx = Transaction::create(&secret_account, timestamp, content);
        vec![tx]
    }

    #[test]
    fn create_empty_transaction() {
        let height = 42;
        let timestamp = Timestamp::now();
        let previous_digest = [0; 32];
        let difficulty = Difficulty::new(1);
        let transactions: Vec<Transaction<Stab, Verified>> = vec![];

        let result = Block::create(height, timestamp, previous_digest, difficulty, transactions);

        assert!(matches!(result, Err(BlockError::Empty)));
    }

    #[test]
    fn verify_block_fail_empty_transaction() {
        let height = 42;
        let timestamp = Timestamp::now();
        let previous_digest = [0; 32];
        let difficulty = Difficulty::new(1);
        let transactions = {
            let secret_account = SecretAccount::create(&mut rand_core::OsRng {});
            let content = Stab("hello");
            let tx = Transaction::create(&secret_account, timestamp, content);
            vec![tx]
        };

        let mut block =
            Block::create(height, timestamp, previous_digest, difficulty, transactions).unwrap();

        // Cheat transactions
        block.transactions.clear();

        let result = block.verify_block(|_header| true);
        assert!(matches!(result, Err(BlockError::Empty)));
    }

    #[test]
    fn verify_block() {
        let height = 42;
        let timestamp = Timestamp::now();
        let previous_digest = [0; 32];
        let difficulty = Difficulty::new(1);
        let transactions = stab_transactions();

        let mut block = Block::create(
            height,
            timestamp,
            previous_digest.clone(),
            difficulty,
            transactions.clone(),
        )
        .unwrap();

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
        let header = block.header();

        assert_eq!(header.height(), height);
        assert_eq!(header.timestamp(), timestamp);
        assert_eq!(header.previous_digest(), &previous_digest);
        assert_eq!(header.difficulty(), difficulty);
        assert_eq!(block.transactions(), transactions);

        // Proof-of-Work check
        assert!(header.difficulty().verify_digest(header.digest()));
    }

    #[test]
    fn verify_block_fail_merkle_root() {
        let height = 42;
        let timestamp = Timestamp::now();
        let previous_digest = [0; 32];
        let difficulty = Difficulty::new(1);
        let transactions = stab_transactions();

        let mut block =
            Block::create(height, timestamp, previous_digest, difficulty, transactions).unwrap();
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
        block.transactions.clear();

        let result = block.verify_block(|_header| true);
        assert!(result.is_err());
    }

    #[test]
    fn verify_block_fail_difficulty() {
        let height = 42;
        let timestamp = Timestamp::now();
        let previous_digest = [0; 32];
        let difficulty = Difficulty::new(1);
        let transactions = stab_transactions();

        let mut block = Block::create(
            height,
            timestamp,
            previous_digest.clone(),
            difficulty,
            transactions.clone(),
        )
        .unwrap();

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
        let height = 42;
        let timestamp = Timestamp::now();
        let previous_digest = [0; 32];
        let difficulty = Difficulty::new(1);
        let transactions = stab_transactions();

        let mut block = Block::create(
            height,
            timestamp,
            previous_digest.clone(),
            difficulty,
            transactions.clone(),
        )
        .unwrap();

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
        let height = 42;
        let timestamp = Timestamp::now();
        let previous_digest = [0; 32];
        let difficulty = Difficulty::new(1);
        let transactions = stab_transactions();

        let mut block = Block::create(
            height,
            timestamp,
            previous_digest.clone(),
            difficulty,
            transactions.clone(),
        )
        .unwrap();

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
        let tx = Transaction::create(&secret_account, timestamp, content);

        let expected_merkle_root = calculate_digest(tx.sign());

        let tree = super::build_merkle_tree(&vec![tx]);
        let merkle_root = tree.root().unwrap();

        assert_eq!(merkle_root, expected_merkle_root);
    }

    #[test]
    fn build_merkle_tree_empty() {
        let tree = super::build_merkle_tree::<Stab, Verified>(&[]);
        assert!(tree.root().is_none());
    }
}
