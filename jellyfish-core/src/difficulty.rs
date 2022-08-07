use serde::{Deserialize, Serialize};

use crate::{byteorder::ByteOrder, Sha256Digest};

/// Difficulty to find a new block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Difficulty(u64);

impl Difficulty {
    pub const fn new(difficulty: u64) -> Self {
        Self(difficulty)
    }

    /// Returns more difficult condition by 1 step.
    pub fn raise(&self) -> Self {
        Self(self.0 + 1)
    }

    /// Returns easer condition by 1 step, but the returned value never be negative.
    pub fn ease(&self) -> Self {
        let inner = self.0.checked_sub(1).unwrap_or(0);
        Self(inner)
    }

    /// Checks whether the given digest satisfies the difficulty.
    pub fn verify_digest(&self, digest: &Sha256Digest) -> bool {
        let count = count_first_0_bits(digest.as_ref());
        count >= self.0
    }
}

impl ByteOrder for Difficulty {
    fn append_bytes(&self, buf: &mut Vec<u8>) {
        buf.extend(self.0.to_le_bytes());
    }
}

fn count_first_0_bits(bytes: &[u8]) -> u64 {
    let mut count = 0;

    for &byte in bytes {
        match count_first_0_bit(byte) {
            8 => count += 8,
            c => {
                count += c;
                break;
            }
        }
    }

    count
}

fn count_first_0_bit(x: u8) -> u64 {
    let mut count = 0;
    let mut flag = 1 << (8 - 1);
    while flag > 0 {
        if x & flag == 0 {
            count += 1;
            flag >>= 1;
        } else {
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raise() {
        assert_eq!(Difficulty(101), Difficulty(100).raise());
    }

    #[test]
    fn ease() {
        assert_eq!(Difficulty(99), Difficulty(100).ease());
        assert_eq!(Difficulty(0), Difficulty(0).ease());
    }

    #[test]
    fn byte_order() {
        let d = Difficulty(2 + 256 * 1);
        let byte_order = d.build_byte_order();

        assert_eq!(byte_order, &[2, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn verify_bytes() {
        // The beginning 8bits are zero, the following is one.
        let digest = [
            0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ];

        assert!(Difficulty(8).verify_digest(&digest));
        assert!(!Difficulty(9).verify_digest(&digest));
    }
}
