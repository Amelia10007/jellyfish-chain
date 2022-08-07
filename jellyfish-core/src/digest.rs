use sha2::{Digest as _, Sha256};

/// SHA256 digest.
pub type Sha256Digest = [u8; 32];

pub fn calculate_digest<T: AsRef<[u8]> + ?Sized>(msg: &T) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    const DIGEST_SOURCE: &'static str = "abc";
    const DIGEST_BYTES: [u8; 32] = [
        186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 176, 3, 97, 163,
        150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173,
    ];

    #[test]
    fn calculate_digest() {
        let digest = super::calculate_digest(DIGEST_SOURCE);
        assert_eq!(digest.as_ref(), DIGEST_BYTES);
    }
}
