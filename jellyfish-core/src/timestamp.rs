use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ByteOrder;

/// Duration from Unix Epoch (1970-01-01 00:00:00 UTC) in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Returns current timestamp.
    pub fn now() -> Self {
        // SystemTime::now() is never smaller than UNIX_EPOCH.
        // So unwrapping duration always succeeds.
        let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let nanos = duration.as_nanos() as i64;
        Self(nanos)
    }

    /// Returns unix timestamp in nanoseconds.
    pub fn nanos(&self) -> i64 {
        self.0
    }
}

impl ByteOrder for Timestamp {
    fn append_bytes(&self, buf: &mut Vec<u8>) {
        buf.extend(self.0.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byteorder::ByteOrderBuilder;

    #[test]
    fn byte_order() {
        let timestamp = Timestamp(3 + 256 * 2 + 65536 * 1);
        let byte_order = ByteOrderBuilder::new().append(&timestamp).finalize();

        // Byte order must be alligned with little endian
        assert_eq!(byte_order, &[3, 2, 1, 0, 0, 0, 0, 0]);
    }
}
