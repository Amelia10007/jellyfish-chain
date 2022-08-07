/// Represents its implementator as a byte sequence based on jellyfish protocol.
///
/// This is used to build source of signature and digest.
pub trait ByteOrder: Sized {
    /// Based on jellyfish protocol, append byte-sequence representation of the structure.
    fn append_bytes(&self, buf: &mut Vec<u8>);

    fn build_byte_order(&self) -> Vec<u8> {
        ByteOrderBuilder::new().append(self).finalize()
    }
}

/// Builds a byte sequence for signature and digest.
/// # Examples
/// ```ignore
/// use jellyfish_core::byteorder::{ByteOrder, ByteOrderBuilder};
///
/// struct Stab(u8);
///
/// // Trait implementation for stab
/// impl ByteOrder for Stab {
///     fn append_bytes(&self, buf: &mut Vec<u8>) {
///         buf.push(self.0);
///     }
/// }
///
/// let src1 = Stab(0x01);
/// let src2 = Stab(0x02);
///
/// // Create byte sequence by using builder
/// let bytes =  ByteOrderBuilder::new()
///     .append(&src1)
///     .append(&src2)
///     .finalize();
/// assert_eq!(bytes, vec![0x01, 0x02]);
/// ```
#[derive(Debug)]
pub(crate) struct ByteOrderBuilder {
    buf: Vec<u8>,
}

impl ByteOrderBuilder {
    /// Returns a builder with empty buffer.
    pub fn new() -> Self {
        Self { buf: vec![] }
    }

    /// Append bytes into inner buffer.
    pub fn append<T: ByteOrder>(mut self, src: &T) -> Self {
        src.append_bytes(&mut self.buf);
        self
    }

    /// Returns the current byte sequence.
    pub fn finalize(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stab type
    struct Stab(u8);

    impl ByteOrder for Stab {
        fn append_bytes(&self, buf: &mut Vec<u8>) {
            buf.push(self.0);
        }
    }

    #[test]
    fn byte_order_builder() {
        let src1 = Stab(0x01);
        let src2 = Stab(0x02);

        let bytes = ByteOrderBuilder::new()
            .append(&src1)
            .append(&src2)
            .finalize();

        assert_eq!(bytes, vec![0x01, 0x02]);
    }
}
