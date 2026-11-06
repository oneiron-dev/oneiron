//! Resumable outer hashing of the original bounded canonical byte buffer.

pub(super) struct EncodedDigest {
    bytes: Vec<u8>,
    hasher: blake3::Hasher,
    next: usize,
}

impl EncodedDigest {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            hasher: blake3::Hasher::new(),
            next: 0,
        }
    }

    pub(super) fn advance(&mut self, max_chunks: usize) -> bool {
        let bytes = max_chunks.max(1).saturating_mul(blake3::CHUNK_LEN);
        let end = self.next.saturating_add(bytes).min(self.bytes.len());
        self.hasher.update(&self.bytes[self.next..end]);
        self.next = end;
        self.next == self.bytes.len()
    }

    pub(super) fn into_digest(self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}
