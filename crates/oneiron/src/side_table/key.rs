//! Key types: what a table's key contributes after its declared prefix.

use crate::entity_id::EntityId;

/// The bytes a key spells after its table's prefix. A decode reads exactly those bytes, so a
/// row of another shape under the same prefix is refused rather than sliced at a fixed offset.
pub(crate) trait SideKey: Sized {
    fn encode_into(&self, out: &mut Vec<u8>);
    fn decode_key(bytes: &[u8]) -> Option<Self>;
}

/// A key part of fixed width, so it can lead a composite key.
pub(crate) trait FixedSideKey: SideKey {
    const WIDTH: usize;
}

/// The singleton row: its key is the prefix itself.
impl SideKey for () {
    fn encode_into(&self, _out: &mut Vec<u8>) {}

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        bytes.is_empty().then_some(())
    }
}

impl SideKey for EntityId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        EntityId::from_bytes(bytes.try_into().ok()?).ok()
    }
}

impl FixedSideKey for EntityId {
    const WIDTH: usize = 16;
}

impl<const N: usize> SideKey for [u8; N] {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok()
    }
}

impl<const N: usize> FixedSideKey for [u8; N] {
    const WIDTH: usize = N;
}

/// Big-endian, so keys order by number.
impl SideKey for u64 {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Some(u64::from_be_bytes(bytes.try_into().ok()?))
    }
}

impl FixedSideKey for u64 {
    const WIDTH: usize = 8;
}

/// The rest of the key, as bytes.
impl SideKey for Vec<u8> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Some(bytes.to_vec())
    }
}

/// The rest of the key, as UTF-8 text.
impl SideKey for String {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        String::from_utf8(bytes.to_vec()).ok()
    }
}

/// An id spelled as 32 lower-case hex characters, the `sync_state` spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct HexId(pub(crate) EntityId);

impl SideKey for HexId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.0.to_hex().as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        EntityId::from_hex(std::str::from_utf8(bytes).ok()?)
            .ok()
            .map(HexId)
    }
}

impl FixedSideKey for HexId {
    const WIDTH: usize = 32;
}

impl<A: FixedSideKey, B: SideKey> SideKey for (A, B) {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
        self.1.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (head, tail) = bytes.split_at_checked(A::WIDTH)?;
        Some((A::decode_key(head)?, B::decode_key(tail)?))
    }
}

impl<A: FixedSideKey, B: FixedSideKey> FixedSideKey for (A, B) {
    const WIDTH: usize = A::WIDTH + B::WIDTH;
}

impl<A: FixedSideKey, B: FixedSideKey, C: SideKey> SideKey for (A, B, C) {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
        self.1.encode_into(out);
        self.2.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (a, rest) = bytes.split_at_checked(A::WIDTH)?;
        let (b, c) = rest.split_at_checked(B::WIDTH)?;
        Some((A::decode_key(a)?, B::decode_key(b)?, C::decode_key(c)?))
    }
}
