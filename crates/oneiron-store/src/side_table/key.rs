//! Key types: what a table's key contributes after its declared prefix.

use oneiron_contracts::entity_id::EntityId;

// `#[derive(SideKey)]`, documented on the trait below.
pub use oneiron_side_key_derive::SideKey;

/// The bytes a key spells after its table's prefix. A decode reads exactly those bytes, so a
/// row of another shape under the same prefix is refused rather than sliced at a fixed offset.
///
/// # Deriving
///
/// `#[derive(SideKey)]` declares a key's parts once: a struct's fields, in order, are its parts,
/// and `encode_into` and `decode_key` both follow from that declaration. A key may start with
/// `#[side_key(prefix = b"..")]` and join its parts with one byte, `#[side_key(sep = b':')]`.
/// A decode finds where each part ends by one rule:
/// - a part is fixed width by default: its type is a [`FixedSideKey`];
/// - `#[side_key(len = u16)]` (or `len = u64`) writes the part's byte count, big-endian, before it
///   ([`LengthPrefix`]);
/// - `#[side_key(rest)]` marks the one part, anywhere in the key, that takes the bytes the other
///   parts leave. The parts after it are read from the end of the key, so they are fixed width.
///
/// `#[side_key(with = P)]` spells a field through the part type `P`, a [`FieldSpelling`] of the
/// field's type, so the field keeps its own type: [`HexU64`] for a `u64`, [`HexId`] for an
/// [`EntityId`]. A decode refuses any byte the declaration does not account for, and a key whose
/// parts are all fixed width is itself a [`FixedSideKey`], so it can lead another key.
///
/// ```
/// use oneiron_store::side_table::key::{HexU64, SideKey};
///
/// // `{window}:{seq:016x}`: the window may hold `:`, so it is the rest part, and the
/// // fixed-width sequence number is read from the end.
/// #[derive(SideKey, Debug, PartialEq)]
/// #[side_key(sep = b':')]
/// struct UpdateKey {
///     #[side_key(rest)]
///     window: String,
///     #[side_key(with = HexU64)]
///     seq: u64,
/// }
///
/// let key = UpdateKey { window: "w:1".to_owned(), seq: 7 };
/// let mut bytes = Vec::new();
/// key.encode_into(&mut bytes);
/// assert_eq!(bytes, b"w:1:0000000000000007");
/// assert_eq!(UpdateKey::decode_key(&bytes), Some(key));
/// assert_eq!(UpdateKey::decode_key(b"w:1:000000000000000A"), None);
/// ```
///
/// ```
/// use oneiron_store::side_table::key::{FixedSideKey, SideKey};
///
/// #[derive(SideKey)]
/// #[side_key(prefix = b"r:")]
/// struct ReservationKey {
///     #[side_key(len = u16)]
///     budget: String,
///     attempt: [u8; 4],
/// }
///
/// #[derive(SideKey)]
/// struct PairKey([u8; 2], u64);
///
/// let mut bytes = Vec::new();
/// ReservationKey { budget: "b".to_owned(), attempt: [9; 4] }.encode_into(&mut bytes);
/// assert_eq!(bytes, b"r:\x00\x01b\x09\x09\x09\x09");
/// assert_eq!(PairKey::WIDTH, 10);
/// ```
///
/// A key has at most one rest part; another variable part takes a length prefix:
///
/// ```compile_fail
/// use oneiron_store::side_table::key::SideKey;
///
/// #[derive(SideKey)]
/// #[side_key(sep = b'\0')]
/// struct TwoRestParts {
///     #[side_key(rest)]
///     voice: String,
///     #[side_key(rest)]
///     target: String,
/// }
/// ```
///
/// ```
/// use oneiron_store::side_table::key::SideKey;
///
/// #[derive(SideKey)]
/// #[side_key(sep = b'\0')]
/// struct OneRestPart {
///     #[side_key(len = u16)]
///     voice: String,
///     #[side_key(rest)]
///     target: String,
/// }
/// ```
///
/// The separator is one byte:
///
/// ```compile_fail
/// use oneiron_store::side_table::key::SideKey;
///
/// #[derive(SideKey)]
/// #[side_key(sep = b"::")]
/// struct TwoByteSeparator([u8; 2], [u8; 2]);
/// ```
///
/// ```
/// use oneiron_store::side_table::key::SideKey;
///
/// #[derive(SideKey)]
/// #[side_key(sep = b':')]
/// struct OneByteSeparator([u8; 2], [u8; 2]);
/// ```
///
/// A part with neither `len` nor `rest` is fixed width:
///
/// ```compile_fail
/// use oneiron_store::side_table::key::SideKey;
///
/// #[derive(SideKey)]
/// struct UnmarkedVariablePart(String, [u8; 2]);
/// ```
pub trait SideKey: Sized {
    fn encode_into(&self, out: &mut Vec<u8>);
    fn decode_key(bytes: &[u8]) -> Option<Self>;
}

/// A key part of fixed width, so it can lead a composite key.
pub trait FixedSideKey: SideKey {
    const WIDTH: usize;
}

/// A part type that spells a field of another type (`#[side_key(with = ..)]`), so the field keeps
/// its own type.
pub trait FieldSpelling<F>: SideKey {
    fn encode_field(field: &F, out: &mut Vec<u8>);
    fn into_field(self) -> F;
}

/// The count before a length-prefixed part (`#[side_key(len = u16)]` or `len = u64`): the part's
/// byte count, big-endian.
pub trait LengthPrefix {
    /// The count's own width in bytes.
    const WIDTH: usize;

    /// Writes `len` into `slot`, which is [`Self::WIDTH`] bytes. A count past this type's range
    /// writes its largest value: such a part is far past LMDB's 511-byte key limit, so the store
    /// refuses the key either way.
    fn write_count(len: usize, slot: &mut [u8]);

    /// Reads the count from `slot`, which is [`Self::WIDTH`] bytes.
    fn read_count(slot: &[u8]) -> Option<usize>;

    /// Appends the count of the bytes `encode_part` appends, then those bytes.
    fn encode_prefixed(out: &mut Vec<u8>, encode_part: impl FnOnce(&mut Vec<u8>)) {
        let count_at = out.len();
        out.resize(count_at + Self::WIDTH, 0);
        encode_part(out);
        let len = out.len() - count_at - Self::WIDTH;
        Self::write_count(len, &mut out[count_at..count_at + Self::WIDTH]);
    }

    /// Splits a length-prefixed part off the front of `bytes`: the part's own bytes, then the
    /// bytes after it.
    fn split_prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
        let (count, rest) = bytes.split_at_checked(Self::WIDTH)?;
        rest.split_at_checked(Self::read_count(count)?)
    }
}

impl LengthPrefix for u16 {
    const WIDTH: usize = 2;

    fn write_count(len: usize, slot: &mut [u8]) {
        slot.copy_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    }

    fn read_count(slot: &[u8]) -> Option<usize> {
        Some(usize::from(u16::from_be_bytes(slot.try_into().ok()?)))
    }
}

impl LengthPrefix for u64 {
    const WIDTH: usize = 8;

    fn write_count(len: usize, slot: &mut [u8]) {
        slot.copy_from_slice(&u64::try_from(len).unwrap_or(u64::MAX).to_be_bytes());
    }

    fn read_count(slot: &[u8]) -> Option<usize> {
        usize::try_from(u64::from_be_bytes(slot.try_into().ok()?)).ok()
    }
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
pub struct HexId(pub EntityId);

impl SideKey for HexId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.0.to_hex().as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        EntityId::from_lower_hex(std::str::from_utf8(bytes).ok()?)
            .ok()
            .map(HexId)
    }
}

impl FixedSideKey for HexId {
    const WIDTH: usize = 32;
}

impl FieldSpelling<EntityId> for HexId {
    fn encode_field(field: &EntityId, out: &mut Vec<u8>) {
        Self(*field).encode_into(out);
    }

    fn into_field(self) -> EntityId {
        self.0
    }
}

/// `N` bytes spelled as `2 * N` lower-case hex characters. A decode refuses upper case and any
/// other length (HEX-CASE-POLICY = A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexLower<const N: usize>(pub [u8; N]);

impl<const N: usize> SideKey for HexLower<N> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        Self::encode_field(&self.0, out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        oneiron_hex::decode::<N>(std::str::from_utf8(bytes).ok()?).map(Self)
    }
}

impl<const N: usize> FixedSideKey for HexLower<N> {
    const WIDTH: usize = 2 * N;
}

impl<const N: usize> FieldSpelling<[u8; N]> for HexLower<N> {
    fn encode_field(field: &[u8; N], out: &mut Vec<u8>) {
        out.extend_from_slice(oneiron_hex::encode(field).as_bytes());
    }

    fn into_field(self) -> [u8; N] {
        self.0
    }
}

/// A `u32` spelled as 8 lower-case hex characters (`{:08x}`), so keys order by number. A decode
/// refuses upper case, a sign and any other length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexU32(pub u32);

impl SideKey for HexU32 {
    fn encode_into(&self, out: &mut Vec<u8>) {
        Self::encode_field(&self.0, out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let HexLower(digits) = HexLower::<4>::decode_key(bytes)?;
        Some(Self(u32::from_be_bytes(digits)))
    }
}

impl FixedSideKey for HexU32 {
    const WIDTH: usize = 8;
}

impl FieldSpelling<u32> for HexU32 {
    fn encode_field(field: &u32, out: &mut Vec<u8>) {
        HexLower::<4>::encode_field(&field.to_be_bytes(), out);
    }

    fn into_field(self) -> u32 {
        self.0
    }
}

/// A `u64` spelled as 16 lower-case hex characters (`{:016x}`), so keys order by number. A decode
/// refuses upper case, a sign and any other length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexU64(pub u64);

impl SideKey for HexU64 {
    fn encode_into(&self, out: &mut Vec<u8>) {
        Self::encode_field(&self.0, out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let HexLower(digits) = HexLower::<8>::decode_key(bytes)?;
        Some(Self(u64::from_be_bytes(digits)))
    }
}

impl FixedSideKey for HexU64 {
    const WIDTH: usize = 16;
}

impl FieldSpelling<u64> for HexU64 {
    fn encode_field(field: &u64, out: &mut Vec<u8>) {
        HexLower::<8>::encode_field(&field.to_be_bytes(), out);
    }

    fn into_field(self) -> u64 {
        self.0
    }
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
