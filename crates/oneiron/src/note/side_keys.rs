//! Colon-joined composite key shapes shared by several NOTE side-table rows.
//! Each spells exactly the bytes the pre-typed hand-formatted keys already had.

use crate::side_table::{HexId, SideKey};
use oneiron_store::side_table::key::HexLower;

/// Two colon-joined 32-hex entity ids: `hex32(a) ":" hex32(b)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SideKey)]
#[side_key(sep = b':')]
pub(super) struct HexPair(pub(super) HexId, pub(super) HexId);

/// One [`HexPair`] for `test_doors::side_key_pins`.
#[cfg(oneiron_test_support)]
pub(crate) fn hex_pair_pin_for_test(
    a: crate::EntityId,
    b: crate::EntityId,
) -> crate::test_doors::side_key_pins::Pin {
    crate::test_doors::side_key_pins::Pin::of(&HexPair(HexId(a), HexId(b)))
}

/// Three colon-joined 32-hex entity ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SideKey)]
#[side_key(sep = b':')]
pub(super) struct HexTriple(pub(super) HexId, pub(super) HexId, pub(super) HexId);

/// One [`HexTriple`] for `test_doors::side_key_pins`.
#[cfg(oneiron_test_support)]
pub(crate) fn hex_triple_pin_for_test(
    a: crate::EntityId,
    b: crate::EntityId,
    c: crate::EntityId,
) -> crate::test_doors::side_key_pins::Pin {
    crate::test_doors::side_key_pins::Pin::of(&HexTriple(HexId(a), HexId(b), HexId(c)))
}

/// Two colon-joined 32-hex entity ids then a 64-hex hash: the NOTE reverse
/// citation-pin index shape (`note.pin/source|claim|citing/...`). The hash is a
/// BLAKE3 `to_hex()`, read back only as 64 lower-case hex characters.
#[derive(Debug, Clone, PartialEq, Eq, SideKey)]
#[side_key(sep = b':')]
pub(super) struct HexHexHash(
    pub(super) HexId,
    pub(super) HexId,
    #[side_key(with = HexLower<32>)] pub(super) String,
);

/// One [`HexHexHash`] for `test_doors::side_key_pins`.
#[cfg(oneiron_test_support)]
pub(crate) fn hex_hex_hash_pin_for_test(
    a: crate::EntityId,
    b: crate::EntityId,
    hash: &str,
) -> crate::test_doors::side_key_pins::Pin {
    crate::test_doors::side_key_pins::Pin::of(&HexHexHash(HexId(a), HexId(b), hash.to_owned()))
}
