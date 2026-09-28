//! Colon-joined composite key shapes shared by several entity-document
//! side-table rows. Spells exactly the bytes the pre-typed hand-formatted
//! keys already had.

use crate::side_table::{HexId, SideKey};

/// Two colon-joined 32-hex entity ids: `hex32(a) ":" hex32(b)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HexPair(pub(super) HexId, pub(super) HexId);

impl SideKey for HexPair {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
        out.push(b':');
        self.1.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (a, rest) = bytes.split_at_checked(32)?;
        let b = rest.strip_prefix(b":")?;
        Some(Self(HexId::decode_key(a)?, HexId::decode_key(b)?))
    }
}
