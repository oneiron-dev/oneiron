//! Colon-joined composite key shapes shared by several NOTE side-table rows.
//! Each spells exactly the bytes the pre-typed hand-formatted keys already had.

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

/// Three colon-joined 32-hex entity ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HexTriple(pub(super) HexId, pub(super) HexId, pub(super) HexId);

impl SideKey for HexTriple {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
        out.push(b':');
        self.1.encode_into(out);
        out.push(b':');
        self.2.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (a, rest) = bytes.split_at_checked(32)?;
        let rest = rest.strip_prefix(b":")?;
        let (b, rest) = rest.split_at_checked(32)?;
        let c = rest.strip_prefix(b":")?;
        Some(Self(
            HexId::decode_key(a)?,
            HexId::decode_key(b)?,
            HexId::decode_key(c)?,
        ))
    }
}

/// Two colon-joined 32-hex entity ids then a 64-hex hash: the NOTE reverse
/// citation-pin index shape (`note.pin/source|claim|citing/...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HexHexHash(pub(super) HexId, pub(super) HexId, pub(super) String);

impl SideKey for HexHexHash {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
        out.push(b':');
        self.1.encode_into(out);
        out.push(b':');
        out.extend_from_slice(self.2.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (a, rest) = bytes.split_at_checked(32)?;
        let rest = rest.strip_prefix(b":")?;
        let (b, rest) = rest.split_at_checked(32)?;
        let hash = rest.strip_prefix(b":")?;
        if hash.len() != 64
            || !hash
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        {
            return None;
        }
        Some(Self(
            HexId::decode_key(a)?,
            HexId::decode_key(b)?,
            String::from_utf8(hash.to_vec()).ok()?,
        ))
    }
}
