//! Colon-joined composite key shapes shared by several entity-document
//! side-table rows. Spells exactly the bytes the pre-typed hand-formatted
//! keys already had.

use crate::side_table::key::{HexId, SideKey};

/// Two colon-joined 32-hex entity ids: `hex32(a) ":" hex32(b)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SideKey)]
#[side_key(sep = b':')]
pub struct HexPair(pub HexId, pub HexId);
