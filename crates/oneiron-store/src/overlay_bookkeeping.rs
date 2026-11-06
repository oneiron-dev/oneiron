//! Vault-meta row prefixes a session overlay stages as a write's bookkeeping
//! rather than as content it stages. The side-table declarations in `oneiron`
//! own these tables; `oneiron` checks at compile time that each prefix here
//! equals its declaration's.

/// `SCOPE_RECORD`: a record's birth-position scope stamp.
pub const SCOPE_RECORD_PREFIX: &[u8] = b"scope:record:v2:";
/// `PROVENANCE_ROW_BIRTH`: one row's immutable birth envelope.
pub const PROVENANCE_ROW_BIRTH_PREFIX: &[u8] = b"provenance:row_birth:v1:";
/// `PROVENANCE_BIRTH_BY_TRIGGER`: the born-from index over row births.
pub const PROVENANCE_BIRTH_BY_TRIGGER_PREFIX: &[u8] = b"provenance:birth_by_trigger:v1:";
