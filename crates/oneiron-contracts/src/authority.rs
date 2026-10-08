//! Authority-log hash vocabulary the write path shares. The authority log itself stays in
//! `oneiron::authority`, which re-exports these.

/// BLAKE3 authority entry hash length.
pub const AUTHORITY_HASH_LEN: usize = 32;

/// Content hash of a canonical authority entry.
pub type AuthorityEntryHash = [u8; AUTHORITY_HASH_LEN];
