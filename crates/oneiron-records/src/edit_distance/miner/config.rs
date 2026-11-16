//! Moved from `crates/oneiron/src/edit_distance/miner/config.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

// ---------------------------------------------------------------------------
// Pinned strings
// ---------------------------------------------------------------------------

/// The predicate a mined LEXICAL substitution claims.
///
/// `preference.*` is an existing public claim family (`serialize.rs` already
/// treats it as manifest-critical), so a mined phrasing preference is readable
/// by the same prompt-assembly path that reads a stated one — which is the
/// whole point of §4's "the edits stop happening". Defined in the owning module
/// rather than `claim.rs` for the `identity_topology::PREDICATE_ENTITY_DISTINCT_FROM`
/// reason: `CLAIM_PREDICATE_REGISTRY` is a documented well-known list whose
/// arity is coordinated across lanes, and a predicate does not need to join it
/// to be written through the public gate.
pub const PREDICATE_PREFERENCE_PHRASING: &str = "preference.phrasing";

/// Only accepted schema version for any row this module stores.
pub const ROW_VERSION: u8 = 1;
