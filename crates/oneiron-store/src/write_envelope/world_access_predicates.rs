//! World-access authority claim predicates.

/// Predicate of the OWNER-granted ALLOWED-SET rows — the outer bound on what
/// an agent may ever read.
///
/// Every ACTIVE, APPROVED, USER-STATED row folds by INTERSECTION, so writing
/// another row can only NARROW the grant, and no row at all resolves to the
/// EMPTY authority (never to [`WorldScope::All`]). Ordinary bitemporal CLAIM
/// rows: `valid_from` / `valid_to`, lifecycle, source, approval and
/// supersession all apply, and no new entity type or table is introduced.
pub const PREDICATE_WORLD_ACCESS_ALLOWED_SET: &str = "core.world_access.allowed_set";

/// Predicate of the DEFAULT-SUBSET rows — the selection a turn inherits when
/// it supplies none of its own.
///
/// The active default may be written by the agent itself, which is why the
/// resolver REJECTS a default that exceeds the owner's ALLOWED-SET rather than
/// clamping it: an agent must never reach a wider read through its own
/// default. Consumed only when the turn supplies no explicit selection.
pub const PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET: &str = "core.world_access.default_subset";
