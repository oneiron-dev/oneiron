//! The run-time kind lookups for PROJECT and its revision companion: the pack
//! and short-id prefixes they are registered under, read from the store's
//! in-memory structural kind registrations. `workspace_roster::project`
//! re-exports each item at its old path.

/// The short-id prefix PROJECT is registered under at run time.
pub const PROJECT_SHORT_ID_PREFIX: &str = "pj";
/// The pack PROJECT is registered under at run time.
pub const PROJECT_PACK: &str = "oneiron.project";
pub const PACK: &str = PROJECT_PACK;

/// The short-id prefix the revision kind is registered under at run time,
/// beside PROJECT in PROJECT's pack.
pub const PROJECT_REVISION_SHORT_ID_PREFIX: &str = "pv";

