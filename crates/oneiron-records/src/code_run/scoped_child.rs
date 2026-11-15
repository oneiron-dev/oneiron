//! Moved from `crates/oneiron/src/code_run/scoped_child.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

/// The name a reader child, read or scoped, reads its primary input by.
pub const READER_SOURCE_NAME: &str = "src";

/// The refusal a scoped child's lent verb gets when no adapter its host
/// registered serves it (`scoped_child_service_admission`): the job reports
/// it and never runs as a read child in its place.
pub const SCOPED_CHILD_SERVICE_UNBOUND: &str = "scoped_child_service_unbound";

/// The refusal every call of a scoped child gets once its parent actor no
/// longer stands (`scoped_child_authority`).
pub const SCOPED_CHILD_AUTHORITY_LAPSED: &str = "scoped_child_authority_lapsed";

/// Why a scoped child that borrowed its parent attempt's lease settles, and
/// every call of it is refused, once that lease no longer holds
/// (`scoped_parent_lease_holds`); and why a loan is refused a lease that is
/// absent or stale when it is lent.
pub const SCOPED_CHILD_PARENT_LEASE_LOST: &str = "scoped_child_parent_lease_lost";

/// One lent input as a port read it: its name, its handle, the range read,
/// the rows its parent's read of it was checked against (`None` when one
/// answer kept no set), and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedInputRead {
    pub name: String,
    pub handle: String,
    pub range: (u64, u64),
    pub rows: Option<Vec<EntityId>>,
    pub text: String,
}
