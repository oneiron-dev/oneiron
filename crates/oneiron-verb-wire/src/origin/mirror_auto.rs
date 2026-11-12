//! Moved from `crates/oneiron/src/origin/mirror_auto.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::ErrorKind;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::git_wire::ids::GitOid;
use oneiron_store::git_wire::ids::GitRefName;
use oneiron_store::git_wire::repo::GitWireRepo;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

/// What the mirror's automatic pushes last did beyond the run record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorAutomation {
    /// The newest automatic push plan, its review digest, and whether it
    /// settled.
    pub plan_id: Option<EntityId>,
    pub plan_digest: Option<String>,
    pub plan_settled: bool,
    /// A run held before any ref went out: its review or plan could not be
    /// read or stored. The next run reviews again from scratch.
    pub review_unavailable: Option<OriginMirrorHold>,
    /// The open plan's reconcile read keeps failing: it stays frozen, and
    /// past the second failure each run resends that same plan.
    pub reconcile_unavailable: Option<OriginMirrorHold>,
    /// Full-auto heads with no green evidence.
    pub pending_checks: Vec<OriginMirrorPendingCheck>,
    /// The refs the last settled plan found moved by someone else, and the
    /// refs the mirror refused twice.
    pub remote_moved: Vec<String>,
    pub refused: Vec<String>,
}

/// One hold or wait, as it was last seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorHold {
    pub cause: OriginMirrorHoldCause,
    /// The error's stable kind; never its text.
    pub error_kind: String,
    /// Seconds, on the vault clock.
    pub last_seen: u64,
    /// Runs in a row that met it.
    pub times: u32,
}

/// Why an automatic run held or waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginMirrorHoldCause {
    /// The vault's store could not be read or written.
    Storage,
    /// A stored row did not decode.
    Decode,
    /// The repository could not be read to review what would go out.
    Review,
    /// The mirror could not be read with its credential.
    RemoteRead,
}

impl OriginMirrorHoldCause {
    /// The cause of a run that failed with `error`.
    #[must_use]
    pub fn of(error: &Error) -> Self {
        match error.kind() {
            ErrorKind::Storage | ErrorKind::Io | ErrorKind::MapFull => Self::Storage,
            ErrorKind::CorruptedIndex | ErrorKind::SideTableRow => Self::Decode,
            _ => Self::Review,
        }
    }
}

/// A full-auto head held for checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorPendingCheck {
    pub ref_name: String,
    /// The published head with no green evidence.
    pub head: String,
    /// The newest green ancestor the mirror gets in its place, if any.
    pub sent: Option<String>,
}
