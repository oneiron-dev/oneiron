//! Full-auto mirrors, and what every automatic push run shows on its mirror
//! (FIX 6866 part 2).
//!
//! A `full_auto` mirror pushes as soon as the vault's published refs move
//! (CALLS "FIX 6866 full-auto trigger"), with no delay floor, and only heads
//! the merge queue proved green (CALLS "FIX 6866 full-auto green"): a head
//! goes out only with this repository's exact `GreenAdvanced` evidence for
//! that commit (`merge_queue::mirror_green`). Each run pushes every ref's
//! newest green head (CALLS "FIX 6866 full-auto newest green per ref"): a
//! ref whose tip is green goes at its tip; a ref whose tip is not goes at
//! its newest green ancestor, which carries every superseded green head in
//! its reviewed ancestry; a ref with none, or whose tip is not a commit,
//! waits `pending_checks` on the mirror's status, or goes out by an exact
//! request. Deletions need no green head. A ref the mirror already holds,
//! or holds a descendant of, is never rewound. There is no durable queue of
//! transitions: the vault-owned wake (`mirror_wake`) starts a run at once,
//! and each lifecycle tick repairs a missed wake.
//!
//! Every automatic run, `schedule` and `full_auto`, writes its holds and
//! waits on the mirror row ([`OriginMirrorAutomation`]): a run whose review
//! or plan could not be read or stored stops before any ref goes out and
//! shows `review_unavailable` with its typed cause and when it was last
//! seen (Engine 10-21 07:5x); an open plan whose reconcile read keeps
//! failing shows `reconcile_unavailable`. A status that cannot be written
//! warns, and never fails the run or anything local.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::repo::GitWireRepo;
use crate::origin::publish::mirror_plan::MirrorSelection;
use oneiron_base::error::Error;
use oneiron_base::error::ErrorKind;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The least a full-auto mirror waits after a published-ref move or a green
/// landing before its run starts, in seconds: none (CALLS "FIX 6866
/// full-auto trigger"). Only wakes that come together coalesce.
pub const ORIGIN_MIRROR_FULL_AUTO_MIN_DELAY_SECS: u64 = 0;

/// Whether a full-auto mirror pushes a head only with exact merge-queue
/// green evidence for it (CALLS "FIX 6866 full-auto green").
pub const FULL_AUTO_REQUIRES_GREEN: bool = true;

/// Whether a full-auto run pushes each ref's newest green head, a green
/// head superseded before the run riding in the newer one's ancestry (CALLS
/// "FIX 6866 full-auto newest green per ref").
pub const FULL_AUTO_PUSHES_NEWEST_GREEN_PER_REF: bool = true;

/// The WARN code of an automatic run held before egress.
pub const ORIGIN_MIRROR_REVIEW_UNAVAILABLE: &str = "review_unavailable";

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
