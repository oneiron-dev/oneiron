//! OF-234 / ONE-1545: Dreamer-run inbox grouping + auto-approve exception queue.
//!
//! The inbox is an EXCEPTION QUEUE, never a review queue: gated Dreamer
//! proposals are grouped by the run that produced them (group key = the
//! run-tree ROOT id, OF-193), and only exception rows surface by default.
//! Which pending items exist at all stays gate law
//! (`PolicyApprovalCeiling{Auto,Proposed}`, gate.rs); this module only
//! projects, classifies, and resolves what already landed pending:
//!
//! * grouping is a projection over the pending-consent tray — nothing here
//!   mints grouping state;
//! * bulk verbs (accept-all / reject-all / review-each) are B2 RS6 bundle
//!   consent at run × verb-class: per-item receipts plus ONE bundle receipt
//!   carrying the run id, whose RS3 door reopens the group;
//! * gap-decay stays PER-ITEM (`Vault::let_go_pending_ask`) — a lapsing
//!   member never drops its siblings, and the group closes only when every
//!   member is resolved;
//! * cross-run same-claim-hash duplicates collapse into the EARLIEST open
//!   group; the later group shows a pointer row, and a duplicate's exception
//!   classes propagate to the owning row so the dial can never hide them;
//! * the settings dial (approve-all ↔ exceptions-only ↔ review-everything)
//!   adjusts SURFACING only. Manifest-critical rows surface under every dial
//!   position — the dial cannot waive them. Auto-redemption of non-surfaced
//!   rows awaits the ONE-1183-D2 auto_checker knob; until it lands, hidden
//!   rows stay consentable (bundle verbs, tray) and gap-decay per item, so
//!   receipts remain the always-on audit trail.

mod model;
mod projection;
mod resolve;

pub use self::model::{
    INBOX_GROUP_DOOR_PREFIX, INBOX_PENDING_SCAN_LIMIT, INBOX_REASON_CHECKER_PREFIX,
    INBOX_SUBCLUSTER_MIN_MEMBERS, InboxAmendedApproval, InboxBulkVerb, InboxBundleResolution,
    InboxCheckInException, InboxExceptionClass, InboxGroup, InboxGroupMember, InboxGroupReopen,
    InboxPointerRow, InboxQuery, InboxReviewDial, InboxSubCluster,
};

pub(crate) use self::projection::inbox_claim_hash;

#[cfg(test)]
mod tests;

// The flat inbox.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every inbox-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{model::*, projection::*, resolve::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::AttemptQueue;
#[cfg(test)]
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    PREDICATE_CONFLICT_OPEN,
};
#[cfg(test)]
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
#[cfg(test)]
use crate::edit_distance::delta::OUTCOME_APPROVED_AMENDED;
#[cfg(test)]
use crate::entity_id::{EntityId, bytes_to_hex_lower};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::store::GateDecisionRecord;
#[cfg(test)]
use crate::temporal::TimeRange;
