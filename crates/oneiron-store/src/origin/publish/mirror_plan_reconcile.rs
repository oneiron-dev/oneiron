//! Reconciling an automatic mirror push plan before any resend (FIX 6866 part
//! 2; CALLS "FIX 6866 automatic retry" and "FIX 6866 automatic unreadable
//! reconcile").
//!
//! A ref whose push did not prove its own outcome (no acknowledgement, a
//! first refusal, or a claim a crash left) is read again at the mirror with
//! the mirror's credential before anything is sent again. At its new object
//! (a deletion: absent), it settles and is never resent. At the tip the plan
//! leased on, it gets the same-plan resend only: the same ref, the same
//! object, the same lease. At neither, or when the plan read no tip to lease
//! on, it ends `remote_moved`. A resend the mirror refuses again ends
//! `refused`. Nothing is ever recomputed or widened: a new plan waits for
//! this one to settle.
//!
//! A ref the publication gate held (`secret_hold`) is read the same way
//! before its same-plan send asks the gate again; one the plan read no tip
//! for goes unleased, as it was planned.
//!
//! When the read itself fails, the plan stays frozen and the read is tried
//! again at the next opportunity; once it has failed
//! [`AUTOMATIC_RECONCILE_UNREAD_BEFORE_RESEND`] times in a row, each further
//! opportunity resends that same frozen tuple (exact refs and objects,
//! forced and with deletions, each under its frozen lease), never a broader
//! or newer plan (Engine E1, 10-21 09:5x).

use crate::git_wire::ids::GitRefName;
use crate::git_wire::mirror_push::MIRROR_PUSH_REFSPECS;
use crate::origin::publish::mirror_plan_types::MirrorObservedTip;
use crate::origin::publish::mirror_plan_types::MirrorRefOutcome;
use oneiron_base::error::Result;

/// Whether an unproven automatic push whose reconcile read keeps failing
/// resends its same frozen tuple (Engine E1; CALLS "FIX 6866 automatic
/// unreadable reconcile").
pub const AUTOMATIC_UNREADABLE_RECONCILE_RESENDS_SAME_PLAN: bool = true;

/// Reconcile reads that fail in a row before the same frozen tuple goes out
/// again: the first failure waits for the next tick or wake, the second
/// resends (Engine E1).
pub const AUTOMATIC_RECONCILE_UNREAD_BEFORE_RESEND: u32 = 2;

/// How one reconcile went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorReconcile {
    /// Nothing was unproven.
    Nothing,
    /// The read answered: each unproven ref settled or was resent.
    Read,
    /// The read failed, `unread` times in a row now, with its redacted
    /// cause; past the bound, the frozen tuple was resent.
    Unreadable { cause: String, unread: u32 },
}
