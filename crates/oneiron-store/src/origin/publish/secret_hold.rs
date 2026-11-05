//! The publication gate at both kinds of send (FIX 7608 slice 9, A1): an
//! exact request's one push and each batch of an automatic plan ask
//! `require_no_marked_live_history` (`origin::secret_publication`) after
//! their claim and before the mirror's credential leaves custody.
//!
//! A held exact request settles `refused`, typed `marked_live_secret` or
//! `secret_history_unknown`, with the hold's value-free notice: it is never
//! sent, and a new request goes once a way out is taken. A held automatic
//! ref is never sent and stays `held` in its open plan (CALLS HOLD-AUTO):
//! each later run's reconcile reads it at the mirror, and its same frozen
//! tuple asks the gate again, so a mark written since holds it too. The
//! batch's clean refs go out as before, and so do the plan's later batches.

use crate::git_wire::ids::GitOid;
use crate::git_wire::mirror_plan_push::GitPlanPushReport;
use crate::git_wire::repo::GitWireRepo;
use crate::origin::secret_publication::SecretPublicationHold;
use oneiron_base::error::Result;

/// What one batch's send did.
pub struct MirrorPlanSend {
    /// The members the gate held, never sent, and why.
    pub held: Vec<(u32, SecretPublicationHold)>,
    /// The members that went out in one child, in order.
    pub sent: Vec<u32>,
    /// That child's report; an empty one when the gate held every member
    /// and no child ran.
    pub report: Result<GitPlanPushReport>,
}

impl MirrorPlanSend {
    /// The notice of the first hold, if the gate held any member.
    pub fn hold_notice(&self) -> Option<String> {
        self.held.first().map(|(_, hold)| hold.notice())
    }
}

/// A run's failure part for the refs the gate holds, first in the run's
/// failure: the typed codes and the ways out, never a key or a mark.
pub fn held_refs_failure(names: &[String]) -> String {
    format!(
        "secret_hold: {} held (marked_live_secret or secret_history_unknown): mark it not a \
         secret, revoke it at its provider, purge it, or state the mirror private",
        names.join(",")
    )
}
