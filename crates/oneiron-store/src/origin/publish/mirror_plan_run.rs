//! One automatic run over a mirror's plans (FIX 6866 part 2): the mirror's
//! open plan settles first, and only a mirror with none freezes a new one.
//!
//! The caller holds the mirror's push hold for the whole run, so a plan
//! left claimed by a crash has no child alive when the run reads it. An open
//! plan's run releases those stale claims, reconciles every unproven ref
//! (`mirror_plan_reconcile`), sends the batches left (`mirror_plan_dispatch`)
//! and settles the plan once every ref needs nothing more. A new plan is
//! frozen (`mirror_plan`) and sent the same way. Every error here ends the
//! run before anything more goes out; the caller holds it and records why.

use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::origin::mirror_auto::OriginMirrorHoldCause;
use crate::origin::publish::mirror_plan::MirrorSelection;
use crate::origin::publish::mirror_plan_types::MirrorBatchClaim;
use crate::origin::publish::mirror_plan_types::MirrorRefOutcome;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The longest failure a run summary names.
const MIRROR_RUN_MAX_FAILURE_BYTES: usize = 512;

/// A failure cut to [`MIRROR_RUN_MAX_FAILURE_BYTES`] on a character
/// boundary.
pub fn bounded_failure(mut text: String) -> String {
    let mut cut = text.len().min(MIRROR_RUN_MAX_FAILURE_BYTES);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text
}
