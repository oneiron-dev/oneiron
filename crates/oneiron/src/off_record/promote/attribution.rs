//! FIX 3103 (OF-540): a promotion witnesses the edges it replays for the
//! runs that journaled them, never for its promoter.

use std::collections::BTreeSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::session_overlay::{PromotePlan, replayed_subject};

/// Records, in the promotion's `wtxn`, the DerivedFrom edges among the ops
/// it just replayed from `plan` as derivations of the runs whose journal
/// entries kept them: every op, or with `fresh` only the ops of the copy's
/// fresh subjects. An op no run journaled records nothing. Capture-only: a
/// witness that fails is dropped whole and the promotion stands.
pub(super) fn witness_replayed_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    plan: &PromotePlan,
    fresh: Option<&BTreeSet<EntityId>>,
) {
    let landed = plan.ops_with_source_runs().filter(|(op, _)| {
        fresh.is_none_or(|fresh| replayed_subject(op).is_some_and(|id| fresh.contains(&id)))
    });
    crate::skill_attribution::note_promoted_ops_in_txn(vault, wtxn, landed);
}
