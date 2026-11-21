//! The actor-binding merge of [`super::merge_states`].

use std::cmp::Ordering;

use super::*;

/// Higher epoch wins; conflict poison is per-epoch, carried by the winner.
///
/// Equal epoch with divergent content is the dangerous case: two branches each
/// believe a different actor holds this key. Keeping the byte-wise smaller
/// tuple makes the merge deterministic in every arrival order, and
/// `conflicted` makes it never Active — a fork over identity fails closed
/// rather than silently picking a winner.
///
/// Poison deliberately does NOT leak across epochs: a strictly higher epoch
/// supersedes the conflicted state outright. It has to, or one historical
/// divergence would brick the key forever with no way to rebind. The
/// fail-closed property survives because two branches that each advance past
/// a conflict must themselves land on the same epoch to be concurrent, and
/// that tie re-poisons at the new epoch.
pub(super) fn merge_actor_bindings(
    left: &ActorBindingState,
    right: &ActorBindingState,
) -> ActorBindingState {
    match left.epoch.cmp(&right.epoch) {
        Ordering::Greater => left.clone(),
        Ordering::Less => right.clone(),
        Ordering::Equal => {
            let left_tuple = (left.actor_ref, left.actor_class.as_str());
            let right_tuple = (right.actor_ref, right.actor_class.as_str());
            let mut winner = if left_tuple <= right_tuple {
                left.clone()
            } else {
                right.clone()
            };
            winner.observed_revocations = left
                .observed_revocations
                .intersection(&right.observed_revocations)
                .copied()
                .collect();
            winner.conflicted |= left_tuple != right_tuple || left.conflicted || right.conflicted;
            winner
        }
    }
}
