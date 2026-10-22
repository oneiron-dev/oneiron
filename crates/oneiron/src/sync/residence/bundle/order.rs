//! The order the home committed its generations in (FIX 8885). A slot may
//! hold more than one generation, and a generation's id is its slot and a
//! random nonce, so the id says nothing of which came last. Each commit takes
//! the next number past every generation kept, in the commit's own
//! transaction; the newest is the one committed last, and the existing keep
//! and age rule ([`retired_bundle_generations`]) runs in that order.
//! `SealedBundleEntry::commit_order` carries it to every reader.
//!
//! [`retired_bundle_generations`]: crate::world_keys::retired_bundle_generations

use super::SealedBundleEntry;
use crate::world_keys::{SEALED_BUNDLE_KEEP, SealedBundleGeneration};

/// The commit order the next commit takes: one past every generation kept.
/// The newest is never retired, so the number only grows while the home
/// keeps any generation.
pub(super) fn next_commit_order(kept: &[SealedBundleEntry]) -> u64 {
    kept.iter()
        .map(|entry| entry.commit_order)
        .max()
        .map_or(1, |last| last.saturating_add(1))
}

/// The generations a home retires from `kept`, oldest committed first, in
/// slot `now_slot`: every one past the newest [`SEALED_BUNDLE_KEEP`], and
/// every older one that many slots old, the rule of
/// `retired_bundle_generations` read in commit order. The newest, the one
/// committed last, is never retired by age.
pub(super) fn retired_in_commit_order(
    now_slot: u64,
    kept: &[SealedBundleEntry],
) -> Vec<SealedBundleGeneration> {
    let keep_slots = SEALED_BUNDLE_KEEP as u64;
    kept.iter()
        .rev()
        .enumerate()
        .filter(|(rank, entry)| {
            *rank >= SEALED_BUNDLE_KEEP
                || (*rank > 0 && entry.generation.slot.saturating_add(keep_slots) <= now_slot)
        })
        .map(|(_, entry)| entry.generation)
        .collect()
}
