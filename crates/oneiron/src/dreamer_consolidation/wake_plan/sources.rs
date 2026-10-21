//! A multi-part branch's parts at the wake's one pin (FIX 7524, Engine
//! ruling B). A part whose parent or TURN no longer reads, or one of whose
//! TURNs' witnessed MESSAGE texts is refused or away, splits off as a
//! one-part owed sibling so the other parts run: no all-parts wait, no
//! timeout, never failing the other parts and never silently skipping that
//! one. When every part is so, the first stays and takes the whole
//! attempt's outcome, as a one-part attempt's; the rest split off.

use std::collections::BTreeMap;

use super::PreparedConsolidationAttempt;
use super::chunks::{self, WakePreparationChunks};
use super::retry::Lineage;
use crate::EntityId;

/// Splits every part of `plan` that cannot be read whole in `sources`, or
/// one of whose TURNs' texts is in `refused_texts`, off into owed siblings,
/// narrowing `plan` to the rest. Nothing for a one-part plan.
pub(super) fn split_unreadable(
    plan: &mut PreparedConsolidationAttempt,
    sources: &BTreeMap<EntityId, (u8, u64, Vec<u8>)>,
    refused_texts: &BTreeMap<EntityId, &'static str>,
    lineage: Option<&Lineage>,
) -> Option<WakePreparationChunks> {
    if plan.branch.parts.len() < 2 {
        return None;
    }
    let lineage = lineage?;
    let unreadable: Vec<usize> = plan
        .branch
        .parts
        .iter()
        .enumerate()
        .filter(|(_, part)| {
            !sources.contains_key(&part.conversation_ref)
                || part
                    .turns
                    .iter()
                    .any(|turn| !sources.contains_key(turn) || refused_texts.contains_key(turn))
        })
        .map(|(index, _)| index)
        .collect();
    if unreadable.is_empty() {
        return None;
    }
    let split = if unreadable.len() == plan.branch.parts.len() {
        unreadable[1..].to_vec()
    } else {
        unreadable
    };
    let chunks = chunks::split_parts(&plan.branch, &split);
    let mut index = 0_usize;
    plan.branch.parts.retain(|_| {
        let keep = !split.contains(&index);
        index += 1;
        keep
    });
    plan.turn_ids = plan.branch.turn_ids();
    plan.input = super::super::partition::encode_branch_payload(&plan.branch, None);
    WakePreparationChunks::new(*plan.attempt_id.as_bytes(), lineage, chunks)
}
