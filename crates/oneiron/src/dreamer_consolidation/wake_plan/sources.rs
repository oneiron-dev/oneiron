//! A multi-part branch's parts at the wake's one pin (FIX 7524, Engine
//! ruling B). A part whose parent or TURN no longer reads, or one of whose
//! TURNs' witnessed MESSAGE texts is refused or away, splits off as a
//! one-part owed sibling so the other parts run: no all-parts wait, no
//! timeout, never failing the other parts and never silently skipping that
//! one. When every part is so, the first stays and takes the whole
//! attempt's outcome, as a one-part attempt's; the rest split off.
//!
//! A part whose bucket the attempt's effective scope (a host scope among
//! its bounds) does not name splits off the same way while the scope names
//! another part's (FIX 7728): the named parts run now and the rest stay
//! owed, never a refusal of the whole child.

use std::collections::BTreeMap;

use super::PreparedConsolidationAttempt;
use super::chunk_identity::ChunkPin;
use super::chunks::{self, WakePreparationChunks};
use super::retry::Lineage;
use crate::EntityId;
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::ScopeResource;

/// Splits every part of `plan` that cannot be read whole in `sources`, or
/// one of whose TURNs' texts is in `refused_texts`, off into owed siblings,
/// narrowing `plan` to the rest. Nothing for a one-part plan.
pub(super) fn split_unreadable(
    plan: &mut PreparedConsolidationAttempt,
    sources: &BTreeMap<EntityId, (u8, u64, Vec<u8>)>,
    refused_texts: &BTreeMap<EntityId, &'static str>,
    lineage: Option<&Lineage>,
    pin: ChunkPin<'_>,
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
    split_off(plan, &split, lineage, pin)
}

/// Splits every part of `plan` whose bucket its effective scope does not
/// read off into owed siblings, narrowing `plan` to the parts it names
/// (FIX 7728). Nothing for a one-part plan, a plan with no scope, one whose
/// scope names no part's bucket or every part's (as before: it runs whole,
/// or its own read refuses it), and one whose queued payload carries a
/// branch scope of its own, which a sibling would not carry.
pub(super) fn split_unnamed(
    plan: &mut PreparedConsolidationAttempt,
    lineage: Option<&Lineage>,
    pin: ChunkPin<'_>,
) -> Option<WakePreparationChunks> {
    if plan.branch.parts.len() < 2 {
        return None;
    }
    let scope = plan.scope.as_ref()?;
    let queued_scope = super::super::branch_scope::decode_branch_scope(&plan.queued_input);
    if !matches!(queued_scope, Ok(None)) {
        return None;
    }
    let lineage = lineage?;
    let unnamed: Vec<usize> = plan
        .branch
        .parts
        .iter()
        .enumerate()
        .filter(|(_, part)| {
            let key = plan.branch.part_key(part.conversation_ref);
            !scope.allows_read(&ScopeResource::Bucket {
                key: bytes_to_hex_lower(&key.partition_hash()),
            })
        })
        .map(|(index, _)| index)
        .collect();
    if unnamed.is_empty() || unnamed.len() == plan.branch.parts.len() {
        return None;
    }
    split_off(plan, &unnamed, lineage, pin)
}

/// Splits the parts of `plan` at `split` off into one-part siblings owed
/// under `lineage`, narrowing `plan` to the rest.
fn split_off(
    plan: &mut PreparedConsolidationAttempt,
    split: &[usize],
    lineage: &Lineage,
    pin: ChunkPin<'_>,
) -> Option<WakePreparationChunks> {
    let chunks = chunks::split_parts(&plan.branch, split);
    let mut index = 0_usize;
    plan.branch.parts.retain(|_| {
        let keep = !split.contains(&index);
        index += 1;
        keep
    });
    plan.turn_ids = plan.branch.turn_ids();
    plan.input = super::super::partition::encode_branch_payload(&plan.branch, None);
    WakePreparationChunks::new(*plan.attempt_id.as_bytes(), lineage, chunks, pin)
}
