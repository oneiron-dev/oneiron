//! The unprocessed items a board's prefix carries (FIX 7740,
//! CROSS-ARCH-0002c): the caller's emotionally heavy memories that have
//! settled for days and still wait to be worked through.

use super::UnprocessedItem;
use super::WorldPresence;
use super::memories_projection::constraint_predicate;
use crate::claim::{
    ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedRead, base_world_id, decode_claim_body,
};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::write_envelope::claim_vad::CLAIM_VAD_REAPPRAISAL_PREDICATE;
use crate::{EntityId, Result};
use std::collections::{BTreeMap, BTreeSet};

/// A memory whose consolidated valence is at or below this is heavy enough.
const UNPROCESSED_VALENCE_MAX: f32 = -0.35;
/// A memory younger than this, in seconds (three days), has not settled.
const UNPROCESSED_MIN_AGE_SECS: u64 = 3 * 24 * 60 * 60;
/// Claim-VAD state ids one page of the predicate posting-list walk reads.
const UNPROCESSED_SCAN_PAGE: usize = 256;
/// Admitted candidates one call collects before the walk stops (FIX 9449):
/// paging ends once this many candidates have passed every filter, then the
/// collected set sorts and truncates to this length, so priority is exact
/// only within the collected set.
const UNPROCESSED_LIMIT: usize = 128;

/// Every unprocessed item `read` admits, highest priority first, up to
/// [`UNPROCESSED_LIMIT`] collected candidates.
///
/// A candidate is the subject CLAIM of an Active `affect.claim_vad` state,
/// the VAD consolidated over the turns that mention it, when `read` admits
/// both, the state's valence is at or below -0.35, and the subject is Active
/// and was learned at least three days before `now` (seconds). A candidate
/// drops out when an admitted Active `affect.processed` state marks it
/// processed, when an admitted Active `boundary.*` claim names it, or when
/// its WORLD reads as fiction. Processed, boundary and fiction evidence the
/// caller's read cannot admit counts as absent, so the candidate still
/// shows. The walk stops once [`UNPROCESSED_LIMIT`] candidates have passed
/// every filter, so priority is exact only within the collected set. Order
/// (CALL P3-a): arousal descending, then mention count (the state's
/// distinct evidence turns) descending, then older first, then id; no
/// weighted score.
pub fn unprocessed_items(read: &ScopedRead<'_>, now: u64) -> Result<Vec<UnprocessedItem>> {
    let store = &read.vault().store;
    let mut seen: BTreeSet<EntityId> = BTreeSet::new();
    let mut collected: Vec<(f32, u64, u64, EntityId, ClaimBody)> = Vec::new();
    let mut after = None;
    loop {
        let page = {
            let txn = store.env.read_txn()?;
            crate::claim::claim_ids_for_predicate_page_in_txn(
                store,
                &txn,
                CLAIM_VAD_REAPPRAISAL_PREDICATE,
                after,
                UNPROCESSED_SCAN_PAGE,
            )?
        };
        let Some(&last) = page.last() else {
            break;
        };
        after = Some(last);
        let admitted = read.get_entities_parts_with_receipt(&page, None)?.value;
        let mut page_states: BTreeMap<EntityId, (f32, u64)> = BTreeMap::new();
        for (entity_type, _, body) in admitted.into_iter().flatten() {
            if entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            let Ok(state) = decode_claim_body(&body, true) else {
                continue;
            };
            let ClaimSubject::Entity(subject) = &state.subject else {
                continue;
            };
            let Some((valence, arousal, mentions)) = claim_vad_reading(&state.value) else {
                continue;
            };
            if state.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE
                && state.lifecycle == ClaimLifecycleStatus::Active
                && valence <= UNPROCESSED_VALENCE_MAX
                && seen.insert(*subject)
            {
                page_states.insert(*subject, (arousal, mentions));
            }
        }
        if !page_states.is_empty() {
            let subjects: Vec<EntityId> = page_states.keys().copied().collect();
            let admitted = read.get_entities_parts_with_receipt(&subjects, None)?.value;
            let mut candidates = Vec::new();
            for (subject, parts) in subjects.iter().zip(admitted) {
                let Some((entity_type, learned_at, body)) = parts else {
                    continue;
                };
                if entity_type != ENTITY_TYPE_CLAIM
                    || learned_at.saturating_add(UNPROCESSED_MIN_AGE_SECS) > now
                {
                    continue;
                }
                let Ok(claim) = decode_claim_body(&body, true) else {
                    continue;
                };
                let Some(&(arousal, mentions)) = page_states.get(subject) else {
                    continue;
                };
                if claim.lifecycle == ClaimLifecycleStatus::Active {
                    candidates.push((arousal, mentions, learned_at, *subject, claim));
                }
            }
            if !candidates.is_empty() {
                let subjects: Vec<EntityId> = candidates
                    .iter()
                    .map(|(_, _, _, subject, _)| *subject)
                    .collect();
                let processed = read
                    .vault()
                    .store
                    .record_hooks
                    .processed_subjects(read, &subjects)?;
                candidates.retain(|(_, _, _, subject, _)| !processed.contains(subject));
            }
            if !candidates.is_empty() {
                let subjects: Vec<EntityId> = candidates
                    .iter()
                    .map(|(_, _, _, subject, _)| *subject)
                    .collect();
                let blocked = boundary_blocked_subjects(read, &subjects)?;
                candidates.retain(|(_, _, _, subject, _)| !blocked.contains(subject));
            }
            if !candidates.is_empty() {
                let worlds: BTreeSet<EntityId> = candidates
                    .iter()
                    .map(|(_, _, _, _, claim)| claim.world.unwrap_or(base_world_id()))
                    .collect();
                let worlds: Vec<EntityId> = worlds.into_iter().collect();
                let fiction: BTreeSet<EntityId> = WorldPresence::read_admitted(read, &worlds)?
                    .into_iter()
                    .filter(|world| world.fiction)
                    .map(|world| world.id)
                    .collect();
                candidates.retain(|(_, _, _, _, claim)| {
                    !fiction.contains(&claim.world.unwrap_or(base_world_id()))
                });
            }
            collected.extend(candidates);
            if collected.len() >= UNPROCESSED_LIMIT {
                break;
            }
        }
        if page.len() < UNPROCESSED_SCAN_PAGE {
            break;
        }
    }
    collected.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.cmp(&right.3))
    });
    collected.truncate(UNPROCESSED_LIMIT);
    Ok(collected
        .into_iter()
        .map(|(_, _, learned_at, id, claim)| UnprocessedItem {
            id: id.to_hex(),
            entity_type: ENTITY_TYPE_CLAIM,
            learned_at,
            body: item_body(claim),
        })
        .collect())
}

/// The candidates an admitted Active `boundary.*` claim blocks: each
/// candidate's inbound `claim_of` ids, admitted through the caller's read —
/// the same admitted read as the processed filter — judged by the MEMORIES
/// constraint-namespace test, so a boundary the read withholds counts as
/// absent (fail open).
fn boundary_blocked_subjects(
    read: &ScopedRead<'_>,
    subjects: &[EntityId],
) -> Result<BTreeSet<EntityId>> {
    let mut pairs = Vec::new();
    for subject in subjects {
        for claim_id in read.vault().claims_for_subject(subject)? {
            pairs.push((claim_id, *subject));
        }
    }
    let mut blocked = BTreeSet::new();
    if pairs.is_empty() {
        return Ok(blocked);
    }
    let ids: Vec<EntityId> = pairs.iter().map(|(id, _)| *id).collect();
    let admitted = read.get_entities_parts_with_receipt(&ids, None)?.value;
    for ((_, subject), parts) in pairs.into_iter().zip(admitted) {
        let Some((entity_type, _, body)) = parts else {
            continue;
        };
        if entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        let Ok(claim) = decode_claim_body(&body, true) else {
            continue;
        };
        if constraint_predicate(&claim.predicate)
            && claim.subject == ClaimSubject::Entity(subject)
            && claim.lifecycle == ClaimLifecycleStatus::Active
        {
            blocked.insert(subject);
        }
    }
    Ok(blocked)
}

/// A claim-VAD state value's valence, arousal and mention count: its
/// `turn_count`, the distinct turns whose VAD it consolidates, as the affect
/// consolidation writes them.
fn claim_vad_reading(value: &rmpv::Value) -> Option<(f32, f32, u64)> {
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    let leaf = |key: &str| {
        entries
            .iter()
            .find(|(entry, _)| entry.as_str() == Some(key))
            .map(|(_, value)| value)
    };
    let unit = |key: &str| {
        leaf(key)?
            .as_f64()
            .map(|value| value as f32)
            .filter(|value| value.is_finite())
    };
    Some((
        unit("valence")?,
        unit("arousal")?,
        leaf("turn_count")?.as_u64()?,
    ))
}

/// An item's body as its admitted claim reads: its predicate and value,
/// both withheld when the claim reads as a secret.
fn item_body(claim: ClaimBody) -> serde_json::Value {
    if crate::batch::export::claim_reads_as_secret(&claim) {
        return serde_json::json!({ "pred": null, "val": "[redacted]" });
    }
    serde_json::json!({
        "pred": claim.predicate,
        "val": crate::batch::export::served_messagepack_json(claim.value),
    })
}
