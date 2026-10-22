//! The unprocessed items a board's prefix carries (FIX 7740,
//! CROSS-ARCH-0002c): the caller's emotionally heavy memories that have
//! settled for days and still wait to be worked through.

use super::UnprocessedItem;
use crate::affect::CLAIM_VAD_REAPPRAISAL_PREDICATE;
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedRead, decode_claim_body};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Result};
use std::collections::BTreeMap;

/// A memory whose consolidated valence is at or below this is heavy enough.
const UNPROCESSED_VALENCE_MAX: f32 = -0.35;
/// A memory younger than this, in seconds (three days), has not settled.
const UNPROCESSED_MIN_AGE_SECS: u64 = 3 * 24 * 60 * 60;
/// Claim-VAD state ids one page of the predicate posting-list walk reads.
const UNPROCESSED_SCAN_PAGE: usize = 256;

/// Every unprocessed item `read` admits, highest priority first. No count
/// cap applies here: the board's budget and shed path decide what renders.
///
/// A candidate is the subject CLAIM of an Active `affect.claim_vad` state,
/// the VAD consolidated over the turns that mention it, when `read` admits
/// both, the state's valence is at or below -0.35, and the subject is Active
/// and was learned at least three days before `now` (seconds). No record
/// marks a memory processed at this head, so every candidate reads
/// `processed=false`. Order (CALL P3-a): arousal descending, then mention
/// count (the state's distinct evidence turns) descending, then older
/// first, then id; no weighted score.
pub fn unprocessed_items(read: &ScopedRead<'_>, now: u64) -> Result<Vec<UnprocessedItem>> {
    let states = heavy_claim_vad_states(read)?;
    let subjects: Vec<EntityId> = states.keys().copied().collect();
    let admitted = read.get_entities_parts_with_receipt(&subjects, None)?.value;
    let mut items = Vec::new();
    for (subject, parts) in subjects.into_iter().zip(admitted) {
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
        let Some(&(arousal, mentions)) = states.get(&subject) else {
            continue;
        };
        if claim.lifecycle == ClaimLifecycleStatus::Active {
            items.push((arousal, mentions, learned_at, subject, claim));
        }
    }
    items.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.cmp(&right.3))
    });
    Ok(items
        .into_iter()
        .map(|(_, _, learned_at, id, claim)| UnprocessedItem {
            id: id.to_hex(),
            entity_type: ENTITY_TYPE_CLAIM,
            learned_at,
            body: item_body(claim),
        })
        .collect())
}

/// Each subject of an Active `affect.claim_vad` state `read` admits whose
/// valence is heavy enough, with that state's arousal and mention count.
/// The walk pages through the whole posting list.
fn heavy_claim_vad_states(read: &ScopedRead<'_>) -> Result<BTreeMap<EntityId, (f32, u64)>> {
    let store = &read.vault().store;
    let mut states = BTreeMap::new();
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
            {
                states.entry(*subject).or_insert((arousal, mentions));
            }
        }
        if page.len() < UNPROCESSED_SCAN_PAGE {
            break;
        }
    }
    Ok(states)
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
