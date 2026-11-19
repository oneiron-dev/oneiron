//! A standing answer never stays in a facet its room no longer reads (FIX
//! STANDING-ANSWER-STAYS-IN-LEFT-FACET, Engine ruling A, 19 Nov 13:29).
//!
//! An answer sits in a facet every row it rests on is read in
//! ([`super::answer_facets_in`]). A room's facet set can narrow under rows
//! that do not change; an answer written before then would sit in a facet
//! the room left, wider than the row it rests on. The narrowing marks it
//! stale in its own transaction and drops its dedup key, so the next refresh
//! lands a fresh answer where the row is read now; a question that refreshes
//! on arrival queues that refresh.

use std::collections::BTreeSet;

use super::super::store::{AnswerKey, QUESTION_ANSWER, family_prefix};
use super::{QUESTION_BACKFILL, answer_facets_in, singleton};
use crate::claim::{ClaimDemotionAction, ClaimLifecycleStatus};
use crate::side_table::SideKey;
use crate::{EntityId, Result, Vault};

/// Marks stale, in `txn`, every standing answer whose claim sits in a facet
/// of `left` (the facets the room `room` read before the act in `txn`
/// narrowed its set, and reads no longer) and that rests on a row of that
/// room (its unit or an evidence row) that may no longer hold an answer in
/// that facet. Each marked answer gives up its dedup key, and its unit's
/// arrival is queued where its question refreshes on arrival. Returns how
/// many answers it marked.
pub(crate) fn mark_answers_stale_in_left_facets_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    left: &BTreeSet<EntityId>,
    now: u64,
) -> Result<usize> {
    if left.is_empty() {
        return Ok(0);
    }
    let mut answers = Vec::new();
    for row in QUESTION_ANSWER.iter_raw_from(&vault.store, txn, &[])? {
        let (key, value) = row?;
        let Some(key) = AnswerKey::decode_key(&key) else {
            continue;
        };
        // A row that does not decode is passed over with a WARN, as the
        // erase does: it never blocks the owner's act.
        match QUESTION_ANSWER.decode_value(&value) {
            Ok(answer) => answers.push((key, answer)),
            Err(_) => tracing::warn!(
                "a question answer does not decode: the room narrowing passes it over"
            ),
        }
    }
    let mut marked = 0;
    for (key, answer) in answers {
        let Some(body) = vault.get_claim_in_txn(txn, &key.claim)? else {
            continue;
        };
        if body.stale
            || body.lifecycle != ClaimLifecycleStatus::Active
            || !left.contains(&body.scope_facet)
        {
            continue;
        }
        let mut wider = false;
        for row in std::iter::once(answer.unit).chain(answer.decision.evidence.iter().copied()) {
            if rests_wider_on_room_row_in(vault, txn, room, row, body.scope_facet)? {
                wider = true;
                break;
            }
        }
        if !wider {
            continue;
        }
        vault.apply_claim_demotion_in_txn(txn, &key.claim, ClaimDemotionAction::MarkStale, now)?;
        let backfills = QUESTION_BACKFILL.scan_from(
            &vault.store,
            txn,
            &family_prefix(key.question, b"backfill"),
        )?;
        for (backfill, claim) in backfills {
            if claim.0 == *key.claim.as_bytes() {
                QUESTION_BACKFILL.delete(&vault.store, txn, &backfill)?;
            }
        }
        // A question that refreshes on arrival takes the narrowing as one.
        super::super::arrival::queue_arrival_in_txn(&vault.store, txn, key.question, answer.unit)?;
        marked += 1;
    }
    Ok(marked)
}

/// Whether `row` sits in the room `room` and an answer on it may not sit in
/// `facet` now. A row whose record Scope names no single facet bounds no
/// answer, so none may sit on it.
fn rests_wider_on_room_row_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    row: EntityId,
    facet: EntityId,
) -> Result<bool> {
    let Some(kind) = vault.get_entity_type_in_txn(txn, &row)? else {
        return Ok(false);
    };
    if crate::federation::facet_read::room_of(&vault.store, txn, row, kind)? != Some(room) {
        return Ok(false);
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &row)? else {
        return Ok(false);
    };
    let Some(scope) =
        crate::federation::record_scope::scope_for_blob(&vault.store, txn, row, &raw)?
    else {
        return Ok(true);
    };
    let Some(stamped) = singleton(&scope.facets) else {
        return Ok(true);
    };
    Ok(!answer_facets_in(vault, &vault.store, txn, row, kind, stamped)?.contains(&facet))
}
