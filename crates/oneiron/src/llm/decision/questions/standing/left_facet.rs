//! A standing answer never stays in a facet its room no longer reads (FIX
//! STANDING-ANSWER-STAYS-IN-LEFT-FACET, Engine ruling A, 19 Nov 13:29; FIX
//! STANDING-ANSWER-LEFT-FACET-OTHER-WRITERS).
//!
//! An answer sits in a facet every row it rests on is read in
//! ([`super::answer_facets_in`]). What a room reads can narrow under rows
//! that do not change; an answer written before then would sit in a facet
//! the room left, wider than the row it rests on. The write that narrows the
//! room queues it (`workspace_roster`'s room narrowing), and its batch marks
//! each such answer stale in its own transaction and drops its dedup key, so
//! the next refresh lands a fresh answer where the row is read now; a
//! question that refreshes on arrival queues that refresh.

use std::collections::BTreeSet;

use super::super::records::AnswerRecord;
use super::super::store::{AnswerKey, QUESTION_ANSWER, family_prefix};
use super::{QUESTION_BACKFILL, answer_facets_in, singleton};
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimDemotionAction, ClaimLifecycleStatus};
use crate::side_table::SideKey;
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// Every standing answer. A row that does not decode is passed over with a
/// WARN, as the erase does: it never blocks the act that narrowed a room.
fn answers_in(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Vec<(AnswerKey, AnswerRecord)>> {
    let mut answers = Vec::new();
    for row in QUESTION_ANSWER.iter_raw_from(store, txn, &[])? {
        let (key, value) = row?;
        let Some(key) = AnswerKey::decode_key(&key) else {
            continue;
        };
        match QUESTION_ANSWER.decode_value(&value) {
            Ok(answer) => answers.push((key, answer)),
            Err(_) => tracing::warn!(
                "a question answer does not decode: the room narrowing passes it over"
            ),
        }
    }
    Ok(answers)
}

/// The rows an answer rests on: its unit, then its evidence.
fn rows_of(answer: &AnswerRecord) -> impl Iterator<Item = EntityId> + '_ {
    std::iter::once(answer.unit).chain(answer.decision.evidence.iter().copied())
}

/// The type of the stored row `id`, if it is stored.
fn kind_in(store: &Store, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Option<u8>> {
    Ok(
        crate::ports::EntityStoreRead::port_entity_with_raw(store, txn, &id, |raw| {
            Ok(EntityMetadataHeader::parse(raw).map(|header| header.entity_type))
        })?
        .flatten(),
    )
}

/// Every row a standing answer rests on that sits in `room` now.
pub(crate) fn answer_rows_in_room_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Vec<EntityId>> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for (_, answer) in answers_in(store, txn)? {
        for row in rows_of(&answer) {
            if !seen.insert(row) {
                continue;
            }
            let Some(kind) = kind_in(store, txn, row)? else {
                continue;
            };
            if crate::federation::facet_read::room_of(store, txn, row, kind)? == Some(room) {
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

/// Marks stale, in `txn`, every standing answer that sits in a facet one of
/// its rows of the room `room` (its unit or an evidence row) is no longer
/// read in. `detached` names the room's rows when a delete has taken them
/// off it; empty, the rows that still name the room count. Each marked
/// answer gives up its dedup key, and its unit's arrival is queued where its
/// question refreshes on arrival. Returns how many answers it marked.
pub(crate) fn mark_answers_stale_in_left_facets_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    detached: &[EntityId],
    now: u64,
) -> Result<usize> {
    let mut marked = 0;
    for (key, answer) in answers_in(&vault.store, txn)? {
        let Some(body) = vault.get_claim_in_txn(txn, &key.claim)? else {
            continue;
        };
        if body.stale || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let mut wider = false;
        for row in rows_of(&answer) {
            let in_room = if detached.is_empty() {
                Some(room)
            } else if detached.contains(&row) {
                None
            } else {
                continue;
            };
            if rests_wider_on_row_in(vault, txn, in_room, row, body.scope_facet)? {
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

/// Whether an answer on `row` may not sit in `facet` now, for a row that
/// sits in the room `room` (any row, with no room named). A row whose
/// record Scope names no single facet bounds no answer, so none may sit on
/// it.
fn rests_wider_on_row_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: Option<EntityId>,
    row: EntityId,
    facet: EntityId,
) -> Result<bool> {
    let Some(kind) = vault.get_entity_type_in_txn(txn, &row)? else {
        return Ok(false);
    };
    if let Some(room) = room
        && crate::federation::facet_read::room_of(&vault.store, txn, row, kind)? != Some(room)
    {
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
