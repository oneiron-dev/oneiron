//! Reactions follow the room deletion doors: deleting a conversation record
//! deletes the reaction claims about it (and their echo bindings) with the
//! same reason, and erasing a person from a room erases every reaction that
//! person made there. Selection reads every family claim, whatever its
//! approval or lifecycle, so a retracted put is erased with the live ones.
//!
//! A person's selection in a room reads the room's records in keyset pages,
//! however many there are: the count only feeds the advisory
//! [`EngineScan::EdgePeerRows`] check for the room, which never refuses the
//! erasure.
use super::chain::{claim_ids_about, stored_claim_in};
use super::value::{
    PREDICATE_CONVERSATION_REACTION, PREDICATE_CONVERSATION_REACTION_ECHO, ReactionValue,
};
use crate::deletion::DeleteReason;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::scan_check::{EngineScan, ScanCount};
use crate::{EntityId, Vault};

/// The edges by which a record sits in its room: a MESSAGE's own room, and a
/// DAG TURN's place under it.
pub(crate) const ROOM_RECORD_KINDS: [EdgeKind; 2] = [EdgeKind::BelongsTo, EdgeKind::ChildOf];

/// Room records one selection page reads.
pub(crate) const ROOM_RECORD_PAGE: usize = 256;

fn family_claims_about(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: EntityId,
    predicate: &str,
) -> Result<Vec<(EntityId, crate::ClaimBody)>> {
    let mut rows = Vec::new();
    for id in claim_ids_about(vault, txn, subject)? {
        if let Some((body, _)) = stored_claim_in(vault, txn, &id)?
            && body.predicate == predicate
        {
            rows.push((id, body));
        }
    }
    Ok(rows)
}

fn with_echoes(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reactions: Vec<EntityId>,
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for reaction in reactions {
        ids.extend(super::outcomes::source_outcomes_in(vault, txn, reaction)?);
        for (echo, _) in
            family_claims_about(vault, txn, reaction, PREDICATE_CONVERSATION_REACTION_ECHO)?
        {
            ids.push(echo);
        }
        ids.push(reaction);
    }
    Ok(ids)
}

/// Every reaction-family claim about `record`, echo bindings first.
pub(crate) fn record_reaction_claims_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> Result<Vec<EntityId>> {
    let reactions = family_claims_about(vault, txn, record, PREDICATE_CONVERSATION_REACTION)?
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    with_echoes(vault, txn, reactions)
}

/// Every reaction `person` made on a record of `room`, echo bindings first,
/// read page by page in `txn`.
pub(crate) fn person_reaction_claims_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    person: EntityId,
) -> Result<Vec<EntityId>> {
    let mut claims = Vec::new();
    for kind in ROOM_RECORD_KINDS {
        let scope = [
            &[EdgeDirection::In as u8][..],
            room.as_bytes(),
            &[kind as u8][..],
        ]
        .concat();
        let mut count = ScanCount::start(&vault.store, txn, EngineScan::EdgePeerRows, &scope)?;
        let mut after = None;
        loop {
            let (records, page) =
                person_reaction_page_in(vault, txn, room, person, kind, after, ROOM_RECORD_PAGE)?;
            count.rows(records.len());
            claims.extend(page);
            if records.len() < ROOM_RECORD_PAGE {
                break;
            }
            after = records.last().copied();
        }
        count.finish(vault);
    }
    Ok(claims)
}

/// One keyset page of `room`'s records by `kind` (one of
/// [`ROOM_RECORD_KINDS`]), strictly after the record `after`: the records
/// read, at most `page`, and every reaction `person` made on them, echo
/// bindings first. A page shorter than `page` is the kind's last. Each page
/// stands alone, so an erasure can read each in a transaction of its own and
/// delete its claims before it reads the next.
pub(crate) fn person_reaction_page_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    person: EntityId,
    kind: EdgeKind,
    after: Option<EntityId>,
    page: usize,
) -> Result<(Vec<EntityId>, Vec<EntityId>)> {
    let records = vault
        .store
        .port_edges(txn, &room, EdgeDirection::In, Some(kind), after)?
        .take(page)
        .map(|edge| edge.map(|info| info.target))
        .collect::<Result<Vec<_>>>()?;
    let mut reactions = Vec::new();
    for &record in &records {
        for (id, body) in family_claims_about(vault, txn, record, PREDICATE_CONVERSATION_REACTION)?
        {
            if ReactionValue::from_value(&body.value).is_ok_and(|value| value.by == person)
                || crate::memory::claim_author(&body) == Some(person)
            {
                reactions.push(id);
            }
        }
    }
    Ok((records, with_echoes(vault, txn, reactions)?))
}

/// Deletes each claim with `reason`; one already gone is skipped.
pub(crate) fn erase_reaction_claims(
    vault: &Vault,
    ids: &[EntityId],
    reason: DeleteReason,
) -> Result<()> {
    for id in ids {
        match vault.delete_entity_with_reason(id, reason) {
            Ok(_) | Err(Error::EntityNotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
