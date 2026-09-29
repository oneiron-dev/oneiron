//! Reactions follow the room deletion doors: deleting a conversation record
//! deletes the reaction claims about it (and their echo bindings) with the
//! same reason, and erasing a person from a room erases every reaction that
//! person made there. Selection reads every family claim, whatever its
//! approval or lifecycle, so a retracted put is erased with the live ones.
use super::chain::{claim_ids_about, stored_claim_in};
use super::value::{
    PREDICATE_CONVERSATION_REACTION, PREDICATE_CONVERSATION_REACTION_ECHO, ReactionValue,
};
use crate::deletion::DeleteReason;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::{EntityId, Vault};

/// Room records one erasure may scan before it refuses loudly.
const MAX_ROOM_RECORDS: usize = 1_000_000;

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

/// Every reaction `person` made on a record of `room`, echo bindings first.
pub(crate) fn person_reaction_claims_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    person: EntityId,
) -> Result<Vec<EntityId>> {
    let mut reactions = Vec::new();
    let mut scanned = 0usize;
    for kind in [EdgeKind::BelongsTo, EdgeKind::ChildOf] {
        for edge in vault
            .store
            .port_edges(txn, &room, EdgeDirection::In, Some(kind), None)?
        {
            scanned += 1;
            if scanned > MAX_ROOM_RECORDS {
                return Err(Error::IndexOverflow("room reaction erasure"));
            }
            let record = edge?.target;
            for (id, body) in
                family_claims_about(vault, txn, record, PREDICATE_CONVERSATION_REACTION)?
            {
                if ReactionValue::from_value(&body.value).is_ok_and(|value| value.by == person)
                    || crate::memory::claim_author(&body) == Some(person)
                {
                    reactions.push(id);
                }
            }
        }
    }
    with_echoes(vault, txn, reactions)
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
