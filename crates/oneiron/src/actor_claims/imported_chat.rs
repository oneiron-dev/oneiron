//! Source-derived inert CHAT proposals; native actor heads are not touched.

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::provenance::birth::{RowBirth, stamp_row_birth_in_txn};
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::{EntityId, Error, Result, TimeRange, Vault};

use super::evidence::{ActorClaimEvidence, ActorClaimLane};
use super::invalid;
use super::rows::ActorClaimRow;
use super::write::scope_with_lineage;

pub(super) fn write_imported_chat_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &ActorClaimRow,
    evidence: &ActorClaimEvidence,
    birth: Option<&RowBirth>,
) -> Result<Option<EntityId>> {
    let ActorClaimLane::Chat { session, turns } = &evidence.lane else {
        return Ok(None);
    };
    match vault.get_entity_type_in_txn(txn, session)? {
        Some(ENTITY_TYPE_SESSION) => {}
        Some(_) => return Err(invalid("a chat-lane citation must name a SESSION")),
        None => return Err(Error::EntityNotFound),
    }
    for turn in turns {
        if vault.get_entity_type_in_txn(txn, turn)? != Some(ENTITY_TYPE_TURN) {
            return Err(invalid("actor row cites a turn that is not a TURN"));
        }
    }
    let imported = crate::ingest::history::imported_evidence_in_txn(vault, txn, turns, &[])?;
    if !imported.imported {
        return Ok(None);
    }
    let (value, pair_scope) = row.value_and_scope()?;
    let mut body = ClaimBody::new(
        row.predicate(),
        ClaimSubject::Entity(row.actor()),
        value,
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )?;
    body.evidence = Some(evidence.to_value());
    body.scope = Some(scope_with_lineage(pair_scope, ClaimSource::Imported));
    body.valid_from = Some(evidence.at);
    body.source = Some(ClaimSource::Imported);
    // The same facet rule as a born actor claim (write.rs): a PERSON's
    // substrate, else the actor's stored birth FACET, else the vault default.
    body.scope_facet = super::write::actor_claim_facet_in_txn(vault, txn, row.actor())?;
    let id = vault.store.clock.entity_id()?;
    vault.put_reserved_claim_in_txn(
        txn,
        &id,
        &body,
        TimeRange {
            start: evidence.at,
            end: evidence.at,
        },
        evidence.at,
    )?;
    if let Some(birth) = birth {
        stamp_row_birth_in_txn(&vault.store, txn, &id, birth)?;
    }
    Ok(Some(id))
}
