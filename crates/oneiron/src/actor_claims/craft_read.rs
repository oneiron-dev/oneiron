//! A resident's own craft as its runs read it (OF-490): the lessons and
//! failure modes the system learned about it, and the ones its owner
//! approved, every one.

use std::cmp::Reverse;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, claim_surfaceable};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;

use super::candidate::is_approved_craft_verdict;
use super::rows::{PREDICATE_ACTOR_FAILURE_MODE, PREDICATE_ACTOR_LESSON};

/// The ids of `resident`'s craft current at `at`, read on one snapshot,
/// newest first: each lesson and failure mode about exactly it that is
/// surfaceable, valid at `at` and owes no owner confirmation, and is either
/// learned (Auto and Observed, the projector and Coach inlet) or its owner's
/// Approved verdict on a craft candidate. Proposed and Rejected rows never
/// are. Each is a row the resident's pack door
/// ([`Vault::load_resident_actor_claim`]) admits; that door follows no
/// Supersedes, so an approval is its verdict row, never the candidate. Rule 5
/// caps none: every eligible row.
///
/// # Errors
///
/// Storage errors, and a claim with no entity header.
pub fn resident_craft_claim_ids(
    vault: &Vault,
    resident: &EntityId,
    at: u64,
) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for id in vault.claims_for_subject_in_txn(&rtxn, resident)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &id)? else {
            continue;
        };
        if !is_current_craft(&body, resident, at)
            || !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, &rtxn, &id)?
        {
            continue;
        }
        let raw = vault
            .store
            .port_entity_record(&rtxn, &id)?
            .map(|row| row.encode())
            .ok_or(Error::CorruptedIndex("actor claim entity"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        rows.push(craft_order(&body, header.occurred_start, id));
    }
    rows.sort_unstable();
    Ok(rows.into_iter().map(|Reverse((_, id))| id).collect())
}

/// Whether `body` is `resident`'s craft at `at`: a surfaceable lesson or
/// failure mode about exactly it, valid at `at`, learned or owner-approved.
fn is_current_craft(body: &ClaimBody, resident: &EntityId, at: u64) -> bool {
    matches!(
        body.predicate.as_str(),
        PREDICATE_ACTOR_LESSON | PREDICATE_ACTOR_FAILURE_MODE
    ) && matches!(&body.subject, ClaimSubject::Entity(subject) if subject == resident)
        && claim_surfaceable(body)
        && body.valid_from.is_none_or(|start| start <= at)
        && body.valid_to.is_none_or(|end| end > at)
        && ((body.approval == ClaimApprovalStatus::Auto
            && body.source == Some(ClaimSource::Observed))
            || is_approved_craft_verdict(body))
}

/// The order craft reads in: newest effective time first (`valid_from`, else
/// the row's occurred start), then the larger claim id first.
fn craft_order(body: &ClaimBody, occurred_start: u64, id: EntityId) -> Reverse<(u64, EntityId)> {
    Reverse((body.valid_from.unwrap_or(occurred_start), id))
}
