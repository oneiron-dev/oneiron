//! Reaction claims on one conversation record, read in the caller's snapshot.
//!
//! Reads see a claim the way every claim read does: through its projected
//! MACHINE history, and only once it is causally admitted, so a replica never
//! shows a signed claim whose signer's history has not arrived. Erasure
//! selection reads the raw rows instead.
use super::value::{
    PREDICATE_CONVERSATION_REACTION_ECHO, ReactionExternalId, ReactionValue, decode_echo,
    decode_reaction, machine_written,
};
use crate::authority::AuthorityFold;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, claim_surfaceable};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Vault};

/// One admitted `conversation.reaction` claim.
#[derive(Debug, Clone)]
pub(crate) struct StoredReaction {
    pub(crate) id: EntityId,
    pub(crate) body: ClaimBody,
    pub(crate) value: ReactionValue,
    pub(crate) learned_at: u64,
}

impl StoredReaction {
    pub(crate) fn live(&self) -> bool {
        claim_surfaceable(&self.body)
    }

    pub(crate) fn retracted_at(&self) -> Option<u64> {
        (self.body.lifecycle == ClaimLifecycleStatus::Retracted)
            .then(|| self.body.valid_to.unwrap_or(self.learned_at))
    }

    /// Written by the reacting person on this vault, not mirrored in.
    pub(crate) fn first_party(&self) -> bool {
        self.value.external_id.is_none() && !machine_written(&self.body)
    }

    /// The MACHINE whose signed history closes this claim, if it wrote it.
    pub(crate) fn writer(&self) -> Option<crate::WriteActor> {
        machine_written(&self.body)
            .then(|| crate::memory::claim_author(&self.body))
            .flatten()
            .map(|machine| crate::WriteActor::new(machine, crate::edge::EdgeActorClass::System))
    }
}

/// The authority state one snapshot's reaction reads admit claims under.
pub(crate) fn admission_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<AuthorityFold> {
    vault.authority_fold_readonly_in_txn(txn)
}

/// Every CLAIM attached to `subject`, uncapped: an erasure must never be
/// blocked by how many rows others attached to the record.
pub(crate) fn claim_ids_about(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: EntityId,
) -> Result<Vec<EntityId>> {
    vault
        .store
        .port_edges(
            txn,
            &subject,
            EdgeDirection::In,
            Some(EdgeKind::ClaimOf),
            None,
        )?
        .map(|edge| edge.map(|edge| edge.target))
        .collect()
}

/// The raw body of a stored, body-bearing CLAIM row.
pub(crate) fn stored_claim_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(ClaimBody, u64)>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM
        || raw.len() == ENTITY_METADATA_HEADER_LEN
        || vault.archive_tombstone_in_txn(txn, id)?.is_some()
    {
        return Ok(None);
    }
    let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
        return Ok(None);
    };
    Ok(Some((body, header.learned_at)))
}

/// The projected, causally admitted, approved body of a CLAIM row.
fn admitted_claim_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    id: &EntityId,
) -> Result<Option<(ClaimBody, u64)>> {
    let Some((_, learned_at)) = stored_claim_in(vault, txn, id)? else {
        return Ok(None);
    };
    let Some(body) = vault.get_claim_in_txn(txn, id)? else {
        return Ok(None);
    };
    if !matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) || !crate::authority::claim_causal_admitted(&vault.store, txn, fold, id, &body)?
    {
        return Ok(None);
    }
    Ok(Some((body, learned_at)))
}

/// Every admitted reaction claim about `record`, oldest first. A malformed
/// value written through a generic door is skipped, never read as a reaction.
pub(crate) fn reactions_on_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    record: EntityId,
) -> Result<Vec<StoredReaction>> {
    let mut rows = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, &record)? {
        let Some((body, learned_at)) = admitted_claim_in(vault, txn, fold, &id)? else {
            continue;
        };
        let Some(value) = decode_reaction(&body) else {
            continue;
        };
        rows.push(StoredReaction {
            id,
            body,
            value,
            learned_at,
        });
    }
    rows.sort_by_key(|row| (row.learned_at, row.id));
    Ok(rows)
}

/// The (record, person, glyph) chain, oldest first.
pub(crate) fn chain_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    record: EntityId,
    by: EntityId,
    glyph: &str,
) -> Result<Vec<StoredReaction>> {
    let mut rows = reactions_on_in(vault, txn, fold, record)?;
    rows.retain(|row| row.value.by == by && row.value.glyph == glyph);
    Ok(rows)
}

/// Provider generations bound to a first-party reaction claim by its echo.
pub(crate) fn echoes_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    reaction: EntityId,
) -> Result<Vec<ReactionExternalId>> {
    let mut rows = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, &reaction)? {
        let Some((body, _)) = admitted_claim_in(vault, txn, fold, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CONVERSATION_REACTION_ECHO || !claim_surfaceable(&body) {
            continue;
        }
        if let Some(external) = decode_echo(&body) {
            rows.push(external);
        }
    }
    Ok(rows)
}

/// Whether `generation` names this claim: its own mirrored id or an echo.
pub(crate) fn names_generation(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    row: &StoredReaction,
    generation: &ReactionExternalId,
) -> Result<bool> {
    if row.value.external_id.as_ref() == Some(generation) {
        return Ok(true);
    }
    Ok(echoes_in(vault, txn, fold, row.id)?.contains(generation))
}
