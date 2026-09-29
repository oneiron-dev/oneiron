//! Reaction claims on one conversation record, read in the caller's snapshot.
use super::value::{
    PREDICATE_CONVERSATION_REACTION_ECHO, ReactionExternalId, ReactionValue, decode_echo,
    decode_reaction, machine_written,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, claim_surfaceable};
use crate::error::Result;
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

    pub(crate) fn writer(&self) -> Option<crate::WriteActor> {
        machine_written(&self.body)
            .then(|| crate::memory::claim_author(&self.body))
            .flatten()
            .map(|machine| crate::WriteActor::new(machine, crate::edge::EdgeActorClass::System))
    }
}

/// The claim body and learned time of a stored, body-bearing CLAIM row.
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

fn admitted(body: &ClaimBody) -> bool {
    matches!(
        body.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    )
}

/// Every admitted reaction claim about `record`, oldest first. A malformed
/// value written through a generic door is skipped, never read as a reaction.
pub(crate) fn reactions_on_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> Result<Vec<StoredReaction>> {
    let mut rows = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, &record)? {
        let Some((body, learned_at)) = stored_claim_in(vault, txn, &id)? else {
            continue;
        };
        if !admitted(&body) {
            continue;
        }
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
    record: EntityId,
    by: EntityId,
    glyph: &str,
) -> Result<Vec<StoredReaction>> {
    let mut rows = reactions_on_in(vault, txn, record)?;
    rows.retain(|row| row.value.by == by && row.value.glyph == glyph);
    Ok(rows)
}

/// Provider generations bound to a first-party reaction claim by its echo.
pub(crate) fn echoes_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reaction: EntityId,
) -> Result<Vec<(EntityId, ReactionExternalId)>> {
    let mut rows = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, &reaction)? {
        let Some((body, _)) = stored_claim_in(vault, txn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CONVERSATION_REACTION_ECHO || !claim_surfaceable(&body) {
            continue;
        }
        if let Some(external) = decode_echo(&body) {
            rows.push((id, external));
        }
    }
    Ok(rows)
}

/// Whether `generation` names this claim: its own mirrored id or an echo.
pub(crate) fn names_generation(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &StoredReaction,
    generation: &ReactionExternalId,
) -> Result<bool> {
    if row.value.external_id.as_ref() == Some(generation) {
        return Ok(true);
    }
    Ok(echoes_in(vault, txn, row.id)?
        .iter()
        .any(|(_, bound)| bound == generation))
}
