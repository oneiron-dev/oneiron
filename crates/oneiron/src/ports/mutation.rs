//! Mutation audit composition. Payloads never get copied into immutable audit rows.
use super::{ChangeLogRecord, ChangeLogStore, ChangeOp, recorded_at_in_txn};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, VerifiedClaimTransition};
use crate::error::Result;
use crate::store::Store;
use crate::write_envelope::WriteEnvelope;
use crate::{EntityId, TimeRange};

/// A storage service principal, not a user, person, session, or runtime slot.
/// Used when the mutation door carries no authenticated actor binding, and
/// the actor a critical-confirm timeout demotion settles as (FIX 1093).
pub(crate) fn storage_service_principal() -> Result<EntityId> {
    let digest = blake3::hash(b"oneiron:storage-service-principal:v1");
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(bytes)
}

pub(crate) struct MutationAudit<'a> {
    pub entity: EntityId,
    pub op: ChangeOp,
    pub actor_principal: Option<EntityId>,
    pub occurred_at: u64,
    pub input: &'a [u8],
    pub reason: Option<&'a str>,
}
pub(crate) fn audit_mutation_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    mutation: MutationAudit<'_>,
) -> Result<()> {
    let id = store.clock.ulid()?;
    let recorded_at = recorded_at_in_txn(store, txn)?;
    store.port_changelog_append(
        txn,
        &ChangeLogRecord {
            id,
            entity: mutation.entity,
            op: mutation.op,
            actor_principal: match mutation.actor_principal {
                Some(actor) => actor,
                None => storage_service_principal()?,
            },
            // A principal's person is a separate relationship. Never infer equality.
            actor_person: None,
            occurred_at: mutation.occurred_at,
            recorded_at,
            input_hash: *blake3::hash(mutation.input).as_bytes(),
            patch: None,
            reason: mutation.reason.map(str::to_owned),
        },
    )
}

pub(crate) struct EntityPutAudit<'a> {
    pub id: EntityId,
    pub entity_type: u8,
    pub occurred: TimeRange,
    pub learned_at: u64,
    pub data: &'a [u8],
    pub envelope: Option<&'a WriteEnvelope>,
    /// The verified transition this put materializes, if any: a lifecycle
    /// door's close names its closer and close time here (FIX 10044, 10045).
    pub transition: Option<&'a VerifiedClaimTransition>,
}
pub(crate) fn audit_entity_put_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    put: EntityPutAudit<'_>,
) -> Result<()> {
    let old = store.entities.get(txn, put.id.as_bytes())?;
    if let Some(raw) = old.as_ref()
        && let Some(header) = EntityMetadataHeader::parse(raw)
        && raw.get(ENTITY_METADATA_HEADER_LEN..) == Some(put.data)
        && header.occurred_start == put.occurred.start
        && header.occurred_end == put.occurred.end
        && header.learned_at == put.learned_at
    {
        return Ok(());
    }
    let mut op = if old.is_some() {
        ChangeOp::Update
    } else {
        ChangeOp::Create
    };
    if let Some(raw) = old.as_ref() {
        let prior = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        if put.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            if let (Ok(before), Ok(after)) = (
                crate::claim::decode_claim_body(prior, true),
                crate::claim::decode_claim_body(put.data, true),
            ) && before.lifecycle != after.lifecycle
                && after.lifecycle == crate::claim::ClaimLifecycleStatus::Superseded
            {
                op = ChangeOp::Supersede;
            }
        } else if put.entity_type == crate::registry::ENTITY_TYPE_SKILL
            && let (Ok(before), Ok(after)) = (
                crate::skill::decode_skill_record(prior),
                crate::skill::decode_skill_record(put.data),
            )
            && before.governance_tier != after.governance_tier
        {
            op = ChangeOp::TierTransition;
        }
    }
    // A lifecycle door's verified close names the closer it verified and the
    // time it closed at (FIX 10044, 10045). Without one, supersession's
    // materialized envelope carries the old author's provenance, not whoever
    // closed the claim, so the row names the storage service principal.
    let closer = put.transition.and_then(VerifiedClaimTransition::closer);
    let actor_principal = match closer {
        Some(closer) => Some(closer.entity_ref()),
        None if op == ChangeOp::Supersede => None,
        None => put.envelope.map(|envelope| envelope.actor().entity_ref()),
    };
    let occurred_at = put
        .transition
        .and_then(VerifiedClaimTransition::closed_at)
        .unwrap_or(put.occurred.start);
    audit_mutation_in_txn(
        store,
        txn,
        MutationAudit {
            entity: put.id,
            op,
            actor_principal,
            occurred_at,
            input: put.data,
            reason: None,
        },
    )
}
