//! Stored authority bindings and append-only protection for administrative rulings.
use super::rulings::{AdminRulingReceipt, RULING_PREDICATE, ruling_anchor_id};
use super::{FederationGrantScope, decode_federation_grant_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::store::Store;
use crate::{EntityId, Error, Result, TimeRange};

fn invalid() -> Error {
    Error::InvalidClaimBody("administrative ruling authority or immutable history")
}

fn is_ruling(raw: &[u8]) -> Result<bool> {
    let header =
        EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("ruling guard header"))?;
    Ok(header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && raw.len() > ENTITY_METADATA_HEADER_LEN
        && crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?.predicate
            == RULING_PREDICATE)
}

pub(crate) fn reject_ruling_delete(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if let Some(raw) = store.entities.get(txn, id.as_bytes())?
        && is_ruling(&raw)?
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn guard_ruling_overwrite(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
) -> Result<()> {
    if let Some(raw) = store.entities.get(txn, id.as_bytes())?
        && is_ruling(&raw)?
    {
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("ruling header"))?;
        if kind != header.entity_type
            || occurred.start != header.occurred_start
            || occurred.end != header.occurred_end
            || learned_at != header.learned_at
            || data != &raw[ENTITY_METADATA_HEADER_LEN..]
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Malformed or unbound rows are not administrative history. A partially
/// replicated row can become admissible only after its actual grant arrives.
pub(super) fn admitted_ruling(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    learned_at: u64,
) -> Result<Option<AdminRulingReceipt>> {
    if body.predicate != RULING_PREDICATE
        || body.approval != ClaimApprovalStatus::Auto
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
        || body.source != Some(ClaimSource::UserStated)
        || body.world.is_some()
        || body.scope.is_some()
    {
        return Ok(None);
    }
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &body.value).map_err(|_| invalid())?;
    let Ok(receipt) = rmp_serde::from_slice::<AdminRulingReceipt>(&encoded) else {
        return Ok(None);
    };
    let row = &receipt.ruling;
    if row.id != id.to_hex()
        || row.learned_at != learned_at
        || row.ledger_order == 0
        || row.key.trim().is_empty()
        || row.key.len() > 1024
        || body.subject != ClaimSubject::Entity(ruling_anchor_id(row.vault_id)?)
    {
        return Ok(None);
    }
    let (Ok(holder), Ok(grant_ref)) = (
        EntityId::from_hex(&row.holder),
        EntityId::from_hex(&row.grant_ref),
    ) else {
        return Ok(None);
    };
    let Some(rmpv::Value::Map(fields)) = body.evidence.as_ref() else {
        return Ok(None);
    };
    let field = |name: &str| {
        let mut matches = fields.iter().filter(|(k, _)| k.as_str() == Some(name));
        let value = matches.next().map(|(_, v)| v)?;
        matches.next().is_none().then_some(value)
    };
    if !matches!(field(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY), Some(rmpv::Value::Binary(bytes)) if bytes.as_slice() == holder.as_bytes())
        || field(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY)
            .and_then(rmpv::Value::as_u64)
            != Some(crate::EdgeActorClass::Human as u64)
    {
        return Ok(None);
    }
    let Some(raw) = store.entities.get(txn, grant_ref.as_bytes())? else {
        return Ok(None);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("ruling grant header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_FEDERATION_GRANT
        || header.occurred_start > row.learned_at
    {
        return Ok(None);
    }
    let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if grant.scope != FederationGrantScope::vault(row.vault_id)
        || grant.member_ref != holder
        || !grant.is_admin()
        || !grant.confers_at(row.learned_at)
    {
        return Ok(None);
    }
    Ok(Some(receipt))
}

pub(crate) fn validate_ruling_claim(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    learned_at: u64,
    envelope: Option<&crate::WriteEnvelope>,
    replicated: bool,
) -> Result<()> {
    if body.predicate != RULING_PREDICATE || replicated {
        return Ok(());
    }
    // Replay stores data; only the fold grants it administrative effect, once
    // referenced grants are present. Local authoring must bind a real envelope.
    let receipt = admitted_ruling(store, txn, id, body, learned_at)?.ok_or_else(invalid)?;
    if !envelope.is_some_and(|e| {
        e.actor().actor_class() == crate::EdgeActorClass::Human
            && e.actor().entity_ref().to_hex() == receipt.ruling.holder
    }) {
        return Err(invalid());
    }
    Ok(())
}
