//! Stored authority bindings and append-only protection for administrative rulings.
//!
//! **Issued authority (FIX 8740).** A ruling is admitted against the grant
//! it names. A role change rewrites that grant in place and a removal
//! deletes it, so before either lands, in the same writer (local or
//! replicated), each ruling the stored grant row admits gets an immutable
//! witness: the ruling's id, the grant, and the hash of the grant row that
//! admitted it. A witnessed ruling stays admitted whatever its grant becomes
//! (ARCH-0043: equal holders' rulings, newest wins, the ledger keeps both).
use heed::RwTxn;

use super::rulings::{AdminRulingReceipt, RULING_PREDICATE, ruling_anchor_id};
use super::{FederationGrantScope, decode_federation_grant_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Error, Result, TimeRange};

/// A ruling's admission, kept before the grant row that admitted it changed
/// or went. Key: id16 (the ruling).
const RULING_WITNESS: SideTable<EntityId, RulingWitness, Named> =
    SideTable::new(&side_table::FEDERATION_RULING_WITNESS);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RulingWitness {
    /// The grant the ruling names.
    grant_ref: EntityId,
    /// The blake3 hash of that grant's stored row (header and body) when it
    /// admitted the ruling.
    grant_row: [u8; 32],
}

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
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)?
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
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)?
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
/// A ruling admitted under a grant row since rewritten or deleted keeps that
/// admission through its witness (FIX 8740).
pub(super) fn admitted_ruling(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    learned_at: u64,
) -> Result<Option<AdminRulingReceipt>> {
    let Some((receipt, grant_ref)) = issued_ruling(id, body, learned_at)? else {
        return Ok(None);
    };
    if RULING_WITNESS
        .get(store, txn, id)?
        .is_some_and(|witness| witness.grant_ref == grant_ref)
    {
        return Ok(Some(receipt));
    }
    Ok(grant_admits_in_txn(store, txn, &receipt, grant_ref)?.then_some(receipt))
}

/// The ruling `body` stores under `id`, with the grant it names, when it is
/// well formed and bound to its human holder; `None` for any other row.
fn issued_ruling(
    id: &EntityId,
    body: &ClaimBody,
    learned_at: u64,
) -> Result<Option<(AdminRulingReceipt, EntityId)>> {
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
    Ok(Some((receipt, grant_ref)))
}

/// Whether the grant row stored as `grant_ref` now admits `receipt`'s
/// ruling: a vault Admin grant of its holder that conferred when it was
/// learned.
fn grant_admits_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt: &AdminRulingReceipt,
    grant_ref: EntityId,
) -> Result<bool> {
    let row = &receipt.ruling;
    let Ok(holder) = EntityId::from_hex(&row.holder) else {
        return Ok(false);
    };
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &grant_ref)? else {
        return Ok(false);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("ruling grant header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_FEDERATION_GRANT
        || header.occurred_start > row.learned_at
    {
        return Ok(false);
    }
    let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    Ok(!grant.role.is_guest()
        && grant.scope == FederationGrantScope::vault(row.vault_id)
        && grant.member_ref == holder
        && grant.is_admin()
        && grant.confers_at(row.learned_at))
}

/// Before the FEDERATION_GRANT row stored as `grant`, `row`, is rewritten or
/// deleted, each ruling it admits and no witness keeps yet gets one (FIX
/// 8740). The caller runs this in the writer that changes the row, while
/// `row` is still stored; any other row kind is no grant and is skipped.
///
/// # Errors
/// A store failure, or a grant body that does not decode.
pub(crate) fn witness_grant_rulings_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    grant: &EntityId,
    row: &[u8],
) -> Result<()> {
    if row.len() <= ENTITY_METADATA_HEADER_LEN
        || EntityMetadataHeader::parse(row).is_none_or(|header| {
            header.entity_type != crate::registry::ENTITY_TYPE_FEDERATION_GRANT
        })
    {
        return Ok(());
    }
    let grant_row = *blake3::hash(row).as_bytes();
    let mut admitted = Vec::new();
    for id in crate::claim::claim_ids_for_predicate_in_txn(store, wtxn, RULING_PREDICATE)? {
        if RULING_WITNESS.get(store, wtxn, &id)?.is_some() {
            continue;
        }
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, &id)? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() <= ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
        else {
            continue;
        };
        let Some((receipt, grant_ref)) = issued_ruling(&id, &body, header.learned_at)? else {
            continue;
        };
        if grant_ref == *grant && grant_admits_in_txn(store, wtxn, &receipt, grant_ref)? {
            admitted.push(id);
        }
    }
    for id in admitted {
        RULING_WITNESS.put(
            store,
            wtxn,
            &id,
            &RulingWitness {
                grant_ref: *grant,
                grant_row,
            },
        )?;
    }
    Ok(())
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
