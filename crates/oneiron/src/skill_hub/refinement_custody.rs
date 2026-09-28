//! Candidate-owned custody for inert refinement rulings. Content lives in
//! ordinary scanned ASSET rows; indexes, latest pointers and retirements carry
//! only opaque ids. Neither an ASSET nor a receipt grants write authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ClaimRefinementMergeReceipt, SharedSkillMergeReceipt, package_codec::invalid};
use crate::side_table::{self, CodecError, HexId, Raw, RawValue, SideTable};
use crate::{
    Vault,
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    entity_id::EntityId,
    error::{Error, Result},
    registry::ENTITY_TYPE_ASSET,
    store::Store,
    temporal::TimeRange,
};

const MAGIC: &[u8] = b"oneiron.refinement-receipt.v1\0";
const DOMAIN: &[u8] = b"oneiron.refinement-receipt.asset.v1\0";
/// Empty marker per (holder, carrier id) the holder currently owns.
const OWNED: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_OWNED);
/// Carrier id to the holder (candidate) it was indexed under.
const BINDING: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_BINDING);
/// The local gate's latest ruling for a holder.
const LATEST: SideTable<EntityId, LatestRuling, Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_LATEST);
/// Empty marker that a holder's custody is permanently closed.
const RETIRED_HOLDER: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_HOLDER_RETIRED);
/// Empty marker that one carrier id is permanently retired.
const RETIRED_SOURCE: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_SOURCE_RETIRED);
/// The ARCH-0023b global local hard-delete marker (owned by
/// `crate::deletion::tombstone`); read-only here for the retired-holder check.
const HARD_DELETE_MARKER: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_HARD_DELETE_MARKER);
const ERASE_CHUNK: usize = 128;

/// Latest-ruling pointer: the ruling id, then the carrier id (32 bytes).
struct LatestRuling {
    ruling: [u8; 16],
    carrier: [u8; 16],
}

impl RawValue for LatestRuling {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok([self.ruling, self.carrier].concat())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes.len() != 32 {
            return Err(Error::CorruptedIndex("refinement latest pointer").into());
        }
        let mut ruling = [0; 16];
        let mut carrier = [0; 16];
        ruling.copy_from_slice(&bytes[..16]);
        carrier.copy_from_slice(&bytes[16..]);
        Ok(Self { ruling, carrier })
    }
}

fn receipt_id(candidate: &EntityId, ruling: &EntityId) -> Result<EntityId> {
    let hash = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(candidate.as_bytes())
        .chain_update(ruling.as_bytes())
        .finalize();
    EntityId::from_bytes(
        hash[..16]
            .try_into()
            .map_err(|_| invalid("receipt id width"))?,
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "receipt",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum RefinementReceipt {
    Skill(SharedSkillMergeReceipt),
    Claim(ClaimRefinementMergeReceipt),
}
impl RefinementReceipt {
    fn identity(&self) -> Result<(EntityId, EntityId)> {
        let (candidate, ruling) = match self {
            Self::Skill(row) => (&row.delta.candidate, &row.receipt_id),
            Self::Claim(row) => (&row.candidate, &row.receipt_id),
        };
        Ok((EntityId::from_hex(candidate)?, EntityId::from_hex(ruling)?))
    }
}
fn encode(candidate: &EntityId, receipt: &RefinementReceipt) -> Result<(EntityId, Vec<u8>)> {
    let (bound, ruling) = receipt.identity()?;
    if bound != *candidate {
        return Err(invalid("refinement receipt candidate moved"));
    }
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(candidate.as_bytes());
    bytes.extend_from_slice(ruling.as_bytes());
    bytes.extend_from_slice(
        &serde_json::to_vec(receipt).map_err(|_| invalid("receipt encode failed"))?,
    );
    Ok((receipt_id(candidate, &ruling)?, bytes))
}
fn decode(bytes: &[u8]) -> Result<Option<(EntityId, EntityId, RefinementReceipt)>> {
    let Some(rest) = bytes.strip_prefix(MAGIC) else {
        return Ok(None);
    };
    let candidate = EntityId::from_bytes(
        rest.get(..16)
            .ok_or_else(|| invalid("truncated receipt candidate"))?
            .try_into()
            .map_err(|_| invalid("receipt candidate width"))?,
    )?;
    let ruling = EntityId::from_bytes(
        rest.get(16..32)
            .ok_or_else(|| invalid("truncated receipt id"))?
            .try_into()
            .map_err(|_| invalid("receipt id width"))?,
    )?;
    let payload: RefinementReceipt = serde_json::from_slice(&rest[32..])
        .map_err(|_| invalid("invalid refinement receipt body"))?;
    if encode(&candidate, &payload)? != (receipt_id(&candidate, &ruling)?, bytes.to_vec()) {
        return Err(invalid("noncanonical refinement receipt"));
    }
    Ok(Some((candidate, ruling, payload)))
}

/// A malformed carrier can still be scrubbed by its fixed holder prefix.
#[cfg(feature = "sync")]
pub(crate) fn refinement_carrier_holder(bytes: &[u8]) -> Option<EntityId> {
    EntityId::from_bytes(bytes.strip_prefix(MAGIC)?.get(..16)?.try_into().ok()?).ok()
}
#[cfg(feature = "sync")]
pub(crate) fn refinement_carrier_matches_id(bytes: &[u8], id: &EntityId) -> bool {
    decode(bytes)
        .ok()
        .flatten()
        .and_then(|(candidate, ruling, _)| receipt_id(&candidate, &ruling).ok())
        == Some(*id)
}

/// The batch put door invokes this on both local and replicated ASSET puts.
pub(crate) fn validate_refinement_carrier_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    bytes: &[u8],
) -> Result<()> {
    let source = if kind == ENTITY_TYPE_ASSET {
        decode(bytes)?
    } else {
        None
    };
    if BINDING.contains(store, txn, id)? && source.is_none() {
        return Err(invalid("refinement source id cannot change type"));
    }
    let Some((candidate, ruling, _)) = source else {
        return Ok(());
    };
    if *id == candidate
        || receipt_id(&candidate, &ruling)? != *id
        || RETIRED_HOLDER.contains(store, txn, &candidate)?
        || super::refinement_admission::read_control(store, txn, &candidate)?.is_some_and(
            |control| control.state == super::refinement_admission::RefinementState::Erased,
        )
        || RETIRED_SOURCE.contains(store, txn, id)?
        || HARD_DELETE_MARKER.contains(store, txn, &HexId(candidate))?
    {
        return Err(invalid("retired or misbound refinement carrier"));
    }
    if let Some(bound) = BINDING.get(store, txn, id)?
        && bound != candidate
    {
        return Err(Error::CorruptedIndex("refinement carrier binding"));
    }
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? {
        let head = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("refinement carrier header"))?;
        if head.entity_type != ENTITY_TYPE_ASSET || raw[ENTITY_METADATA_HEADER_LEN..] != *bytes {
            return Err(invalid("refinement carrier cannot be overwritten"));
        }
    }
    Ok(())
}
/// Index the exact bytes only AFTER all put refusals have passed.
pub(crate) fn stage_refinement_carrier_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    kind: u8,
    bytes: &[u8],
) -> Result<()> {
    if kind == ENTITY_TYPE_ASSET
        && let Some((candidate, _, _)) = decode(bytes)?
    {
        BINDING.put(store, txn, id, &candidate)?;
        OWNED.put(store, txn, &(candidate, *id), &())?;
        // Deliberately NO latest projection: a raw or replicated inert source
        // cannot claim to be the local gate's authoritative ruling.
    }
    Ok(())
}

impl Vault {
    pub(super) fn put_refinement_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        candidate: EntityId,
        receipt: RefinementReceipt,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let (_, ruling) = receipt.identity()?;
        let (id, bytes) = encode(&candidate, &receipt)?;
        self.batch_in()
            .put(&id, ENTITY_TYPE_ASSET, occurred, learned_at, &bytes)
            .apply(txn)?;
        // Only this private same-transaction gate writer selects a latest
        // ruling. An imported ASSET still gets indexed for custody, never
        // promoted into the local decision ledger.
        let replace = LATEST
            .get(&self.store, txn, &candidate)?
            .is_none_or(|prior| *ruling.as_bytes() >= prior.ruling);
        if replace {
            let pointer = LatestRuling {
                ruling: *ruling.as_bytes(),
                carrier: *id.as_bytes(),
            };
            LATEST.put(&self.store, txn, &candidate, &pointer)?;
        }
        Ok(())
    }
    pub(super) fn latest_refinement_receipt_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        candidate: EntityId,
    ) -> Result<Option<RefinementReceipt>> {
        if RETIRED_HOLDER.contains(&self.store, txn, &candidate)? {
            return Ok(None);
        }
        let Some(pointer) = LATEST.get(&self.store, txn, &candidate)? else {
            return Ok(None);
        };
        let id = crate::entity_id::parse_entity_id(&pointer.carrier, "refinement latest receipt")?;
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &id)?
            .ok_or(Error::CorruptedIndex("refinement latest source"))?;
        let head = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("refinement source header"))?;
        if head.entity_type != ENTITY_TYPE_ASSET {
            return Err(Error::CorruptedIndex("refinement source kind"));
        }
        let (holder, ruling, payload) = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?
            .ok_or(Error::CorruptedIndex("refinement source body"))?;
        if holder != candidate || receipt_id(&holder, &ruling)? != id {
            return Err(Error::CorruptedIndex("refinement latest binding"));
        }
        Ok(Some(payload))
    }
}

/// The active payload scope is the candidate's OWNED prefix, not a scan of
/// unrelated receipt bodies or a remembered latest pointer.
pub(crate) fn refinement_custody_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    candidate: &EntityId,
) -> Result<bool> {
    let mut owned = OWNED.iter_raw_from(store, txn, candidate.as_bytes())?;
    Ok(owned.next().transpose()?.is_some() || LATEST.contains(store, txn, candidate)?)
}

/// Source-id deletion drops ownership and retains only a content-free ID fence.
pub(crate) fn remove_refinement_carrier_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(holder) = BINDING.get(store, txn, id)? else {
        return Ok(());
    };
    OWNED.delete(store, txn, &(holder, *id))?;
    // A malformed pointer is left in place, as before: only a well-formed
    // pointer naming this carrier is dropped.
    if LATEST
        .get_lenient(store, txn, &holder)?
        .is_some_and(|pointer| pointer.carrier == *id.as_bytes())
    {
        LATEST.delete(store, txn, &holder)?;
    }
    RETIRED_SOURCE.put(store, txn, id, &())?;
    Ok(())
}

/// A replayed soft tombstone can arrive before a carrier or even its holder.
/// Close the holder id so delayed ASSET replay cannot reintroduce payload.
pub(crate) fn retire_refinement_holder_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    candidate: &EntityId,
) -> Result<()> {
    RETIRED_HOLDER.put(store, txn, candidate, &())?;
    erase_refinement_custody_in_txn(store, txn, candidate)?;
    Ok(())
}

/// Erase at most 128 carrier ids per iteration. Removing the OWNED key makes
/// the next prefix cursor start at new work; no total-history delete ceiling.
pub(crate) fn erase_refinement_custody_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    candidate: &EntityId,
) -> Result<bool> {
    let had_payload = refinement_custody_exists_in_txn(store, txn, candidate)?;
    if !had_payload {
        return Ok(false);
    }
    RETIRED_HOLDER.put(store, txn, candidate, &())?;
    LATEST.delete(store, txn, candidate)?;
    loop {
        let ids: Vec<EntityId> = OWNED
            .iter_from(store, &*txn, candidate.as_bytes())?
            .take(ERASE_CHUNK)
            .map(|entry| entry.map(|((_, id), ())| id))
            .collect::<Result<_>>()?;
        if ids.is_empty() {
            break;
        }
        for id in ids {
            if BINDING.get(store, txn, &id)? != Some(*candidate) {
                return Err(Error::CorruptedIndex("refinement owned source binding"));
            }
            if crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?.is_some() {
                let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, &id)?;
                crate::ppr::invalidate_ppr_for_delete(store, txn, &id, &neighbors)?;
                if graph {
                    crate::ppr::increment_graph_version(store, txn)?;
                }
                if vector {
                    crate::hnsw::increment_vector_version(store, txn)?;
                }
            } else {
                remove_refinement_carrier_in_txn(store, txn, &id)?;
            }
        }
    }
    Ok(true)
}
/// Test-only inspection of currently owned carrier ids; deletion itself is
/// chunked and never materializes this unbounded set.
#[cfg(test)]
pub(crate) fn refinement_carriers_for_holder_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    candidate: &EntityId,
) -> Result<Vec<EntityId>> {
    OWNED
        .iter_from(store, txn, candidate.as_bytes())?
        .map(|entry| entry.map(|((_, id), ())| id))
        .collect()
}

#[cfg(test)]
mod tests;
