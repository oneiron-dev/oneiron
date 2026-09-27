//! Candidate-owned custody for inert refinement rulings. Content lives in
//! ordinary scanned ASSET rows; indexes, latest pointers and retirements carry
//! only opaque ids. Neither an ASSET nor a receipt grants write authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ClaimRefinementMergeReceipt, SharedSkillMergeReceipt, package_codec::invalid};
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
const OWNED: &[u8] = b"skill_hub/refinement-owned/v1\0";
const BINDING: &[u8] = b"skill_hub/refinement-binding/v1\0";
const LATEST: &[u8] = b"skill_hub/refinement-latest/v1\0";
const RETIRED_HOLDER: &[u8] = b"skill_hub/refinement-holder-retired/v1\0";
const RETIRED_SOURCE: &[u8] = b"skill_hub/refinement-source-retired/v1\0";
const ERASE_CHUNK: usize = 128;

fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut out = prefix.to_vec();
    out.extend_from_slice(id.as_bytes());
    out
}
fn owned_key(prefix: &[u8], candidate: &EntityId, receipt: &EntityId) -> Vec<u8> {
    let mut out = key(prefix, candidate);
    out.extend_from_slice(receipt.as_bytes());
    out
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
    if store.vault_meta.get(txn, &key(BINDING, id))?.is_some() && source.is_none() {
        return Err(invalid("refinement source id cannot change type"));
    }
    let Some((candidate, ruling, _)) = source else {
        return Ok(());
    };
    if *id == candidate
        || receipt_id(&candidate, &ruling)? != *id
        || store
            .vault_meta
            .get(txn, &key(RETIRED_HOLDER, &candidate))?
            .is_some()
        || super::refinement_admission::read_control(store, txn, &candidate)?.is_some_and(
            |control| control.state == super::refinement_admission::RefinementState::Erased,
        )
        || store
            .vault_meta
            .get(txn, &key(RETIRED_SOURCE, id))?
            .is_some()
        || store
            .sync_state
            .get(txn, &format!("dt:{}", candidate.to_hex()))?
            .is_some()
    {
        return Err(invalid("retired or misbound refinement carrier"));
    }
    if let Some(bound) = store.vault_meta.get(txn, &key(BINDING, id))?
        && bound.as_ref() != candidate.as_bytes()
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
        store
            .vault_meta
            .put(txn, &key(BINDING, id), candidate.as_bytes())?;
        store
            .vault_meta
            .put(txn, &owned_key(OWNED, &candidate, id), &[])?;
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
        let latest_key = key(LATEST, &candidate);
        let prior = self.store.vault_meta.get(txn, &latest_key)?;
        let replace = match prior {
            Some(ref prior) if prior.len() == 32 => ruling.as_bytes().as_slice() >= &prior[..16],
            Some(_) => return Err(Error::CorruptedIndex("refinement latest pointer")),
            None => true,
        };
        if replace {
            let mut pointer = ruling.as_bytes().to_vec();
            pointer.extend_from_slice(id.as_bytes());
            self.store.vault_meta.put(txn, &latest_key, &pointer)?;
        }
        Ok(())
    }
    pub(super) fn latest_refinement_receipt_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        candidate: EntityId,
    ) -> Result<Option<RefinementReceipt>> {
        if self
            .store
            .vault_meta
            .get(txn, &key(RETIRED_HOLDER, &candidate))?
            .is_some()
        {
            return Ok(None);
        }
        let Some(id) = self.store.vault_meta.get(txn, &key(LATEST, &candidate))? else {
            return Ok(None);
        };
        if id.len() != 32 {
            return Err(Error::CorruptedIndex("refinement latest pointer"));
        }
        let id = crate::entity_id::parse_entity_id(&id[16..], "refinement latest receipt")?;
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
    let mut cursor = store.vault_meta.prefix_iter(txn, &key(OWNED, candidate))?;
    Ok(cursor.next().transpose()?.is_some()
        || store
            .vault_meta
            .get(txn, &key(LATEST, candidate))?
            .is_some())
}

/// Source-id deletion drops ownership and retains only a content-free ID fence.
pub(crate) fn remove_refinement_carrier_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(holder_bytes) = store.vault_meta.get(txn, &key(BINDING, id))? else {
        return Ok(());
    };
    let holder = crate::entity_id::parse_entity_id(&holder_bytes, "refinement source holder")?;
    store
        .vault_meta
        .delete(txn, &owned_key(OWNED, &holder, id))?;
    if store
        .vault_meta
        .get(txn, &key(LATEST, &holder))?
        .is_some_and(|pointer| pointer.len() == 32 && &pointer[16..] == id.as_bytes())
    {
        store.vault_meta.delete(txn, &key(LATEST, &holder))?;
    }
    store.vault_meta.put(txn, &key(RETIRED_SOURCE, id), &[])?;
    Ok(())
}

/// A replayed soft tombstone can arrive before a carrier or even its holder.
/// Close the holder id so delayed ASSET replay cannot reintroduce payload.
pub(crate) fn retire_refinement_holder_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    candidate: &EntityId,
) -> Result<()> {
    store
        .vault_meta
        .put(txn, &key(RETIRED_HOLDER, candidate), &[])?;
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
    store
        .vault_meta
        .put(txn, &key(RETIRED_HOLDER, candidate), &[])?;
    store.vault_meta.delete(txn, &key(LATEST, candidate))?;
    loop {
        let prefix = key(OWNED, candidate);
        let ids: Vec<EntityId> = store
            .vault_meta
            .prefix_iter(&*txn, &prefix)?
            .take(ERASE_CHUNK)
            .map(|entry| {
                let (row_key, _) = entry?;
                crate::entity_id::parse_entity_id(
                    &row_key[prefix.len()..],
                    "refinement owned source",
                )
            })
            .collect::<Result<_>>()?;
        if ids.is_empty() {
            break;
        }
        for id in ids {
            if store.vault_meta.get(txn, &key(BINDING, &id))?.as_deref()
                != Some(candidate.as_bytes().as_slice())
            {
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
    let prefix = key(OWNED, candidate);
    store
        .vault_meta
        .prefix_iter(txn, &prefix)?
        .map(|entry| {
            let (row_key, _) = entry?;
            crate::entity_id::parse_entity_id(&row_key[prefix.len()..], "refinement source id")
        })
        .collect()
}

#[cfg(test)]
mod tests;
