//! Source-only retirement and payload cleanup, shared by local/raw/replay/erase.
//! Retained index rows contain only holder/hash identities, never source bytes.
use super::package_codec::invalid;
use super::source_carrier::{decode_source_carrier, source_carrier_id};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SKILL};
use crate::side_table::{self, CodecError, HexId, Raw, RawValue, SideTable};
use crate::skill::{SkillContentHash, SkillRecord};
use crate::store::Store;

/// Source-custody state for one (holder, content hash) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyState {
    Live,
    Dead,
    Unseen,
}

impl RawValue for CustodyState {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![match self {
            Self::Live => 0,
            Self::Dead => 1,
            Self::Unseen => 2,
        }])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes {
            [0] => Ok(Self::Live),
            [1] => Ok(Self::Dead),
            [2] => Ok(Self::Unseen),
            _ => Err(Error::CorruptedIndex("source custody index value").into()),
        }
    }
}

/// Source-custody state (live/dead/unseen byte) for one (holder, content
/// hash) pair.
const INDEX: SideTable<(EntityId, [u8; 32]), CustodyState, Raw> =
    SideTable::new(&side_table::SKILL_HUB_SOURCE_CUSTODY);
/// Empty-marker that a source holder's custody has been permanently retired.
const RETIRED: SideTable<EntityId, (), Raw> = SideTable::new(&side_table::SKILL_HUB_SOURCE_RETIRED);
/// The ARCH-0023b global local hard-delete marker (owned by
/// `crate::deletion::tombstone`); read-only here for the retired/deleted check.
const HARD_DELETE_MARKER: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_HARD_DELETE_MARKER);

/// Fixed 48-byte carrier/hash binding recorded for a pending or materialized
/// source holder.
struct SourceBinding {
    holder: EntityId,
    hash: SkillContentHash,
}

impl RawValue for SourceBinding {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = self.holder.as_bytes().to_vec();
        out.extend_from_slice(self.hash.as_bytes());
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes.len() != 48 {
            return Err(Error::CorruptedIndex("source binding").into());
        }
        let holder = crate::entity_id::parse_entity_id(&bytes[..16], "source binding holder")?;
        let hash: [u8; 32] = bytes[16..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("source binding hash"))?;
        Ok(Self {
            holder,
            hash: SkillContentHash::from_bytes(hash),
        })
    }
}

const BINDING: SideTable<EntityId, SourceBinding, Raw> =
    SideTable::new(&side_table::SKILL_HUB_SOURCE_BINDING);

/// Pure preflight: a retired holder/revision cannot regain its byte custody.
/// An absent holder is allowed so clean sync orders remain symmetric.
pub(super) fn check_source_custody(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
    hash: &SkillContentHash,
) -> Result<()> {
    if store.off_record_sessions.contains_entity(holder)? {
        return Err(Error::OffRecord(
            OffRecordError::OffRecordTaintedBaseWrite {
                entity_ref: holder.to_hex(),
            },
        ));
    }
    check_source_target(store, txn, holder)?;
    if INDEX
        .get(store, txn, &(*holder, *hash.as_bytes()))?
        .is_some_and(|state| state != CustodyState::Live)
    {
        return Err(invalid("source custody has been retired"));
    }
    if let Some(raw) = store.entities.get(txn, holder.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("source holder header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL || raw.len() == ENTITY_METADATA_HEADER_LEN {
            return Err(invalid(
                "source holder must be a live SKILL or not yet materialized",
            ));
        }
    }
    Ok(())
}

pub(super) fn check_source_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if RETIRED.contains(store, txn, id)? || HARD_DELETE_MARKER.contains(store, txn, &HexId(*id))? {
        return Err(invalid("source custody target has been retired"));
    }
    Ok(())
}

/// A once-admitted source ID cannot be reused as an unrelated entity after
/// erasure. This binds only that concrete ID; it reserves no generic namespace.
pub(super) fn validate_registered_source_target(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    bytes: &[u8],
) -> Result<()> {
    let Some(binding) = BINDING.get(store, txn, id)? else {
        return Ok(());
    };
    if entity_type != ENTITY_TYPE_ASSET {
        return Err(invalid("source ID cannot change type"));
    }
    let Some((holder, package)) = decode_source_carrier(bytes)? else {
        return Err(invalid("source ID cannot become an unrelated asset"));
    };
    if binding.holder != holder || binding.hash != package.content_hash()? {
        return Err(invalid("source ID binding changed"));
    }
    Ok(())
}

fn source_rows(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<Vec<(SkillContentHash, CustodyState)>> {
    Ok(INDEX
        .scan_from(store, txn, holder.as_bytes())?
        .into_iter()
        .map(|((_, hash), state)| (SkillContentHash::from_bytes(hash), state))
        .collect())
}

pub(crate) fn source_custody_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<bool> {
    Ok(source_rows(store, txn, holder)?
        .iter()
        .any(|(_, state)| *state == CustodyState::Live))
}

/// Only IDs remain after deletion, so the existing hard-history sweep can
/// cover every revision and pending carrier without retaining its payload.
pub(crate) fn source_carriers_for_holder_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    holder: &EntityId,
) -> Result<Vec<EntityId>> {
    source_rows(store, txn, holder)?
        .iter()
        .filter(|(_, state)| *state != CustodyState::Unseen)
        .map(|(hash, _)| source_carrier_id(holder, hash))
        .collect()
}

/// Called after all put refusals and before commit. Source revisions retire
/// only the prior hash, never a pending new version or another SKILL holder.
pub(crate) fn stage_source_custody_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    bytes: &[u8],
    previous: Option<&SkillRecord>,
    current: Option<&SkillRecord>,
) -> Result<()> {
    if entity_type == ENTITY_TYPE_ASSET
        && let Some((holder, package)) = decode_source_carrier(bytes)?
    {
        let hash = package.content_hash()?;
        BINDING.put(store, txn, id, &SourceBinding { holder, hash })?;
        INDEX.put(store, txn, &(holder, *hash.as_bytes()), &CustodyState::Live)?;
    }
    // A pending source cannot reserve another entity's kind. If the actual
    // holder is born as a non-SKILL, discard those invalid pending carriers
    // without refusing that unrelated entity or minting deletion authority.
    if entity_type != ENTITY_TYPE_SKILL {
        for (hash, state) in source_rows(store, txn, id)? {
            if state == CustodyState::Live {
                retire_revision(store, txn, id, &hash)?;
            }
        }
    }
    if let (Some(previous), Some(current)) = (previous, current)
        && previous.content_hash != current.content_hash
    {
        super::package_codec::remove_package_sidecar_in_txn(store, txn, id)?;
        if let Some(hash) = previous.content_hash {
            retire_revision(store, txn, id, &hash)?;
        }
    }
    Ok(())
}

fn retire_revision(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    holder: &EntityId,
    hash: &SkillContentHash,
) -> Result<()> {
    let carrier = source_carrier_id(holder, hash)?;
    let seen = BINDING.contains(store, txn, &carrier)?;
    // Do not remove an unrelated row that merely occupies a derived ID.
    if seen && let Some(raw) = store.entities.get(txn, carrier.as_bytes())? {
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("source custody carrier header"))?;
        if header.entity_type != ENTITY_TYPE_ASSET {
            return Err(Error::CorruptedIndex("source custody carrier type"));
        }
        let (bound_holder, package) = decode_source_carrier(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::CorruptedIndex("source custody carrier body"))?
            .ok_or(Error::CorruptedIndex("source custody carrier body"))?;
        if bound_holder != *holder
            || package
                .content_hash()
                .map_err(|_| Error::CorruptedIndex("source custody carrier hash"))?
                != *hash
        {
            return Err(Error::CorruptedIndex("source custody carrier binding"));
        }
        let (_, vector, graph, neighbors) = crate::batch::deindex_entity(store, txn, &carrier)?;
        crate::ppr::invalidate_ppr_for_delete(store, txn, &carrier, &neighbors)?;
        if graph {
            crate::ppr::increment_graph_version(store, txn)?;
        }
        if vector {
            crate::hnsw::increment_vector_version(store, txn)?;
        }
    }
    INDEX.put(
        store,
        txn,
        &(*holder, *hash.as_bytes()),
        &if seen {
            CustodyState::Dead
        } else {
            CustodyState::Unseen
        },
    )?;
    Ok(())
}

/// Source-only denial fact, not a fabricated generic tombstone or delete grant.
/// Replay calls this even when the holder has never had a local header.
pub(crate) fn retire_source_holder_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    holder: &EntityId,
) -> Result<()> {
    RETIRED.put(store, txn, holder, &())?;
    super::package_codec::remove_package_sidecar_in_txn(store, txn, holder)?;
    for (hash, state) in source_rows(store, txn, holder)? {
        if state == CustodyState::Live {
            retire_revision(store, txn, holder, &hash)?;
        }
    }
    Ok(())
}

/// Every active-store purge calls this before tearing down its entity row.
/// Deleting a carrier also deletes the sidecar's duplicate bytes, not its SKILL.
pub(crate) fn remove_source_custody_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let raw = store.entities.get(txn, id.as_bytes())?;
    if let Some(raw) = &raw {
        let header = EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("source delete header"))?;
        if header.entity_type == ENTITY_TYPE_ASSET
            && let Some((holder, package)) =
                decode_source_carrier(&raw[ENTITY_METADATA_HEADER_LEN..])
                    .map_err(|_| Error::CorruptedIndex("source delete body"))?
        {
            let hash = package.content_hash()?;
            if source_carrier_id(&holder, &hash)? != *id {
                return Err(Error::CorruptedIndex("source delete identity"));
            }
            INDEX.put(store, txn, &(holder, *hash.as_bytes()), &CustodyState::Dead)?;
            super::package_codec::remove_matching_package_sidecar_in_txn(
                store, txn, &holder, &hash,
            )?;
            return Ok(());
        }
        if header.entity_type == ENTITY_TYPE_SKILL {
            return retire_source_holder_in_txn(store, txn, id);
        }
    }
    if source_custody_exists_in_txn(store, txn, id)? {
        return retire_source_holder_in_txn(store, txn, id);
    }
    super::package_codec::remove_package_sidecar_in_txn(store, txn, id)
}
