//! Local write-door authentication for manifest contributions. Replay never creates permits.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

/// Authenticity hash stamped when a policy manifest is contributed directly (non-replicated).
/// Key: hex32.
const TRUSTED_ORIGIN: SideTable<HexId, [u8; 32], Raw> =
    SideTable::new(&side_table::GATE_MANIFEST_TRUSTED_ORIGIN);
/// Marks a policy-manifest contribution as quarantined by an explicit owner action. Key: hex32.
const QUARANTINED: SideTable<HexId, [u8; 32], Raw> =
    SideTable::new(&side_table::GATE_MANIFEST_QUARANTINED);
/// Maps a legacy policy-manifest id forward to its re-authored replacement id. Key: hex32.
const REKEY: SideTable<HexId, EntityId, Raw> = SideTable::new(&side_table::GATE_MANIFEST_REKEY);

/// `store::handle`'s vault-bootstrap seed writes this row directly, before any vault (and so any
/// typed door) exists to read it back through — kept as a plain string builder so that raw write
/// keeps landing under [`TRUSTED_ORIGIN`]'s declared prefix byte-for-byte.
pub(crate) fn trusted_manifest_key(id: &EntityId) -> String {
    format!("manifest:trusted:{}", id.to_hex())
}
pub(crate) fn stamp_manifest_origin(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &[u8],
    replicated: bool,
) -> Result<()> {
    let hash = blake3::hash(body);
    let origin_key = HexId(*id);
    if !replicated {
        TRUSTED_ORIGIN.put(store, txn, &origin_key, hash.as_bytes())?;
    } else {
        let existing_matches = store.entities.get(txn, id.as_bytes())?.is_some_and(|raw| {
            EntityMetadataHeader::parse(&raw)
                .is_some_and(|h| h.entity_type == ENTITY_TYPE_POLICY_MANIFEST)
                && raw.get(ENTITY_METADATA_HEADER_LEN..) == Some(body)
        });
        if !existing_matches
            || TRUSTED_ORIGIN
                .get(store, txn, &origin_key)?
                .is_none_or(|old| old != *hash.as_bytes())
        {
            TRUSTED_ORIGIN.delete(store, txn, &origin_key)?;
        }
    }
    Ok(())
}

pub(crate) fn manifest_is_trusted(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(TRUSTED_ORIGIN
        .get(store, txn, &HexId(*id))?
        .is_some_and(|hash| hash == *blake3::hash(body).as_bytes()))
}

pub(in crate::gate) fn manifest_is_quarantined(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(QUARANTINED
        .get(store, txn, &HexId(*id))?
        .is_some_and(|hash| hash == *blake3::hash(body).as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ManifestContribution {
    pub id: String,
    pub trusted: bool,
    pub restrict_only: bool,
    pub quarantined: bool,
}
impl Vault {
    /// Surface unauthenticated narrowing as actionable rows, without granting it authority.
    pub fn manifest_contributions(&self) -> Result<Vec<ManifestContribution>> {
        let txn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for row in self
            .store
            .type_index
            .prefix_iter(&txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
        {
            let (index, _) = row?;
            let id = crate::vault::entity_id_from_type_index_key(&index)?;
            let raw = self
                .store
                .entities
                .get(&txn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("manifest contribution"))?;
            let body = raw
                .get(ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("manifest contribution header"))?;
            let trusted = manifest_is_trusted(&self.store, &txn, &id, body)?;
            out.push(ManifestContribution {
                id: id.to_hex(),
                trusted,
                restrict_only: !trusted,
                quarantined: manifest_is_quarantined(&self.store, &txn, &id, body)?,
            });
        }
        Ok(out)
    }

    /// Human removal of an untrusted narrowing, pinned to these exact bytes.
    pub fn quarantine_manifest_contribution(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let raw = self
            .store
            .entities
            .get(&txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|h| h.entity_type != ENTITY_TYPE_POLICY_MANIFEST)
        {
            return Err(Error::InvalidConfig("not a policy manifest".into()));
        }
        let hash = blake3::hash(&raw[ENTITY_METADATA_HEADER_LEN..]);
        QUARANTINED.put(&self.store, &mut txn, &HexId(id), hash.as_bytes())?;
        txn.commit()?;
        Ok(())
    }

    /// Explicit owner re-authoring, never grandfathering a product-band permit.
    /// The legacy carrier remains inert; the mapping records the re-key provenance.
    pub fn reauthor_legacy_policy_manifest(
        &self,
        owner: &AuthenticatedOwner,
        legacy: EntityId,
        target: EntityId,
        now: u64,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let raw = self
            .store
            .entities
            .get(&txn, legacy.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("legacy manifest header"))?;
        if crate::registry::zone_of(header.entity_type)
            != crate::registry::TypeByteZone::CompiledProduct
            || self.store.entities.get(&txn, target.as_bytes())?.is_some()
        {
            return Err(Error::InvalidConfig(
                "manifest re-key requires legacy source and fresh target".into(),
            ));
        }
        let data = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        if super::decode::decode_policy_manifest(&data).is_none() {
            return Err(Error::InvalidConfig("malformed legacy manifest".into()));
        }
        crate::batch::apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut txn,
            vec![crate::batch::BatchOp::Put {
                id: target,
                entity_type: ENTITY_TYPE_POLICY_MANIFEST,
                occurred: crate::TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        REKEY.put(&self.store, &mut txn, &HexId(legacy), &target)?;
        txn.commit()?;
        Ok(())
    }
}

pub(crate) fn update_manifest_origin(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    kind: u8,
    body: &[u8],
    replicated: bool,
) -> Result<()> {
    if kind == ENTITY_TYPE_POLICY_MANIFEST {
        stamp_manifest_origin(store, txn, id, body, replicated)?;
    } else {
        TRUSTED_ORIGIN.delete(store, txn, &HexId(*id))?;
    }
    Ok(())
}
