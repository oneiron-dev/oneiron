//! Local write-door authentication for manifest contributions. Replay never creates permits.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;
use crate::{EntityId, Vault};

fn key(id: &EntityId, prefix: &str) -> String {
    format!("manifest:{prefix}:{}", id.to_hex())
}

pub(crate) fn trusted_manifest_key(id: &EntityId) -> String {
    key(id, "trusted")
}
/// Body-bound seed origin, distinct from trust. An owner write clears this key.
pub(crate) fn seeded_manifest_key(id: &EntityId) -> String {
    key(id, "seeded_confidence")
}

pub(crate) fn manifest_is_seeded_default(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(store
        .sync_state
        .get(txn, &seeded_manifest_key(id))?
        .is_some_and(|hash| hash.as_ref() == blake3::hash(body).as_bytes()))
}

pub(crate) fn stamp_manifest_origin(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &[u8],
    replicated: bool,
) -> Result<()> {
    let hash = blake3::hash(body);
    let origin_key = trusted_manifest_key(id);
    let seed_key = seeded_manifest_key(id);
    if !replicated {
        // Every local re-authoring is authored even if it keeps the seeded ID,
        // pack name or byte-identical default value.
        store.sync_state.delete(txn, &seed_key)?;
        store.sync_state.put(txn, &origin_key, hash.as_bytes())?;
    } else {
        let existing_matches = store.entities.get(txn, id.as_bytes())?.is_some_and(|raw| {
            EntityMetadataHeader::parse(&raw)
                .is_some_and(|h| h.entity_type == ENTITY_TYPE_POLICY_MANIFEST)
                && raw.get(ENTITY_METADATA_HEADER_LEN..) == Some(body)
        });
        if !existing_matches
            || store
                .sync_state
                .get(txn, &seed_key)?
                .is_none_or(|old| old.as_ref() != hash.as_bytes())
        {
            store.sync_state.delete(txn, &seed_key)?;
        }
        if !existing_matches
            || store
                .sync_state
                .get(txn, &origin_key)?
                .is_none_or(|old| old.as_ref() != hash.as_bytes())
        {
            store.sync_state.delete(txn, &origin_key)?;
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
    Ok(store
        .sync_state
        .get(txn, &key(id, "trusted"))?
        .is_some_and(|hash| hash.as_ref() == blake3::hash(body).as_bytes()))
}

pub(in crate::gate) fn manifest_is_quarantined(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(store
        .sync_state
        .get(txn, &key(id, "quarantined"))?
        .is_some_and(|hash| hash.as_ref() == blake3::hash(body).as_bytes()))
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
        self.store
            .sync_state
            .put(&mut txn, &key(&id, "quarantined"), hash.as_bytes())?;
        txn.commit()?;
        Ok(())
    }

    /// Shared owner-authenticated manifest write door. Fixture policies and
    /// re-authoring take the same decode, target-type and write checks.
    pub(crate) fn write_owner_policy_manifest_in_txn(
        &self,
        owner: &AuthenticatedOwner,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: Vec<u8>,
        now: u64,
    ) -> Result<()> {
        owner.revalidate_in_txn(self, txn)?;
        if super::decode::decode_policy_manifest(&data).is_none() {
            return Err(Error::InvalidConfig("malformed policy manifest".into()));
        }
        if let Some(raw) = self.store.entities.get(txn, id.as_bytes())? {
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("policy manifest header"))?;
            if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
                return Err(Error::InvalidConfig(
                    "policy manifest id belongs to another entity".into(),
                ));
            }
        }
        crate::batch::apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id,
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
        )
    }

    /// Installs a locally authored policy manifest through the authenticated
    /// owner door. Hosts can grant connector effects without bypassing origin
    /// attestation or writing a reserved maintenance type through `put_entity`.
    ///
    /// # Errors
    /// Refuses unauthenticated owners, malformed manifests or IDs owned by another type.
    pub fn install_owner_policy_manifest(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        data: Vec<u8>,
        now: u64,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, id, data, now)?;
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
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, target, data, now)?;
        self.store
            .sync_state
            .put(&mut txn, &key(&legacy, "rekey"), target.as_bytes())?;
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
    if kind == ENTITY_TYPE_POLICY_MANIFEST
        && (super::project_depth::is_project_depth_id(id)
            || super::project_depth::is_project_depth_contribution(body))
    {
        // A signed project policy is authenticated by its immutable carrier
        // and authority fold, never the local-only trusted-manifest sidecar.
        store.sync_state.delete(txn, &trusted_manifest_key(id))?;
    } else if kind == ENTITY_TYPE_POLICY_MANIFEST {
        stamp_manifest_origin(store, txn, id, body, replicated)?;
    } else {
        store.sync_state.delete(txn, &trusted_manifest_key(id))?;
    }
    Ok(())
}
