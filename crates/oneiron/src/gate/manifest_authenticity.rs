//! Local write-door authentication for manifest contributions. Replay never creates permits.
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, GateError, Result};
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
/// Body-bound seed origin, distinct from trust: the body hash of an engine-seeded default policy
/// manifest. An owner write clears it. Key: hex32.
const SEEDED: SideTable<HexId, [u8; 32], Raw> =
    SideTable::new(&side_table::GATE_MANIFEST_SEEDED_CONFIDENCE);

/// `store::handle`'s vault-bootstrap seed writes this row directly, before any vault (and so any
/// typed door) exists to read it back through — kept as a plain string builder so that raw write
/// keeps landing under [`TRUSTED_ORIGIN`]'s declared prefix byte-for-byte.
pub(crate) fn trusted_manifest_key(id: &EntityId) -> String {
    format!("manifest:trusted:{}", id.to_hex())
}

/// Separate proof that an authenticated vault owner authored an override
/// row. A generic local manifest trust stamp is not holder authority.
const RETENTION_HOLDER: SideTable<HexId, [u8; 32], Raw> =
    SideTable::new(&side_table::GATE_MANIFEST_RETENTION_HOLDER);

pub(in crate::gate) fn retention_holder_verified(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(RETENTION_HOLDER
        .get(store, txn, &HexId(*id))?
        .is_some_and(|hash| hash == *blake3::hash(body).as_bytes()))
}

/// The bootstrap seed's [`SEEDED`] row key, spelled for the same raw write as
/// [`trusted_manifest_key`].
pub(crate) fn seeded_manifest_key(id: &EntityId) -> String {
    format!("manifest:seeded_confidence:{}", id.to_hex())
}

pub(crate) fn manifest_is_seeded_default(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(SEEDED
        .get(store, txn, &HexId(*id))?
        .is_some_and(|hash| hash == *blake3::hash(body).as_bytes()))
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
        // Every local re-authoring is authored even if it keeps the seeded ID,
        // pack name or byte-identical default value.
        SEEDED.delete(store, txn, &origin_key)?;
        TRUSTED_ORIGIN.put(store, txn, &origin_key, hash.as_bytes())?;
    } else {
        let existing_matches = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
            .is_some_and(|raw| {
                EntityMetadataHeader::parse(&raw)
                    .is_some_and(|h| h.entity_type == ENTITY_TYPE_POLICY_MANIFEST)
                    && raw.get(ENTITY_METADATA_HEADER_LEN..) == Some(body)
            });
        if !existing_matches
            || SEEDED
                .get(store, txn, &origin_key)?
                .is_none_or(|old| old != *hash.as_bytes())
        {
            SEEDED.delete(store, txn, &origin_key)?;
        }
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
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(TRUSTED_ORIGIN
        .get(store, txn, &HexId(*id))?
        .is_some_and(|hash| hash == *blake3::hash(body).as_bytes()))
}

pub(crate) fn manifest_is_quarantined(
    store: &impl crate::store::ManifestDbs,
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
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &id)?
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
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &id)?
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
        // An optional notification table is made explicit on admission, so
        // an authenticated install is immediately editable by the owner.
        let data = super::default_manifest::with_default_owner_policy_notifications(data)?;
        let Some(decoded) = super::decode::decode_policy_manifest(&data) else {
            return Err(Error::InvalidConfig("malformed policy manifest".into()));
        };
        if let Some(row) = super::policy_values::unadmitted_row(&decoded.policy_values) {
            return Err(GateError::PolicyValueLevelNotAdmitted {
                key: row.key.as_str(),
                level: row.scope.level(),
            }
            .into());
        }
        if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &id)? {
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("policy manifest header"))?;
            if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
                return Err(Error::InvalidConfig(
                    "policy manifest id belongs to another entity".into(),
                ));
            }
        }
        let holder_hash = blake3::hash(&data);
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
        )?;
        RETENTION_HOLDER.put(&self.store, txn, &HexId(id), holder_hash.as_bytes())?;
        Ok(())
    }

    /// Installs a locally authored policy manifest through the authenticated
    /// owner door. Hosts can grant connector effects without bypassing origin
    /// attestation or writing a reserved maintenance type through `put_entity`.
    ///
    /// # Errors
    /// Refuses unauthenticated owners, malformed manifests, value rows at a level
    /// their key does not admit, or IDs owned by another type.
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

    /// Apply an explanation drafted by a model only to an empty row. An
    /// authenticated owner may instead write their own why; a draft never
    /// overwrites that owner text. The engine never invents the prose.
    pub fn set_policy_value_why(
        &self,
        owner: &AuthenticatedOwner,
        manifest: EntityId,
        row_ref: &str,
        text: &str,
        drafted: bool,
        now: u64,
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let raw = self
            .store
            .entities
            .get(&txn, manifest.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_POLICY_MANIFEST)
        {
            return Err(Error::InvalidConfig("not a policy manifest".into()));
        }
        let Some(updated) = super::policy_values::with_policy_why(
            &raw[ENTITY_METADATA_HEADER_LEN..],
            row_ref,
            text,
            drafted,
        ) else {
            return Ok(false);
        };
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, manifest, updated, now)?;
        txn.commit()?;
        Ok(true)
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
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &legacy)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("legacy manifest header"))?;
        if crate::registry::zone_of(header.entity_type)
            != crate::registry::TypeByteZone::CompiledProduct
            || crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &target)?.is_some()
        {
            return Err(Error::InvalidConfig(
                "manifest re-key requires legacy source and fresh target".into(),
            ));
        }
        let data = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        self.write_owner_policy_manifest_in_txn(owner, &mut txn, target, data, now)?;
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
    // Any generic write (including replay) invalidates the holder's exact
    // body attestation. The authenticated owner door re-stamps it afterwards.
    RETENTION_HOLDER.delete(store, txn, &HexId(*id))?;
    if kind == ENTITY_TYPE_POLICY_MANIFEST
        && (super::project_depth::is_project_depth_id(id)
            || super::project_depth::is_project_depth_contribution(body))
    {
        // A signed project policy is authenticated by its immutable carrier
        // and authority fold, never the local-only trusted-manifest sidecar.
        TRUSTED_ORIGIN.delete(store, txn, &HexId(*id))?;
    } else if kind == ENTITY_TYPE_POLICY_MANIFEST {
        stamp_manifest_origin(store, txn, id, body, replicated)?;
    } else {
        TRUSTED_ORIGIN.delete(store, txn, &HexId(*id))?;
    }
    Ok(())
}
