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
pub(crate) fn stamp_manifest_origin(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &[u8],
    replicated: bool,
) -> Result<()> {
    let hash = blake3::hash(body);
    let origin_key = trusted_manifest_key(id);
    if !replicated {
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
/// Inert exception request. ONE-1548 owns filing and delivery; this result
/// cannot change a live policy row or itself authorize an act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOverrideProposal {
    pub row_ref: String,
    pub scope: String,
}

/// A non-holder's proposed override is inert; all other denied mutations are
/// refusals. Only the exact row that needs another holder may be proposed.
enum PolicyMutationDenial {
    Row {
        row_ref: String,
        scope: String,
        override_parent: bool,
    },
    NonValue,
}

fn non_value_fields(data: &[u8]) -> Result<rmpv::Value> {
    let mut input = data;
    let mut value = rmpv::decode::read_value(&mut input)
        .map_err(|_| Error::InvalidConfig("malformed policy manifest".into()))?;
    if !input.is_empty() {
        return Err(Error::InvalidConfig("malformed policy manifest".into()));
    }
    let rmpv::Value::Map(entries) = &mut value else {
        return Err(Error::InvalidConfig("malformed policy manifest".into()));
    };
    entries.retain(|(key, _)| key.as_str() != Some("policy_values"));
    Ok(value)
}

impl Vault {
    /// Authorize OLD and NEW scopes for every mutated row in one snapshot.
    /// All other manifest content requires vault policy power when it changes.
    fn policy_mutation_denial_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        id: EntityId,
        data: &[u8],
        now: u64,
    ) -> Result<Option<PolicyMutationDenial>> {
        let new = super::decode::decode_policy_manifest(data)
            .ok_or_else(|| Error::InvalidConfig("malformed policy manifest".into()))?;
        let old_body = self
            .store
            .entities
            .get(txn, id.as_bytes())?
            .map(|raw| {
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("policy manifest header"))?;
                if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
                    return Err(Error::InvalidConfig(
                        "policy manifest id belongs to another entity".into(),
                    ));
                }
                raw.get(ENTITY_METADATA_HEADER_LEN..)
                    .map(<[u8]>::to_vec)
                    .ok_or(Error::CorruptedIndex("policy manifest body"))
            })
            .transpose()?;
        let old = old_body
            .as_ref()
            .map(|body| {
                super::decode::decode_policy_manifest(body).ok_or_else(|| {
                    Error::InvalidConfig("existing policy manifest is malformed".into())
                })
            })
            .transpose()?;
        // Compare without the value-table key: even deleting an old field
        // cannot hide a vault-wide policy edit inside a project-only update.
        if old_body.as_deref().map(non_value_fields).transpose()? != Some(non_value_fields(data)?)
            && !self.policy_power_in_txn(
                txn,
                actor,
                super::policy_values::PolicyRowScope::Vault,
                now,
            )?
        {
            return Ok(Some(PolicyMutationDenial::NonValue));
        }
        let empty = Vec::new();
        let old_rows = old
            .as_ref()
            .map_or(empty.as_slice(), |old| old.policy_values.as_slice());
        for row in old_rows {
            if new
                .policy_values
                .iter()
                .find(|new_row| new_row.row_ref == row.row_ref)
                == Some(row)
            {
                continue;
            }
            if !self.policy_power_in_txn(txn, actor, row.scope, now)? {
                // Same-scope override edits may be proposed. A deletion or
                // rescope still needs power over the old row independently.
                let proposed = new.policy_values.iter().find(|new_row| {
                    new_row.row_ref == row.row_ref
                        && new_row.scope == row.scope
                        && new_row.override_parent
                });
                let denied = proposed.unwrap_or(row);
                return Ok(Some(PolicyMutationDenial::Row {
                    row_ref: denied.row_ref.clone(),
                    scope: denied.scope.as_str(),
                    override_parent: proposed.is_some(),
                }));
            }
        }
        for row in &new.policy_values {
            if old_rows
                .iter()
                .find(|old_row| old_row.row_ref == row.row_ref)
                == Some(row)
            {
                continue;
            }
            if !self.policy_power_in_txn(txn, actor, row.scope, now)? {
                return Ok(Some(PolicyMutationDenial::Row {
                    row_ref: row.row_ref.clone(),
                    scope: row.scope.as_str(),
                    override_parent: row.override_parent,
                }));
            }
        }
        Ok(None)
    }

    /// Propose a manifest with explicit overrides. A holder applies it; a
    /// non-holder receives an inert typed proposal for the host's later route.
    /// Nothing is persisted for the non-holder.
    pub fn propose_policy_value_override(
        &self,
        actor: &AuthenticatedOwner,
        id: EntityId,
        data: Vec<u8>,
        now: u64,
    ) -> Result<Option<PolicyOverrideProposal>> {
        let mut txn = self.store.env.write_txn()?;
        actor.revalidate_in_txn(self, &txn)?;
        let decoded = super::decode::decode_policy_manifest(&data)
            .ok_or_else(|| Error::InvalidConfig("malformed policy manifest".into()))?;
        if !decoded.policy_values.iter().any(|row| row.override_parent) {
            return Err(Error::InvalidConfig("no policy override row".into()));
        }
        match self.policy_mutation_denial_in_txn(&txn, actor.actor(), id, &data, now)? {
            Some(PolicyMutationDenial::Row {
                row_ref,
                scope,
                override_parent: true,
            }) => {
                return Ok(Some(PolicyOverrideProposal { row_ref, scope }));
            }
            Some(_) => {
                return Err(Error::InvalidConfig(
                    "policy write requires a holder".into(),
                ));
            }
            None => {}
        }
        self.write_owner_policy_manifest_in_txn(actor, &mut txn, id, data, now)?;
        txn.commit()?;
        Ok(None)
    }

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
        if self
            .policy_mutation_denial_in_txn(txn, owner.actor(), id, &data, now)?
            .is_some()
        {
            return Err(Error::InvalidConfig(
                "policy write requires a holder".into(),
            ));
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

    /// Apply an explanation drafted by a model only to an empty row. An
    /// authenticated holder may instead write their own why; a draft never
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
    if kind == ENTITY_TYPE_POLICY_MANIFEST {
        stamp_manifest_origin(store, txn, id, body, replicated)?;
    } else {
        store.sync_state.delete(txn, &trusted_manifest_key(id))?;
    }
    Ok(())
}
