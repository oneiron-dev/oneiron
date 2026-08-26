use std::collections::BTreeSet;

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillContentHash, SkillRecord, decode_skill_record};
use crate::temporal::TimeRange;

use super::package::{MAX_CAPABILITY_TEXT_BYTES, SkillCapabilitySurface};
use super::record::HubRef;
use super::support::{
    decode_value, encode_value, exact_map, map_value, required_value, validate_text,
};

/// Claim predicate for mutable hub aliases attached to canonical skill identity.
pub const PREDICATE_SKILL_HUB_PROVENANCE: &str = "skill.hub_provenance";

const CAPABILITY_STATE_PREFIX: &[u8] = b"skill_hub/capability/v1\0";
const CONTENT_HASH_INDEX_PREFIX: &[u8] = b"skill_hub/content_hash_index/v1\0";
pub(super) const CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY: &[u8] =
    b"skill_hub/content_hash_index_schema_version";
pub(super) const CONTENT_HASH_INDEX_SCHEMA_VERSION: u8 = 1;

pub(super) const MAX_HUB_SKILL_SCAN_ENTRIES: usize = 100_000;

impl Vault {
    /// The holder of these exact canonical bytes, whichever birth path put it
    /// there — the shared-namespace dedup probe (ONE-1446 reads it too).
    pub(crate) fn skill_entity_for_content_hash_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        content_hash: SkillContentHash,
    ) -> Result<Option<EntityId>> {
        Ok(self
            .structured_skills_for_content_hash_in_txn(rtxn, content_hash)?
            .into_iter()
            .next()
            .map(|(entity, _)| entity))
    }

    pub(super) fn imported_skill_entity_for_content_hash_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        content_hash: SkillContentHash,
    ) -> Result<Option<EntityId>> {
        for (entity, record) in
            self.structured_skills_for_content_hash_in_txn(rtxn, content_hash)?
        {
            if record.source == ClaimSource::Imported {
                return Ok(Some(entity));
            }
        }
        Ok(None)
    }

    pub(super) fn structured_skills_for_content_hash_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        content_hash: SkillContentHash,
    ) -> Result<Vec<(EntityId, SkillRecord)>> {
        let prefix = content_hash_index_prefix(content_hash);
        let mut skills = Vec::new();
        for (scanned, entry) in self
            .store
            .vault_meta
            .prefix_iter(rtxn, &prefix)?
            .enumerate()
        {
            if scanned >= MAX_HUB_SKILL_SCAN_ENTRIES {
                return Err(Error::IndexOverflow("skill_entity_for_content_hash"));
            }
            let (key, _) = entry?;
            let entity =
                crate::entity_id::parse_entity_id(&key[prefix.len()..], "skill content hash index")
                    .map_err(|_| Error::CorruptedIndex("skill content hash index"))?;
            let Some(raw) = self.store.entities.get(rtxn, entity.as_bytes())? else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_SKILL {
                continue;
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let record = match decode_skill_record(body) {
                Ok(record) => record,
                Err(error)
                    if error.kind() == ErrorKind::InvalidSkillBody
                        && crate::skill::is_legacy_opaque_skill_body(body) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if record.content_hash == Some(content_hash) {
                skills.push((entity, record));
            }
        }
        Ok(skills)
    }

    fn find_structured_skill_entity_in_txn<T>(
        &self,
        rtxn: &heed::RoTxn<'_>,
        mut find: impl FnMut(EntityId, &SkillRecord) -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        for (scanned, entry) in self
            .store
            .type_index
            .prefix_iter(rtxn, &[ENTITY_TYPE_SKILL])?
            .enumerate()
        {
            if scanned >= MAX_HUB_SKILL_SCAN_ENTRIES {
                return Err(Error::IndexOverflow("skill_entity_for_content_hash"));
            }
            let (key, _) = entry?;
            let id = crate::vault::entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("skill type index"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_SKILL {
                return Err(Error::CorruptedIndex("skill type index"));
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let record = match decode_skill_record(body) {
                Ok(record) => record,
                Err(error)
                    if error.kind() == ErrorKind::InvalidSkillBody
                        && crate::skill::is_legacy_opaque_skill_body(body) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if let Some(found) = find(id, &record)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    fn active_hub_aliases_on_other_skill_entities_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        entity: &EntityId,
        hub_ref: &HubRef,
    ) -> Result<Vec<(EntityId, u64)>> {
        let mut prior_rows = Vec::new();
        self.find_structured_skill_entity_in_txn(rtxn, |candidate, _| {
            if candidate == *entity {
                return Ok(None::<()>);
            }
            for (claim_id, body, occurred_start) in self.active_claims_for_predicate_in_txn(
                rtxn,
                &candidate,
                PREDICATE_SKILL_HUB_PROVENANCE,
            )? {
                let stored_ref = HubRef::from_value(map_value(&body.value, "hubRef").ok_or(
                    Error::InvalidSkillBody("hub provenance claim is missing hubRef"),
                )?)?;
                if same_hub_alias(&stored_ref, hub_ref) {
                    prior_rows.push((claim_id, occurred_start));
                }
            }
            Ok(None)
        })?;
        Ok(prior_rows)
    }

    pub(super) fn append_hub_provenance_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        content_hash: SkillContentHash,
        hub_ref: &HubRef,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let hub_value = hub_ref.to_value()?;
        let prior_rows =
            self.active_hub_aliases_on_other_skill_entities_in_txn(&*wtxn, entity, hub_ref)?;
        let mut replacement_id = None;
        for (claim_id, body, _) in
            self.active_claims_for_predicate_in_txn(&*wtxn, entity, PREDICATE_SKILL_HUB_PROVENANCE)?
        {
            let stored_ref = HubRef::from_value(map_value(&body.value, "hubRef").ok_or(
                Error::InvalidSkillBody("hub provenance claim is missing hubRef"),
            )?)?;
            if same_hub_alias(&stored_ref, hub_ref) {
                replacement_id = Some(claim_id);
                break;
            }
        }
        let replacement_id = if let Some(replacement_id) = replacement_id {
            replacement_id
        } else {
            let replacement_id = EntityId::now();
            let mut body = ClaimBody::new(
                PREDICATE_SKILL_HUB_PROVENANCE,
                ClaimSubject::Entity(*entity),
                Value::Map(vec![
                    (
                        Value::from("contentHash"),
                        Value::from(content_hash.to_hex()),
                    ),
                    (Value::from("hubRef"), hub_value),
                ]),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.source = Some(ClaimSource::Observed);
            self.put_reserved_claim_in_txn(wtxn, &replacement_id, &body, occurred, learned_at)?;
            replacement_id
        };
        for (prior_id, prior_start) in prior_rows {
            self.supersede_reserved_claim_in_txn(
                wtxn,
                &replacement_id,
                &prior_id,
                learned_at.max(prior_start),
            )?;
        }
        Ok(())
    }

    pub(super) fn replace_hub_provenance_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        content_hash: SkillContentHash,
        hub_ref: &HubRef,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let hub_value = hub_ref.to_value()?;
        let mut prior_rows = Vec::new();
        for (id, body, occurred_start) in
            self.active_claims_for_predicate_in_txn(&*wtxn, entity, PREDICATE_SKILL_HUB_PROVENANCE)?
        {
            HubRef::from_value(map_value(&body.value, "hubRef").ok_or(
                Error::InvalidSkillBody("hub provenance claim is missing hubRef"),
            )?)?;
            prior_rows.push((id, occurred_start));
        }

        let replacement_id = EntityId::now();
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_HUB_PROVENANCE,
            ClaimSubject::Entity(*entity),
            Value::Map(vec![
                (
                    Value::from("contentHash"),
                    Value::from(content_hash.to_hex()),
                ),
                (Value::from("hubRef"), hub_value),
            ]),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Observed);
        self.put_reserved_claim_in_txn(wtxn, &replacement_id, &body, occurred, learned_at)?;
        for (prior_id, prior_start) in prior_rows {
            self.supersede_reserved_claim_in_txn(
                wtxn,
                &replacement_id,
                &prior_id,
                learned_at.max(prior_start),
            )?;
        }
        Ok(replacement_id)
    }

    /// Drops the content-hash index row for a SKILL as it leaves the active
    /// store, so import/sync dedup never resolves a deleted holder. The
    /// soft-erase path relies on this because it truncates the entity body in
    /// place rather than routing through `deindex_entity` (which maintains the
    /// index for hard purges and batch deletes). Verdict discovery no longer
    /// depends on this index (verdicts anchor to the content bytes), so a
    /// departing holder never disturbs a verdict.
    pub(crate) fn maintain_skill_content_hash_index_on_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
    ) -> Result<()> {
        let Some(raw) = self.store.entities.get(&*wtxn, entity.as_bytes())? else {
            return Ok(());
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Ok(());
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let content_hash = match decode_skill_record(body) {
            Ok(record) => record.content_hash,
            Err(error)
                if error.kind() == ErrorKind::InvalidSkillBody
                    && crate::skill::is_legacy_opaque_skill_body(body) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        let Some(content_hash) = content_hash else {
            return Ok(());
        };
        maintain_skill_content_hash_index_for_delete(&self.store, wtxn, entity, content_hash)
    }

    pub(super) fn active_claims_for_predicate(
        &self,
        entity: &EntityId,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let rtxn = self.store.env.read_txn()?;
        self.active_claims_for_predicate_in_txn(&rtxn, entity, predicate)
            .map(|rows| rows.into_iter().map(|(id, body, _)| (id, body)).collect())
    }

    pub(super) fn active_claims_for_predicate_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        entity: &EntityId,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody, u64)>> {
        let mut rows = Vec::new();
        for id in self.claims_for_subject_in_txn(rtxn, entity)? {
            let Some(body) = self.get_claim_in_txn(rtxn, &id)? else {
                continue;
            };
            if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active {
                let raw = self
                    .store
                    .entities
                    .get(rtxn, id.as_bytes())?
                    .ok_or(Error::CorruptedIndex("claim_of edge"))?;
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("entity header"))?;
                rows.push((id, body, header.occurred_start));
            }
        }
        Ok(rows)
    }

    pub(super) fn read_admitted_capability_surface_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<Option<SkillCapabilitySurface>> {
        let key = capability_state_key(entity);
        self.store
            .vault_meta
            .get(rtxn, &key)?
            .map(|bytes| decode_capability_surface(&bytes))
            .transpose()
    }

    pub(super) fn write_admitted_capability_surface_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        surface: &SkillCapabilitySurface,
    ) -> Result<()> {
        surface.validate()?;
        let value = encode_value(
            &encode_capability_surface_value(surface),
            "capability surface MessagePack encode failed",
        )?;
        let key = capability_state_key(entity);
        self.store.vault_meta.put(wtxn, &key, &value)?;
        Ok(())
    }
}

fn capability_state_key(entity: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CAPABILITY_STATE_PREFIX.len() + 16);
    key.extend_from_slice(CAPABILITY_STATE_PREFIX);
    key.extend_from_slice(entity.as_bytes());
    key
}

fn content_hash_index_prefix(content_hash: SkillContentHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(CONTENT_HASH_INDEX_PREFIX.len() + 32);
    key.extend_from_slice(CONTENT_HASH_INDEX_PREFIX);
    key.extend_from_slice(content_hash.as_bytes());
    key
}

pub(super) fn content_hash_index_key(content_hash: SkillContentHash, entity: &EntityId) -> Vec<u8> {
    let mut key = content_hash_index_prefix(content_hash);
    key.extend_from_slice(entity.as_bytes());
    key
}

pub(crate) fn maintain_skill_content_hash_index_for_put(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    previous_hash: Option<SkillContentHash>,
    content_hash: Option<SkillContentHash>,
) -> Result<()> {
    if previous_hash != content_hash
        && let Some(previous_hash) = previous_hash
    {
        store
            .vault_meta
            .delete(wtxn, &content_hash_index_key(previous_hash, entity))?;
    }
    if let Some(content_hash) = content_hash {
        store
            .vault_meta
            .put(wtxn, &content_hash_index_key(content_hash, entity), &[])?;
    }
    Ok(())
}

pub(crate) fn maintain_skill_content_hash_index_for_delete(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    content_hash: SkillContentHash,
) -> Result<()> {
    store
        .vault_meta
        .delete(wtxn, &content_hash_index_key(content_hash, entity))?;
    Ok(())
}

/// Rebuilds the content-hash → holder index at open time when it is missing or
/// stale (schema-version gated), so import/sync dedup can resolve holders that
/// pre-date the index. ONE-1741: scan verdicts no longer ride this table (they
/// anchor to the content bytes), so this reconstructs ONLY the holder index —
/// the old verdict-dedup migration is gone.
pub(crate) fn backfill_content_hash_index_if_needed(vault: &Vault) -> Result<()> {
    let store = &vault.store;
    let rtxn = store.env.read_txn()?;
    let stored_version = match store
        .vault_meta
        .get(&rtxn, CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY)?
    {
        Some(raw) if raw.len() == 1 => raw[0],
        Some(_) => return Err(Error::InvalidKey),
        None => 0,
    };
    drop(rtxn);

    if stored_version > CONTENT_HASH_INDEX_SCHEMA_VERSION {
        return Err(Error::InvalidKey);
    }
    if stored_version == CONTENT_HASH_INDEX_SCHEMA_VERSION {
        return Ok(());
    }

    // Collect holders first, then write: the type-index cursor is dropped
    // before any vault_meta write, matching the proven pre-ONE-1741 pattern.
    let mut wtxn = store.env.write_txn()?;
    let mut holders = Vec::<(SkillContentHash, EntityId)>::new();
    for entry in store.type_index.prefix_iter(&wtxn, &[ENTITY_TYPE_SKILL])? {
        let (key, _) = entry?;
        let entity = crate::vault::entity_id_from_type_index_key(&key)?;
        let raw = store
            .entities
            .get(&wtxn, entity.as_bytes())?
            .ok_or(Error::CorruptedIndex("skill type index"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::CorruptedIndex("skill type index"));
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let record = match decode_skill_record(body) {
            Ok(record) => record,
            Err(error)
                if error.kind() == ErrorKind::InvalidSkillBody
                    && crate::skill::is_legacy_opaque_skill_body(body) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Some(content_hash) = record.content_hash {
            holders.push((content_hash, entity));
        }
    }

    for (content_hash, entity) in &holders {
        store.vault_meta.put(
            &mut wtxn,
            &content_hash_index_key(*content_hash, entity),
            &[],
        )?;
    }

    store.vault_meta.put(
        &mut wtxn,
        CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY,
        &[CONTENT_HASH_INDEX_SCHEMA_VERSION],
    )?;
    wtxn.commit()?;
    Ok(())
}

pub(super) fn encode_capability_surface_value(surface: &SkillCapabilitySurface) -> Value {
    Value::Map(vec![
        (Value::from("bins"), string_set_value(&surface.bins)),
        (Value::from("env"), string_set_value(&surface.env)),
        (Value::from("mcp"), string_set_value(&surface.mcp)),
        (
            Value::from("allowedTools"),
            string_set_value(&surface.allowed_tools),
        ),
    ])
}

fn decode_capability_surface(bytes: &[u8]) -> Result<SkillCapabilitySurface> {
    const KEYS: [&str; 4] = ["bins", "env", "mcp", "allowedTools"];
    let value = decode_value(bytes, "invalid admitted capability surface")?;
    let entries = exact_map(&value, &KEYS, "invalid admitted capability surface")?;
    let surface = SkillCapabilitySurface {
        bins: decode_string_set(required_value(
            entries,
            KEYS[0],
            "invalid admitted capability surface",
        )?)?,
        env: decode_string_set(required_value(
            entries,
            KEYS[1],
            "invalid admitted capability surface",
        )?)?,
        mcp: decode_string_set(required_value(
            entries,
            KEYS[2],
            "invalid admitted capability surface",
        )?)?,
        allowed_tools: decode_string_set(required_value(
            entries,
            KEYS[3],
            "invalid admitted capability surface",
        )?)?,
    };
    surface.validate()?;
    Ok(surface)
}

fn string_set_value(values: &BTreeSet<String>) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::from(value.as_str()))
            .collect(),
    )
}

fn decode_string_set(value: &Value) -> Result<BTreeSet<String>> {
    let Value::Array(values) = value else {
        return Err(Error::InvalidSkillBody(
            "capability entries must be an array",
        ));
    };
    let mut decoded = BTreeSet::new();
    for value in values {
        let text = value
            .as_str()
            .ok_or(Error::InvalidSkillBody("capability entry must be text"))?;
        validate_text(
            text,
            MAX_CAPABILITY_TEXT_BYTES,
            "capability entries must be non-empty",
        )?;
        if !decoded.insert(text.to_owned()) {
            return Err(Error::InvalidSkillBody("duplicate capability entry"));
        }
    }
    Ok(decoded)
}

pub(super) fn same_hub_alias(left: &HubRef, right: &HubRef) -> bool {
    left.hub_id == right.hub_id && left.ref_string == right.ref_string && left.pin == right.pin
}
