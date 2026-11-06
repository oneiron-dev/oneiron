//! Skill provenance and capability indexes.
//! Entry: `PREDICATE_SKILL_HUB_PROVENANCE`.
//! Defines its own items.

use crate::ports::EntityStoreRead;
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
use crate::error::ArtifactError;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

pub use crate::store::skill_hub_predicates::PREDICATE_SKILL_HUB_PROVENANCE;

/// Cached capability-surface projection for a hub-derived skill entity.
const CAPABILITY: SideTable<EntityId, SkillCapabilitySurface, Raw> =
    SideTable::new(&side_table::SKILL_HUB_CAPABILITY);
pub(super) use crate::store::skill_content_index::{
    CONTENT_HASH_INDEX, CONTENT_HASH_INDEX_SCHEMA_VERSION, SCHEMA_VERSION,
};
pub(crate) use crate::store::skill_content_index::{
    backfill_content_hash_index_if_needed, maintain_skill_content_hash_index_for_delete,
    maintain_skill_content_hash_index_for_put,
};

pub(super) use crate::store::skill_package::capability::encode_capability_surface_value;

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
        source: Option<&HubRef>,
    ) -> Result<Option<EntityId>> {
        // Explicit restore may have minted a newer live holder for these exact
        // bytes. Prefer it; otherwise ordinary re-import preserves an inactive
        // holder and adds the new provenance without reviving it (owner ruling A).
        // Every source is eligible: an authored or converted holder of the exact
        // tree is named as-is, its lifecycle and approval untouched.
        let mut exact_live = None;
        let mut other_live = None;
        let mut exact_inactive = None;
        let mut other_inactive = None;
        for (entity, record) in
            self.structured_skills_for_content_hash_in_txn(rtxn, content_hash)?
        {
            let exact = if let Some(source) = source {
                self.default_skill_present_for_entity_in_txn(rtxn, &entity, source)?
            } else {
                false
            };
            match (record.lifecycle_status, exact) {
                (
                    crate::skill::SkillLifecycle::Candidate | crate::skill::SkillLifecycle::Active,
                    true,
                ) => {
                    exact_live.get_or_insert(entity);
                }
                (
                    crate::skill::SkillLifecycle::Candidate | crate::skill::SkillLifecycle::Active,
                    false,
                ) => {
                    other_live.get_or_insert(entity);
                }
                (_, true) => {
                    exact_inactive.get_or_insert(entity);
                }
                (_, false) => {
                    other_inactive.get_or_insert(entity);
                }
            }
        }
        Ok(exact_live
            .or(other_live)
            .or(exact_inactive)
            .or(other_inactive))
    }

    pub(super) fn structured_skills_for_content_hash_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        content_hash: SkillContentHash,
    ) -> Result<Vec<(EntityId, SkillRecord)>> {
        let mut skills = Vec::new();
        for entry in CONTENT_HASH_INDEX.iter_from(&self.store, rtxn, content_hash.as_bytes())? {
            let ((_, entity), ()) = entry?;
            // User delete can retain an erased body as a tombstone shell.
            // The hash-index entry may still exist, but a shell is not a
            // candidate holder and its bytes are not a SkillRecord.
            if crate::ports::TombstoneStoreRead::port_deletion_state(&self.store, rtxn, &entity)?
                .deleted
            {
                continue;
            }
            let Some(raw) = self
                .store
                .port_entity_record(rtxn, &entity)?
                .map(|row| row.encode())
            else {
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
        for entry in self
            .store
            .port_entity_ids_by_type(rtxn, ENTITY_TYPE_SKILL, None)?
        {
            let id = entry?;
            if crate::ports::TombstoneStoreRead::port_deletion_state(&self.store, rtxn, &id)?
                .deleted
            {
                continue;
            }
            let raw = self
                .store
                .port_entity_record(rtxn, &id)?
                .map(|row| row.encode())
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
                    Error::Artifact(ArtifactError::InvalidSkillBody(
                        "hub provenance claim is missing hubRef",
                    )),
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
            let stored_ref =
                HubRef::from_value(map_value(&body.value, "hubRef").ok_or(Error::Artifact(
                    ArtifactError::InvalidSkillBody("hub provenance claim is missing hubRef"),
                ))?)?;
            if same_hub_alias(&stored_ref, hub_ref) {
                replacement_id = Some(claim_id);
                break;
            }
        }
        let replacement_id = if let Some(replacement_id) = replacement_id {
            replacement_id
        } else {
            let replacement_id = self.store.clock.entity_id()?;
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
            )?;
            body.source = Some(ClaimSource::Observed);
            body.scope_facet = self.default_facet_in_txn(wtxn)?;
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
            HubRef::from_value(map_value(&body.value, "hubRef").ok_or(Error::Artifact(
                ArtifactError::InvalidSkillBody("hub provenance claim is missing hubRef"),
            ))?)?;
            prior_rows.push((id, occurred_start));
        }

        let replacement_id = self.store.clock.entity_id()?;
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
        )?;
        body.source = Some(ClaimSource::Observed);
        body.scope_facet = self.default_facet_in_txn(wtxn)?;
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
        let Some(raw) = self
            .store
            .port_entity_record(&*wtxn, entity)?
            .map(|row| row.encode())
        else {
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
                    .port_entity_record(rtxn, &id)?
                    .ok_or(Error::CorruptedIndex("claim_of edge"))?;
                rows.push((id, body, raw.occurred.start));
            }
        }
        Ok(rows)
    }

    pub(super) fn read_admitted_capability_surface_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<Option<SkillCapabilitySurface>> {
        CAPABILITY.get(&self.store, rtxn, entity)
    }

    pub(super) fn write_admitted_capability_surface_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        surface: &SkillCapabilitySurface,
    ) -> Result<()> {
        surface.validate()?;
        CAPABILITY.put(&self.store, wtxn, entity, surface)
    }

    /// The installed holder of one hub skill alias: the loadable skill of
    /// this `name`, or its Superseded lineage anchor, whose current bytes
    /// one consolidation-eligible provenance claim ties to `source` (same
    /// claim carries the alias, the matching content hash and the
    /// eligibility). Pure vault read; only actual consumers decide Active
    /// load. No Candidate/Quarantined/Stale lift.
    pub(crate) fn installed_hub_skill_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &HubRef,
        name: &str,
    ) -> Result<Option<EntityId>> {
        self.find_structured_skill_entity_in_txn(txn, |entity, record| {
            if record.skill_id.as_str() != name {
                return Ok(None);
            }
            if !crate::skill::skill_loadable(record)
                && record.lifecycle_status != crate::skill::SkillLifecycle::Superseded
            {
                return Ok(None);
            }
            let Some(content_hash) = record.content_hash else {
                return Ok(None);
            };
            let expected = content_hash.to_hex();
            for (claim_id, body, _) in self.active_claims_for_predicate_in_txn(
                txn,
                &entity,
                PREDICATE_SKILL_HUB_PROVENANCE,
            )? {
                let Some(hash_text) = map_value(&body.value, "contentHash").and_then(Value::as_str)
                else {
                    continue;
                };
                if hash_text != expected {
                    continue;
                }
                let Some(ref_value) = map_value(&body.value, "hubRef") else {
                    continue;
                };
                if !same_hub_alias(&HubRef::from_value(ref_value)?, source) {
                    continue;
                }
                if !crate::gate::claim_consolidation_eligible_in_txn(
                    &self.store,
                    txn,
                    &claim_id,
                    crate::gate::ConsolidationReader::HubDefaultPresence,
                )? {
                    continue;
                }
                return Ok(Some(entity));
            }
            Ok(None)
        })
    }
}

pub(super) fn same_hub_alias(left: &HubRef, right: &HubRef) -> bool {
    left.hub_id == right.hub_id && left.ref_string == right.ref_string && left.pin == right.pin
}

/// The same hub ref ignoring its pin: the pin is what a sync moves to.
pub(super) fn same_hub_ref(left: &HubRef, right: &HubRef) -> bool {
    left.hub_id == right.hub_id && left.ref_string == right.ref_string
}
