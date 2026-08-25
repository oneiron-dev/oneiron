use rmpv::Value;

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::{
    SkillContentHash, SkillLifecycle, cross_check_declared_content_hash, encode_skill_record,
};
use crate::temporal::TimeRange;

use super::adapter::SkillHubAdapter;
use super::index::{
    PREDICATE_SKILL_HUB_PROVENANCE, encode_capability_surface_value, same_hub_alias,
};
use super::package::{HubIndexEntry, HubPackage};
use super::record::{HubPin, HubRef, HubSyncPolicy};
use super::support::{map_text, map_value};

/// Claim predicate for capability-widening update proposals.
pub const PREDICATE_SKILL_HUB_UPDATE_PROPOSAL: &str = "skill.hub_update_proposal";

/// Result of a policy-checked hub sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubSyncDisposition {
    Applied,
    Proposed {
        proposal_id: EntityId,
        approval: ClaimApprovalStatus,
    },
    RefusedByPolicy,
}

impl HubSyncDisposition {
    /// Approval carried by a proposal disposition.
    #[must_use]
    pub const fn approval_status(&self) -> Option<ClaimApprovalStatus> {
        match self {
            Self::Proposed { approval, .. } => Some(*approval),
            Self::Applied | Self::RefusedByPolicy => None,
        }
    }

    /// Whether the incoming package landed as canon.
    #[must_use]
    pub const fn applied(&self) -> bool {
        matches!(self, Self::Applied)
    }
}

/// Refusal-first dependency resolution result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubDependencyResolution {
    Materialized(EntityId),
    RefusedCrossHub,
    RefusedMissingPackage,
}

impl Vault {
    /// Imports a package directly through the offline hub door.
    pub fn import_skill_from_hub(
        &self,
        hub_ref: &HubRef,
        package: &HubPackage,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.import_skill_from_hub_with_id(hub_ref, package, EntityId::now(), occurred, learned_at)
    }

    /// Fetches through an adapter and enters the same import door.
    pub fn import_skill_from_adapter<A: SkillHubAdapter>(
        &self,
        adapter: &A,
        hub_ref: &HubRef,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let package = adapter.fetch_package(hub_ref)?;
        self.import_skill_from_hub(hub_ref, &package, occurred, learned_at)
    }

    /// Fetches an indexed adapter package and cross-checks its declared hash
    /// against the engine's canonical recomputation before any write begins.
    pub fn ingest_skill_from_adapter_checked<A: SkillHubAdapter>(
        &self,
        adapter: &A,
        entry: &HubIndexEntry,
        preferred_id: EntityId,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let declared_hex = entry.content_hash.to_hex();
        let hub_ref = HubRef::new(
            adapter.hub_id(),
            entry.ref_string.clone(),
            HubPin::ContentHash(declared_hex.clone()),
        )?;
        let package = adapter.fetch_package(&hub_ref)?;
        let canonical_hash = package.content_hash()?;
        let mut canonical_record = package.record.clone();
        canonical_record.content_hash = Some(canonical_hash);
        cross_check_declared_content_hash(&canonical_record, &declared_hex)?;
        self.import_skill_from_hub_with_id(&hub_ref, &package, preferred_id, occurred, learned_at)
    }

    pub(super) fn import_skill_from_hub_with_id(
        &self,
        hub_ref: &HubRef,
        package: &HubPackage,
        preferred_id: EntityId,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        hub_ref.validate()?;
        encode_skill_record(&package.record)?;
        let content_hash = package.content_hash()?;
        if package
            .record
            .content_hash
            .is_some_and(|declared| declared != content_hash)
        {
            return Err(Error::InvalidSkillBody(
                "package content hash does not match its canonical file tree",
            ));
        }
        if let HubPin::ContentHash(pinned_hash) = &hub_ref.pin
            && SkillContentHash::parse_hex(pinned_hash)? != content_hash
        {
            return Err(Error::InvalidSkillBody("content-hash-pinned ref drifted"));
        }
        if package.record.source != ClaimSource::Imported {
            return Err(Error::InvalidSkillBody(
                "hub import package must carry imported source",
            ));
        }

        let mut wtxn = self.store.env.write_txn()?;
        let entity =
            match self.imported_skill_entity_for_content_hash_in_txn(&wtxn, content_hash)? {
                Some(existing) => {
                    let existing_record = self.read_skill_record_in_txn(&wtxn, &existing)?;
                    if existing_record.skill_id != package.record.skill_id {
                        return Err(Error::InvalidSkillBody(
                            "hub import content hash collides with a different skill id",
                        ));
                    }
                    existing
                }
                None => {
                    let mut candidate = package.record.clone();
                    candidate.lifecycle_status = SkillLifecycle::Candidate;
                    // ONE-1892: consent is a LOCAL act, so the import door
                    // stamps it rather than copying it. A hub package is
                    // untrusted input all the way down — it declares its own
                    // `approvalStatus`, and an `approved` stamp arriving that
                    // way would be a remote party answering the owner's
                    // question for him: the activation consult only escalates
                    // `auto`, so a self-declared approval would walk a
                    // credential-bearing skill into `active` with no tap. The
                    // sync door already holds this law one line at a time
                    // ("canonical approval/lifecycle state stays local"); the
                    // import door is where the FIRST stamp is minted, and
                    // `auto` — the same default a locally born candidate gets
                    // — is the only honest one.
                    candidate.approval_status = ClaimApprovalStatus::Auto;
                    candidate.content_hash = Some(content_hash);
                    self.apply_hub_import_skill_record(
                        &mut wtxn,
                        &preferred_id,
                        &candidate,
                        occurred,
                        learned_at,
                    )?;
                    self.write_admitted_capability_surface_in_txn(
                        &mut wtxn,
                        &preferred_id,
                        &package.capabilities,
                    )?;
                    preferred_id
                }
            };

        match self.read_admitted_capability_surface_in_txn(&wtxn, &entity)? {
            Some(admitted) if admitted != package.capabilities => {
                return Err(Error::InvalidSkillBody(
                    "matching content hash carries conflicting capabilities",
                ));
            }
            Some(_) => {}
            None => self.write_admitted_capability_surface_in_txn(
                &mut wtxn,
                &entity,
                &package.capabilities,
            )?,
        }
        self.append_hub_provenance_in_txn(
            &mut wtxn,
            &entity,
            content_hash,
            hub_ref,
            occurred,
            learned_at,
        )?;
        // ONE-1892: the ONE producer hook for the import family — the two
        // public import doors and the dependency-materialization door all
        // delegate here, so imported bytes carry a scanner receipt without any
        // caller remembering to ask for one.
        self.scan_and_ingest_on_import_in_txn(
            &mut wtxn,
            &entity,
            content_hash,
            package,
            occurred,
            learned_at,
        )?;
        wtxn.commit()?;
        Ok(entity)
    }

    /// Counts active mutable provenance aliases for one skill entity.
    pub fn skill_hub_provenance_count(&self, entity: &EntityId) -> Result<usize> {
        Ok(self
            .active_claims_for_predicate(entity, PREDICATE_SKILL_HUB_PROVENANCE)?
            .len())
    }

    /// Applies same/narrower updates and proposes capability widening.
    pub fn sync_skill_from_hub(
        &self,
        entity: &EntityId,
        hub_ref: &HubRef,
        package: &HubPackage,
        sync_policy: HubSyncPolicy,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<HubSyncDisposition> {
        hub_ref.validate()?;
        encode_skill_record(&package.record)?;
        let content_hash = package.content_hash()?;
        let mut wtxn = self.store.env.write_txn()?;
        let current = self.read_skill_record_in_txn(&wtxn, entity)?;
        if current.source != ClaimSource::Imported
            || package.record.source != ClaimSource::Imported
            || current.skill_id != package.record.skill_id
        {
            return Err(Error::InvalidSkillBody(
                "hub sync package must match an imported skill",
            ));
        }
        if package
            .record
            .content_hash
            .is_some_and(|declared| declared != content_hash)
        {
            return Err(Error::InvalidSkillBody(
                "package content hash does not match its canonical file tree",
            ));
        }
        // A content-hash pin binds the ref's identity on every sync path, not only under the
        // frozen policy (mirrors the import door at import_skill_from_hub_with_id).
        if let HubPin::ContentHash(pinned) = &hub_ref.pin
            && SkillContentHash::parse_hex(pinned)? != content_hash
        {
            return Err(Error::InvalidSkillBody("content-hash-pinned ref drifted"));
        }
        if sync_policy == HubSyncPolicy::ContentHashFrozen
            && !matches!(&hub_ref.pin, HubPin::ContentHash(_))
        {
            return Err(Error::InvalidSkillBody(
                "content-hash-frozen policy requires a content_hash pin",
            ));
        }
        if !sync_policy.allows_automatic_update() {
            return Ok(HubSyncDisposition::RefusedByPolicy);
        }

        let provenance_rows =
            self.active_claims_for_predicate_in_txn(&wtxn, entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
        // Legacy direct imports remain permissive until vault-bound authority lands in ONE-1751.
        if !provenance_rows.is_empty() {
            let mut matches_provenance_alias = false;
            for (_, body, _) in &provenance_rows {
                let stored_ref = HubRef::from_value(map_value(&body.value, "hubRef").ok_or(
                    Error::InvalidSkillBody("hub provenance claim is missing hubRef"),
                )?)?;
                if same_hub_alias(&stored_ref, hub_ref) {
                    matches_provenance_alias = true;
                    break;
                }
            }
            if !matches_provenance_alias {
                return Ok(HubSyncDisposition::RefusedByPolicy);
            }
        }

        let admitted = self
            .read_admitted_capability_surface_in_txn(&wtxn, entity)?
            .unwrap_or_default();
        if !package.capabilities.is_same_or_narrower_than(&admitted) {
            let hub_value = hub_ref.to_value()?;
            let hash_hex = content_hash.to_hex();
            let encoded_caps = encode_capability_surface_value(&package.capabilities);
            for (proposal_id, body, _) in self.active_claims_for_predicate_in_txn(
                &wtxn,
                entity,
                PREDICATE_SKILL_HUB_UPDATE_PROPOSAL,
            )? {
                if map_value(&body.value, "hubRef") == Some(&hub_value)
                    && map_text(&body.value, "contentHash") == Some(hash_hex.as_str())
                    && map_text(&body.value, "version") == Some(package.record.version.as_str())
                    && map_value(&body.value, "capabilities") == Some(&encoded_caps)
                {
                    return Ok(HubSyncDisposition::Proposed {
                        proposal_id,
                        approval: ClaimApprovalStatus::Proposed,
                    });
                }
            }

            let proposal_id = EntityId::now();
            let mut proposal = ClaimBody::new(
                PREDICATE_SKILL_HUB_UPDATE_PROPOSAL,
                ClaimSubject::Entity(*entity),
                Value::Map(vec![
                    (Value::from("hubRef"), hub_value),
                    (
                        Value::from("version"),
                        Value::from(package.record.version.as_str()),
                    ),
                    (Value::from("contentHash"), Value::from(hash_hex)),
                    (Value::from("capabilities"), encoded_caps),
                ]),
                1.0,
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
            );
            proposal.source = Some(ClaimSource::Imported);
            self.put_reserved_claim_in_txn(
                &mut wtxn,
                &proposal_id,
                &proposal,
                occurred,
                learned_at,
            )?;
            wtxn.commit()?;
            return Ok(HubSyncDisposition::Proposed {
                proposal_id,
                approval: ClaimApprovalStatus::Proposed,
            });
        }

        let content_hash_changed = current.content_hash != Some(content_hash);
        if content_hash_changed
            && self
                .skill_entity_for_content_hash_in_txn(&wtxn, content_hash)?
                .is_some_and(|owner| owner != *entity)
        {
            return Ok(HubSyncDisposition::RefusedByPolicy);
        }

        let mut updated = package.record.clone();
        // Hub sync mutates content fields; canonical approval/lifecycle state stays local.
        updated.approval_status = current.approval_status;
        updated.lifecycle_status = current.lifecycle_status;
        updated.content_hash = Some(content_hash);
        self.apply_hub_sync_skill_record(&mut wtxn, entity, &updated, occurred, learned_at)?;
        self.write_admitted_capability_surface_in_txn(&mut wtxn, entity, &package.capabilities)?;
        if content_hash_changed {
            self.replace_hub_provenance_in_txn(
                &mut wtxn,
                entity,
                content_hash,
                hub_ref,
                occurred,
                learned_at,
            )?;
        }
        // ONE-1892: the update door's half of the producer. Unconditional
        // rather than gated on `content_hash_changed` because the guard that
        // matters is content-keyed — an unchanged hash that already carries a
        // static receipt is a no-op here, while a hash that never got one
        // (bytes born through a non-hub path) is scanned on this pass.
        self.scan_and_ingest_on_import_in_txn(
            &mut wtxn,
            entity,
            content_hash,
            package,
            occurred,
            learned_at,
        )?;
        wtxn.commit()?;
        Ok(HubSyncDisposition::Applied)
    }

    /// Refuses cross-hub dependencies before any package can materialize.
    pub fn resolve_hub_dependency(
        &self,
        importing_ref: &HubRef,
        dependency_ref: &HubRef,
        dependency_entity: &EntityId,
        package: Option<&HubPackage>,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<HubDependencyResolution> {
        importing_ref.validate()?;
        dependency_ref.validate()?;
        if importing_ref.hub_id != dependency_ref.hub_id {
            return Ok(HubDependencyResolution::RefusedCrossHub);
        }
        let Some(package) = package else {
            return Ok(HubDependencyResolution::RefusedMissingPackage);
        };
        self.import_skill_from_hub_with_id(
            dependency_ref,
            package,
            *dependency_entity,
            occurred,
            learned_at,
        )
        .map(HubDependencyResolution::Materialized)
    }
}
