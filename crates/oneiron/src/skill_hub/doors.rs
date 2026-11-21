//! Skill hub import, update and dependency doors.
//! Entry: `Vault::sync_skill_from_hub`.
//! Defines its own items.

mod sync_query;
mod update_settlement;

use rmpv::Value;

use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::{
    SkillContentHash, SkillLifecycle, cross_check_declared_content_hash, encode_skill_record,
};
use crate::temporal::TimeRange;

use super::adapter::SkillHubAdapter;
use super::index::{PREDICATE_SKILL_HUB_PROVENANCE, encode_capability_surface_value, same_hub_ref};
use super::package::{HubIndexEntry, HubPackage};
use super::record::{HubPin, HubRef, HubSyncPolicy};
use super::support::{map_text, map_value};
use crate::error::ArtifactError;

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
        self.import_skill_from_hub_with_id(
            hub_ref,
            package,
            self.store.clock.entity_id()?,
            occurred,
            learned_at,
        )
    }

    /// Fetches through an adapter and enters the same import door, as
    /// `owner`: the owner proof is checked before the fetch and again in the
    /// writer that commits the skill, its provenance and scan receipts.
    pub fn import_skill_from_adapter<A: SkillHubAdapter>(
        &self,
        owner: &AuthenticatedOwner,
        adapter: &A,
        hub_ref: &HubRef,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.check_restore_owner_in_txn(&self.store.env.read_txn()?, owner)?;
        let package = adapter.fetch_package(hub_ref)?;
        let inventory = super::osv::dependency_inventory(&package)?;
        Ok(self
            .install_skill_with_advisories(
                owner,
                hub_ref,
                &package,
                &inventory,
                super::osv::hub_advisory_query(adapter.kind()),
                occurred,
                learned_at,
            )?
            .entity)
    }

    /// Fetches an indexed adapter package and cross-checks its declared skill
    /// id, version and hash against the fetched record and the engine's
    /// canonical recomputation before any write begins.
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
        if package.record.skill_id != entry.name || package.record.version != entry.version {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "fetched package skill id or version does not match the declared entry",
            )));
        }
        let canonical_hash = package.content_hash()?;
        let mut canonical_record = package.record.clone();
        canonical_record.content_hash = Some(canonical_hash);
        cross_check_declared_content_hash(&canonical_record, &declared_hex)?;
        let inventory = super::osv::dependency_inventory(&package)?;
        Ok(self
            .import_with_advisories(
                None,
                &hub_ref,
                &package,
                preferred_id,
                &inventory,
                super::osv::hub_advisory_query(adapter.kind()),
                occurred,
                learned_at,
                &mut super::SkillImportRows::default(),
            )?
            .entity)
    }

    pub(super) fn import_skill_from_hub_with_id(
        &self,
        hub_ref: &HubRef,
        package: &HubPackage,
        preferred_id: EntityId,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let mut wtxn = self.store.env.write_txn()?;
        let entity = self.import_skill_from_hub_in_txn(
            &mut wtxn,
            hub_ref,
            package,
            preferred_id,
            occurred,
            learned_at,
            &mut super::SkillImportRows::default(),
        )?;
        wtxn.commit()?;
        Ok(entity)
    }

    /// Imports `package` with its scan receipts in one writer. With `owner`,
    /// the owner proof is checked in that writer before anything lands.
    /// `rows` notes the stored skill its content deduplicated to.
    #[expect(
        clippy::too_many_arguments,
        reason = "the import binds the owner proof, package identity, scans and import timing"
    )]
    pub(super) fn import_skill_from_hub_with_scans(
        &self,
        owner: Option<&AuthenticatedOwner>,
        hub_ref: &HubRef,
        package: &HubPackage,
        preferred_id: EntityId,
        scans: &[super::SkillScanReceipt],
        occurred: TimeRange,
        learned_at: u64,
        rows: &mut super::SkillImportRows,
    ) -> Result<EntityId> {
        let mut wtxn = self.store.env.write_txn()?;
        if let Some(owner) = owner {
            self.check_restore_owner_in_txn(&wtxn, owner)?;
        }
        let entity = self.import_skill_from_hub_in_txn(
            &mut wtxn,
            hub_ref,
            package,
            preferred_id,
            occurred,
            learned_at,
            rows,
        )?;
        let content_hash = package.content_hash()?;
        for receipt in scans {
            self.ingest_skill_scan_verdict_in_txn(
                &mut wtxn,
                &entity,
                content_hash,
                receipt,
                occurred,
                learned_at,
            )?;
        }
        wtxn.commit()?;
        Ok(entity)
    }

    /// Imports `package` in `wtxn`, deduplicating by content; `rows` notes
    /// the stored skill a dedup answers (FIX 11699).
    #[expect(
        clippy::too_many_arguments,
        reason = "the import's writer, package identity, timing and its read report"
    )]
    pub(super) fn import_skill_from_hub_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        hub_ref: &HubRef,
        package: &HubPackage,
        preferred_id: EntityId,
        occurred: TimeRange,
        learned_at: u64,
        rows: &mut super::SkillImportRows,
    ) -> Result<EntityId> {
        self.import_skill_from_hub_checked_in_txn(
            wtxn,
            hub_ref,
            package,
            preferred_id,
            occurred,
            learned_at,
            false,
            rows,
        )
    }

    /// Explicit restore births a new holder instead of deduplicating to a
    /// locally changed or retired default. Its caller must establish the
    /// shipped source and must select a fresh, non-tombstoned ID.
    pub(super) fn restore_skill_from_hub_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        hub_ref: &HubRef,
        package: &HubPackage,
        preferred_id: EntityId,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.import_skill_from_hub_checked_in_txn(
            wtxn,
            hub_ref,
            package,
            preferred_id,
            occurred,
            learned_at,
            true,
            &mut super::SkillImportRows::default(),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "import and explicit fresh restore share the same admission path"
    )]
    fn import_skill_from_hub_checked_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        hub_ref: &HubRef,
        package: &HubPackage,
        preferred_id: EntityId,
        occurred: TimeRange,
        learned_at: u64,
        fresh: bool,
        rows: &mut super::SkillImportRows,
    ) -> Result<EntityId> {
        hub_ref.validate()?;
        encode_skill_record(&package.record)?;
        let content_hash = package.content_hash()?;
        if package
            .record
            .content_hash
            .is_some_and(|declared| declared != content_hash)
        {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "package content hash does not match its canonical file tree",
            )));
        }
        if let HubPin::ContentHash(pinned_hash) = &hub_ref.pin
            && SkillContentHash::parse_hex(pinned_hash)? != content_hash
        {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "content-hash-pinned ref drifted",
            )));
        }
        if package.record.source != ClaimSource::Imported {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "hub import package must carry imported source",
            )));
        }
        if fresh
            && (crate::ports::EntityStoreRead::port_entity_present(
                &self.store,
                wtxn,
                &preferred_id,
            )? || self.local_hard_delete_marker_exists_in_txn(wtxn, &preferred_id)?)
        {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "restore target is not a fresh entity id",
            )));
        }
        let entity = match if fresh {
            None
        } else {
            self.imported_skill_entity_for_content_hash_in_txn(wtxn, content_hash, Some(hub_ref))?
        } {
            Some(existing) => {
                // The import stands on the holder it found, refused or not.
                rows.existing = Some(existing);
                let existing_record = self.read_skill_record_in_txn(wtxn, &existing)?;
                if existing_record.skill_id != package.record.skill_id {
                    return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                        "hub import content hash collides with a different skill id",
                    )));
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
                    wtxn,
                    &preferred_id,
                    &candidate,
                    occurred,
                    learned_at,
                )?;
                self.write_admitted_capability_surface_in_txn(
                    wtxn,
                    &preferred_id,
                    &package.capabilities,
                )?;
                preferred_id
            }
        };

        match self.read_admitted_capability_surface_in_txn(wtxn, &entity)? {
            Some(admitted) if admitted != package.capabilities => {
                return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                    "matching content hash carries conflicting capabilities",
                )));
            }
            Some(_) => {}
            None => {
                self.write_admitted_capability_surface_in_txn(
                    wtxn,
                    &entity,
                    &package.capabilities,
                )?;
            }
        }
        self.append_hub_provenance_in_txn(
            wtxn,
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
            wtxn,
            &entity,
            content_hash,
            package,
            occurred,
            learned_at,
        )?;
        let mut saved = package.clone();
        saved.record = self.read_skill_record_in_txn(wtxn, &entity)?;
        self.persist_hub_package_in_txn(wtxn, &entity, &saved)?;
        crate::team::pattern::bind_hub_pattern_in_txn(
            self,
            wtxn,
            &entity,
            &saved.files,
            learned_at,
        )?;
        self.write_hub_import_receipt_in_txn(
            wtxn,
            &entity,
            content_hash,
            hub_ref,
            None,
            learned_at,
        )?;
        Ok(entity)
    }

    /// Counts active mutable provenance aliases for one skill entity.
    pub fn skill_hub_provenance_count(&self, entity: &EntityId) -> Result<usize> {
        Ok(self
            .active_claims_for_predicate(entity, PREDICATE_SKILL_HUB_PROVENANCE)?
            .len())
    }

    /// Under an automatic policy, applies same-or-narrower updates and
    /// proposes capability widening. A changed Active body applies unless
    /// the owner's hash rule blocks it; a blocked one is proposed and the
    /// live bytes stay. A scanner flag on the update's bytes holds
    /// nothing: the scanner is a signal, and its verdict rows stay on the
    /// update (ARCH-0053 #promise-gate-23).
    pub fn sync_skill_from_hub(
        &self,
        entity: &EntityId,
        hub_ref: &HubRef,
        package: &HubPackage,
        sync_policy: HubSyncPolicy,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<HubSyncDisposition> {
        self.sync_skill_from_hub_with_query(
            entity,
            hub_ref,
            package,
            sync_policy,
            occurred,
            learned_at,
            &super::osv::OsvDevClient,
        )
    }

    /// Lands a same-or-narrower hub update on `entity` in `txn`: the record
    /// with its local axes kept, the capability surface, provenance, the
    /// static and advisory scan receipts and the package. Answers whether
    /// the update's own admission passed: the owner's hash rule does not
    /// block the bytes. A scanner flag on the bytes holds nothing — the
    /// scanner is a signal, and its verdict rows stay on the update with
    /// the approval as it was (ARCH-0053 #promise-gate-23).
    #[expect(
        clippy::too_many_arguments,
        reason = "the sync's checked record, package identity, scans and write timing"
    )]
    fn apply_hub_sync_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        current: &crate::skill::SkillRecord,
        hub_ref: &HubRef,
        package: &HubPackage,
        content_hash: SkillContentHash,
        scans: &[super::SkillScanReceipt],
        occurred: TimeRange,
        learned_at: u64,
        authorization: Option<&crate::consent::ApproveOnceAuthorization>,
    ) -> Result<bool> {
        let updated = local_sync_record(package, current, content_hash);
        if let Some(authorization) = authorization {
            self.apply_hub_update_record_with_consent_in_txn(
                txn,
                entity,
                &updated,
                occurred,
                learned_at,
                authorization,
            )?;
        } else {
            self.apply_hub_sync_skill_record(txn, entity, &updated, occurred, learned_at)?;
        }
        self.write_admitted_capability_surface_in_txn(txn, entity, &package.capabilities)?;
        if current.content_hash != Some(content_hash) {
            self.replace_hub_provenance_in_txn(
                txn,
                entity,
                content_hash,
                hub_ref,
                occurred,
                learned_at,
            )?;
        }
        // ONE-1892: the update door's half of the producer. Unconditional
        // rather than gated on a content-hash change because the guard that
        // matters is content-keyed — an unchanged hash that already carries a
        // static receipt is a no-op here, while a hash that never got one
        // (bytes born through a non-hub path) is scanned on this pass.
        self.scan_and_ingest_on_import_in_txn(
            txn,
            entity,
            content_hash,
            package,
            occurred,
            learned_at,
        )?;
        for receipt in scans {
            self.ingest_skill_scan_verdict_in_txn(
                txn,
                entity,
                content_hash,
                receipt,
                occurred,
                learned_at,
            )?;
        }
        let mut saved = package.clone();
        saved.record = self.read_skill_record_in_txn(txn, entity)?;
        self.persist_hub_package_in_txn(txn, entity, &saved)?;
        crate::team::pattern::bind_hub_pattern_in_txn(self, txn, entity, &saved.files, learned_at)?;
        // GATE-23 (ARCH-0053 #promise-gate-23): a scanner flag on the
        // update's bytes holds nothing — the scanner is a signal, and the
        // verdict rows ingested above stay on the update with the record's
        // approval as it was. Only the owner's hash rule decides admission.
        Ok(!super::import_receipt::marketplace_hash_blocked_in_txn(
            &self.store,
            txn,
            content_hash,
        )?)
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

/// The identity, content-hash and pin checks a hub sync package must pass
/// before its sync policy is consulted.
fn validate_sync_package(
    current: &crate::skill::SkillRecord,
    package: &HubPackage,
    hub_ref: &HubRef,
    content_hash: SkillContentHash,
    sync_policy: HubSyncPolicy,
) -> Result<()> {
    if current.source != ClaimSource::Imported
        || package.record.source != ClaimSource::Imported
        || current.skill_id != package.record.skill_id
    {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "hub sync package must match an imported skill",
        )));
    }
    if package
        .record
        .content_hash
        .is_some_and(|declared| declared != content_hash)
    {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "package content hash does not match its canonical file tree",
        )));
    }
    // A content-hash pin binds the ref's identity on every sync path, not only under the
    // frozen policy (mirrors the import door at import_skill_from_hub_with_id).
    if let HubPin::ContentHash(pinned) = &hub_ref.pin
        && SkillContentHash::parse_hex(pinned)? != content_hash
    {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "content-hash-pinned ref drifted",
        )));
    }
    if sync_policy == HubSyncPolicy::ContentHashFrozen
        && !matches!(&hub_ref.pin, HubPin::ContentHash(_))
    {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "content-hash-frozen policy requires a content_hash pin",
        )));
    }
    Ok(())
}

/// The package record a hub sync writes, with the local approval, lifecycle
/// and governance axes kept from `current`.
fn local_sync_record(
    package: &HubPackage,
    current: &crate::skill::SkillRecord,
    content_hash: SkillContentHash,
) -> crate::skill::SkillRecord {
    let mut updated = package.record.clone();
    // Hub sync mutates content fields; canonical approval/lifecycle state stays local.
    updated.approval_status = current.approval_status;
    updated.lifecycle_status = current.lifecycle_status;
    // ONE-1448: `governance_tier` is the THIRD state axis — `skill.rs`'s
    // `skill_content_changed` normalizes it away beside the first two, and
    // it is the OWNER's axis in the same way they are. The mark says what
    // the local automated edit loop may do WITH these instructions, never
    // what the instructions ARE, so upstream has nothing to say about it:
    // taking it from the package would let a revision that merely omits
    // the key (the wire elides an absent mark) delete an owner's Identity
    // mark, and an unmarked record carrying a hub-provenance alias then
    // resolves to `LegacyStandard`
    // ([`crate::skill_optimize::skill_governance_tier`]) — i.e. straight
    // back into the loop the mark existed to keep it out of. The owner
    // moves this axis through the ordinary update door; sync never does.
    updated.governance_tier = current.governance_tier;
    updated.content_hash = Some(content_hash);
    updated
}
