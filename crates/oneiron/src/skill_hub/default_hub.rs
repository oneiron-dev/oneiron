//! First-party library source: offline seeding, immutable Git ref, explicit import.

use super::{
    ForeignSkillPublisher, GitEndpointSkillHubAdapter, HubPin, HubRef, HubSyncPolicy, SkillHubKind,
    SkillHubRecord, SkillHubTrustTier, TrackedHubRef, encode_skill_hub_record,
    pack_catalog::{
        PackFitPolicy, PackFitVerdict, PackInstallDisposition, PackInstallReceipt, PackPermissions,
        PackSource,
    },
};
use crate::entity_id::derived_domains::FIRST_PARTY_SKILL_HUB;
use crate::{EntityId, Vault, consent::AuthenticatedOwner, error::Result, temporal::TimeRange};

/// Released oneiron-hub revision for library skills, and the model catalog
/// ref's pin until the owner sets that ref's own policy. A floating branch or
/// network lookup never changes an opened vault's skill source.
const HUB_COMMIT: &str = "e1040cbcc1ca2a1eb8404c8fc80956b0e75ae3e5";
const HUB_ENDPOINT: &str = "https://github.com/oneiron-dev/oneiron-hub.git";
/// Library data, deliberately not a fifth build-embedded bootstrap skill.
pub const REVIEW_BUNDLE_EXPLAINER_SUBTREE: &str = "skills/review-bundle-explainer";
/// The model catalog has no authority of its own. Its rows count once the
/// fetched bytes carry scan evidence and the pack installs; which bytes are
/// fetched is the ref's sync policy, vault data rather than an engine constant.
pub(crate) const MODEL_PACK_SUBTREE: &str = "packs/model-catalog";
pub(crate) const MODEL_PACK_NAME: &str = "oneiron.models";
/// The publisher an owner admits when syncing the first-party catalog.
const MODEL_PACK_PUBLISHER: &str = "publisher:oneiron-hub";

/// The model catalog ref as an owner reads it: its policy and pin, the
/// revisions seen and trusted, and the installed pack's receipt.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ModelCatalogSync {
    pub sync_policy: &'static str,
    pub pin_type: &'static str,
    pub pin_value: Option<String>,
    pub latest_seen: Option<String>,
    pub latest_trusted: Option<String>,
    pub installed: Option<PackInstallReceipt>,
}

/// The engine's fit rung for a knowledge-only pack: nothing runs, nothing is
/// granted, nothing wakes and no skill rides along.
struct KnowledgeOnlyFit;
impl PackFitPolicy for KnowledgeOnlyFit {
    fn evaluate(
        &self,
        source: &PackSource,
        permissions: &PackPermissions,
    ) -> Result<PackFitVerdict> {
        Ok(PackFitVerdict {
            fits: !source.has_code()
                && permissions.grants.is_empty()
                && permissions.wakes.is_empty()
                && permissions.bundled_skills.is_empty(),
            rules_hit: false,
            code_auto_install: false,
        })
    }
}

/// Stable identity of the first-party library hub in every vault.
pub fn default_skill_hub_id() -> Result<EntityId> {
    EntityId::derive(FIRST_PARTY_SKILL_HUB, &[])
}

/// Immutable revision used for imports from the shipped library.
#[must_use]
pub const fn default_skill_hub_commit() -> &'static str {
    HUB_COMMIT
}

pub(crate) fn seed_default_skill_hub(vault: &Vault) -> Result<()> {
    // The other registries-family seed rides this open-time call: the
    // compiled `comm.*` claim-class descriptors (type 91), each at a fixed id
    // with a fixed body, so every node seeds the same rows.
    crate::comm::seed_claim_class_descriptors(vault)?;
    let id = default_skill_hub_id()?;
    let mut txn = vault.store.env.write_txn()?;
    // Reopens never revert an owner's endpoint, trust, or policy changes. Nor
    // does an erased default come back without an explicit restore decision.
    if crate::ports::EntityStoreRead::port_entity_present(&vault.store, &txn, &id)?
        || vault.local_hard_delete_marker_exists_in_txn(&txn, &id)?
    {
        return Ok(());
    }
    let row = SkillHubRecord::new(
        SkillHubKind::Git,
        HUB_ENDPOINT,
        SkillHubTrustTier::Verified,
        HubSyncPolicy::PinnedCommit,
    )?;
    crate::batch::apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        &mut txn,
        vec![crate::batch::BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_SKILL_HUB,
            occurred: TimeRange { start: 0, end: 0 },
            learned_at: 0,
            data: encode_skill_hub_record(&row)?,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        true,
        true,
    )?;
    txn.commit()?;
    Ok(())
}

impl Vault {
    /// Reads a configured hub without granting it activation authority.
    pub fn skill_hub_record(&self, id: &EntityId) -> Result<SkillHubRecord> {
        let txn = self.store.env.read_txn()?;
        self.hub_record_in_txn(&txn, id)
    }

    /// Fetches a library skill from the shipped commit through the ordinary Git
    /// adapter and import/scanner doors. No network access occurs during open.
    /// An owner may change the configured endpoint, but cannot change the commit
    /// pinned by this door; a source that lacks it fails closed.
    pub fn import_default_hub_skill(
        &self,
        subtree: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.import_default_hub_skill_at_commit(subtree, HUB_COMMIT, occurred, learned_at)
    }

    /// Imports the review explainer through the pinned library/scanner path.
    /// Activation, governance and optimized forks use the ordinary skill doors.
    /// The returned entity (or an optimized descendant) is supplied to
    /// `entity_doc::review_explainer::ReviewExplainerExecution` by its host.
    pub fn import_review_bundle_explainer_skill(
        &self,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.import_default_hub_skill(REVIEW_BUNDLE_EXPLAINER_SUBTREE, occurred, learned_at)
    }

    /// The model catalog ref's policy: the owner's stored row, else the
    /// released commit.
    pub fn model_catalog_ref(&self) -> Result<TrackedHubRef> {
        let hub = default_skill_hub_id()?;
        match self.hub_ref_sync(&hub, MODEL_PACK_SUBTREE)? {
            Some(tracked) => Ok(tracked),
            None => Ok(TrackedHubRef::new(
                HubRef::new(hub, MODEL_PACK_SUBTREE, HubPin::Commit(HUB_COMMIT.into()))?,
                HubSyncPolicy::PinnedCommit,
            )),
        }
    }

    /// The catalog ref and the installed pack, for the owner's view.
    pub fn model_catalog_sync(&self) -> Result<ModelCatalogSync> {
        let tracked = self.model_catalog_ref()?;
        Ok(ModelCatalogSync {
            sync_policy: tracked.sync_policy.as_str(),
            pin_type: tracked.hub_ref.pin.pin_type(),
            pin_value: match tracked.hub_ref.pin {
                HubPin::Commit(value)
                | HubPin::Tag(value)
                | HubPin::Semver(value)
                | HubPin::ContentHash(value) => Some(value),
                HubPin::None => None,
            },
            latest_seen: tracked.latest_seen,
            latest_trusted: tracked.latest_trusted,
            installed: self.installed_pack(MODEL_PACK_NAME)?,
        })
    }

    /// Owner door: point the model catalog ref at a commit (pinned-commit), a
    /// tag it follows (pinned-ref) or one content hash (content-hash-frozen).
    /// Nothing is fetched until the next sync.
    pub fn set_model_catalog_sync(
        &self,
        owner: &AuthenticatedOwner,
        sync_policy: HubSyncPolicy,
        pin: String,
    ) -> Result<ModelCatalogSync> {
        let pin = match sync_policy {
            HubSyncPolicy::PinnedCommit => HubPin::Commit(pin),
            HubSyncPolicy::PinnedRef => HubPin::Tag(pin),
            HubSyncPolicy::ContentHashFrozen => HubPin::ContentHash(pin),
            HubSyncPolicy::MirrorOfHub => {
                return Err(crate::error::Error::InvalidConfig(
                    "the model catalog ref has no mirror source".to_owned(),
                ));
            }
        };
        let reference = HubRef::new(default_skill_hub_id()?, MODEL_PACK_SUBTREE, pin)?;
        self.set_hub_ref_sync(owner, reference, sync_policy)?;
        self.model_catalog_sync()
    }

    /// Fetch the model catalog at its ref's policy through the Git transport
    /// and pack source door, which lands scan verdicts on the bytes' hash. The
    /// caller must still qualify and explicitly install the pack.
    pub fn fetch_model_catalog_pack(
        &self,
        publisher: &ForeignSkillPublisher,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<(EntityId, HubRef)> {
        let (source_id, pinned, _) =
            self.fetch_model_catalog_at_ref(publisher, occurred, learned_at)?;
        Ok((source_id, pinned))
    }

    fn fetch_model_catalog_at_ref(
        &self,
        publisher: &ForeignSkillPublisher,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<(EntityId, HubRef, String)> {
        let id = default_skill_hub_id()?;
        let row = self.skill_hub_record(&id)?;
        if row.kind != SkillHubKind::Git {
            return Err(crate::error::Error::InvalidConfig(
                "model catalog requires the Git hub".to_owned(),
            ));
        }
        let tracked = self.model_catalog_ref()?;
        // Each policy names the commit this fetch must resolve. The commit is
        // transport identity only: a followed tag is pinned to what it names now.
        let (adapter, reference) =
            super::ref_sync::git_ref_adapter(id, &row.endpoint, &tracked, Some(HUB_COMMIT))?;
        let (source_id, pinned) =
            self.fetch_pack_from_adapter(&adapter, &reference, publisher, occurred, learned_at)?;
        let commit = adapter.resolved_commit().to_owned();
        self.mark_hub_ref(&tracked, &commit, false)?;
        let source = self.get_pack_source(&source_id)?.ok_or_else(|| {
            crate::error::Error::InvalidConfig("fetched model pack is missing".into())
        })?;
        if source.manifest().name != MODEL_PACK_NAME {
            return Err(crate::error::Error::InvalidConfig(
                "fetched pack is not the model catalog".into(),
            ));
        }
        Ok((source_id, pinned, commit))
    }

    /// Owner door: sync the model catalog to its ref's policy. Fetch, the
    /// engine's knowledge-only fit and the ordinary install door run in turn;
    /// the install activates the rows that inference admission reads.
    pub fn sync_model_catalog(&self, owner: &AuthenticatedOwner) -> Result<PackInstallDisposition> {
        let at = self.now_recorded_at();
        let hub = default_skill_hub_id()?;
        let publisher = self.admit_skill_publisher(owner, MODEL_PACK_PUBLISHER, hub)?;
        let tracked = self.model_catalog_ref()?;
        let (source_id, pinned, commit) =
            self.fetch_model_catalog_at_ref(&publisher, TimeRange { start: at, end: at }, at)?;
        let ask = self.prepare_pack_install(source_id, &pinned, &publisher, &KnowledgeOnlyFit)?;
        let disposition = self.install_pack(&ask)?;
        if matches!(disposition, PackInstallDisposition::Installed(_)) {
            self.mark_hub_ref(&tracked, &commit, true)?;
        }
        Ok(disposition)
    }

    fn import_default_hub_skill_at_commit(
        &self,
        subtree: &str,
        commit: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        let id = default_skill_hub_id()?;
        let row = self.skill_hub_record(&id)?;
        if row.kind != SkillHubKind::Git || row.sync_policy != HubSyncPolicy::PinnedCommit {
            return Err(crate::error::Error::InvalidConfig(
                "default skill hub requires pinned Git configuration".to_owned(),
            ));
        }
        let adapter = GitEndpointSkillHubAdapter::new(id, &row.endpoint, commit)?;
        let reference = HubRef::new(id, subtree, HubPin::Commit(commit.to_owned()))?;
        self.import_skill_from_adapter(&adapter, &reference, occurred, learned_at)
    }

    /// Re-imports a deleted or locally retired library skill from the pinned
    /// first-party commit. Unchanged imports are left alone; a restore births
    /// a new Candidate rather than reviving the old entity or its authority.
    pub fn restore_default_hub_skill(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        subtree: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        self.restore_default_hub_skill_at_commit(owner, subtree, HUB_COMMIT, occurred, learned_at)
    }

    fn restore_default_hub_skill_at_commit(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        subtree: &str,
        commit: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<EntityId> {
        use super::SkillHubAdapter;
        let id = default_skill_hub_id()?;
        self.check_restore_owner_in_txn(&self.store.env.read_txn()?, owner)?;
        let row = self.skill_hub_record(&id)?;
        if row.kind != SkillHubKind::Git || row.sync_policy != HubSyncPolicy::PinnedCommit {
            return Err(crate::error::Error::InvalidConfig(
                "default skill hub requires pinned Git configuration".to_owned(),
            ));
        }
        let adapter = GitEndpointSkillHubAdapter::new(id, &row.endpoint, commit)?;
        let source = HubRef::new(id, subtree, HubPin::Commit(commit.to_owned()))?;
        let package = adapter.fetch_package(&source)?;
        let hash = package.content_hash()?;
        // A no-op restore makes no advisory request. Recheck after the
        // network work inside the write transaction before minting an ID.
        let existing = {
            let txn = self.store.env.read_txn()?;
            self.check_restore_owner_in_txn(&txn, owner)?;
            if self.hub_record_in_txn(&txn, &id)? != row {
                return Err(crate::error::Error::InvalidConfig(
                    "default skill hub configuration changed during fetch".to_owned(),
                ));
            }
            self.default_skill_present_in_txn(&txn, &source, hash, &package.record.skill_id)?
        };
        if let Some(entity) = existing {
            return Ok(entity);
        }
        let coordinates = super::osv::dependency_inventory(&package)?;
        let (_, _, scans) =
            self.dependency_advisories(hash, &coordinates, &super::osv::OsvDevClient, learned_at)?;
        let mut txn = self.store.env.write_txn()?;
        self.check_restore_owner_in_txn(&txn, owner)?;
        if self.hub_record_in_txn(&txn, &id)? != row {
            return Err(crate::error::Error::InvalidConfig(
                "default skill hub configuration changed during fetch".to_owned(),
            ));
        }
        if let Some(entity) =
            self.default_skill_present_in_txn(&txn, &source, hash, &package.record.skill_id)?
        {
            return Ok(entity);
        }
        let entity = self.restore_default_skill_in_txn(
            &mut txn,
            owner,
            &source,
            &package,
            self.store.clock.entity_id()?,
            occurred,
            learned_at,
        )?;
        for scan in &scans {
            self.ingest_skill_scan_verdict_in_txn(
                &mut txn, &entity, hash, scan, occurred, learned_at,
            )?;
        }
        txn.commit()?;
        Ok(entity)
    }
}

#[cfg(test)]
mod tests;
