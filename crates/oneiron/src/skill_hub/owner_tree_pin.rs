//! The owner's pinned team-shape revisions (ARCH-0079 #seed-pin; lead
//! COORD-E2E-TREE-PIN = A, 24 Nov 2026 22:45): the one write that admits a
//! same-skill revision of the vault team-shape head carrying the tree the
//! owner put in force, on the owner's own yes, and what says a revision is
//! one: its own record, which every device holding it reads alike. The
//! Coach's tree gate and a shared merge read it on the head they would
//! replace, and leave their revision a proposal. Also the owner's pin of a
//! tree on an open fork, the one tree a promote takes from that fork.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::package_codec::invalid;
use super::{HubAdmissionProof, SkillPackageFormat};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::consent::{AuthenticatedOwner, ComposedEffect, EffectFacts};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::task_type::TaskTypeTree;
use crate::temporal::TimeRange;

/// The provenance `source` of an owner-pinned revision.
const OWNER_TREE_PIN_SOURCE: &str = "owner-tree-pin";

/// The owner's pin of one tree on one open fork (`vault.task_types.pin`):
/// the version the pin stored the tree at, and the fork's package hash right
/// after that write. A promote takes the fork's tree only while both hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerTreeStage {
    tree_version: u64,
    package_hash: String,
}

/// The owner's last pin on each fork. Key: the fork's id.
const OWNER_TREE_STAGE: SideTable<EntityId, OwnerTreeStage, Named> =
    SideTable::new(&side_table::SKILL_HUB_OWNER_TREE_STAGE);

/// Whether `record` is a revision [`crate::Vault::admit_owner_tree_revision_in_txn`]
/// admitted: a revision the user stated and the owner approved, whose
/// provenance names the owner's pin as its source and the head it revises
/// (any skill id: a fork put in force keeps its own). The record replicates with the revision, so an own-device
/// replica reads the pin as its origin does. A record that carries these
/// fields some other way reads as pinned too; that only keeps the Coach and
/// a shared merge from replacing it, and the owner still can.
fn owner_pinned_record(record: &SkillRecord) -> bool {
    let Value::Map(fields) = &record.provenance else {
        return false;
    };
    let field = |name: &str| {
        fields.iter().find_map(|(key, value)| {
            (key.as_str() == Some(name))
                .then(|| value.as_str())
                .flatten()
        })
    };
    matches!(record.source, ClaimSource::UserStated)
        && record.approval_status == ClaimApprovalStatus::Approved
        && field("source") == Some(OWNER_TREE_PIN_SOURCE)
        && field("revises").is_some()
}

/// Where the tree an owner-pinned revision carries came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerTreeOrigin {
    /// The tree the owner stored on this open fork (`vault.task_types.pin`).
    Pin(EntityId),
    /// The tree this earlier revision on the vault chain carried: a revert.
    Restore(EntityId),
}

impl crate::Vault {
    /// Whether `skill` is a team-shape revision the owner pinned, read from
    /// its own record ([`owner_pinned_record`]), so one revision's answer
    /// never changes and is the same on every device that holds it. A skill
    /// this vault does not hold is not pinned.
    pub(crate) fn owner_pinned_tree_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        skill: &EntityId,
    ) -> Result<bool> {
        Ok(self
            .get_skill_record_in_txn(txn, skill)?
            .is_some_and(|record| owner_pinned_record(&record)))
    }

    /// Records, in the caller's write that just stored the owner's pin on
    /// `fork`, that the fork's tree at `tree_version` is the owner's: the
    /// version and the fork's package hash as that write left it. The next
    /// pin on the fork replaces it.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::InvalidSkillBody`] for a fork with no package hash;
    /// storage errors.
    pub(crate) fn stage_owner_tree_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fork: &EntityId,
        tree_version: u64,
    ) -> Result<()> {
        let package_hash = self
            .read_skill_record_in_txn(txn, fork)?
            .content_hash
            .ok_or_else(|| invalid("the owner's pinned fork has no package hash"))?
            .to_hex();
        OWNER_TREE_STAGE.put(
            &self.store,
            txn,
            fork,
            &OwnerTreeStage {
                tree_version,
                package_hash,
            },
        )
    }

    /// Whether the owner's last pin on `fork` (whose record is `record`)
    /// stored its tree at `tree_version`, and the fork's package is still
    /// the one that pin left.
    pub(crate) fn owner_staged_tree_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fork: &EntityId,
        record: &SkillRecord,
        tree_version: u64,
    ) -> Result<bool> {
        let Some(stage) = OWNER_TREE_STAGE.get(&self.store, txn, fork)? else {
            return Ok(false);
        };
        Ok(stage.tree_version == tree_version
            && record.content_hash.as_ref().map(|hash| hash.to_hex()) == Some(stage.package_hash))
    }

    /// Puts `tree` in force on the vault team-shape head `head`, in the
    /// caller's write, as the owner: a fresh revision of the head's skill,
    /// owner-authored, at a new skill version, whose package is the head's
    /// with only the tree and SKILL.md's `name:` and `version:` lines
    /// changed. It keeps the head's resident, role, call contract,
    /// dependencies, admitted capability surface and resolved governance
    /// tier. The owner is checked again in this write; the yes is an
    /// approve-once receipt for this exact revision, spent by its admission.
    /// The revision's record names it owner-pinned ([`owner_pinned_record`])
    /// and it supersedes `head`, which freezes. No optimizer origin and no
    /// held-out verdict are claimed.
    /// Returns the new head.
    ///
    /// # Errors
    ///
    /// A stale or non-owner proof; [`ArtifactError::InvalidSkillBody`] for a
    /// head that is not active or a revision that does not load;
    /// [`ArtifactError::SkillPackageUnavailable`] for a head whose package
    /// this vault no longer holds; the materialization door's and the
    /// supersession door's refusals; storage errors.
    pub(crate) fn admit_owner_tree_revision_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        head: &EntityId,
        tree: &TaskTypeTree,
        origin: OwnerTreeOrigin,
        at: u64,
    ) -> Result<EntityId> {
        self.check_restore_owner_in_txn(txn, owner)?;
        let base = self.read_skill_record_in_txn(txn, head)?;
        if base.lifecycle_status != SkillLifecycle::Active {
            return Err(invalid(
                "the owner's tree goes onto the active team-shape head",
            ));
        }
        let mut package =
            self.runtime_skill_package_in_txn(txn, head, &base)?
                .ok_or(Error::Artifact(ArtifactError::SkillPackageUnavailable {
                    revision: *head,
                }))?;
        let mut record = owner_revision_record(&base, head, origin)?;
        // A revision with no tier reads ambiguous and the Coach could never
        // propose over it: the head's resolved tier is stamped explicitly.
        record.governance_tier =
            crate::skill_optimize::tier_verdict_in_txn(self, txn, head, &base)?.tier();
        let content =
            serde_json::to_vec_pretty(tree).map_err(|_| invalid("type tree does not encode"))?;
        package.files = crate::agent_dispatch::fork_files(
            &package,
            &record.skill_id,
            &record.version,
            &content,
        )?;
        package.format = SkillPackageFormat::Native;
        let hash = package.content_hash()?;
        record.content_hash = Some(hash);
        let package = super::folder::package_from_source(&record, package.files, package.format)?;
        let revision = self.store.clock.entity_id()?;
        let occurred = TimeRange { start: at, end: at };
        self.put_skill_record_in_txn(txn, &revision, &record, occurred, at)?;
        self.persist_hub_package_in_txn(txn, &revision, &package)?;
        self.scan_and_ingest_on_import_in_txn(txn, &revision, hash, &package, occurred, at)?;
        if let Some(surface) = self.read_admitted_capability_surface_in_txn(txn, head)? {
            self.write_admitted_capability_surface_in_txn(txn, &revision, &surface)?;
        }
        let effect = ComposedEffect::new(EffectFacts::new(format!(
            "task_types.promote:{}:{}:{}",
            head.to_hex(),
            revision.to_hex(),
            hash.to_hex(),
        ))?)
        .digest();
        self.approve_once_in_txn(txn, owner, effect)?;
        let answer = crate::consent::approve_once_authorization_in_txn(&self.store, txn, &effect)?
            .ok_or_else(|| invalid("the owner's promote answer is missing"))?;
        record.lifecycle_status = SkillLifecycle::Active;
        record.approval_status = ClaimApprovalStatus::Approved;
        let data = crate::skill::encode_skill_record(&record)?;
        let proof = HubAdmissionProof::consent(&self.store, txn, revision, &data, &answer)?;
        self.admit_hub_skill_record_in_txn(txn, occurred, at, data, proof)?;
        let admitted = self.read_skill_record_in_txn(txn, &revision)?;
        if !crate::skill::skill_loadable(&admitted) {
            return Err(invalid("the owner's team-shape revision does not load"));
        }
        if !owner_pinned_record(&admitted) {
            return Err(invalid(
                "the owner's team-shape revision does not read as owner-pinned",
            ));
        }
        self.supersede_skill_record_in_txn(txn, head, &revision, occurred, at)?;
        Ok(revision)
    }
}

/// The Candidate record of the owner's revision of `base` (the head `head`):
/// `base`'s skill id, description, role, call contract and dependencies at a
/// new version, owner-authored, with provenance naming the head it revises
/// and where its tree came from, and `base`'s resident.
fn owner_revision_record(
    base: &SkillRecord,
    head: &EntityId,
    origin: OwnerTreeOrigin,
) -> Result<SkillRecord> {
    let (origin_key, origin_ref) = match origin {
        OwnerTreeOrigin::Pin(fork) => ("pins", fork),
        OwnerTreeOrigin::Restore(revision) => ("restores", revision),
    };
    let mut provenance = vec![
        (Value::from("source"), Value::from(OWNER_TREE_PIN_SOURCE)),
        (Value::from("revises"), Value::from(head.to_hex())),
        (Value::from(origin_key), Value::from(origin_ref.to_hex())),
    ];
    if let Some(resident) = crate::skill::resident_of(base)? {
        provenance.push((
            Value::from(crate::skill::resident::RESIDENT_PROVENANCE_KEY),
            Value::from(resident.to_hex()),
        ));
    }
    Ok(SkillRecord::new(
        base.skill_id.as_str(),
        base.desc.clone(),
        crate::agent_dispatch::next_version(&base.version, &base.version),
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        base.dependencies.clone(),
        Value::Map(provenance),
    )
    .with_role(base.role, base.call.clone()))
}
