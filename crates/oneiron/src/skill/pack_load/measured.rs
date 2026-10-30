//! The pack load of a paired eval measurement's skill arm (FIX 10677). An
//! arm pins skill content by its digest; the measuring host loads exactly
//! that content on its own leased attempt, through the pinned-pack load.
//!
//! - An active approved shared skill, or the open optimizer proposal of
//!   one, loads through [`Vault::load_attempt_pinned_skill_pack`].
//! - An agent-born callable helper still Candidate and Proposed, the subject
//!   of the helper gate, loads the same way: its exact revision, its
//!   manifest row once, its read set. No exploration trial routes it and no
//!   resident is bound.
//! - Anything else does not load, and the host says why on the row.

use super::{LoadedSkillPack, skill_loadable};
use crate::attempt_queue::{AttemptRecord, ManifestEntry, ManifestKind, ReadSetProducer};
use crate::claim::ClaimApprovalStatus;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillLifecycle, SkillRecord, SkillRole};
use crate::{EntityId, Error, Result, Vault};

/// What a measured skill arm's load came to.
#[derive(Debug, Clone)]
pub enum MeasuredSkillPack {
    /// The pinned content, loaded and stamped on the attempt.
    Loaded(LoadedSkillPack),
    /// No live skill carries the pinned content now.
    Gone,
    /// A live skill carries it, and its pack does not load for a
    /// measurement: a resident's own skill, a retired or rejected one, or a
    /// revision that moved under the load.
    Refused,
}

/// The door a live skill carrying the content loads through.
enum MeasuredArm {
    /// The pinned-pack load, under the shared skill it binds.
    Pinned(EntityId),
    /// A Candidate helper awaiting its gate.
    Helper,
    Refused,
}

/// Whether `record` is an agent-born helper awaiting its gate.
fn awaiting_helper_gate(record: &SkillRecord) -> bool {
    record.role == SkillRole::Callable
        && record.call.is_some()
        && record.lifecycle_status == SkillLifecycle::Candidate
        && record.approval_status == ClaimApprovalStatus::Proposed
}

fn content_hex(record: &SkillRecord) -> Option<String> {
    record.content_hash.as_ref().map(|hash| hash.to_hex())
}

impl Vault {
    /// Loads the skill content a measurement arm pins, by its content
    /// `digest` (hex), on `leased`, the measuring host's own attempt, in
    /// that attempt's lease generation. The first executor stamps the
    /// attempt, as the pinned door's does.
    ///
    /// # Errors
    ///
    /// An attempt not on its live lease; storage errors. A pack that does
    /// not load is [`MeasuredSkillPack::Gone`] or
    /// [`MeasuredSkillPack::Refused`], never an error.
    pub fn load_attempt_measured_skill_pack(
        &self,
        leased: &AttemptRecord,
        digest: &str,
        executor_model: &str,
        at: u64,
    ) -> Result<MeasuredSkillPack> {
        let mut carriers = Vec::new();
        for id in self.entities_by_type(ENTITY_TYPE_SKILL)? {
            let Some(record) = self.get_skill_record(&id)? else {
                continue;
            };
            if content_hex(&record).as_deref() == Some(digest) {
                carriers.push((id, record));
            }
        }
        if carriers.is_empty() {
            return Ok(MeasuredSkillPack::Gone);
        }
        let mut found = None;
        {
            let txn = self.store.env.read_txn()?;
            for (id, record) in &carriers {
                if !crate::vault::live_entity_row_in_txn(&self.store, &txn, id)?.is_live() {
                    continue;
                }
                match measured_arm_in_txn(self, &txn, id, record)? {
                    MeasuredArm::Refused => {}
                    arm => {
                        found = Some((*id, record.version.clone(), arm));
                        break;
                    }
                }
            }
        }
        let Some((entity, version, arm)) = found else {
            return Ok(MeasuredSkillPack::Refused);
        };
        let loaded = match arm {
            MeasuredArm::Pinned(bound) => self.load_attempt_pinned_skill_pack(
                leased,
                &bound,
                (&entity, &version),
                executor_model,
                at,
            ),
            MeasuredArm::Helper => {
                self.load_attempt_helper_pack(leased, &entity, &version, executor_model, at)
            }
            MeasuredArm::Refused => return Ok(MeasuredSkillPack::Refused),
        };
        match loaded {
            Ok(pack) if content_hex(&pack.record).as_deref() == Some(digest) => {
                Ok(MeasuredSkillPack::Loaded(pack))
            }
            // The revision moved under the load: another content.
            Ok(_) | Err(Error::EntityNotFound) => Ok(MeasuredSkillPack::Gone),
            Err(Error::InvalidClaimBody(_)) => Ok(MeasuredSkillPack::Refused),
            Err(error) => Err(error),
        }
    }

    /// One Candidate helper at `version`, loaded on `leased` as the pinned
    /// door loads an arm: its runtime package, its manifest row once, its
    /// read set, in one transaction.
    fn load_attempt_helper_pack(
        &self,
        leased: &AttemptRecord,
        entity: &EntityId,
        version: &str,
        executor_model: &str,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        let lease_owner = leased
            .lease_owner
            .as_deref()
            .ok_or(Error::InvalidClaimBody(
                "a measured pack load requires the caller's live attempt lease",
            ))?;
        self.with_write_txn_grouped(|txn| {
            if !crate::vault::live_entity_row_in_txn(&self.store, txn, entity)?.is_live() {
                return Err(Error::EntityNotFound);
            }
            let record = self.read_skill_record_in_txn(txn, entity)?;
            if !awaiting_helper_gate(&record) {
                return Err(Error::InvalidClaimBody(
                    "the measured helper is no longer awaiting its gate",
                ));
            }
            if record.version != version {
                return Err(Error::InvalidClaimBody(
                    "the helper moved off the measured revision",
                ));
            }
            let source_files = self
                .runtime_skill_package_in_txn(txn, entity, &record)?
                .map(|package| package.files);
            let entry =
                ManifestEntry::new(ManifestKind::Skill, &record.skill_id, &record.version, at);
            let entry = crate::skill::loaded_revision::pin_loaded_in_txn(
                self, txn, entity, &record, entry,
            )?;
            self.record_manifest_once_in_txn(txn, leased, lease_owner, executor_model, entry)?;
            let read =
                self.pack_source_rows_in_txn(txn, entity, &record, source_files.is_some())?;
            self.record_attempt_sources_best_effort_in_txn(
                txn,
                leased.id,
                ReadSetProducer::SKILL_PACK,
                Some(read),
            );
            Ok(LoadedSkillPack {
                entity: *entity,
                record,
                source_files,
            })
        })
    }
}

/// The door `record`, live as `id`, loads through for a measurement.
fn measured_arm_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    record: &SkillRecord,
) -> Result<MeasuredArm> {
    if crate::skill::resident_of(record)?.is_none() && skill_loadable(record) {
        return Ok(MeasuredArm::Pinned(*id));
    }
    if let Some(basis) = crate::skill_optimize::skill_edit_trial_basis_in_txn(vault, txn, id)? {
        return Ok(MeasuredArm::Pinned(basis.target));
    }
    Ok(if awaiting_helper_gate(record) {
        MeasuredArm::Helper
    } else {
        MeasuredArm::Refused
    })
}
