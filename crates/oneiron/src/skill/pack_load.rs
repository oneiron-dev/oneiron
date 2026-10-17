//! Attempt-bound pack reads stamp their actual revision in the same transaction.

use super::{SkillLifecycle, SkillRecord};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ManifestEntry, ManifestKind};
use crate::claim::{ClaimApprovalStatus, ClaimBody, claim_surfaceable, encode_claim_body};
use crate::{EntityId, Error, Result, Vault};

/// One actual tier-2 load. Native record-only skills have no file tree.
#[derive(Debug, Clone)]
pub struct LoadedSkillPack {
    /// The entity whose body loaded: the requested skill, or the open
    /// proposal its exploration trial routed this attempt to. Bindings and
    /// invocation witnesses name this entity, never the request.
    pub entity: EntityId,
    pub record: SkillRecord,
    pub source_files: Option<Vec<crate::skill_hub::HubFile>>,
}

/// The one runtime admission invariant used by the load door and hub installs.
#[must_use]
pub(crate) fn skill_loadable(record: &SkillRecord) -> bool {
    record.lifecycle_status == SkillLifecycle::Active
        && matches!(
            record.approval_status,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
}

impl Vault {
    /// Bind one live attempt to its executing actor (PERSON, AGENT_DEF or
    /// MACHINE), even when it loads only shared skills or no skill at all.
    /// The marker is written before terminalization and is immutable.
    pub fn bind_actor_attempt(&self, attempt: AttemptId, actor: &EntityId) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let row = AttemptQueue::new(self)
                .get_in_txn(txn, attempt)?
                .ok_or(Error::EntityNotFound)?;
            if row.state.is_terminal() {
                return Err(Error::InvalidClaimBody("cannot bind a terminal attempt"));
            }
            super::resident::bind_receipt_in_txn(
                self,
                txn,
                &crate::receipt::attempt_pack_receipt_id(&attempt),
                actor,
            )
        })
    }

    /// Mid-run tier-2 record load. Merely listing a skill at tier 1 is not evidence of body use.
    pub fn load_attempt_skill(
        &self,
        attempt: AttemptId,
        skill: &EntityId,
        lease_owner: &str,
        attempt_count: u32,
        executor_model: &str,
        at: u64,
    ) -> Result<SkillRecord> {
        Ok(self
            .load_attempt_skill_pack(
                attempt,
                skill,
                lease_owner,
                attempt_count,
                executor_model,
                at,
            )?
            .record)
    }

    /// Loads the exact stored SKILL.md/scripts when present and stamps one row
    /// atomically. A failed package check never records a successful load.
    /// While an exploration trial of the skill's open proposal routes this
    /// attempt, the proposal loads instead: [`LoadedSkillPack::entity`] names
    /// what loaded.
    pub fn load_attempt_skill_pack(
        &self,
        attempt: AttemptId,
        skill: &EntityId,
        lease_owner: &str,
        attempt_count: u32,
        executor_model: &str,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        self.load_skill_pack_bound(
            attempt,
            skill,
            None,
            lease_owner,
            attempt_count,
            Some(executor_model),
            at,
        )
    }

    /// Loads a resident fork only for its named owner. The check and manifest
    /// stamp share a transaction; an unscoped load cannot use a bound fork.
    #[expect(
        clippy::too_many_arguments,
        reason = "the load door binds the resident, skill, lease generation, executor revision and timestamp atomically"
    )]
    pub fn load_resident_skill_pack(
        &self,
        attempt: AttemptId,
        resident: &EntityId,
        skill: &EntityId,
        lease_owner: &str,
        attempt_count: u32,
        executor_model: &str,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        self.load_skill_pack_bound(
            attempt,
            skill,
            Some(*resident),
            lease_owner,
            attempt_count,
            Some(executor_model),
            at,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the load door binds the resident, skill, lease generation, executor revision and timestamp atomically"
    )]
    fn load_skill_pack_bound(
        &self,
        attempt: AttemptId,
        skill: &EntityId,
        resident: Option<EntityId>,
        lease_owner: &str,
        attempt_count: u32,
        executor_model: Option<&str>,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        let (loaded, ask) = self.with_write_txn_grouped(|txn| {
            if !crate::vault::live_entity_row_in_txn(&self.store, txn, skill)?.is_live() {
                return Err(Error::EntityNotFound);
            }
            let record = self.read_skill_record_in_txn(txn, skill)?;
            if super::resident_of(&record)? != resident {
                return Err(Error::InvalidClaimBody(
                    "skill belongs to a different resident",
                ));
            }
            if !skill_loadable(&record) {
                return Err(Error::InvalidClaimBody(
                    "pack load requires an active approved skill",
                ));
            }
            // The requested skill is the incumbent arm. An exploration trial
            // of its open proposal may route this attempt to the proposal,
            // reserving the run's charge in this same transaction.
            let routed =
                super::exploration_trial::route_in_txn(self, txn, attempt, skill, &record, at)?;
            let (entity, record, source_files) = match routed.load {
                Some(trial) => (trial.entity, trial.record, trial.source_files),
                None => {
                    let source_files = self
                        .runtime_skill_package_in_txn(txn, skill, &record)?
                        .map(|package| package.files);
                    (*skill, record, source_files)
                }
            };
            let queue = AttemptQueue::new(self);
            queue.require_skill_load_lease_in_txn(txn, attempt, lease_owner, attempt_count)?;
            if let Some(executor_model) = executor_model {
                queue.set_executor_model_in_txn(
                    txn,
                    attempt,
                    lease_owner,
                    attempt_count,
                    executor_model,
                )?;
            }
            if let Some(resident) = resident {
                let receipt = crate::receipt::attempt_pack_receipt_id(&attempt);
                super::resident::bind_receipt_in_txn(self, txn, &receipt, &resident)?;
                super::resident::bind_skill_in_txn(self, txn, &receipt, &entity)?;
            }
            queue.append_manifest_entry_in_txn(
                txn,
                attempt,
                ManifestEntry::new(ManifestKind::Skill, &record.skill_id, &record.version, at),
            )?;
            Ok((
                LoadedSkillPack {
                    entity,
                    record,
                    source_files,
                },
                routed.ask,
            ))
        })?;
        // Over the slice the loop asks, outside the load's transaction: the
        // queue opens its own. The load stands either way, and the Coach
        // queues an ask that did not land here.
        if let Some(proposal) = ask
            && let Err(error) = super::exploration_trial::queue_trial_ask(self, &proposal)
        {
            tracing::warn!(%error, "an exploration trial's overrun ask is not queued yet");
        }
        Ok(loaded)
    }

    /// The callable door runs the shared load in the caller's own lease
    /// generation, so a stale worker cannot append a manifest entry on a
    /// re-leased or terminal attempt. The first executor stamps the attempt;
    /// a later step's executor is bound per invocation instead of rebinding it.
    pub(crate) fn load_leased_callable_skill_pack(
        &self,
        leased: &AttemptRecord,
        skill: &EntityId,
        executor: &str,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        let lease_owner = leased
            .lease_owner
            .as_deref()
            .ok_or(Error::InvalidClaimBody(
                "callable execution requires the caller's live attempt lease",
            ))?;
        let stamped = AttemptQueue::new(self)
            .get(leased.id)?
            .ok_or(Error::EntityNotFound)?
            .executor_model
            .is_some();
        self.load_skill_pack_bound(
            leased.id,
            skill,
            None,
            lease_owner,
            leased.attempt_count,
            (!stamped).then_some(executor),
            at,
        )
    }

    /// Pick a resident's best version with the shared UCB bandit and stamp
    /// exactly that entity's manifest/evidence binding in one pack-load call.
    /// A winner that is no longer active refuses at the load door rather than
    /// silently loading a runner-up under an out-of-date candidate ranking.
    /// A winner whose open proposal is on trial may load that proposal; the
    /// returned entity is the one that loaded.
    #[expect(
        clippy::too_many_arguments,
        reason = "the load door binds the resident, skill, lease generation, executor revision and timestamp atomically"
    )]
    pub fn select_and_load_resident_skill_pack(
        &self,
        attempt: AttemptId,
        resident: &EntityId,
        versions: &[EntityId],
        lease_owner: &str,
        attempt_count: u32,
        executor_model: &str,
        reliability: &crate::skill_reliability::SkillReliabilityQuery,
        at: u64,
    ) -> Result<Option<(EntityId, LoadedSkillPack)>> {
        let Some((winner, _)) = crate::skill_reliability::rank_resident_skill_versions(
            self,
            resident,
            versions,
            executor_model,
            reliability,
        )?
        .into_iter()
        .next() else {
            return Ok(None);
        };
        let pack = self.load_resident_skill_pack(
            attempt,
            resident,
            &winner,
            lease_owner,
            attempt_count,
            executor_model,
            at,
        )?;
        Ok(Some((pack.entity, pack)))
    }

    /// Load one surfaceable actor claim; content digest is its revision, never a made-up counter.
    pub fn load_attempt_actor_claim(
        &self,
        attempt: AttemptId,
        claim: &EntityId,
        at: u64,
    ) -> Result<ClaimBody> {
        self.load_actor_claim_bound(attempt, claim, None, at)
    }

    /// Loads one resident's self-model, never another actor's lesson or fit.
    pub fn load_resident_actor_claim(
        &self,
        attempt: AttemptId,
        resident: &EntityId,
        claim: &EntityId,
        at: u64,
    ) -> Result<ClaimBody> {
        self.load_actor_claim_bound(attempt, claim, Some(*resident), at)
    }

    fn load_actor_claim_bound(
        &self,
        attempt: AttemptId,
        claim: &EntityId,
        resident: Option<EntityId>,
        at: u64,
    ) -> Result<ClaimBody> {
        self.with_write_txn_grouped(|txn| {
            let body = self
                .get_claim_in_txn(txn, claim)?
                .ok_or(Error::EntityNotFound)?;
            if body.predicate.starts_with("actor.")
                && !matches!(&body.subject,
                    crate::claim::ClaimSubject::Entity(actor) if Some(*actor) == resident)
            {
                return Err(Error::InvalidClaimBody(
                    "actor self-model belongs to a different resident",
                ));
            }
            if !body.predicate.starts_with("actor.")
                || !claim_surfaceable(&body)
                || !crate::gate::claim_critical_confirm_settled_in_txn(&self.store, txn, claim)?
                || body.valid_from.is_some_and(|start| start > at)
                || body.valid_to.is_some_and(|end| end <= at)
            {
                return Err(Error::InvalidClaimBody(
                    "pack load requires a current actor claim",
                ));
            }
            if let Some(resident) = resident {
                super::resident::bind_receipt_in_txn(
                    self,
                    txn,
                    &crate::receipt::attempt_pack_receipt_id(&attempt),
                    &resident,
                )?;
            }
            let revision = blake3::hash(&encode_claim_body(&body)?);
            AttemptQueue::new(self).append_manifest_entry_in_txn(
                txn,
                attempt,
                ManifestEntry::new(
                    ManifestKind::ActorClaim,
                    claim.to_hex(),
                    revision.to_hex().as_str(),
                    at,
                ),
            )?;
            Ok(body)
        })
    }
}
