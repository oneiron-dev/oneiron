//! Attempt-bound pack reads stamp their actual revision in the same transaction.

use super::{SkillLifecycle, SkillRecord, SkillRole};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, ManifestEntry, ManifestKind, ReadSetProducer,
};
use crate::claim::{ClaimApprovalStatus, ClaimBody, claim_surfaceable, encode_claim_body};
use crate::skill_optimize::exploration_trial;
use crate::{EntityId, Error, Result, Vault};

// A paired eval measurement's skill arm, by its pinned content (FIX 10677).
mod measured;

pub use self::measured::MeasuredSkillPack;

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

/// Whose skill a load may bind.
#[derive(Clone, Copy)]
enum LoadResident {
    /// The named resident's own fork; `None` loads shared skills only.
    Named(Option<EntityId>),
    /// The live attempt's own agent, read from its leased row in the load's
    /// transaction (FIX 10153): its resident-bound fork, else shared skills.
    Attempt,
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
            LoadResident::Named(None),
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
            LoadResident::Named(Some(*resident)),
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
        resident: LoadResident,
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
            let resident = match resident {
                LoadResident::Named(resident) => resident,
                LoadResident::Attempt => self.attempt_resident_in_txn(txn, attempt, &record)?,
            };
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
            let routed = exploration_trial::route_in_txn(self, txn, attempt, skill, &record, at)?;
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
            let entry =
                ManifestEntry::new(ManifestKind::Skill, &record.skill_id, &record.version, at);
            let entry =
                super::loaded_revision::pin_loaded_in_txn(self, txn, &entity, &record, entry)?;
            queue.append_manifest_entry_in_txn(txn, attempt, entry)?;
            let read =
                self.pack_source_rows_in_txn(txn, &entity, &record, source_files.is_some())?;
            self.record_attempt_sources_best_effort_in_txn(
                txn,
                attempt,
                ReadSetProducer::SKILL_PACK,
                Some(read),
            );
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
            && let Err(error) = exploration_trial::queue_trial_ask(self, &proposal)
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
            LoadResident::Attempt,
            lease_owner,
            leased.attempt_count,
            (!stamped).then_some(executor),
            at,
        )
    }

    /// Loads the exact revision a frozen plan names, in the caller's own
    /// lease generation (DOOR-111 S4c-3): `skill` itself at `version`, read
    /// as [`Self::exact_workflow_pack_in_txn`] reads it. No exploration
    /// trial routes it and no other arm stands in; a revision that moved or
    /// is gone refuses. The first executor stamps the attempt, as the
    /// callable door's does. Its manifest row lands once: a row of the same
    /// kind, skill and revision already on the attempt stands for this load.
    pub(crate) fn load_leased_exact_skill_pack(
        &self,
        leased: &AttemptRecord,
        skill: &EntityId,
        version: &str,
        executor: &str,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        let lease_owner = leased
            .lease_owner
            .as_deref()
            .ok_or(Error::InvalidClaimBody(
                "an exact pack load requires the caller's live attempt lease",
            ))?;
        self.with_write_txn_grouped(|txn| {
            let loaded = self.exact_workflow_pack_in_txn(txn, skill, version)?;
            self.stamp_exact_load_in_txn(txn, leased, lease_owner, executor, &loaded, at)?;
            Ok(loaded)
        })
    }

    /// Loads the site skills a page matched (CUA E10), each at the revision
    /// its match read, in the caller's own lease generation and in one
    /// write: each skill itself, live, shared and active approved at that
    /// revision, of any role, its instructions the runtime package the hub
    /// verified. No exploration trial routes them and no other arm stands
    /// in. A skill that moved off its revision or stopped loading since its
    /// match is left out; a lease that no longer holds refuses the whole
    /// load. Each revision's manifest row lands once, as the exact door's
    /// does.
    pub(crate) fn load_leased_site_skill_packs(
        &self,
        leased: &AttemptRecord,
        matched: &[(EntityId, String)],
        executor: &str,
        at: u64,
    ) -> Result<Vec<LoadedSkillPack>> {
        let lease_owner = leased
            .lease_owner
            .as_deref()
            .ok_or(Error::InvalidClaimBody(
                "a site skill load requires the caller's live attempt lease",
            ))?;
        self.with_write_txn_grouped(|txn| {
            AttemptQueue::new(self).require_skill_load_lease_in_txn(
                txn,
                leased.id,
                lease_owner,
                leased.attempt_count,
            )?;
            let mut loaded = Vec::with_capacity(matched.len());
            for (skill, version) in matched {
                let pack = match self.exact_skill_pack_in_txn(txn, skill, version, None) {
                    Ok(pack) => pack,
                    Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => continue,
                    Err(error) => return Err(error),
                };
                self.stamp_exact_load_in_txn(txn, leased, lease_owner, executor, &pack, at)?;
                loaded.push(pack);
            }
            Ok(loaded)
        })
    }

    /// Stamps an exact load of `loaded` on `leased` in the caller's write,
    /// under the live lease `lease_owner` holds: its revision pinned, its
    /// manifest row once, and the rows its instructions came from on the
    /// attempt's read set.
    fn stamp_exact_load_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        leased: &AttemptRecord,
        lease_owner: &str,
        executor: &str,
        loaded: &LoadedSkillPack,
        at: u64,
    ) -> Result<()> {
        let entry = ManifestEntry::new(
            ManifestKind::Skill,
            &loaded.record.skill_id,
            &loaded.record.version,
            at,
        );
        let entry = super::loaded_revision::pin_loaded_in_txn(
            self,
            txn,
            &loaded.entity,
            &loaded.record,
            entry,
        )?;
        self.record_manifest_once_in_txn(txn, leased, lease_owner, executor, entry)?;
        let packaged = loaded.source_files.is_some();
        let read = self.pack_source_rows_in_txn(txn, &loaded.entity, &loaded.record, packaged)?;
        self.record_attempt_sources_best_effort_in_txn(
            txn,
            leased.id,
            ReadSetProducer::SKILL_PACK,
            Some(read),
        );
        Ok(())
    }

    /// Loads the exact arm a job pinned (FIX 7549), in the caller's own
    /// lease generation: `entity` at `version`, under the shared `skill` the
    /// owner bound. `entity` is `skill` itself, or the open proposal of it
    /// an exploration trial routed the pinning load to; no trial routes this
    /// load. A pinned proposal's run reserves its trial-slice charge in the
    /// load's transaction, as a routed run does, and loads the pinned arm
    /// whatever the slice answers (FIX 10306). `skill` must still be an active
    /// approved shared skill, and a revision that moved or is gone refuses.
    /// The first executor stamps the attempt, and its manifest row lands
    /// once, as the exact door's does.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] or [`Error::InvalidClaimBody`] when the
    /// pinned arm no longer loads; an attempt not on its live lease; storage
    /// errors.
    pub fn load_attempt_pinned_skill_pack(
        &self,
        leased: &AttemptRecord,
        skill: &EntityId,
        pinned: (&EntityId, &str),
        executor_model: &str,
        at: u64,
    ) -> Result<LoadedSkillPack> {
        let lease_owner = leased
            .lease_owner
            .as_deref()
            .ok_or(Error::InvalidClaimBody(
                "a pinned pack load requires the caller's live attempt lease",
            ))?;
        let (entity, version) = pinned;
        let (loaded, ask) = self.with_write_txn_grouped(|txn| {
            if !crate::vault::live_entity_row_in_txn(&self.store, txn, skill)?.is_live() {
                return Err(Error::EntityNotFound);
            }
            let current = self.read_skill_record_in_txn(txn, skill)?;
            if super::resident_of(&current)?.is_some() || !skill_loadable(&current) {
                return Err(Error::InvalidClaimBody(
                    "a pinned pack load requires an active approved shared skill",
                ));
            }
            let record = if entity == skill {
                current
            } else {
                if !crate::vault::live_entity_row_in_txn(&self.store, txn, entity)?.is_live() {
                    return Err(Error::EntityNotFound);
                }
                let proposal =
                    crate::skill_optimize::skill_edit_trial_basis_in_txn(self, txn, entity)?
                        .filter(|basis| basis.target == *skill)
                        .map(|basis| basis.proposal)
                        .ok_or(Error::InvalidClaimBody(
                            "the pinned proposal no longer revises its skill",
                        ))?;
                if proposal.role != current.role || proposal.call != current.call {
                    return Err(Error::InvalidClaimBody(
                        "the pinned proposal no longer keeps its skill's interface",
                    ));
                }
                proposal
            };
            if record.version != version {
                return Err(Error::InvalidClaimBody(
                    "the skill moved off the pinned revision",
                ));
            }
            let source_files = self
                .runtime_skill_package_in_txn(txn, entity, &record)?
                .map(|package| package.files);
            let entry =
                ManifestEntry::new(ManifestKind::Skill, &record.skill_id, &record.version, at);
            let entry =
                super::loaded_revision::pin_loaded_in_txn(self, txn, entity, &record, entry)?;
            self.record_manifest_once_in_txn(txn, leased, lease_owner, executor_model, entry)?;
            let ask = if entity == skill {
                None
            } else {
                exploration_trial::charge_pinned_in_txn(self, txn, leased.id, skill, entity, at)?
            };
            let read =
                self.pack_source_rows_in_txn(txn, entity, &record, source_files.is_some())?;
            self.record_attempt_sources_best_effort_in_txn(
                txn,
                leased.id,
                ReadSetProducer::SKILL_PACK,
                Some(read),
            );
            Ok((
                LoadedSkillPack {
                    entity: *entity,
                    record,
                    source_files,
                },
                ask,
            ))
        })?;
        // As the load door does: the overrun ask is queued outside the
        // load's transaction, and the load stands either way.
        if let Some(proposal) = ask
            && let Err(error) = exploration_trial::queue_trial_ask(self, &proposal)
        {
            tracing::warn!(%error, "an exploration trial's overrun ask is not queued yet");
        }
        Ok(loaded)
    }

    /// The skill's resident when the live attempt runs as that very agent,
    /// its leased row decoded in the load's own transaction (FIX 10153). The
    /// lease itself is fenced later in that transaction. Any other attempt,
    /// or a row the dispatch decoder does not read, loads as before: shared
    /// skills only.
    fn attempt_resident_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
        record: &SkillRecord,
    ) -> Result<Option<EntityId>> {
        let Some(owner) = super::resident_of(record)? else {
            return Ok(None);
        };
        let actor = AttemptQueue::new(self)
            .get_in_txn(txn, attempt)?
            .as_ref()
            .and_then(crate::agent_dispatch::record_dispatch_input)
            .and_then(|input| crate::agent_dispatch::agent_dispatch_actor(&input).ok());
        Ok(actor
            .map(|actor| actor.entity_ref())
            .filter(|actor| *actor == owner))
    }

    /// The rows a pack load read `entity`'s instructions from (FIX 7017):
    /// its SKILL row, which holds its local package, and the replicated
    /// carrier ASSET a `packaged` load absent locally was recovered from.
    /// Capture only: the load door reports them on its attempt's read set.
    fn pack_source_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        record: &SkillRecord,
        packaged: bool,
    ) -> Result<Vec<EntityId>> {
        let mut rows = vec![*entity];
        if packaged {
            rows.extend(self.runtime_package_carrier_in_txn(txn, entity, record)?);
        }
        Ok(rows)
    }

    /// Records `entry` on the manifest of `leased`, in the caller's writer
    /// and under the live lease `lease_owner` holds in its generation: once,
    /// since a row of the same kind, skill and revision already on the
    /// attempt stands for it. The first executor stamps the attempt, as the
    /// load door's does.
    pub(crate) fn record_manifest_once_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        leased: &AttemptRecord,
        lease_owner: &str,
        executor: &str,
        entry: ManifestEntry,
    ) -> Result<()> {
        let queue = AttemptQueue::new(self);
        queue.require_skill_load_lease_in_txn(txn, leased.id, lease_owner, leased.attempt_count)?;
        let live = queue
            .get_in_txn(txn, leased.id)?
            .ok_or(Error::EntityNotFound)?;
        if live.executor_model.is_none() {
            queue.set_executor_model_in_txn(
                txn,
                leased.id,
                lease_owner,
                leased.attempt_count,
                executor,
            )?;
        }
        let recorded = live.manifest().iter().any(|row| {
            row.kind == entry.kind
                && row.reference == entry.reference
                && row.version == entry.version
        });
        if !recorded {
            queue.append_manifest_entry_in_txn(txn, leased.id, entry)?;
        }
        Ok(())
    }

    /// One exact workflow revision as its admitted package, on the caller's
    /// snapshot: `skill` live, no resident's, an active approved workflow
    /// skill at `version`, its instructions the runtime package the hub
    /// verified against the record. No exploration trial routes it, and
    /// nothing is stamped.
    pub(crate) fn exact_workflow_pack_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        skill: &EntityId,
        version: &str,
    ) -> Result<LoadedSkillPack> {
        self.exact_skill_pack_in_txn(txn, skill, version, Some(SkillRole::Workflow))
    }

    /// One exact skill revision as its admitted package, read as
    /// [`Self::exact_workflow_pack_in_txn`] reads it, of `role` when one is
    /// named, else of any role.
    fn exact_skill_pack_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        skill: &EntityId,
        version: &str,
        role: Option<SkillRole>,
    ) -> Result<LoadedSkillPack> {
        if !crate::vault::live_entity_row_in_txn(&self.store, txn, skill)?.is_live() {
            return Err(Error::EntityNotFound);
        }
        let record = self.read_skill_record_in_txn(txn, skill)?;
        if super::resident_of(&record)?.is_some() {
            return Err(Error::InvalidClaimBody(
                "an exact pack load reads shared skills, not a resident's",
            ));
        }
        if !skill_loadable(&record) || role.is_some_and(|role| record.role != role) {
            return Err(Error::InvalidClaimBody(match role {
                Some(_) => "an exact pack load runs an active approved workflow skill",
                None => "an exact pack load runs an active approved skill",
            }));
        }
        if record.version != version {
            return Err(Error::InvalidClaimBody(
                "the skill moved off the exact revision asked for",
            ));
        }
        let source_files = self
            .runtime_skill_package_in_txn(txn, skill, &record)?
            .map(|package| package.files);
        Ok(LoadedSkillPack {
            entity: *skill,
            record,
            source_files,
        })
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
            // A claim whose every cited TURN is erased has no live support,
            // however late it replicated (FIX 8643): it is not loaded.
            if !body.predicate.starts_with("actor.")
                || !claim_surfaceable(&body)
                || !crate::gate::claim_critical_confirm_settled_in_txn(&self.store, txn, claim)?
                || !crate::claim::has_live_support_in_txn(&self.store, txn, &body)?
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
            // Capture only (FIX 7017): the CLAIM this load read.
            self.record_attempt_sources_best_effort_in_txn(
                txn,
                attempt,
                ReadSetProducer::ACTOR_CLAIM,
                Some(vec![*claim]),
            );
            Ok(body)
        })
    }
}
