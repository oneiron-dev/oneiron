//! Native Coach Repair jobs retain the original requester as a source reader.
//! The private context is job data, never an owner proof or a wire input.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::doors::EvalAuthoringRef;
use super::repair_case::record_repair_case_in_txn;
use super::{
    EvalAuthoringInventory, EvalRepairAuthoringPlan, EvalRepairCaseRead, EvalRepairCaseRecipe,
    EvalRepairCaseRequest, EvalRepairCohortReport, EvalRepairNominationRequest,
    EvalRepairNominations,
};
use crate::attempt_queue::{AttemptId, AttemptState};
use crate::claim::{ClaimReadStatus, maintenance_kind::COACH_HOST_QUEUE_KIND};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, decode_dreamer_attempt_payload,
};
use crate::ingest::AgUiFileReadInput;
use crate::memory::stored_read::StoredReadContext;
use crate::memory::{Memory, MemoryResult};
use crate::settings::ReadDestination;
use crate::{EntityId, Error, Result, Vault};

/// Explicit, source-bound Repair authoring; not the nightly sweep's facet.
pub const COACH_EVAL_REPAIR_AUTHORING_FACET: &str = "coach.eval_repair_authoring";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundRepairAuthoring {
    nomination: EvalRepairNominationRequest,
    context: StoredReadContext,
}

impl Memory<'_> {
    /// Queue Repair authoring with this handle's original source authority.
    /// The owner authorizes the request write, not any broader source read.
    /// Each call keeps its own context; it never coalesces with another caller
    /// or the existing nightly authoring job.
    pub fn request_eval_repair_authoring(
        &self,
        owner: &AuthenticatedOwner,
        input: &EvalRepairNominationRequest,
        now: u64,
    ) -> MemoryResult<EvalAuthoringRef> {
        let bound = BoundRepairAuthoring {
            nomination: input.clone(),
            context: StoredReadContext::of(self),
        };
        let input = rmp_serde::to_vec_named(&bound).map_err(|_| invalid())?;
        let vault = self.vault();
        Ok(vault.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(vault, txn)?;
            self.recheck_host_action_in_txn(txn)?;
            let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
                txn,
                COACH_HOST_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: COACH_EVAL_REPAIR_AUTHORING_FACET.into(),
                    input: Value::Binary(input.clone()),
                    parent_attempt: None,
                },
                None,
                None,
                now,
            )?;
            let status = match outcome {
                EnqueueDreamerAttemptOutcome::Enqueued(status)
                | EnqueueDreamerAttemptOutcome::Existing(status) => status,
            };
            Ok(EvalAuthoringRef {
                attempt: EntityId::from_bytes(*status.attempt.id.as_bytes())?,
            })
        })?)
    }
}

/// An actual leased Coach job's source reader and its metadata-only choices.
/// Neither the reader nor the captured context is exposed to the host.
#[derive(Clone)]
pub struct EvalRepairAuthoringSource<'v> {
    vault: &'v Vault,
    context: StoredReadContext,
    nomination: EvalRepairNominationRequest,
    destination: Option<ReadDestination>,
    job: RepairJob,
    nominations: EvalRepairNominations,
}

#[derive(Clone)]
struct RepairJob {
    id: AttemptId,
    lease_owner: String,
    generation: u32,
    payload: Vec<u8>,
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid source-bound Repair authoring job".into())
}

/// A generic Dreamer enqueue may carry a Coach facet stamp, but cannot write
/// the private coach.host kind. Read the canonical row, not the admitted
/// argument's decoded payload, and keep its stamp and lease in this snapshot.
fn job_payload_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    lease_owner: &str,
    generation: u32,
) -> Result<Vec<u8>> {
    let row = crate::store::attempt_record_read::get_in_txn(&vault.store, txn, id)?
        .ok_or_else(invalid)?;
    let stamp = vault
        .dreamer_attempt_authority_in_txn(txn, id)?
        .ok_or_else(invalid)?;
    if row.kind != COACH_HOST_QUEUE_KIND
        || row.state != AttemptState::Leased
        || row.lease_owner.as_deref() != Some(lease_owner)
        || row.attempt_count != generation
        || stamp.facet != COACH_EVAL_REPAIR_AUTHORING_FACET
        || stamp.actor != crate::store::base_agent::coach_actor_id()?
    {
        return Err(invalid());
    }
    let payload = decode_dreamer_attempt_payload(&row.payload)?;
    if payload.attempt_type != COACH_EVAL_REPAIR_AUTHORING_FACET {
        return Err(invalid());
    }
    Ok(row.payload)
}

impl Vault {
    /// Restore only the reader captured by this canonical leased Coach job.
    /// Its nominations still use the original credential, room, locality and
    /// destination, with their ordinary current standing and source checks.
    pub fn coach_eval_repair_authoring_source(
        &self,
        attempt: &DreamerAdmittedAttempt,
    ) -> MemoryResult<EvalRepairAuthoringSource<'_>> {
        let record = &attempt.status.attempt;
        let lease_owner = record.lease_owner.as_ref().ok_or_else(invalid)?.clone();
        let payload = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            job_payload_in_txn(self, &txn, record.id, &lease_owner, record.attempt_count)?
        };
        let decoded = decode_dreamer_attempt_payload(&payload)?;
        let Value::Binary(body) = decoded.input else {
            return Err(invalid().into());
        };
        let bound: BoundRepairAuthoring = rmp_serde::from_slice(&body).map_err(|_| invalid())?;
        let reader = bound.context.restore(self)?;
        let nominations = reader.nominate_eval_repairs(&bound.nomination)?;
        Ok(EvalRepairAuthoringSource {
            vault: self,
            context: bound.context,
            nomination: bound.nomination,
            destination: None,
            job: RepairJob {
                id: record.id,
                lease_owner,
                generation: record.attempt_count,
                payload,
            },
            nominations,
        })
    }
}

impl EvalRepairAuthoringSource<'_> {
    fn check_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        let payload = job_payload_in_txn(
            self.vault,
            txn,
            self.job.id,
            &self.job.lease_owner,
            self.job.generation,
        )?;
        if payload != self.job.payload {
            return Err(invalid());
        }
        Ok(())
    }

    fn check(&self) -> Result<()> {
        let txn = self.vault.store.env.read_txn()?;
        self.check_in_txn(&txn)
    }

    /// Read these Repair choices for an actual model destination, through the
    /// original credential and room. The destination only narrows that reader.
    /// Keep the returned handle, including its scoped receipts, before sending
    /// its choices. This admits Repair sources, not the separate inventory.
    pub fn for_destination(&self, destination: &ReadDestination) -> MemoryResult<Self> {
        self.check()?;
        let reader = self
            .context
            .restore(self.vault)?
            .for_destination(destination);
        let mut nominations = reader.nominate_eval_repairs(&self.nomination)?;
        // A new read may discover more captures. This call may send only the
        // exact recipes its original source handle nominated.
        for source in &mut nominations.sources {
            source.tasks.retain(|read| {
                read.as_ref()
                    .ok()
                    .and_then(|read| read.recipe.as_ref())
                    .is_some_and(|recipe| self.nominated(recipe))
            });
        }
        nominations
            .sources
            .retain(|source| !source.tasks.is_empty());
        Ok(Self {
            vault: self.vault,
            context: StoredReadContext::of(&reader),
            nomination: self.nomination.clone(),
            destination: Some(destination.clone()),
            job: self.job.clone(),
            nominations,
        })
    }

    /// Whether every exact recipe in this retained destination-bound read still
    /// reads there now. New choices never stand in for a source that lapsed.
    pub fn recheck_destination(&self, destination: &ReadDestination) -> MemoryResult<bool> {
        if self.destination.as_ref() != Some(destination) {
            return Ok(false);
        }
        self.check()?;
        let reader = self
            .context
            .restore(self.vault)?
            .for_destination(destination);
        for recipe in self.recipes() {
            let read = reader.read_eval_repair_task(&recipe.source)?;
            if !read.task.is_some_and(|task| {
                task.source == recipe.source && task.task_hash == recipe.task_hash
            }) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Only successful source pins, without task bodies, expected responses or
    /// discovery errors. The native read receipts remain on this handle.
    pub fn recipes(&self) -> Vec<EvalRepairCaseRecipe> {
        let mut recipes = Vec::new();
        for recipe in self
            .nominations
            .sources
            .iter()
            .flat_map(|source| &source.tasks)
            .filter_map(|read| read.as_ref().ok())
            .filter_map(|read| read.recipe.as_ref())
        {
            if !recipes.contains(recipe) {
                recipes.push(recipe.clone());
            }
        }
        recipes
    }

    pub(super) fn nominated(&self, recipe: &EvalRepairCaseRecipe) -> bool {
        self.nominations
            .sources
            .iter()
            .flat_map(|source| &source.tasks)
            .filter_map(|read| read.as_ref().ok())
            .any(|read| read.recipe.as_ref() == Some(recipe))
    }

    /// Ordinary authoring metadata plus the actual nominated seats and source
    /// rows. A new seat need not already have receipt-derived cases.
    pub fn inventory_sourced(
        &self,
        now: u64,
    ) -> MemoryResult<(EvalAuthoringInventory, Option<Vec<EntityId>>)> {
        self.check()?;
        Ok(super::authoring::repair_authoring_inventory_sourced(
            self.vault,
            &self.nominations,
            now,
        )?)
    }

    /// Apply the loaded skill's whole plan, with Repair writes before scoped
    /// cut audits and the real Skill author on cuts and retirements. Each stage
    /// retains its ordinary transaction; this is not a whole-plan rollback.
    /// Actual source/audit rows survive a later error in the second result.
    pub fn apply_plan_listing(
        &self,
        input: EvalRepairAuthoringPlan,
        inventory: &EvalAuthoringInventory,
        skill: (EntityId, String),
        now: u64,
    ) -> (MemoryResult<EvalRepairCohortReport>, Vec<EntityId>) {
        let mut rows = Vec::new();
        let answer: MemoryResult<EvalRepairCohortReport> = (|| {
            self.check()?;
            let reader = self.context.restore(self.vault)?;
            super::authoring::apply_repair_authoring_plan(
                &reader,
                self,
                input,
                inventory,
                (self.job.id, skill),
                now,
                &mut rows,
            )
        })();
        rows.sort_unstable();
        rows.dedup();
        (answer, rows)
    }

    /// Original per-source/task errors and scoped receipts, without task bodies
    /// or expected responses. Only successful recipes can be selected to write.
    pub fn nominations(&self) -> &EvalRepairNominations {
        &self.nominations
    }

    /// Record a nominated recipe as the actual leased Coach, not as an owner.
    /// Source/hash reconstruction, family assignment and case admission share
    /// the same writer with the canonical job's current stamp and lease check.
    pub fn record_case(&self, input: &EvalRepairCaseRequest) -> MemoryResult<EvalRepairCaseRead> {
        if !self.nominated(&input.recipe) {
            return Err(invalid().into());
        }
        let source = &input.recipe.source;
        let id = EntityId::from_hex(&source.claim_ref)?;
        let source_pin = AgUiFileReadInput {
            claim_ref: source.claim_ref.clone(),
            source_hash: source.source_hash.clone(),
        };
        let reader = self.context.restore(self.vault)?;
        let lane = reader.read_lane(ClaimReadStatus::Recorded)?;
        lane.persist_grant_clock()?;
        let vault = self.vault;
        let _bodies = vault.pin_all_result_bodies();
        let now = vault.now_recorded_at();
        Ok(vault.with_write_txn_grouped(|txn| {
            self.check_in_txn(txn)?;
            record_repair_case_in_txn(vault, txn, &lane, id, &source_pin, input, now)
        })?)
    }
}
