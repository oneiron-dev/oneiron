//! Scheduled curator and harness-evaluation facets on one gated Dreamer
//! authority, and the Coach's nightly retrieval tune on the same lane. Both
//! Dreamer facets ride the nightly wake: the curator grades the Dreamer's own
//! consolidations and applies what the owner approved, and the harness audit
//! flags the Dreamer's tuning config for a retune. Neither deploys anything.
pub mod action_mode;
pub mod agent_health;
pub mod coach;
pub mod coach_heal;
pub mod coach_learning;
mod coach_repair;
pub mod code_fix;
mod curator;
pub mod detectors;
mod evaluation;
pub mod honesty;
pub mod identity;
pub(crate) mod optimize;
pub use optimize::{CoachLiveSlice, CoachSkillOptimizer};
mod person_threshold;
mod proposals;
mod strength;
pub use strength::CONSOLIDATION_STRENGTH_FACET;
pub mod representation;
mod retrieval_policy;
pub mod stewardship;
#[cfg(test)]
mod tests;
use super::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerAttemptPayload,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::side_table::{LegacyJson, SideTable};
use crate::{Error, Result, Vault};
pub use curator::{CuratorQuestions, CuratorRubric, CuratorTrigger};
pub use evaluation::{
    DREAMER_TUNING_CONFIG_MEDIA_TYPE, DreamerTuningConfig, HarnessEvaluation,
    HarnessEvaluationTarget, RetuneThresholds,
};
use rmpv::Value;
pub const MAINTENANCE_QUEUE_KIND: &str = "dreamer.maintenance";
pub const CURATOR_FACET: &str = "dreamer.curator";
pub const HARNESS_FACET: &str = "dreamer.harness_maintenance";
fn invalid() -> Error {
    Error::InvalidConfig("invalid Dreamer maintenance row".into())
}
impl DreamerRunnerStore<'_> {
    pub(super) fn enqueue_maintenance(
        &self,
        facet: &str,
        input: Value,
        dedupe: String,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.vault.with_write_txn_grouped(|txn| {
            self.enqueue_kind_in_txn(
                txn,
                MAINTENANCE_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: facet.into(),
                    input,
                    parent_attempt: None,
                },
                Some(dedupe),
                None,
                now,
            )
        })
    }
    /// The Dreamer's nightly maintenance, co-committed with a Timer wake or
    /// a Nightly recipe: the curator pass (one per rubric cadence, however
    /// many wakes ask), the relationship-stewardship pass, the identity
    /// re-check, the action-mode refresh (one per owner, OF-335) and the
    /// harness self-audit (one per wake key each).
    pub(crate) fn enqueue_dreamer_nightly_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<crate::attempt_queue::AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<()> {
        self.enqueue_curator_in_txn(
            txn,
            CuratorTrigger::Nightly,
            parent_attempt,
            run_id.clone(),
            now,
        )?;
        self.enqueue_stewardship_in_txn(txn, parent_attempt, wake_key, run_id.clone(), now)?;
        self.enqueue_identity_recheck_in_txn(txn, parent_attempt, wake_key, run_id.clone(), now)?;
        self.enqueue_action_mode_in_txn(txn, parent_attempt, wake_key, run_id.clone(), now)?;
        self.enqueue_harness_audit_in_txn(txn, parent_attempt, wake_key, run_id, now)?;
        Ok(())
    }
    /// The Coach's nightly retrieval tune, co-committed with a Timer wake. The
    /// lane is shared by several facets, so the key is namespaced (one dedupe
    /// key must never name two job types) and hashed, so any wake key the
    /// queue accepts still fits.
    pub(crate) fn enqueue_coach_retrieval_tune_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<crate::attempt_queue::AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.enqueue_kind_in_txn(
            txn,
            MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: super::COACH_RETRIEVAL_TUNE_FACET.into(),
                input: Value::Nil,
                parent_attempt,
            },
            wake_key.map(|key| {
                format!(
                    "{}:{}",
                    super::COACH_RETRIEVAL_TUNE_FACET,
                    blake3::hash(key.as_bytes()).to_hex()
                )
            }),
            run_id,
            now,
        )
    }
    pub fn admit_next_maintenance(
        &self,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerAdmissionOutcome> {
        self.admit_next_kind(MAINTENANCE_QUEUE_KIND, input)
    }
}
pub(crate) fn execute(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
) -> Result<DreamerAttemptExecution> {
    let facet = attempt.status.payload.attempt_type.as_str();
    match facet {
        CONSOLIDATION_STRENGTH_FACET => {
            strength::run(ctx.vault, attempt, ctx.now_ms)?;
        }
        CURATOR_FACET => {
            curator::run(ctx.vault, attempt, ctx.now_ms / 1000)?;
        }
        HARNESS_FACET => {
            evaluation::run(ctx.vault, attempt, ctx.now_ms / 1000)?;
        }
        representation::REPRESENTATION_FACET => {
            representation::run(ctx.vault, attempt, ctx.now_ms / 1000)?;
        }
        stewardship::STEWARDSHIP_FACET => {
            stewardship::run(ctx.vault, attempt, ctx.now_ms / 1000)?;
        }
        identity::IDENTITY_RECHECK_FACET => {
            identity::run(ctx.vault, attempt, ctx.now_ms / 1000)?;
        }
        action_mode::ACTION_MODE_FACET => {
            action_mode::run(ctx.vault, attempt, ctx.now_ms / 1000)?;
        }
        super::COACH_RETRIEVAL_TUNE_FACET => {
            retrieval_policy::run(ctx.vault)?;
        }
        honesty::HONESTY_AUDIT_FACET => {
            let _ = honesty::run(ctx.vault, ctx.now_ms / 1000)?;
        }
        coach::COACH_READ_HARDENING_FACET => {
            coach::run_read_hardening(ctx.vault, ctx.now_ms / 1000)?;
        }
        coach::COACH_TRIPWIRES_FACET => coach::run_tripwires(ctx.vault, ctx.now_ms / 1000)?,
        coach::COACH_TRADEOFF_ESCALATION_FACET => {
            coach::run_tradeoff_escalation(ctx.vault, ctx.now_ms / 1000)?;
        }
        coach::COACH_TRAINING_OFFERS_FACET => {
            coach::run_training_offers(ctx.vault, ctx.now_ms / 1000)?;
        }
        coach::COACH_RESEARCH_SELECT_FACET => {
            coach::run_research_select(ctx.vault, ctx.now_ms / 1000)?;
        }
        coach::COACH_LEARNING_SWEEP_FACET => {
            coach::run_learning_sweep(ctx.vault, ctx.now_ms / 1000)?;
        }
        agent_health::COACH_AGENT_HEALTH_FACET => {
            agent_health::run(ctx.vault, ctx.now_ms / 1000)?;
        }
        _ => return Err(invalid()),
    }
    Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
}
fn load_row<T: serde::Serialize + serde::de::DeserializeOwned>(
    vault: &Vault,
    table: SideTable<(), T, LegacyJson>,
    defaults: &str,
) -> Result<T> {
    let txn = vault.store.env.read_txn()?;
    match table.get(&vault.store, &txn, &())? {
        Some(row) => Ok(row),
        None => serde_json::from_str(defaults).map_err(|_| invalid()),
    }
}

pub mod digest;

/// The owner proof still holds in this write: it was authenticated by THIS
/// vault (a proof from another vault never acts here, whatever PERSON ids the
/// two share), its credential is live, and its actor is a live, active PERSON
/// that owns this vault.
pub(crate) fn validate_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &crate::consent::AuthenticatedOwner,
) -> Result<crate::EntityId> {
    require_active_person_in_txn(vault, txn, owner.revalidate_in_txn(vault, txn)?)
}

/// [`validate_owner_in_txn`] on the person tier, for maintenance a person
/// does on their own behalf: their own judge budget, a judge ask assigned to
/// them, a proposal or a representation review addressed to them. The shared
/// proactivity digest is no such door: it reads every pending proposal and
/// moves the vault's one delivery state.
pub(crate) fn validate_person_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &crate::consent::AuthenticatedOwner,
) -> Result<crate::EntityId> {
    require_active_person_in_txn(vault, txn, owner.revalidate_person_in_txn(vault, txn)?)
}

fn require_active_person_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: crate::EntityId,
) -> Result<crate::EntityId> {
    let refused = || {
        Error::Gate(crate::error::GateError::ConsentOwnerNotAuthenticated(
            "maintenance requires a live owner in this vault",
        ))
    };
    if !matches!(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, &actor)?,
        crate::vault::LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            ..
        }
    ) || vault.entity_lifecycle_state_in_txn(txn, &actor)?
        != crate::identity_topology::EntityLifecycleState::Active
    {
        return Err(refused());
    }
    Ok(actor)
}
