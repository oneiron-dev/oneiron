//! The Coach's jobs on the Dreamer's runner (ARCH-0026 #base-agents, ARCH-0066
//! #coach): skill discovery and authoring, the person-threshold tune and the
//! read-side pass. Each runs under the Coach's stamp; the Dreamer keeps
//! extract, weave, consolidate and cleanup.
//!
//! Two lanes. A job that needs the host's model or facts (the session distill,
//! the attribution sweep, the threshold rule) sits on [`COACH_HOST_QUEUE_KIND`]:
//! a host Coach leases it with [`DreamerRunnerStore::admit_next_coach_host_job`]
//! and runs the `Vault::run_coach_*` door its facet names, as it runs
//! `coach.heal`. A closed-form job rides the maintenance lane, and the wake
//! driver runs it in-engine.
use super::super::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerAttemptPayload,
    DreamerRunnerStore,
};
use super::{MAINTENANCE_QUEUE_KIND, invalid, proposals};
use crate::actor_claims::{
    SessionActorDistiller, SessionDistillDrain, drain_pending_session_actor_distills,
};
use crate::attempt_queue::AttemptId;
use crate::llm::decision::{PersonChangedAnswer, PersonThreshold};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::skill_attribution::{
    AttributionDecisions, AttributionSweepReport, ReceiptAttributionSource,
    run_task_attribution_sweep_with_decisions,
};
use crate::{EntityId, Error, Result, Vault};
use rmpv::Value;

/// Host-run Coach queue kind. The payload `job_type` names the facet.
pub const COACH_HOST_QUEUE_KIND: &str = "coach.host";
/// Skill authoring from sessions: the session-end `actor.*` craft-note distill
/// (ARCH-0003 §G.1 `actor.lesson`).
pub const COACH_SKILL_DISTILL_FACET: &str = "coach.skill_distill";
/// Skill discovery from attempt receipts: the task-attribution sweep, whose
/// `discovery` verdicts become skill edit proposals.
pub const COACH_SKILL_DISCOVERY_FACET: &str = "coach.skill_discovery";
/// Q3 tuning (ARCH-0076 #ask): each case where a person changed the ladder's
/// answer, read once, feeds a proposed person-threshold row.
pub const COACH_PERSON_THRESHOLD_FACET: &str = "coach.person_threshold";
/// Observe, read-side hardening: the retrieval-miss detector over the stored
/// retrieval runs.
pub const COACH_READ_HARDENING_FACET: &str = "coach.read_hardening";
/// Observe, tier-1 detection: the nightly sweep of the signed tripwires and
/// its proposed-only repairs (ARCH-0066 §4).
pub const COACH_TRIPWIRES_FACET: &str = "coach.tripwires";
/// Predicate of the Coach's Proposed person-threshold row.
pub const COACH_PERSON_THRESHOLD_PROPOSAL_PREDICATE: &str = "coach.person_threshold.proposal";

const HOST_FACETS: [&str; 3] = [
    COACH_SKILL_DISTILL_FACET,
    COACH_SKILL_DISCOVERY_FACET,
    COACH_PERSON_THRESHOLD_FACET,
];
const READ_HARDENING_SCOPE: &str = "retrieval";
const READ_HARDENING_RUNS: usize = 256;
const MAX_PERSON_THRESHOLD_BATCH: usize = 1024;

/// Override records the Coach has not read yet. Key: the source the host bound
/// the person's answer to (its ask or receipt).
const PERSON_CHANGED: SideTable<EntityId, PersonChangedAnswer, Named> =
    SideTable::new(&side_table::COACH_PERSON_CHANGED);
/// Sources a threshold run has read, with the time it read them, so a replayed
/// record never counts twice. Key: as above.
const PERSON_CHANGED_READ: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::COACH_PERSON_CHANGED_READ);

/// The rule that turns override records into a threshold. Canon sets no
/// threshold for Q3, so the number is the host's policy, never the engine's.
pub trait PersonThresholdPolicy {
    /// The threshold to propose from the current row and the unread records,
    /// or `None` to leave the row as it is.
    fn revise(
        &self,
        current: Option<PersonThreshold>,
        changed: &[PersonChangedAnswer],
    ) -> Result<Option<f64>>;
}

impl DreamerRunnerStore<'_> {
    /// The Coach's nightly jobs, co-committed with a Timer wake. A host job
    /// keeps one fixed dedupe key, so an unleased one absorbs the next night's
    /// instead of piling up; the read-side pass is keyed per wake, like the
    /// retrieval tune.
    pub(crate) fn enqueue_coach_nightly_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent_attempt: Option<AttemptId>,
        wake_key: Option<&str>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<()> {
        for facet in HOST_FACETS {
            self.enqueue_kind_in_txn(
                txn,
                COACH_HOST_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: facet.into(),
                    input: Value::Nil,
                    parent_attempt,
                },
                Some(facet.into()),
                run_id.clone(),
                now,
            )?;
        }
        self.enqueue_kind_in_txn(
            txn,
            MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: COACH_READ_HARDENING_FACET.into(),
                input: Value::Nil,
                parent_attempt,
            },
            wake_key.map(|key| {
                format!(
                    "{COACH_READ_HARDENING_FACET}:{}",
                    blake3::hash(key.as_bytes()).to_hex()
                )
            }),
            run_id.clone(),
            now,
        )?;
        self.enqueue_kind_in_txn(
            txn,
            MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: COACH_TRIPWIRES_FACET.into(),
                input: Value::Nil,
                parent_attempt,
            },
            wake_key.map(|key| {
                format!(
                    "{COACH_TRIPWIRES_FACET}:{}",
                    blake3::hash(key.as_bytes()).to_hex()
                )
            }),
            run_id,
            now,
        )?;
        Ok(())
    }

    /// Atomically admits the next queued host-run Coach job. The host runs it
    /// through the `Vault::run_coach_*` door its facet names and settles it on
    /// the queue; the wake driver never calls this.
    ///
    /// # Errors
    ///
    /// Storage errors; the queue's own admission errors.
    pub fn admit_next_coach_host_job(
        &self,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerAdmissionOutcome> {
        self.admit_next_kind(COACH_HOST_QUEUE_KIND, input)
    }
}

impl Vault {
    /// Craft notes as the Coach: one bounded pass of the session-end distill
    /// drain under a leased `coach.skill_distill` attempt. The notes keep the
    /// write status the drain gives them.
    pub fn run_coach_skill_distill(
        &self,
        attempt: &DreamerAdmittedAttempt,
        limit: usize,
        distiller: &dyn SessionActorDistiller,
    ) -> Result<SessionDistillDrain> {
        self.require_coach_attempt(attempt, COACH_SKILL_DISTILL_FACET)?;
        drain_pending_session_actor_distills(self, limit, distiller)
    }

    /// Skill discovery as the Coach: one bounded page of the task-attribution
    /// sweep under a leased `coach.skill_discovery` attempt, through the host's
    /// decisions (`None` is the rule tier).
    pub fn run_coach_skill_discovery(
        &self,
        attempt: &DreamerAdmittedAttempt,
        limit: usize,
        source: &dyn ReceiptAttributionSource,
        decisions: Option<&AttributionDecisions<'_>>,
    ) -> Result<AttributionSweepReport> {
        self.require_coach_attempt(attempt, COACH_SKILL_DISCOVERY_FACET)?;
        run_task_attribution_sweep_with_decisions(self, limit, source, decisions)
    }

    /// Keeps one case where a person changed the ladder's answer (from
    /// `HumanDecisionRequest::changed_by`) for the Coach, bound to `source`.
    /// A replay of the same source is a no-op; a different record under it is
    /// refused.
    pub fn record_person_changed_answer(
        &self,
        source: EntityId,
        record: &PersonChangedAnswer,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            if PERSON_CHANGED_READ.contains(&self.store, &*txn, &source)? {
                return Ok(());
            }
            match PERSON_CHANGED.get(&self.store, &*txn, &source)? {
                Some(held) if held == *record => Ok(()),
                Some(_) => Err(Error::InvalidConfig(
                    "another person-changed record already names this source".into(),
                )),
                None => PERSON_CHANGED.put(&self.store, txn, &source, record),
            }
        })
    }

    /// Q3 tuning as the Coach, under a leased `coach.person_threshold` attempt:
    /// reads up to `limit` unread override records once, asks `policy` for a
    /// threshold and files it as a Proposed row. The Coach never sets the live
    /// row; an accepted proposal does. Returns the proposal, if the policy made
    /// one.
    pub fn run_coach_person_threshold(
        &self,
        attempt: &DreamerAdmittedAttempt,
        current: Option<PersonThreshold>,
        policy: &dyn PersonThresholdPolicy,
        limit: usize,
        now: u64,
    ) -> Result<Option<EntityId>> {
        self.require_coach_attempt(attempt, COACH_PERSON_THRESHOLD_FACET)?;
        if !(1..=MAX_PERSON_THRESHOLD_BATCH).contains(&limit) {
            return Err(Error::InvalidConfig(
                "person threshold batch must be in 1..=1024".into(),
            ));
        }
        let unread: Vec<(EntityId, PersonChangedAnswer)> = {
            let txn = self.store.env.read_txn()?;
            PERSON_CHANGED
                .scan(&self.store, &txn)?
                .into_iter()
                .take(limit)
                .collect()
        };
        if unread.is_empty() {
            return Ok(None);
        }
        let records: Vec<PersonChangedAnswer> =
            unread.iter().map(|(_, record)| record.clone()).collect();
        let value = match policy.revise(current, &records)? {
            Some(threshold) if threshold.is_finite() && threshold > 0.0 && threshold <= 1.0 => {
                Some(serde_json::json!({
                    "previous": current.map(|row| serde_json::json!({
                        "threshold": row.threshold,
                        "version": row.version,
                    })),
                    "proposed": {
                        "threshold": threshold,
                        "version": current.map_or(1, |row| row.version.saturating_add(1)),
                    },
                    "changed": records.len(),
                    "sources": unread.iter().map(|(source, _)| source.to_hex()).collect::<Vec<_>>(),
                }))
            }
            Some(_) => {
                return Err(Error::InvalidConfig(
                    "the person threshold policy returned an invalid threshold".into(),
                ));
            }
            None => None,
        };
        let envelope = self
            .dreamer_proposal_envelope(COACH_PERSON_THRESHOLD_FACET, attempt.status.attempt.id)?;
        let subject = envelope.actor().entity_ref();
        self.with_write_txn_grouped(|txn| {
            // A second run that read the same records first has already
            // proposed from them.
            for (source, _) in &unread {
                if PERSON_CHANGED_READ.contains(&self.store, &*txn, source)? {
                    return Ok(None);
                }
            }
            let proposal = value
                .as_ref()
                .map(|value| {
                    proposals::emit_in_txn(
                        self,
                        txn,
                        subject,
                        COACH_PERSON_THRESHOLD_PROPOSAL_PREDICATE,
                        value,
                        &envelope,
                        now,
                    )
                })
                .transpose()?;
            for (source, _) in &unread {
                PERSON_CHANGED.delete(&self.store, txn, source)?;
                PERSON_CHANGED_READ.put(&self.store, txn, source, &now)?;
            }
            Ok(proposal)
        })
    }

    /// The leased attempt is this facet's, stamped for the Coach.
    fn require_coach_attempt(&self, attempt: &DreamerAdmittedAttempt, facet: &str) -> Result<()> {
        let stamp = self
            .dreamer_attempt_authority(attempt.status.attempt.id)?
            .ok_or_else(invalid)?;
        if attempt.status.payload.attempt_type != facet
            || stamp.facet != facet
            || stamp.actor != self.coach_authority()?.entity_ref()
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// The nightly read-side pass. Detector ids are stable, so a night that sees
/// the same runs writes the same events again, and a miss already answered
/// files no second reindex.
pub(super) fn run_read_hardening(vault: &Vault, now: u64) -> Result<()> {
    let misses = vault.run_retrieval_miss_detector(READ_HARDENING_SCOPE, READ_HARDENING_RUNS)?;
    vault.propose_tier1_repairs(&misses, now)?;
    Ok(())
}

/// The nightly tier-1 sweep, as the Coach.
pub(super) fn run_tripwires(vault: &Vault, now: u64) -> Result<()> {
    vault.run_tier1_sweep(now)?;
    Ok(())
}
