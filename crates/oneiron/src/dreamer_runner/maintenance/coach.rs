//! The Coach's jobs on the Dreamer's runner (ARCH-0026 #base-agents, ARCH-0066
//! #coach): skill discovery and authoring, the person-threshold tune, the
//! read-side pass, the tier-1 sweep and the tradeoff-ask climb. Each runs
//! under the Coach's stamp; the Dreamer keeps extract, weave, consolidate and
//! cleanup.
//!
//! Two lanes. A job that needs the host's model or facts (the session distill,
//! the attribution sweep, the threshold rule) sits on [`COACH_HOST_QUEUE_KIND`]:
//! a host Coach leases it with [`DreamerRunnerStore::admit_next_coach_host_job`]
//! and runs the `Vault::run_coach_*` door its facet names, as it runs
//! `coach.heal`. A closed-form job rides the maintenance lane, and the wake
//! driver runs it in-engine. The Issues job rides the `coach.heal` queue
//! itself (see [`super::coach_heal`]).
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
/// Coordination, responsible-role escalation (ARCH-0053 #self-revision,
/// ARCH-0079): a pending skill tradeoff ask that waited out a reminder window
/// climbs one rung of its role chain, ending at the vault owners.
pub const COACH_TRADEOFF_ESCALATION_FACET: &str = "coach.tradeoff_escalation";
/// Training offers (OF-577), drafted on the host from the offer skill's draft
/// and recorded through [`Vault::run_coach_training_offer`].
pub const COACH_TRAINING_OFFER_FACET: &str = "coach.training_offer";
/// One offer's promise check, queued for the host on the offer's check date.
/// The host reads the receipts since and records what they showed through
/// [`Vault::run_coach_offer_check`]. Input: `{offer: <32 hex>}`.
pub const COACH_OFFER_CHECK_FACET: &str = "coach.offer_check";
/// The nightly offer pass: each pending offer reaches every owner's inbox
/// once, and each offer whose check date came queues its promise check.
pub const COACH_TRAINING_OFFERS_FACET: &str = "coach.training_offers";
/// Autoresearch (OF-351): one selection round for each bound campaign whose
/// measured evidence moved, under the campaign's lease.
pub const COACH_RESEARCH_SELECT_FACET: &str = "coach.research_select";
/// Observe, learning upkeep: the cell re-projection that keeps the window
/// fading runs no new evidence reached, and the coordination re-derivation
/// of every labeled or projected run.
pub const COACH_LEARNING_SWEEP_FACET: &str = "coach.learning_sweep";
/// Issues (ARCH-0066 #coach, OF-418): the blocked reports agents filed, each
/// asked which fix its agent needs and filed as a proposed heal. A report
/// wakes it at once; the nightly pass wakes it again while reports wait.
pub const COACH_ISSUES_FACET: &str = "coach.issues";
/// Code fixes (DEC-0005 FIX6, OF-380): for one failure case the Coach filed a
/// heal for, an invented example of the failure and the shadow result of its
/// own candidate fix, each verified in the vault before either may leave.
pub const COACH_CODE_FIX_FACET: &str = "coach.code_fix";
/// Judge-swap upkeep (ARCH-0053, OF-184): the incumbent judge's retests on
/// its own kept judgments, or another judge's shadow pass over them, which
/// rules whether that judge takes over.
pub const COACH_JUDGE_SWAP_FACET: &str = "coach.judge_swap";
/// Tradeoff routing (FIX-LIST 817): each pending project-bound skill tradeoff
/// ask is handed to the leader of every project board it reached, to ask on
/// one of that project's TASKs.
pub const COACH_TRADEOFF_ROUTE_FACET: &str = "coach.tradeoff_route";
/// Predicate of the Coach's Proposed person-threshold row.
pub const COACH_PERSON_THRESHOLD_PROPOSAL_PREDICATE: &str = "coach.person_threshold.proposal";
/// Producer name of a pending training offer's inbox NOTIFICATION.
pub const TRAINING_OFFER_NOTIFICATION_PRODUCER: &str = "coach.training_offer";

const HOST_FACETS: [&str; 6] = [
    COACH_SKILL_DISTILL_FACET,
    COACH_SKILL_DISCOVERY_FACET,
    COACH_PERSON_THRESHOLD_FACET,
    COACH_TRAINING_OFFER_FACET,
    COACH_JUDGE_SWAP_FACET,
    COACH_TRADEOFF_ROUTE_FACET,
];
/// The Coach's closed-form nightly jobs, which the wake driver runs.
const MAINTENANCE_FACETS: [&str; 7] = [
    COACH_READ_HARDENING_FACET,
    COACH_TRIPWIRES_FACET,
    COACH_TRADEOFF_ESCALATION_FACET,
    COACH_TRAINING_OFFERS_FACET,
    COACH_RESEARCH_SELECT_FACET,
    COACH_LEARNING_SWEEP_FACET,
    super::agent_health::COACH_AGENT_HEALTH_FACET,
];
const READ_HARDENING_SCOPE: &str = "retrieval";
const READ_HARDENING_RUNS: usize = 256;
const MAX_PERSON_THRESHOLD_BATCH: usize = 1024;
/// How long a pending tradeoff ask waits on one rung before it climbs. Canon
/// names no window: one night apart, less an hour of wake jitter, so a
/// nightly pass climbs once a night.
const TRADEOFF_REMINDER_SECS: u64 = 23 * 60 * 60;

/// When the Coach last climbed, or first saw, a pending tradeoff ask. Key: the
/// ask's proposal.
const TRADEOFF_CLIMB: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::COACH_TRADEOFF_CLIMB);
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
        for facet in MAINTENANCE_FACETS {
            self.enqueue_kind_in_txn(
                txn,
                MAINTENANCE_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: facet.into(),
                    input: Value::Nil,
                    parent_attempt,
                },
                wake_key.map(|key| format!("{facet}:{}", blake3::hash(key.as_bytes()).to_hex())),
                run_id.clone(),
                now,
            )?;
        }
        if crate::self_heal::blocked_reports::any_pending_in_txn(self.vault, &*txn)? {
            self.enqueue_coach_issues_in_txn(txn, parent_attempt, run_id, now)?;
        }
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

    /// Judge-swap upkeep as the Coach under a leased `coach.judge_swap`
    /// attempt: the incumbent's retests, or another judge's shadow pass, over
    /// the judgments `host` kept.
    pub fn run_coach_judge_swap(
        &self,
        attempt: &DreamerAdmittedAttempt,
        host: &dyn crate::skill_optimize::JudgeShadowHost,
        now: u64,
    ) -> Result<crate::skill_optimize::JudgeSwapReport> {
        self.require_coach_attempt(attempt, COACH_JUDGE_SWAP_FACET)?;
        crate::skill_optimize::run_judge_swap(self, host, now)
    }

    /// Tradeoff routing as the Coach under a leased `coach.tradeoff_route`
    /// attempt: each pending project-bound tradeoff ask's route call, handed
    /// to the leader of each project it reached. The Coach itself never speaks.
    pub fn run_coach_tradeoff_route(
        &self,
        attempt: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<crate::skill_optimize::TradeoffRouteReport> {
        self.require_coach_attempt(attempt, COACH_TRADEOFF_ROUTE_FACET)?;
        crate::skill_optimize::run_tradeoff_route(self, now)
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
        // The run tray's keys, so the owner's run review can accept it.
        let envelope = proposals::run_tray_envelope(
            self,
            COACH_PERSON_THRESHOLD_FACET,
            attempt.status.attempt.id,
        )?;
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
                        &unread.iter().map(|(source, _)| *source).collect::<Vec<_>>(),
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

    /// Records the offer skill's draft as the Coach, under a leased
    /// `coach.training_offer` attempt. The offer waits on the owner; the
    /// nightly offer pass delivers it.
    pub fn run_coach_training_offer(
        &self,
        attempt: &DreamerAdmittedAttempt,
        draft: crate::skill_optimize::TrainingOfferDraft,
        now: u64,
    ) -> Result<crate::skill_optimize::TrainingOffer> {
        self.require_coach_attempt(attempt, COACH_TRAINING_OFFER_FACET)?;
        let offer = crate::skill_optimize::record_training_offer(
            self,
            attempt.status.attempt.id,
            draft,
            now,
        )?;
        self.with_write_txn_grouped(|txn| {
            let owners = crate::policy_model::owners_in_txn(self, &*txn)?;
            notify_offer_in_txn(self, txn, &owners, &offer)
        })?;
        // The digest deadline re-reads: a pending offer arms it.
        self.store.notify_proactivity_changes();
        Ok(offer)
    }

    /// Records what the receipts since showed against one offer's promise,
    /// under the leased `coach.offer_check` attempt its check date queued.
    pub fn run_coach_offer_check(
        &self,
        attempt: &DreamerAdmittedAttempt,
        input: crate::skill_optimize::OfferCheckInput,
        now: u64,
    ) -> Result<crate::skill_optimize::OfferCheck> {
        self.require_coach_attempt(attempt, COACH_OFFER_CHECK_FACET)?;
        let offer = offer_check_target(&attempt.status.payload.input)?;
        crate::skill_optimize::record_offer_check(self, &offer, input, now)
    }

    /// The leased attempt is this facet's, stamped for the Coach.
    pub(super) fn require_coach_attempt(
        &self,
        attempt: &DreamerAdmittedAttempt,
        facet: &str,
    ) -> Result<()> {
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

/// The responsible-role climb. The first pass that sees an ask only starts
/// its window; each window it waits after that climbs one rung, and the top
/// rung stays. The window restarts before the climb, so a pass cut between
/// the two climbs a night late rather than skipping a role. The row of an ask
/// that is answered or withdrawn goes.
pub(super) fn run_tradeoff_escalation(vault: &Vault, now: u64) -> Result<()> {
    let asks = crate::skill_optimize::pending_skill_tradeoff_asks(vault)?;
    for ask in &asks {
        let proposal = ask.question.proposal;
        let since = {
            let txn = vault.store.env.read_txn()?;
            TRADEOFF_CLIMB.get(&vault.store, &txn, &proposal)?
        };
        if since.is_some_and(|since| now.saturating_sub(since) < TRADEOFF_REMINDER_SECS) {
            continue;
        }
        vault
            .with_write_txn_grouped(|txn| TRADEOFF_CLIMB.put(&vault.store, txn, &proposal, &now))?;
        if since.is_some() {
            crate::skill_optimize::escalate_skill_tradeoff_ask(vault, &proposal)?;
        }
    }
    let pending: std::collections::BTreeSet<EntityId> =
        asks.iter().map(|ask| ask.question.proposal).collect();
    let settled: Vec<EntityId> = {
        let txn = vault.store.env.read_txn()?;
        TRADEOFF_CLIMB
            .scan_keys(&vault.store, &txn, &[])?
            .into_iter()
            .filter(|proposal| !pending.contains(proposal))
            .collect()
    };
    if !settled.is_empty() {
        vault.with_write_txn_grouped(|txn| {
            for proposal in &settled {
                TRADEOFF_CLIMB.delete(&vault.store, txn, proposal)?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

/// The offer a `coach.offer_check` job checks.
fn offer_check_target(input: &Value) -> Result<EntityId> {
    match input {
        Value::Map(fields) if fields.len() == 1 && fields[0].0.as_str() == Some("offer") => {
            EntityId::from_hex(fields[0].1.as_str().ok_or_else(invalid)?).map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}

/// One pending offer in every owner's inbox, keyed by offer and owner: a
/// replay finds the row, so an owner's seen and acked marks stay theirs.
fn notify_offer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owners: &[EntityId],
    offer: &crate::skill_optimize::TrainingOffer,
) -> Result<()> {
    let id = offer.id.to_hex();
    for owner in owners {
        vault.record_notification_in_txn(
            txn,
            &crate::inbox::NotificationEvent {
                kind: crate::inbox::NotificationKind::Ask,
                source: crate::inbox::NotificationSource {
                    producer: TRAINING_OFFER_NOTIFICATION_PRODUCER.to_owned(),
                    event: format!("{id}:{}", owner.to_hex()),
                    result: Some(id.clone()),
                    ..crate::inbox::NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: Some(*owner),
                created_at: offer.offered_at,
                origin_conversation: None,
            },
        )?;
    }
    Ok(())
}

/// The nightly offer pass. Each pending offer reaches every owner's inbox as
/// one NOTIFICATION keyed by offer and owner, so a replayed night delivers
/// nothing twice and the owner's seen and acked marks stay theirs. Each
/// offer whose check date came, and that has no check yet, queues its
/// promise check for the host; the queue's dedupe keeps one per offer.
pub(super) fn run_training_offers(vault: &Vault, now: u64) -> Result<()> {
    let pending = crate::skill_optimize::pending_training_offers(vault)?;
    let mut due = Vec::new();
    for (offer, _) in crate::skill_optimize::training_offers(vault, None)? {
        if offer.check_at <= now
            && crate::skill_optimize::training_offer_checks(vault, &offer.id)?.is_empty()
        {
            due.push(offer.id);
        }
    }
    if pending.is_empty() && due.is_empty() {
        return Ok(());
    }
    let store = DreamerRunnerStore::new(vault);
    vault.with_write_txn_grouped(|txn| {
        let owners = crate::policy_model::owners_in_txn(vault, &*txn)?;
        for offer in &pending {
            notify_offer_in_txn(vault, txn, &owners, offer)?;
        }
        for offer in &due {
            store.enqueue_kind_in_txn(
                txn,
                COACH_HOST_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: COACH_OFFER_CHECK_FACET.into(),
                    input: Value::Map(vec![(Value::from("offer"), Value::from(offer.to_hex()))]),
                    parent_attempt: None,
                },
                Some(format!("{COACH_OFFER_CHECK_FACET}:{}", offer.to_hex())),
                None,
                now,
            )?;
        }
        Ok(())
    })
}

/// The autoresearch tick: one selection round for each bound campaign the
/// loop's own record says is due. The round reads the campaign's lease and
/// pauses, never fails, on an empty budget. A campaign whose round errs is
/// left for the next night; the others still run.
pub(super) fn run_research_select(vault: &Vault, now: u64) -> Result<()> {
    use crate::autoreason_campaign::research;
    for root in research::bound_research_roots(vault)? {
        if !research::research_round_due(vault, root)? {
            continue;
        }
        if let Err(error) = research::select_next(
            vault,
            root,
            crate::autoreason_campaign::selection::OracleSignal::NoSignal,
            now,
        ) {
            tracing::warn!(kind = ?error.kind(), "autoresearch round did not run");
        }
    }
    Ok(())
}

/// The nightly learning upkeep. A team whose coordination will not derive is
/// left for the next night; the others still run.
pub(super) fn run_learning_sweep(vault: &Vault, now: u64) -> Result<()> {
    crate::learning::reproject_all_cells(vault, now)?;
    crate::learning::project_all_coordination(vault, now)
}
