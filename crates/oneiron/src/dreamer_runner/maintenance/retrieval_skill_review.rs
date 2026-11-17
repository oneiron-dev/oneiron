//! The Coach's slow retrieval loop (ARCH-0053 #tune-retrieval, census L1-18).
//! The nightly retrieval tune runs the bandit update first; then, when the
//! owner imported the library skill `skills/tune-oneiron-retrieval` and
//! telemetry capture is on, it queues one review on the Coach host queue for
//! the runs published since the last one. The review reads the skill's text
//! and the vault's retrieval receipts, and the host's model answers with one
//! proposal of the four kinds the skill names. The engine checks what it can
//! check without judging retrieval, and keeps the proposal as a receipt
//! stamped with the skill version and hub commit it read.
//!
//! The loop only offers (Engine ruling L1-18-PROPOSAL = A, 14 Nov 03:02): it
//! writes no live value, as the skill says ("You write a proposal. You never
//! write a live value."). An offered owner recommendation or learner re-seed
//! reaches each owner's inbox; a re-seed stays the owner's own act through
//! his retrieval-policy verbs. `vault.retrieval.policy.get` lists the
//! receipts and the last night's slow-loop status.
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::coach::{COACH_HOST_QUEUE_KIND, COACH_RETRIEVAL_SKILL_REVIEW_FACET};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::{InstalledLibrarySkill, TUNE_ONEIRON_RETRIEVAL_SUBTREE};
use crate::store::{
    RetrievalBlendSignal, RetrievalBlendTuningConfig, RetrievalBlendWeightTableEntry,
    RetrievalOutcomeRecord, RetrievalPolicyPins, RetrievalRunId, RetrievalRunRecord,
};
use crate::{EntityId, Error, Result, Vault};

/// The last nightly tune's slow-loop status. Key: ().
const STATUS: SideTable<(), RetrievalSlowLoopStatus, Named> =
    SideTable::new(&side_table::COACH_RETRIEVAL_SLOW_LOOP);
/// One receipt per review. Key: the review attempt's id.
const RECEIPTS: SideTable<[u8; 16], RetrievalTuningReceipt, Named> =
    SideTable::new(&side_table::COACH_RETRIEVAL_TUNING_RECEIPT);

/// Producer name of an offered proposal's inbox NOTIFICATION.
pub const RETRIEVAL_TUNING_NOTIFICATION_PRODUCER: &str = "coach.retrieval_tuning";

const NOT_INSTALLED: &str =
    "tune-oneiron-retrieval is not installed; import skills/tune-oneiron-retrieval";
const CAPTURE_OFF: &str = "retrieval telemetry capture is off; the slow loop reviews captured runs";
const NO_NEW_RUN: &str = "no retrieval run was published since the last review";

/// A proposal's kind: the four the skill's "What runs today" names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalTuningProposalKind {
    /// A change only the owner makes: a host setting, a pin or a floor.
    OwnerRecommendation,
    /// New settings for the blend tuner, never a value it learns.
    LearnerReseed,
    /// A named piece of engine work.
    EngineWork,
    /// What collects the evidence a change needs first.
    CollectEvidence,
}

/// One of the blend tuner's own settings ([`RetrievalBlendTuningConfig`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalLearnerSetting {
    MaxRuns,
    LearningRate,
    MinRewardCount,
}

/// The knob a proposal names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalTuningKnob {
    /// One of the blend tuner's settings: what a learner re-seed moves.
    LearnerSetting(RetrievalLearnerSetting),
    /// One blend weight: a value the learner learns, never set.
    BlendWeight(RetrievalBlendSignal),
    /// The owner's pin over one blend signal: only the owner moves it.
    OwnerPin(RetrievalBlendSignal),
    /// Any other knob, as the skill's references/knobs.md names it.
    Other(String),
}

/// One proposal, as the skill's receipt words it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalTuningProposal {
    pub kind: RetrievalTuningProposalKind,
    /// The symptom, with the run counts and the time window that show it.
    pub symptom: String,
    /// The causes checked, in the skill's order, and what each showed.
    pub causes_checked: Vec<String>,
    pub knob: Option<RetrievalTuningKnob>,
    /// The slice the change is for; `None` is the whole vault.
    pub slice: Option<String>,
    /// The change, from and to.
    pub change: Option<String>,
    /// The published runs that show the symptom.
    pub evidence_runs: Vec<RetrievalRunId>,
}

/// What the engine did with a proposal. Nothing is ever applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalTuningDisposition {
    /// Offered as it stands.
    Offered,
    /// Kept as a receipt only: it broke a rule the engine checks.
    Refused { reason: String },
}

/// One review's receipt, stamped with the skill it read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalTuningReceipt {
    /// The review attempt.
    pub attempt: AttemptId,
    /// The nightly tune that queued it.
    pub tune_attempt: Option<AttemptId>,
    pub skill_id: String,
    pub skill_version: String,
    pub hub_commit: String,
    pub proposal: RetrievalTuningProposal,
    pub disposition: RetrievalTuningDisposition,
    pub at: u64,
}

/// What the last nightly tune did about the slow loop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalSlowLoopStatus {
    pub tune_attempt: AttemptId,
    pub at: u64,
    /// Why that tune queued no review; `None` when it queued one.
    pub skipped: Option<String>,
    /// The latest review a tune queued.
    pub review: Option<AttemptId>,
    /// The newest published run when that review was queued.
    pub reviewed_through: Option<RetrievalRunId>,
}

/// The slow loop as its rows report it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalSlowLoopView {
    pub status: Option<RetrievalSlowLoopStatus>,
    /// Every review's receipt, newest first.
    pub receipts: Vec<RetrievalTuningReceipt>,
}

/// One text file of the installed skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalSkillFile {
    pub path: String,
    pub text: String,
}

/// What a review reads: the installed skill's text and the retrieval
/// receipts its "Read the record" list names.
#[derive(Debug, Clone)]
pub struct RetrievalSkillBrief {
    pub skill: InstalledLibrarySkill,
    /// SKILL.md and the skill's other markdown files, as the import stored them.
    pub files: Vec<RetrievalSkillFile>,
    /// The newest published runs, newest first, up to the blend tuner's window.
    pub runs: Vec<RetrievalRunRecord>,
    /// Every outcome row of those runs.
    pub outcomes: Vec<RetrievalOutcomeRecord>,
    pub blend: RetrievalBlendWeightTableEntry,
    pub pins: RetrievalPolicyPins,
    /// Nearest-rank (p50, p95) one-shot latency, in microseconds.
    pub latency_baseline: Option<(u64, u64)>,
    /// The settings the nightly blend tuner ran with.
    pub learner: RetrievalBlendTuningConfig,
    /// The effective retention, (max age in seconds, max runs); `None` when
    /// the policy manifest grants none.
    pub retention: Option<(u64, usize)>,
}

/// The host's model on the skill: one proposal from one brief.
pub trait RetrievalSkillReviewer {
    /// The proposal `brief` supports.
    fn review(&self, brief: &RetrievalSkillBrief) -> Result<RetrievalTuningProposal>;
}

/// After the nightly tune's bandit update: queues one review on the Coach
/// host queue, with the tune as its parent, or records why it queued none.
pub(super) fn queue_after_tune(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<()> {
    let skipped = if vault
        .installed_default_hub_skill(TUNE_ONEIRON_RETRIEVAL_SUBTREE)?
        .is_none()
    {
        Some(NOT_INSTALLED)
    } else if !vault.store.retrieval_telemetry_capture_enabled() {
        Some(CAPTURE_OFF)
    } else {
        None
    };
    let newest = vault.retrieval_runs(1)?.first().map(|run| run.run_id);
    let tune = attempt.status.attempt.id;
    let run_id = attempt.status.attempt.run_id.clone();
    let store = DreamerRunnerStore::new(vault);
    vault.with_write_txn_grouped(|txn| {
        let held = STATUS.get(&vault.store, &*txn, &())?;
        let review = held.as_ref().and_then(|status| status.review);
        let reviewed_through = held.and_then(|status| status.reviewed_through);
        let status = match (skipped, newest) {
            (None, Some(newest)) if reviewed_through != Some(newest) => {
                let (EnqueueDreamerAttemptOutcome::Enqueued(queued)
                | EnqueueDreamerAttemptOutcome::Existing(queued)) = store.enqueue_kind_in_txn(
                    txn,
                    COACH_HOST_QUEUE_KIND,
                    DreamerAttemptPayload {
                        attempt_type: COACH_RETRIEVAL_SKILL_REVIEW_FACET.into(),
                        input: Value::Nil,
                        parent_attempt: Some(tune),
                    },
                    Some(format!(
                        "{COACH_RETRIEVAL_SKILL_REVIEW_FACET}:{}",
                        newest.to_hex()
                    )),
                    run_id,
                    now,
                )?;
                RetrievalSlowLoopStatus {
                    tune_attempt: tune,
                    at: now,
                    skipped: None,
                    review: Some(queued.attempt.id),
                    reviewed_through: Some(newest),
                }
            }
            (skipped, _) => RetrievalSlowLoopStatus {
                tune_attempt: tune,
                at: now,
                skipped: Some(skipped.unwrap_or(NO_NEW_RUN).to_owned()),
                review,
                reviewed_through,
            },
        };
        STATUS.put(&vault.store, txn, &(), &status)
    })
}

impl Vault {
    /// The slow retrieval loop as the Coach, under a leased
    /// `coach.retrieval_skill_review` attempt: builds the brief from the
    /// installed skill and the retrieval receipts, asks `reviewer` once for a
    /// proposal, checks it and keeps it as this attempt's receipt. An offered
    /// owner recommendation or learner re-seed reaches every owner's inbox in
    /// the same write. Nothing is applied. A replay of the attempt returns
    /// its receipt and asks nothing.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, a skill no longer
    /// installed, the reviewer's own errors, or storage errors.
    pub fn run_coach_retrieval_skill_review(
        &self,
        attempt: &DreamerAdmittedAttempt,
        reviewer: &dyn RetrievalSkillReviewer,
        now: u64,
    ) -> Result<RetrievalTuningReceipt> {
        self.require_coach_attempt(attempt, COACH_RETRIEVAL_SKILL_REVIEW_FACET)?;
        let id = attempt.status.attempt.id;
        let held = {
            let txn = self.store.env.read_txn()?;
            RECEIPTS.get(&self.store, &txn, id.as_bytes())?
        };
        if let Some(held) = held {
            return Ok(held);
        }
        let brief = skill_brief(self)?.ok_or_else(|| Error::InvalidConfig(NOT_INSTALLED.into()))?;
        let proposal = reviewer.review(&brief)?;
        let disposition = refusal(&brief, &proposal)
            .map_or(RetrievalTuningDisposition::Offered, |reason| {
                RetrievalTuningDisposition::Refused { reason }
            });
        let receipt = RetrievalTuningReceipt {
            attempt: id,
            tune_attempt: attempt.status.payload.parent_attempt,
            skill_id: brief.skill.skill_id,
            skill_version: brief.skill.version,
            hub_commit: brief.skill.commit,
            proposal,
            disposition,
            at: now,
        };
        self.with_write_txn_grouped(|txn| {
            if let Some(held) = RECEIPTS.get(&self.store, &*txn, id.as_bytes())? {
                return Ok(held);
            }
            RECEIPTS.put(&self.store, txn, id.as_bytes(), &receipt)?;
            let offered = receipt.disposition == RetrievalTuningDisposition::Offered
                && matches!(
                    receipt.proposal.kind,
                    RetrievalTuningProposalKind::OwnerRecommendation
                        | RetrievalTuningProposalKind::LearnerReseed
                );
            if offered {
                let owners = crate::policy_model::owners_in_txn(self, &*txn)?;
                notify_owners_in_txn(self, txn, &owners, &receipt)?;
            }
            Ok(receipt)
        })
    }

    /// The slow retrieval loop's rows: the last nightly tune's status and
    /// every receipt, newest first. Grants no authority; the owner's
    /// `vault.retrieval.policy.get` lists it.
    pub fn retrieval_slow_loop(&self) -> Result<RetrievalSlowLoopView> {
        let txn = self.store.env.read_txn()?;
        let mut receipts: Vec<RetrievalTuningReceipt> = RECEIPTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect();
        receipts.sort_by_key(|receipt| std::cmp::Reverse((receipt.at, receipt.attempt)));
        Ok(RetrievalSlowLoopView {
            status: STATUS.get(&self.store, &txn, &())?,
            receipts,
        })
    }
}

/// The brief, or `None` before the owner imports the skill.
fn skill_brief(vault: &Vault) -> Result<Option<RetrievalSkillBrief>> {
    let Some(skill) = vault.installed_default_hub_skill(TUNE_ONEIRON_RETRIEVAL_SUBTREE)? else {
        return Ok(None);
    };
    let (files, retention) = {
        let txn = vault.store.env.read_txn()?;
        let record = vault
            .get_skill_record_in_txn(&txn, &skill.entity)?
            .ok_or(Error::EntityNotFound)?;
        let package = vault
            .runtime_skill_package_in_txn(&txn, &skill.entity, &record)?
            .ok_or_else(|| Error::InvalidConfig("the imported skill stores no package".into()))?;
        let files = package
            .files
            .into_iter()
            .filter(|file| file.path.ends_with(".md"))
            .filter_map(|file| {
                Some(RetrievalSkillFile {
                    text: String::from_utf8(file.content).ok()?,
                    path: file.path,
                })
            })
            .collect();
        let retention = crate::gate::resolve_policy_manifest(&vault.store, &txn)?
            .retrieval_retention_policy()
            .map(crate::gate::retrieval_retention::RetrievalRetentionPolicy::effective);
        (files, retention)
    };
    let learner = RetrievalBlendTuningConfig::default();
    let runs = vault.retrieval_runs(learner.max_runs)?;
    let mut outcomes = Vec::new();
    for run in &runs {
        outcomes.extend(vault.retrieval_outcomes(run.run_id)?);
    }
    Ok(Some(RetrievalSkillBrief {
        skill,
        files,
        latency_baseline: vault.retrieval_latency_baseline(learner.max_runs)?,
        runs,
        outcomes,
        blend: vault.retrieval_blend_weight_table()?,
        pins: vault.retrieval_policy_pins()?,
        learner,
        retention,
    }))
}

/// Why the engine refuses `proposal`, or `None` to offer it. The checks
/// judge no retrieval: the evidence is the brief's, a learned value is never
/// set ("The skill never sets a value the bandit learns."), a re-seed names
/// a tuner setting, and only the owner moves a pin ("Never override a pin.
/// Propose a change to it instead.").
fn refusal(brief: &RetrievalSkillBrief, proposal: &RetrievalTuningProposal) -> Option<String> {
    if proposal.symptom.trim().is_empty() {
        return Some("the proposal names no symptom".into());
    }
    if let Some(run) = proposal
        .evidence_runs
        .iter()
        .find(|run| !brief.runs.iter().any(|held| held.run_id == **run))
    {
        return Some(format!(
            "the proposal cites run {}, which the brief does not hold",
            run.to_hex()
        ));
    }
    let sets = proposal.change.is_some();
    match (&proposal.knob, proposal.kind) {
        (Some(RetrievalTuningKnob::BlendWeight(signal)), _) if sets => Some(format!(
            "the proposal sets a value the bandit learns: the {} blend weight",
            signal_name(*signal)
        )),
        (
            Some(RetrievalTuningKnob::LearnerSetting(_)),
            RetrievalTuningProposalKind::LearnerReseed,
        ) if sets => None,
        (_, RetrievalTuningProposalKind::LearnerReseed) => Some(
            "a learner re-seed names one of the blend tuner's settings and its new value".into(),
        ),
        (Some(RetrievalTuningKnob::OwnerPin(_)), kind)
            if sets && kind != RetrievalTuningProposalKind::OwnerRecommendation =>
        {
            Some("only the owner moves a pin: offer the change as an owner recommendation".into())
        }
        _ => None,
    }
}

/// A blend signal's wire name.
fn signal_name(signal: RetrievalBlendSignal) -> &'static str {
    match signal {
        RetrievalBlendSignal::Recency => "recency",
        RetrievalBlendSignal::Salience => "salience",
        RetrievalBlendSignal::Confidence => "confidence",
        RetrievalBlendSignal::Gravity => "gravity",
        RetrievalBlendSignal::Relevance => "relevance",
    }
}

/// One offered proposal in every owner's inbox, keyed by review and owner: a
/// replay finds the row, so an owner's seen and acked marks stay theirs.
fn notify_owners_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owners: &[EntityId],
    receipt: &RetrievalTuningReceipt,
) -> Result<()> {
    let id = bytes_to_hex_lower(receipt.attempt.as_bytes());
    for owner in owners {
        vault.record_notification_in_txn(
            txn,
            &crate::inbox::NotificationEvent {
                kind: crate::inbox::NotificationKind::Ask,
                source: crate::inbox::NotificationSource {
                    producer: RETRIEVAL_TUNING_NOTIFICATION_PRODUCER.to_owned(),
                    event: format!("{id}:{}", owner.to_hex()),
                    attempt: Some(id.clone()),
                    result: Some(id.clone()),
                    detail: Some(receipt.proposal.symptom.clone()),
                    ..crate::inbox::NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: Some(*owner),
                created_at: receipt.at,
                origin_conversation: None,
            },
        )?;
    }
    Ok(())
}
