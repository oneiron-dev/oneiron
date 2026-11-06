//! The matched-fork contribution runner (FIX 3028, FIX 2870, ARCH-0037
//! #lineage-credit, ARCH-0053): one sampled credited run's step, regenerated
//! from its replay capsule once as captured and once without one target's
//! exposure, on the capsule's own model with equal settings, both scored
//! against the run's anchor by one rubric. A loaded skill's check
//! regenerates the run's first step without the skill's body; an ancestor
//! check on one used edge regenerates the earliest step that exposed the
//! edge's source without that source's body ([`ancestor`]). An engine
//! step's pair, when both forks' answers ran as programs against the step's
//! recorded calls under one pin, is scored on each answer's text and what
//! its program did together; any other pair, a workflow step's always, on
//! the answer's text alone, as before (FIX 3607 and L08-A's 07:42 answer,
//! [`execution`]). The host lends the model call, the program run and the
//! scorer; this runner picks the capsule, builds the two requests, keeps
//! each fork's receipt and returns the scored pair. It records no check and
//! publishes nothing from one fork: the Coach's recipe records the pair
//! ([`crate::skill_attribution::record_contribution_pair`]).
//!
//! An owner verdict's pair is generated the same way, then judged by the
//! owner, not by a model (FIX 3609, [`owner`]). Its forks are kept once, and
//! one pending pair asks the owner which of the two blinded answers pass the
//! frozen criterion. A pending pair never regenerates and never pays again.
//! The owner's word scores both forks and records the pair in the ask's
//! settling commit.
//!
//! A knowledge exposure is the one unit: a body the host put in the run's
//! task, tagged where it went. A callable or result-only use, an ancestor
//! the run read through a verb, an anchor that cannot judge a new output,
//! and any missing or ambiguous context are unavailable, never "did not
//! contribute".

mod admission;
mod ancestor;
mod execution;
mod generation;
mod owner;

use serde::{Deserialize, Serialize};

pub use self::admission::ForkMismatch;
pub(crate) use self::admission::matched_contribution_facts_in_txn;
use self::ancestor::target_step;
pub use self::execution::{
    ContributionForkExecution, ContributionForkProgram, ExecutedBody, ExecutedFork,
    ExecutedForkView, ExecutedOutput, ExecutedStepStatus, ForkEvidenceMode, ForkExecutionOutcome,
    ForkExecutionPin, ForkJudge, ForkScore, execute_contribution_fork,
};
use self::execution::{ProgramStep, pair_evidence_mode, retry_pending, scored_in};
pub use self::owner::OwnerJudgment;
pub(crate) use self::owner::{
    OwnerPair, OwnerPairAnswer, OwnerPairChoice, OwnerPairRoute, OwnerPairTexts,
    settle_owner_pair_in_txn,
};
use super::replay_capsule::{ExposureSlot, ReplayRung, StepReplayCapsule, StoredRungBinding};
use super::shadow_runner::ShadowUnavailable;
use super::storage::{
    ForkProvenance, ForkRows, fork_response, fork_rows, put_fork, put_unavailable,
    step_replay_capsules_in_txn,
};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::maintenance::ContributionForks;
use crate::learning::Anchor;
use crate::receipt::attempt_pack_receipt_id;
use crate::retrieval_depth::RetrievalDeadline;
use crate::skill_attribution::{ContributionCandidate, ContributionFork, Experiment};
use crate::{ContentPart, EntityId, Error, LlmRequest, LlmResponse, ModelId, Result, Vault};

/// The step a loaded skill's check regenerates: the run's first, the one
/// input no answer of the run has touched yet. A skill body the host put in
/// the task is in it, so its first exposure is there.
const FIRST_STEP: u64 = 0;
/// A fork receipt's prefix. The rest is an opaque id that names neither the
/// fork's treatment nor its run, so a scorer reading it stays blind.
pub(super) const FORK_RECEIPT_PREFIX: &str = "contribution_fork:";

/// Why a matched pair cannot be run. None of these is a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionReplayUnavailable {
    /// The anchor cannot judge a new output (a world outcome) or does not
    /// settle correctness. An owner verdict's pair is judged by the owner
    /// (FIX 3609).
    AnchorNotReplayable,
    /// The anchor does not resolve to a frozen case and rubric now.
    AnchorUnresolved,
    /// No capsule of the step the check regenerates.
    NoCapsule,
    /// That step's capsule was never finalized: no rung's answer was
    /// recorded for it.
    CapsuleNotFinalized,
    /// The capsule's or a fork's body is gone, withheld or no longer its
    /// hash, or its exposure no longer sits where it was captured.
    Unreadable,
    /// An erase retired the capsule's request or a fork's response body, or
    /// a fork writer found the capsule's content erased (FIX 6256).
    Erased,
    /// No knowledge exposure of the target in a captured step: the skill's
    /// body, or the edge's source's, as the host put it in the run's task. A
    /// callable or result-only use, and an ancestor the run read through a
    /// verb, is not replayed.
    NoExposure,
    /// The target reached the run only as site knowledge on a browser
    /// observation (FIX 11436): it is recorded, but it has no byte span in
    /// the run's task to leave out.
    SiteObservation,
    /// The step carries the target at more than one revision.
    AmbiguousExposure,
    /// The target's record is at another revision than the one the step saw.
    SkillRevisionMoved,
    /// A stored fork came from another capsule or was scored by another
    /// rubric than the pair's now.
    ForksDiverged,
    /// The capsule's model, or the route prompt it answered under, is not
    /// served now.
    ModelUnavailable,
    /// The forks did not finish by the clock, or the scorer did not decide.
    /// A fork writer that found a subject of the pair gone now stops here
    /// too: a soft delete may be restored, so the stop is never lasting
    /// (FIX 6256).
    Unfinished,
    /// An engine step's fork's program did not run against the captured
    /// step now (FIX 3607), for the shadow runner's own reason, one a retry
    /// may clear (no runtime now, a cancelled run). The pair waits for that
    /// one retry; a reason that holds then, or a lasting one, puts the pair
    /// in the `Text` mode instead. Never a loss of the program.
    ProgramReplay(ShadowUnavailable),
}

impl ContributionReplayUnavailable {
    /// The reason's stable name; a program replay's is the shadow runner's
    /// own reason's name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AnchorNotReplayable => "anchor_not_replayable",
            Self::AnchorUnresolved => "anchor_unresolved",
            Self::NoCapsule => "no_capsule",
            Self::CapsuleNotFinalized => "capsule_not_finalized",
            Self::Unreadable => "unreadable",
            Self::Erased => "erased",
            Self::NoExposure => "no_exposure",
            Self::SiteObservation => "site_observation",
            Self::AmbiguousExposure => "ambiguous_exposure",
            Self::SkillRevisionMoved => "skill_revision_moved",
            Self::ForksDiverged => "forks_diverged",
            Self::ModelUnavailable => "model_unavailable",
            Self::Unfinished => "unfinished",
            Self::ProgramReplay(unavailable) => unavailable.reason.as_str(),
        }
    }

    /// Whether the reason holds for good: the pair is recorded unavailable
    /// and no later pass pays for it again. A model not served now, an
    /// anchor that does not resolve now and a pass that ran out of time or
    /// met a subject gone now are asked again, as is a program replay the
    /// shadow runner says a retry may find available.
    #[must_use]
    pub const fn lasting(&self) -> bool {
        match self {
            Self::ProgramReplay(unavailable) => !unavailable.retryable,
            reason => !matches!(
                reason,
                Self::AnchorUnresolved | Self::ModelUnavailable | Self::Unfinished
            ),
        }
    }
}

/// Which side of the pair a fork is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkTreatment {
    /// The step as captured.
    WithSkill,
    /// The step with the target's exposure removed (the skill's body, or the
    /// edge's source's), and nothing else changed.
    WithoutSkill,
}

/// What a fork was scored for, frozen as it was generated: the credited
/// outcome, the goal revision it was checked under and its axis. Admission
/// reads it back against the pair's candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkScoring {
    pub outcome_receipt: String,
    pub goal_revision: Option<String>,
    pub axis: String,
}

impl ForkScoring {
    fn of(candidate: &ContributionCandidate) -> Self {
        Self {
            outcome_receipt: candidate.outcome_receipt.clone(),
            goal_revision: candidate.goal_revision.clone(),
            axis: candidate.axis.clone(),
        }
    }
}

/// A fork's frozen scoring identity: the canonical rubric digest and the
/// scorer-byte digest as resolved at prepare, before either fork. Both
/// forks of a pair copy it; admission rehashes the candidate against it.
/// The identity a fork is scored under is this and its score's evidence
/// mode, the execution pin in the `Executed` mode included (FIX 3607): both
/// forks of a pair share all of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkScoringIdentity {
    pub rubric: [u8; 32],
    pub scorer: [u8; 32],
}

impl ForkScoringIdentity {
    fn of(anchor: &ReplayAnchor) -> Result<Self> {
        let encode =
            |error: serde_json::Error| Error::InvalidConfig(format!("replay anchor: {error}"));
        Ok(Self {
            rubric: *blake3::hash(&serde_json::to_vec(&anchor.rubric).map_err(encode)?).as_bytes(),
            scorer: *blake3::hash(anchor.scorer.as_bytes()).as_bytes(),
        })
    }
}

/// One fork's durable receipt: what it regenerated, how, what it answered,
/// for an engine step what came of its answer's program (FIX 3607) and,
/// once scored, the mode it was scored in and whether it passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionForkReceipt {
    pub receipt: String,
    pub treatment: ForkTreatment,
    /// The capsule it regenerated.
    pub attempt: EntityId,
    pub lease_generation: u32,
    pub step: u64,
    pub capsule_request: [u8; 32],
    /// The canonical hash of the request the fork sent, before its route's
    /// prompt.
    pub request: [u8; 32],
    pub model: ModelId,
    /// The hash of the route prompt's body it was sent under, as its
    /// capsule stores it (FIX 6255): its canonical JSON, each secret in it
    /// its custody handle. `None` when the rung put no prompt.
    pub route_prompt: Option<[u8; 32]>,
    /// The captured seed both forks carried.
    pub seed: Option<u64>,
    /// No seed was captured: both forks ran on identical captured settings.
    pub seed_unsupported: bool,
    /// The fork's answer, by its body ref.
    pub response: crate::compaction::output::OutputRef,
    pub response_path: String,
    /// Whether restore explicitly marked this response body as erased.
    pub response_erased: bool,
    /// The anchor both forks are scored against, by hash.
    pub anchor: [u8; 32],
    /// The frozen scoring identity both forks were scored under.
    pub anchor_scoring: ForkScoringIdentity,
    /// The outcome it was scored for.
    pub scoring: ForkScoring,
    /// What came of an engine step's fork's program: its kept execution,
    /// or why it did not run. `None` until it was run, and always `None`
    /// for a workflow step's.
    pub execution: Option<ForkExecutionOutcome>,
    /// The mode it was scored in and whether it passed; `None` until scored.
    pub score: Option<ForkScore>,
    /// Unix seconds it was generated.
    pub generated_at: u64,
}

/// The model call a fork makes: the capsule's model alone, by its captured
/// route, never a fallback.
pub trait ContributionForkModel {
    /// `request`'s answer from `rung`'s model, stopping by `clock`, with the
    /// route prompt the capsule's body holds put first in place of the one
    /// configured (FIX 6255); `None` when that model is not served now, or
    /// its configured prompt is not the one the capsule's call was sent
    /// under, by `rung`'s digest (FIX 6356).
    ///
    /// # Errors
    ///
    /// A failed model call.
    fn generate(
        &self,
        request: &LlmRequest,
        rung: &ReplayRung,
        clock: &RetrievalDeadline,
    ) -> Result<Option<LlmResponse>>;
}

/// The frozen case and rubric both forks are scored against: the case is
/// the capsule's input, the rubric what the scorer resolved for the
/// candidate's anchor and axis.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayAnchor {
    pub rubric: serde_json::Value,
    /// The scorer and its revision.
    pub scorer: String,
}

/// One fork as its scorer reads it.
#[derive(Debug, Clone, Copy)]
pub struct ScoredFork<'a> {
    pub receipt: &'a str,
    /// The task both forks answered: the step's input without the exposure.
    pub task: &'a LlmRequest,
    pub response: &'a LlmResponse,
    /// In the `Executed` mode, what `response`'s program did when run (FIX
    /// 3607): evidence its scorer reads beside the answer's text, never in
    /// its place. `None` in the `Text` mode, scored on the answer's text.
    pub executed: Option<&'a ExecutedForkView>,
}

/// The anchor's scorer, lent by the host.
pub trait ContributionForkScorer {
    /// The candidate's anchor as a frozen case and rubric, resolved before
    /// either fork is paid for; else why the pair is unavailable now: an
    /// anchor that resolves to none (`AnchorUnresolved`), or a scorer whose
    /// judge is not served now (`ModelUnavailable`, FIX 3611).
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn resolve(
        &self,
        vault: &Vault,
        candidate: &ContributionCandidate,
    ) -> Result<std::result::Result<ReplayAnchor, ContributionReplayUnavailable>>;

    /// Whether `fork` passes `anchor` by the rubric's own pass rule, the same
    /// for both forks; `None` when the scorer did not decide.
    ///
    /// # Errors
    ///
    /// A failed scoring call.
    fn passes(
        &self,
        vault: &Vault,
        candidate: &ContributionCandidate,
        anchor: &ReplayAnchor,
        fork: &ScoredFork<'_>,
        clock: &RetrievalDeadline,
    ) -> Result<Option<bool>>;
}

/// Runs `candidate`'s matched pair, or says why it cannot: both forks of
/// the step its target's check regenerates, each kept as a receipt as soon
/// as it answers, an engine step's program run by `program` and its outcome
/// kept (FIX 3607), and both scored against one anchor in the pair's one
/// evidence mode. A fork already generated, run or scored is reused, never
/// paid for again. A reason that holds for good is recorded, so a later
/// pass returns it without paying.
///
/// # Errors
///
/// Storage errors, and a failed fork or scoring call.
pub fn run_contribution_forks(
    vault: &Vault,
    candidate: &ContributionCandidate,
    model: &dyn ContributionForkModel,
    program: &dyn ContributionForkProgram,
    scorer: &dyn ContributionForkScorer,
    clock: &RetrievalDeadline,
) -> Result<std::result::Result<ContributionForks, ContributionReplayUnavailable>> {
    let (provenance, capsule) = {
        let txn = vault.store.env.read_txn()?;
        let capsules = attempt_capsules_in_txn(vault, &txn, candidate)?;
        let capsule = target_step(&capsules, candidate.target);
        let provenance = ForkProvenance::for_candidate_in_txn(
            vault,
            &txn,
            candidate,
            &capsules,
            capsule.as_ref().ok(),
        )?;
        (provenance, capsule)
    };
    let Some(provenance) = provenance else {
        return Ok(Err(ContributionReplayUnavailable::Unreadable));
    };
    let runner = Runner {
        vault,
        provenance,
        candidate,
        model,
        program,
        scorer,
        clock,
        pair: pair_digest(candidate),
    };
    let mut rows = fork_rows(vault, &runner.pair)?;
    if let Some(reason) = rows.unavailable.take() {
        return Ok(Err(reason));
    }
    let outcome = match runner.prepare(&rows, capsule)? {
        Ok(prepared) => runner.run(&prepared, rows)?,
        Err(reason) => Err(reason),
    };
    if let Err(reason) = &outcome
        && reason.lasting()
    {
        put_unavailable(vault, &runner.pair, &runner.provenance, reason.clone())?;
    }
    Ok(outcome)
}

/// Every fork receipt kept for `candidate`'s pair.
///
/// # Errors
///
/// Storage errors.
pub fn contribution_fork_receipts(
    vault: &Vault,
    candidate: &ContributionCandidate,
) -> Result<Vec<ContributionForkReceipt>> {
    let rows = fork_rows(vault, &pair_digest(candidate))?;
    Ok(rows
        .with_skill
        .into_iter()
        .chain(rows.without_skill)
        .collect())
}

type Outcome<T> = Result<std::result::Result<T, ContributionReplayUnavailable>>;

/// One pair's inputs, settled before any fork is paid for.
struct Prepared {
    capsule: StepReplayCapsule,
    /// The answering rung as the capsule keeps it: its route prompt by ref,
    /// read again before each fork's call (FIX 6255).
    binding: StoredRungBinding,
    with_skill: LlmRequest,
    with_skill_hash: [u8; 32],
    without_skill: LlmRequest,
    without_skill_hash: [u8; 32],
    /// The target's revision as the step saw it.
    exposure_revision: String,
    anchor: ReplayAnchor,
    anchor_scoring: ForkScoringIdentity,
    anchor_hash: [u8; 32],
    /// An engine step's frozen window and execution pin, or why it has none
    /// now; `None` for a workflow step.
    frozen_program: Option<std::result::Result<ProgramStep, ShadowUnavailable>>,
}

struct Runner<'a> {
    vault: &'a Vault,
    candidate: &'a ContributionCandidate,
    model: &'a dyn ContributionForkModel,
    program: &'a dyn ContributionForkProgram,
    scorer: &'a dyn ContributionForkScorer,
    clock: &'a RetrievalDeadline,
    pair: [u8; 32],
    provenance: ForkProvenance,
}

impl Runner<'_> {
    /// One paired draw in a fixed order, the fork with the skill first, then
    /// an engine step's two programs run in that order, then both scored in
    /// the pair's one evidence mode: by the anchor's scorer, or for an owner
    /// verdict by the owner's word on one pending pair (FIX 3609).
    fn run(&self, prepared: &Prepared, rows: ForkRows) -> Outcome<ContributionForks> {
        let with_skill =
            match self.generated(prepared, rows.with_skill, ForkTreatment::WithSkill)? {
                Ok(fork) => fork,
                Err(reason) => return Ok(Err(reason)),
            };
        let without_skill =
            match self.generated(prepared, rows.without_skill, ForkTreatment::WithoutSkill)? {
                Ok(fork) => fork,
                Err(reason) => return Ok(Err(reason)),
            };
        let with_skill = match self.executed(prepared, with_skill)? {
            Ok(fork) => fork,
            Err(reason) => return Ok(Err(reason)),
        };
        let without_skill = match self.executed(prepared, without_skill)? {
            Ok(fork) => fork,
            Err(reason) => return Ok(Err(reason)),
        };
        let host = prepared.capsule.host;
        let Some(mode) = pair_evidence_mode(host, &with_skill, &without_skill) else {
            return Ok(Err(retry_pending([&with_skill, &without_skill])));
        };
        if self.candidate.anchor == Anchor::OwnerVerdict {
            let pending = rows.owner_pair;
            return self.owner_judged(prepared, pending, with_skill, without_skill, mode);
        }
        let with_skill = match self.scored(prepared, with_skill, mode)? {
            Ok(fork) => fork,
            Err(reason) => return Ok(Err(reason)),
        };
        let without_skill = match self.scored(prepared, without_skill, mode)? {
            Ok(fork) => fork,
            Err(reason) => return Ok(Err(reason)),
        };
        let (Some(with_score), Some(without_score)) = (with_skill.score, without_skill.score)
        else {
            return Ok(Err(ContributionReplayUnavailable::Unfinished));
        };
        Ok(Ok(ContributionForks {
            with_skill: ContributionFork {
                receipt: with_skill.receipt,
                passed: with_score.passed,
            },
            without_skill: ContributionFork {
                receipt: without_skill.receipt,
                passed: without_score.passed,
            },
        }))
    }

    /// The fork as scored in `mode`, else scored now in it against the
    /// pair's anchor, its task the step's input without the exposure for
    /// both forks; in the `Executed` mode it is read with what its program
    /// did (FIX 3607). A fork kept scored in another mode diverged. A score
    /// its writer refuses is unavailable for that writer's own reason
    /// (FIX 6256).
    fn scored(
        &self,
        prepared: &Prepared,
        mut fork: ContributionForkReceipt,
        mode: ForkEvidenceMode,
    ) -> Outcome<ContributionForkReceipt> {
        if fork.score.is_some() {
            return Ok(scored_in(fork, mode));
        }
        let Some(response) = fork_response(self.vault, prepared.capsule.run, &fork)? else {
            return Ok(Err(if fork.response_erased {
                ContributionReplayUnavailable::Erased
            } else {
                ContributionReplayUnavailable::Unreadable
            }));
        };
        let executed = match self.executed_view(prepared, &fork, mode)? {
            Ok(executed) => executed,
            Err(reason) => return Ok(Err(reason)),
        };
        let scored = ScoredFork {
            receipt: &fork.receipt,
            task: &prepared.without_skill,
            response: &response,
            executed: executed.as_ref(),
        };
        let Some(passed) = self.scorer.passes(
            self.vault,
            self.candidate,
            &prepared.anchor,
            &scored,
            self.clock,
        )?
        else {
            return Ok(Err(ContributionReplayUnavailable::Unfinished));
        };
        fork.score = Some(ForkScore {
            mode,
            passed,
            judge: ForkJudge::Scorer,
        });
        Ok(put_fork(self.vault, &self.pair, &fork)?.and_then(|kept| scored_in(kept, mode)))
    }
}

/// The attempt's captures even when none exposed the selected target.
fn attempt_capsules_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidate: &ContributionCandidate,
) -> Result<Vec<StepReplayCapsule>> {
    match receipt_attempt(&candidate.attempt_receipt) {
        Some(attempt) => step_replay_capsules_in_txn(vault, txn, attempt),
        None => Ok(Vec::new()),
    }
}

/// The attempt a terminal pack receipt names, when it is one.
fn receipt_attempt(receipt: &str) -> Option<EntityId> {
    let (_, hex) = receipt.rsplit_once(':')?;
    let entity = EntityId::from_hex(hex).ok()?;
    let attempt = AttemptId::from_bytes(entity.as_bytes()).ok()?;
    (attempt_pack_receipt_id(&attempt) == receipt).then_some(entity)
}

/// `request` with exactly `slots` cut out of their text parts, and nothing
/// else changed; `None` when a slot no longer sits where it was captured or
/// two slots overlap.
fn without_exposure(request: &LlmRequest, slots: &[&ExposureSlot]) -> Option<LlmRequest> {
    let mut spans = Vec::with_capacity(slots.len());
    for slot in slots {
        let (_, range) = slot.locate(request)?;
        let message = usize::try_from(slot.message).ok()?;
        let part = usize::try_from(slot.part).ok()?;
        spans.push((message, part, range));
    }
    // Later spans go first, so each cut leaves the earlier ones in place.
    spans.sort_unstable_by_key(|(message, part, range)| {
        std::cmp::Reverse((*message, *part, range.start))
    });
    let mut control = request.clone();
    let mut previous: Option<(usize, usize, usize)> = None;
    for (message, part, range) in spans {
        if previous
            .is_some_and(|(at, within, start)| at == message && within == part && range.end > start)
        {
            return None;
        }
        previous = Some((message, part, range.start));
        let ContentPart::Text { text } =
            control.messages.get_mut(message)?.content.get_mut(part)?
        else {
            return None;
        };
        text.replace_range(range, "");
    }
    Some(control)
}

fn request_hash(request: &LlmRequest) -> Result<[u8; 32]> {
    request
        .canonical_hash()
        .map_err(|error| Error::InvalidConfig(format!("fork request: {error}")))
}

/// The pair's key: the experiment the A side keys its check by (the run,
/// the exact outcome, its goal revision, the axis and the target).
fn pair_digest(candidate: &ContributionCandidate) -> [u8; 32] {
    *Experiment::of_candidate(candidate)
        .hasher("oneiron contribution fork pair v2")
        .finalize()
        .as_bytes()
}

/// The anchor's identity: its kind, the outcome it settled, its axis and
/// the frozen scoring identity both forks were scored under.
fn anchor_hash(
    candidate: &ContributionCandidate,
    identity: &ForkScoringIdentity,
) -> Result<[u8; 32]> {
    let encode = |error: serde_json::Error| Error::InvalidConfig(format!("replay anchor: {error}"));
    let mut hasher = blake3::Hasher::new();
    hasher.update(&serde_json::to_vec(&candidate.anchor).map_err(encode)?);
    hasher.update(&[0]);
    hasher.update(candidate.outcome_receipt.as_bytes());
    hasher.update(&[0]);
    hasher.update(candidate.axis.as_bytes());
    hasher.update(&[0]);
    hasher.update(&identity.rubric);
    hasher.update(&[0]);
    hasher.update(&identity.scorer);
    Ok(*hasher.finalize().as_bytes())
}
