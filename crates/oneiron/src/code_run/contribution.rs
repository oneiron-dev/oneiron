//! The matched-fork contribution runner (FIX 3028, ARCH-0037 #lineage-credit,
//! ARCH-0053): one sampled credited run's first step, regenerated from its
//! replay capsule once as captured and once without one skill's body, on the
//! capsule's own model with equal settings, both scored against the run's
//! anchor by one rubric. The host lends the model call and the scorer; this
//! runner picks the capsule, builds the two requests, keeps each fork's
//! receipt and returns the scored pair. It records no check and publishes
//! nothing from one fork: the Coach's recipe records the pair
//! ([`crate::skill_attribution::record_contribution_pair`]).
//!
//! In this slice a knowledge exposure is the one unit: a skill's body the
//! host put in the first step's input. A callable, result-only or ancestor
//! use, an anchor that cannot judge a new output, and any missing or
//! ambiguous context are unavailable, never "did not contribute".

use serde::{Deserialize, Serialize};

use super::replay_capsule::{CapsuleRungBinding, ExposureSlot, StepReplayCapsule};
use super::storage::{
    ForkRows, capsule_request, fork_response, fork_rows, put_fork, put_unavailable,
    step_replay_capsules, store_fork_response,
};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::maintenance::ContributionForks;
use crate::entity_id::bytes_to_hex_lower;
use crate::learning::Anchor;
use crate::receipt::attempt_pack_receipt_id;
use crate::retrieval_depth::RetrievalDeadline;
use crate::skill_attribution::{ContributionCandidate, ContributionFork};
use crate::{ContentPart, EntityId, Error, LlmRequest, LlmResponse, ModelId, Result, Vault};

/// The step a check regenerates: the run's first, the one input no answer of
/// the run has touched yet. A skill body the host put in the task is in it,
/// so its first exposure is there.
const FIRST_STEP: u64 = 0;
/// A fork receipt's prefix. The rest is a hash that names neither the
/// fork's treatment nor its run, so a scorer reading it stays blind.
const FORK_RECEIPT_PREFIX: &str = "contribution_fork:";

/// Why a matched pair cannot be run. None of these is a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionReplayUnavailable {
    /// The anchor cannot judge a new output (an owner verdict, a world
    /// outcome) or does not settle correctness.
    AnchorNotReplayable,
    /// The anchor does not resolve to a frozen case and rubric now.
    AnchorUnresolved,
    /// No capsule of the run's first step.
    NoCapsule,
    /// The first step's capsule was never finalized: no rung's answer was
    /// recorded for it.
    CapsuleNotFinalized,
    /// The capsule's or a fork's body is gone, withheld or no longer its
    /// hash, or its exposure no longer sits where it was captured.
    Unreadable,
    /// No knowledge exposure of the skill in the first step. A callable,
    /// result-only or ancestor use is not replayed in this slice.
    NoExposure,
    /// The first step carries the skill at more than one revision.
    AmbiguousExposure,
    /// The skill's record is at another revision than the one the step saw.
    SkillRevisionMoved,
    /// A stored fork came from another capsule or was scored by another
    /// rubric than the pair's now.
    ForksDiverged,
    /// The capsule's model, or the route prompt it answered under, is not
    /// served now.
    ModelUnavailable,
    /// The forks did not finish by the clock, or the scorer did not decide.
    Unfinished,
}

impl ContributionReplayUnavailable {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnchorNotReplayable => "anchor_not_replayable",
            Self::AnchorUnresolved => "anchor_unresolved",
            Self::NoCapsule => "no_capsule",
            Self::CapsuleNotFinalized => "capsule_not_finalized",
            Self::Unreadable => "unreadable",
            Self::NoExposure => "no_exposure",
            Self::AmbiguousExposure => "ambiguous_exposure",
            Self::SkillRevisionMoved => "skill_revision_moved",
            Self::ForksDiverged => "forks_diverged",
            Self::ModelUnavailable => "model_unavailable",
            Self::Unfinished => "unfinished",
        }
    }

    /// Whether the reason holds for good: the pair is recorded unavailable
    /// and no later pass pays for it again. A model not served now, an
    /// anchor that does not resolve now and a pass that ran out of time are
    /// asked again.
    #[must_use]
    pub const fn lasting(self) -> bool {
        !matches!(
            self,
            Self::AnchorUnresolved | Self::ModelUnavailable | Self::Unfinished
        )
    }
}

/// Which side of the pair a fork is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkTreatment {
    /// The step as captured.
    WithSkill,
    /// The step with the skill's exposure removed, and nothing else changed.
    WithoutSkill,
}

/// One fork's durable receipt: what it regenerated, how, what it answered
/// and, once scored, whether it passed.
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
    /// BLAKE3 of the route prompt it was sent under, if any.
    pub route_prompt: Option<[u8; 32]>,
    /// The captured seed both forks carried.
    pub seed: Option<u64>,
    /// No seed was captured: both forks ran on identical captured settings.
    pub seed_unsupported: bool,
    /// The fork's answer, by its body ref.
    pub response: crate::compaction::output::OutputRef,
    pub response_path: String,
    /// The anchor both forks are scored against, by hash.
    pub anchor: [u8; 32],
    /// Whether it passed; `None` until scored.
    pub passed: Option<bool>,
    /// Unix seconds it was generated.
    pub generated_at: u64,
}

/// The model call a fork makes: the capsule's model alone, by its captured
/// route, never a fallback.
pub trait ContributionForkModel {
    /// `request`'s answer from `binding`'s model under `binding`'s route
    /// prompt and no other, stopping by `clock`; `None` when that model or
    /// that route prompt is not served now.
    ///
    /// # Errors
    ///
    /// A failed model call.
    fn generate(
        &self,
        request: &LlmRequest,
        binding: &CapsuleRungBinding,
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
}

/// The anchor's scorer, lent by the host.
pub trait ContributionForkScorer {
    /// The candidate's anchor as a frozen case and rubric, resolved before
    /// either fork is paid for; `None` when it resolves to none.
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn resolve(
        &self,
        vault: &Vault,
        candidate: &ContributionCandidate,
    ) -> Result<Option<ReplayAnchor>>;

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
/// its run's first step, each kept as a receipt as soon as it answers and
/// scored against one anchor. A fork already generated or scored is reused,
/// never paid for again. A reason that holds for good is recorded, so a
/// later pass returns it without paying.
///
/// # Errors
///
/// Storage errors, and a failed fork or scoring call.
pub fn run_contribution_forks(
    vault: &Vault,
    candidate: &ContributionCandidate,
    model: &dyn ContributionForkModel,
    scorer: &dyn ContributionForkScorer,
    clock: &RetrievalDeadline,
) -> Result<std::result::Result<ContributionForks, ContributionReplayUnavailable>> {
    let runner = Runner {
        vault,
        candidate,
        model,
        scorer,
        clock,
        pair: pair_digest(candidate),
    };
    let rows = fork_rows(vault, &runner.pair)?;
    if let Some(reason) = rows.unavailable {
        return Ok(Err(reason));
    }
    let outcome = match runner.prepare(&rows)? {
        Ok(prepared) => runner.run(&prepared, rows)?,
        Err(reason) => Err(reason),
    };
    if let Err(reason) = &outcome
        && reason.lasting()
    {
        put_unavailable(vault, &runner.pair, *reason)?;
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
    binding: CapsuleRungBinding,
    with_skill: LlmRequest,
    with_skill_hash: [u8; 32],
    without_skill: LlmRequest,
    without_skill_hash: [u8; 32],
    anchor: ReplayAnchor,
    anchor_hash: [u8; 32],
}

struct Runner<'a> {
    vault: &'a Vault,
    candidate: &'a ContributionCandidate,
    model: &'a dyn ContributionForkModel,
    scorer: &'a dyn ContributionForkScorer,
    clock: &'a RetrievalDeadline,
    pair: [u8; 32],
}

impl Runner<'_> {
    fn prepare(&self, rows: &ForkRows) -> Outcome<Prepared> {
        use ContributionReplayUnavailable as Unavailable;
        if !matches!(
            self.candidate.anchor,
            Anchor::HeldOut | Anchor::Audit { .. }
        ) {
            return Ok(Err(Unavailable::AnchorNotReplayable));
        }
        let Some(capsule) = first_step_capsule(self.vault, &self.candidate.attempt_receipt)? else {
            return Ok(Err(Unavailable::NoCapsule));
        };
        let Some(binding) = capsule.binding.clone() else {
            return Ok(Err(Unavailable::CapsuleNotFinalized));
        };
        let slots: Vec<&ExposureSlot> = capsule
            .exposures
            .iter()
            .filter(|slot| slot.skill == self.candidate.skill)
            .collect();
        let Some(first) = slots.first() else {
            return Ok(Err(Unavailable::NoExposure));
        };
        if slots.iter().any(|slot| slot.revision != first.revision) {
            return Ok(Err(Unavailable::AmbiguousExposure));
        }
        // The pair is admitted against the skill's current record: a skill
        // that moved on since the step cannot be recorded, and its old body
        // is never rebuilt from the new one.
        let current = self
            .vault
            .get_skill_record(&self.candidate.skill)?
            .map(|record| format!("{}@{}", record.skill_id, record.version));
        if current.as_deref() != Some(first.revision.as_str()) {
            return Ok(Err(Unavailable::SkillRevisionMoved));
        }
        let Some(with_skill) = capsule_request(self.vault, &capsule)? else {
            return Ok(Err(Unavailable::Unreadable));
        };
        let Some(without_skill) = without_exposure(&with_skill, &slots) else {
            return Ok(Err(Unavailable::Unreadable));
        };
        let Some(anchor) = self.scorer.resolve(self.vault, self.candidate)? else {
            return Ok(Err(Unavailable::AnchorUnresolved));
        };
        let anchor_hash = anchor_hash(self.candidate, &anchor)?;
        if [&rows.with_skill, &rows.without_skill]
            .into_iter()
            .flatten()
            .any(|fork| fork.anchor != anchor_hash || fork.capsule_request != capsule.request_hash)
        {
            return Ok(Err(Unavailable::ForksDiverged));
        }
        Ok(Ok(Prepared {
            with_skill_hash: request_hash(&with_skill)?,
            without_skill_hash: request_hash(&without_skill)?,
            capsule,
            binding,
            with_skill,
            without_skill,
            anchor,
            anchor_hash,
        }))
    }

    /// One paired draw in a fixed order, the fork with the skill first, then
    /// both scored.
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
        let with_skill = match self.scored(prepared, with_skill)? {
            Ok(fork) => fork,
            Err(reason) => return Ok(Err(reason)),
        };
        let without_skill = match self.scored(prepared, without_skill)? {
            Ok(fork) => fork,
            Err(reason) => return Ok(Err(reason)),
        };
        let (Some(with_passed), Some(without_passed)) = (with_skill.passed, without_skill.passed)
        else {
            return Ok(Err(ContributionReplayUnavailable::Unfinished));
        };
        Ok(Ok(ContributionForks {
            with_skill: ContributionFork {
                receipt: with_skill.receipt,
                passed: with_passed,
            },
            without_skill: ContributionFork {
                receipt: without_skill.receipt,
                passed: without_passed,
            },
        }))
    }

    /// The fork as stored, else generated now and kept before it is scored.
    fn generated(
        &self,
        prepared: &Prepared,
        stored: Option<ContributionForkReceipt>,
        treatment: ForkTreatment,
    ) -> Outcome<ContributionForkReceipt> {
        if let Some(fork) = stored {
            return Ok(Ok(fork));
        }
        if !self.clock.decision_may_start() {
            return Ok(Err(ContributionReplayUnavailable::Unfinished));
        }
        let (request, hash) = match treatment {
            ForkTreatment::WithSkill => (&prepared.with_skill, prepared.with_skill_hash),
            ForkTreatment::WithoutSkill => (&prepared.without_skill, prepared.without_skill_hash),
        };
        let Some(response) = self
            .model
            .generate(request, &prepared.binding, self.clock)?
        else {
            return Ok(Err(ContributionReplayUnavailable::ModelUnavailable));
        };
        let capsule = &prepared.capsule;
        let digest = fork_digest(&self.pair, capsule, treatment);
        let path = format!("replay/contribution/{digest}.response.json");
        let response_ref = store_fork_response(self.vault, capsule.run, path.clone(), &response)?;
        let fork = ContributionForkReceipt {
            receipt: format!("{FORK_RECEIPT_PREFIX}{digest}"),
            treatment,
            attempt: capsule.attempt,
            lease_generation: capsule.lease_generation,
            step: capsule.step,
            capsule_request: capsule.request_hash,
            request: hash,
            model: prepared.binding.model.clone(),
            route_prompt: prepared
                .binding
                .prompt
                .as_deref()
                .map(|prompt| *blake3::hash(prompt.as_bytes()).as_bytes()),
            seed: capsule.seed,
            seed_unsupported: capsule.seed.is_none(),
            response: response_ref,
            response_path: path,
            anchor: prepared.anchor_hash,
            passed: None,
            generated_at: crate::unix_seconds_now(),
        };
        put_fork(self.vault, &self.pair, &fork)?;
        Ok(Ok(fork))
    }

    /// The fork as scored, else scored now against the pair's anchor, its
    /// task the step's input without the exposure for both forks.
    fn scored(
        &self,
        prepared: &Prepared,
        mut fork: ContributionForkReceipt,
    ) -> Outcome<ContributionForkReceipt> {
        if fork.passed.is_some() {
            return Ok(Ok(fork));
        }
        let Some(response) = fork_response(self.vault, prepared.capsule.run, &fork)? else {
            return Ok(Err(ContributionReplayUnavailable::Unreadable));
        };
        let scored = ScoredFork {
            receipt: &fork.receipt,
            task: &prepared.without_skill,
            response: &response,
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
        fork.passed = Some(passed);
        put_fork(self.vault, &self.pair, &fork)?;
        Ok(Ok(fork))
    }
}

/// The first step's capsule of the run `attempt_receipt` names: the one of
/// its latest lease generation, whose answer the run kept.
fn first_step_capsule(vault: &Vault, attempt_receipt: &str) -> Result<Option<StepReplayCapsule>> {
    let Some(attempt) = receipt_attempt(attempt_receipt) else {
        return Ok(None);
    };
    Ok(step_replay_capsules(vault, attempt)?
        .into_iter()
        .filter(|capsule| capsule.step == FIRST_STEP)
        .max_by_key(|capsule| capsule.lease_generation))
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

/// The pair's key: the run, the skill and the axis, as the A side keys its
/// check.
fn pair_digest(candidate: &ContributionCandidate) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(candidate.attempt_receipt.as_bytes());
    hasher.update(&[0]);
    hasher.update(candidate.skill.as_bytes());
    hasher.update(&[0]);
    hasher.update(candidate.axis.as_bytes());
    *hasher.finalize().as_bytes()
}

/// A fork's id: the pair, the capsule and the treatment, hashed.
fn fork_digest(pair: &[u8; 32], capsule: &StepReplayCapsule, treatment: ForkTreatment) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pair);
    hasher.update(&capsule.request_hash);
    hasher.update(match treatment {
        ForkTreatment::WithSkill => b"with",
        ForkTreatment::WithoutSkill => b"sans",
    });
    bytes_to_hex_lower(hasher.finalize().as_bytes())
}

/// The anchor's identity: its kind, the outcome it settled, its axis, the
/// rubric and the scorer.
fn anchor_hash(candidate: &ContributionCandidate, anchor: &ReplayAnchor) -> Result<[u8; 32]> {
    let encode = |error: serde_json::Error| Error::InvalidConfig(format!("replay anchor: {error}"));
    let mut hasher = blake3::Hasher::new();
    hasher.update(&serde_json::to_vec(&candidate.anchor).map_err(encode)?);
    hasher.update(&[0]);
    hasher.update(candidate.outcome_receipt.as_bytes());
    hasher.update(&[0]);
    hasher.update(candidate.axis.as_bytes());
    hasher.update(&[0]);
    hasher.update(&serde_json::to_vec(&anchor.rubric).map_err(encode)?);
    hasher.update(&[0]);
    hasher.update(anchor.scorer.as_bytes());
    Ok(*hasher.finalize().as_bytes())
}
