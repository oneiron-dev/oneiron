//! An owner verdict's matched pair, judged by the owner (FIX 3609). The
//! pair is generated and, for an engine step, run like any other, in its one
//! evidence mode. No model scores it. One pending pair is kept in the pair's
//! fork rows instead: a blinded A/B mapping, both kept answers by their
//! refs, the candidate, its capsule and exposure revision, the frozen
//! criterion and, once asked, the ask that carries its question at its
//! revision. The owner is asked through an ordinary TASK ask
//! ([`crate::task_verb::ask_contribution_pair`]): a witnessed question TURN,
//! and the two answers as its context TURNs. A pending pair never
//! regenerates, never waits in a loop and never pays again.
//!
//! Only the owner's own counted word settles it, in the ask's settling
//! commit ([`settle_owner_pair_in_txn`]). That writer reads both kept
//! answers and the capsule again, unblinds the choice, scores both forks
//! with the owner's judgment and records the pair through the contribution
//! check's own door. A temporary subject fence, or a source admission that
//! lapsed (FIX 20607), keeps the accepted word for the Coach's next pass.
//! "Cannot judge", a fallback, a stale ask and an answer that no longer
//! reads score nothing and close the pair. The pair keeps the original
//! credit's anchor. The owner's word is each fork score's judge, never a
//! world outcome.
//!
//! The owner the pair asks is selected first, and each text it is shown is
//! read under that owner's own admission to the pair's source (FIX 20607).
//! The owner is asked again before the pair is shown. A selected owner row
//! is no credential: the owner reads as a question's own reader reads. The
//! pending pair keeps the Coach's admission to its steps as proof data. The
//! writer that records the owner's word asks it, and the owner's own
//! admission, again before it reads each held answer.

use serde::{Deserialize, Serialize};

use super::super::storage::{
    accept_owner_pair_in_txn, close_owner_pair_in_txn, judge_owner_pair_in_txn, owner_pair_in_txn,
    put_owner_pair,
};
use super::source_admission::PairSourceIdentity;
use super::{
    ContributionForkReceipt, ContributionReplayUnavailable as Unavailable, ExecutedForkView,
    ExecutedStepStatus, ForkEvidenceMode, ForkJudge, ForkScore, ForkScoring, ForkScoringIdentity,
    ForkTreatment, Outcome, PairReader, Prepared, Runner,
};
use crate::compaction::output::OutputRef;
use crate::dreamer_runner::maintenance::ContributionForks;
use crate::learning::Anchor;
use crate::skill_attribution::{
    CheckedEdge, ContributionFork, ContributionPair, ContributionTarget,
};
use crate::{ContentPart, EntityId, Error, LlmMessageRole, LlmRequest, LlmResponse, Result, Vault};

/// The owner's word that scored both forks of a pair (FIX 3609): the ask
/// that carried the pair's question, the counted word that settled it, and
/// the question digest and revision it answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerJudgment {
    pub ask: EntityId,
    pub word: EntityId,
    pub question_digest: [u8; 32],
    pub revision: u64,
    /// Unix seconds the ask settled.
    pub at: u64,
}

/// What the owner may answer about a pair's two shown answers, by stable
/// option id. Each answer is judged on its own against the one criterion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerPairChoice {
    AOnly,
    BOnly,
    Both,
    Neither,
    CannotJudge,
}

impl OwnerPairChoice {
    pub(crate) const ALL: [Self; 5] = [
        Self::AOnly,
        Self::BOnly,
        Self::Both,
        Self::Neither,
        Self::CannotJudge,
    ];

    /// Its stable option id.
    pub(crate) const fn option(self) -> &'static str {
        match self {
            Self::AOnly => "a_only",
            Self::BOnly => "b_only",
            Self::Both => "both",
            Self::Neither => "neither",
            Self::CannotJudge => "cannot_judge",
        }
    }

    /// The label its option shows.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::AOnly => "Only answer A passes",
            Self::BOnly => "Only answer B passes",
            Self::Both => "Both answers pass",
            Self::Neither => "Neither answer passes",
            Self::CannotJudge => "I cannot judge these answers",
        }
    }

    /// The choice an option id names.
    pub(crate) fn of_option(option: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|choice| choice.option() == option)
    }

    /// Whether answer A, then answer B, passed; `None` for "cannot judge".
    const fn shown(self) -> Option<(bool, bool)> {
        match self {
            Self::AOnly => Some((true, false)),
            Self::BOnly => Some((false, true)),
            Self::Both => Some((true, true)),
            Self::Neither => Some((false, false)),
            Self::CannotJudge => None,
        }
    }
}

/// One fork as its pending pair shows it: its receipt and its kept answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwnerPairOutput {
    pub(crate) receipt: String,
    pub(crate) response: OutputRef,
}

impl OwnerPairOutput {
    fn of(fork: &ContributionForkReceipt) -> Self {
        Self {
            receipt: fork.receipt.clone(),
            response: fork.response,
        }
    }

    fn shows(&self, fork: &ContributionForkReceipt) -> bool {
        self.receipt == fork.receipt && self.response == fork.response
    }
}

/// One presented part of a pair's question: the TURN and MESSAGE ids it is
/// witnessed under, reserved before the witness, and the digest of the
/// exact text it shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwnerPairPart {
    pub(crate) turn: EntityId,
    pub(crate) message: EntityId,
    pub(crate) content: [u8; 32],
}

/// Where a pair's question is witnessed: the owner's conversation with the
/// Coach, the question, answer A and answer B, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwnerPairPresentation {
    pub(crate) conversation: EntityId,
    pub(crate) question: OwnerPairPart,
    pub(crate) shown_a: OwnerPairPart,
    pub(crate) shown_b: OwnerPairPart,
    pub(crate) at: u64,
}

/// Where a pending pair's question stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OwnerPairRoute {
    /// Kept, with its ids reserved; no ask carries it yet.
    Reserved,
    /// The ask that carries it, at the revision and question digest it was
    /// admitted with.
    Asked {
        ask: EntityId,
        revision: u64,
        question_digest: [u8; 32],
    },
    /// The owner's word was admitted, but a temporary subject fence, or a
    /// source admission that lapsed (FIX 20607), kept it from scoring the
    /// forks. Its judgment carries the ask and time.
    Accepted {
        with_passed: bool,
        without_passed: bool,
        judgment: OwnerJudgment,
    },
    /// The owner's word scored both forks.
    Judged(OwnerJudgment),
    /// Its ask settled with no score: "cannot judge", no owner's word, a
    /// fallback, a stale ask or an answer that no longer reads.
    Closed { ask: EntityId, at: u64 },
}

/// One owner-judged pair while it waits for, or after, the owner's word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwnerPair {
    /// The opaque id its question and ask name; no subject derives it.
    pub(crate) handle: EntityId,
    /// The vault owner it asks.
    pub(crate) owner: EntityId,
    /// The fork shown as answer A; the other is answer B.
    pub(crate) shown_first: ForkTreatment,
    pub(crate) with_skill: OwnerPairOutput,
    pub(crate) without_skill: OwnerPairOutput,
    /// The capsule both forks regenerated, its run and the target's
    /// revision as its step saw it.
    pub(crate) run: EntityId,
    pub(crate) attempt: EntityId,
    pub(crate) lease_generation: u32,
    pub(crate) step: u64,
    pub(crate) capsule_request: [u8; 32],
    pub(crate) exposure_revision: String,
    /// The Coach's admission to every step both forks were made from, as
    /// proof data (FIX 20607). The writer that records the owner's word
    /// asks it again, with the owner's own admission, before it reads each
    /// held answer.
    pub(crate) source: PairSourceIdentity,
    /// The candidate: its run, scoring skill, target and outcome.
    pub(crate) attempt_receipt: String,
    pub(crate) skill: EntityId,
    pub(crate) target: ContributionTarget,
    pub(crate) scoring: ForkScoring,
    /// The anchor both forks are scored against, as their receipts keep it.
    pub(crate) anchor: [u8; 32],
    pub(crate) anchor_scoring: ForkScoringIdentity,
    /// The pair's one evidence mode, the one the owner reads it in.
    pub(crate) mode: ForkEvidenceMode,
    /// The frozen criterion, as canonical JSON.
    pub(crate) criterion: String,
    pub(crate) presentation: OwnerPairPresentation,
    pub(crate) route: OwnerPairRoute,
}

impl OwnerPair {
    /// Whether it shows exactly these two kept forks.
    fn names(
        &self,
        with_skill: &ContributionForkReceipt,
        without_skill: &ContributionForkReceipt,
    ) -> bool {
        self.with_skill.shows(with_skill) && self.without_skill.shows(without_skill)
    }

    /// Whether `judgment` judged it, on exactly these two kept forks.
    pub(super) fn judged(
        &self,
        judgment: OwnerJudgment,
        with_skill: &ContributionForkReceipt,
        without_skill: &ContributionForkReceipt,
    ) -> bool {
        self.route == OwnerPairRoute::Judged(judgment) && self.names(with_skill, without_skill)
    }

    /// `choice` unblinded: whether the fork with the target passed, then
    /// the fork without it; `None` for "cannot judge".
    fn unblind(&self, choice: OwnerPairChoice) -> Option<(bool, bool)> {
        let (a, b) = choice.shown()?;
        Some(match self.shown_first {
            ForkTreatment::WithSkill => (a, b),
            ForkTreatment::WithoutSkill => (b, a),
        })
    }
}

/// What the owner reads of a pair: the question, with its criterion and the
/// task, then answer A and answer B as shown.
pub(crate) struct OwnerPairTexts {
    pub(crate) question: String,
    pub(crate) shown_a: String,
    pub(crate) shown_b: String,
}

/// The digest a presented part keeps of the text it shows.
fn text_digest(text: &str) -> [u8; 32] {
    *blake3::hash(text.as_bytes()).as_bytes()
}

impl OwnerPairTexts {
    /// Whether these are the exact texts `presentation` reserved.
    fn match_presentation(&self, presentation: &OwnerPairPresentation) -> bool {
        text_digest(&self.question) == presentation.question.content
            && text_digest(&self.shown_a) == presentation.shown_a.content
            && text_digest(&self.shown_b) == presentation.shown_b.content
    }
}

/// What the ask's settling commit hands one pair: the ask, the revision and
/// question digest it settled at, the live owner whose proof came with the
/// settling word, and that word, when it was a counted human answer: the
/// option it named and the judgment it is kept as.
pub(crate) struct OwnerPairAnswer {
    pub(crate) ask: EntityId,
    pub(crate) revision: u64,
    pub(crate) question_digest: [u8; 32],
    pub(crate) owner: Option<EntityId>,
    pub(crate) word: Option<(OwnerPairChoice, OwnerJudgment)>,
}

/// Settles the pending pair `handle` names from its ask's settlement, in
/// that settling transaction. Only its own ask, at the revision and question
/// digest it was admitted with, under the proof of the owner it asked,
/// scores it: both forks get the unblinded passes and the owner's judgment,
/// and the pair is recorded as a contribution check in this same writer.
/// A temporary subject fence, or a source admission that lapsed (FIX
/// 20607), keeps that accepted judgment for a later Coach pass. Every other
/// settlement closes it unscored. A pair already accepted, judged or
/// closed, or no longer kept, is left as it is.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn settle_owner_pair_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    handle: EntityId,
    answer: &OwnerPairAnswer,
    now: u64,
) -> Result<()> {
    let Some((key, pair)) = owner_pair_in_txn(vault, txn, handle)? else {
        return Ok(());
    };
    let OwnerPairRoute::Asked {
        ask,
        revision,
        question_digest,
    } = pair.route
    else {
        return Ok(());
    };
    if ask != answer.ask {
        return Ok(());
    }
    let asked = answer.revision == revision
        && answer.question_digest == question_digest
        && answer.owner == Some(pair.owner);
    let verdict = answer
        .word
        .filter(|_| asked)
        .and_then(|(choice, judgment)| Some((pair.unblind(choice)?, judgment)));
    let Some(((with_passed, without_passed), judgment)) = verdict else {
        return close_owner_pair_in_txn(vault, txn, &key, ask, now);
    };
    // An accepted word survives only a temporary subject fence or a lapsed
    // source admission. The ask is already settled, so the Coach retries
    // from the pair itself.
    let judged =
        match judge_owner_pair_in_txn(vault, txn, &key, with_passed, without_passed, judgment)? {
            Ok(judged) => judged,
            Err(Unavailable::Unfinished) => {
                return accept_owner_pair_in_txn(
                    vault,
                    txn,
                    &key,
                    with_passed,
                    without_passed,
                    judgment,
                );
            }
            Err(reason) => {
                tracing::debug!(
                    reason = reason.as_str(),
                    "an owner-judged pair closes unscored"
                );
                return close_owner_pair_in_txn(vault, txn, &key, ask, now);
            }
        };
    record_owner_pair_in_txn(vault, txn, &judged, with_passed, without_passed, now)
}

/// Records both forks through the contribution check's own door, in the
/// writer that judged them. A refused check keeps its scores for the next
/// Coach pass, as an ask's immediate settlement does.
fn record_owner_pair_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    judged: &OwnerPair,
    with_passed: bool,
    without_passed: bool,
    now: u64,
) -> Result<()> {
    let contribution = ContributionPair {
        attempt_receipt: judged.attempt_receipt.clone(),
        outcome_receipt: judged.scoring.outcome_receipt.clone(),
        skill: Some(judged.skill),
        edge: match judged.target {
            ContributionTarget::LoadedSkill(_) => None,
            ContributionTarget::UsedEdge { derived, source } => Some(CheckedEdge {
                derived: Some(derived),
                source: Some(source),
            }),
        },
        axis: judged.scoring.axis.clone(),
        goal_revision: judged.scoring.goal_revision.clone(),
        anchor: Anchor::OwnerVerdict,
        with_skill: ContributionFork {
            receipt: judged.with_skill.receipt.clone(),
            passed: with_passed,
        },
        without_skill: ContributionFork {
            receipt: judged.without_skill.receipt.clone(),
            passed: without_passed,
        },
        at: now,
    };
    // The check's own door, in this writer: a pair it refuses keeps its
    // scores, and the Coach's next pass submits it again.
    match crate::skill_attribution::record_contribution_pair_in_txn(vault, txn, &contribution, now)
    {
        Ok(_) => Ok(()),
        Err(Error::InvalidClaimBody(reason)) => {
            tracing::warn!(reason, "an owner-judged contribution pair was not recorded");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// The pair as the owner's word scored it, when both forks carry that one
/// word in the pair's mode; else the pair diverged.
fn owner_scored(
    with_skill: &ContributionForkReceipt,
    without_skill: &ContributionForkReceipt,
    mode: ForkEvidenceMode,
) -> std::result::Result<ContributionForks, Unavailable> {
    let by_owner = |score: Option<ForkScore>| {
        score.filter(|score| score.mode == mode && matches!(score.judge, ForkJudge::Owner(_)))
    };
    match (by_owner(with_skill.score), by_owner(without_skill.score)) {
        (Some(with_score), Some(without_score)) if with_score.judge == without_score.judge => {
            Ok(ContributionForks {
                with_skill: ContributionFork {
                    receipt: with_skill.receipt.clone(),
                    passed: with_score.passed,
                },
                without_skill: ContributionFork {
                    receipt: without_skill.receipt.clone(),
                    passed: without_score.passed,
                },
            })
        }
        _ => Err(Unavailable::ForksDiverged),
    }
}

impl Runner<'_> {
    /// An owner verdict's pair once both forks are kept and their programs
    /// settled: the pair as the owner's word scored it, else its pending
    /// pair, kept now on the first pass and asked while no ask carries it.
    /// A pending pair reads its kept answers again to ask, and pays for
    /// nothing; it is `Unfinished` until the owner's word lands. The owner
    /// it asks is admitted again before it is shown the pair (FIX 20607).
    pub(super) fn owner_judged(
        &self,
        prepared: &Prepared,
        pending: Option<OwnerPair>,
        with_skill: ContributionForkReceipt,
        without_skill: ContributionForkReceipt,
        mode: ForkEvidenceMode,
    ) -> Outcome<ContributionForks> {
        if with_skill.score.is_some() || without_skill.score.is_some() {
            return Ok(owner_scored(&with_skill, &without_skill, mode));
        }
        let pair = match pending {
            Some(pair) if pair.names(&with_skill, &without_skill) && pair.mode == mode => pair,
            Some(_) => return Ok(Err(Unavailable::ForksDiverged)),
            None => match self.reserve_owner_pair(prepared, &with_skill, &without_skill, mode)? {
                Ok(pair) => pair,
                Err(reason) => return Ok(Err(reason)),
            },
        };
        if matches!(pair.route, OwnerPairRoute::Accepted { .. }) {
            return self.retry_owner_pair(pair.handle);
        }
        if pair.route == OwnerPairRoute::Reserved {
            let texts = match self.owner_pair_texts(
                prepared,
                &pair.criterion,
                pair.shown_first,
                [&with_skill, &without_skill],
                mode,
                pair.owner,
            )? {
                Ok(texts) => texts,
                Err(reason) => return Ok(Err(reason)),
            };
            // Texts that no longer read as reserved are no question to ask.
            if !texts.match_presentation(&pair.presentation) {
                return Ok(Err(Unavailable::Unreadable));
            }
            let owner = PairReader::Consumer {
                owner: Some(pair.owner),
            };
            if !prepared.source.admits_now(self.vault, owner)? {
                return Ok(Err(Unavailable::Unfinished));
            }
            crate::task_verb::ask_contribution_pair(self.vault, &pair, &texts);
        }
        Ok(Err(Unavailable::Unfinished))
    }

    /// Retries an already admitted owner's word, once, under the same
    /// capsule, provenance and held-answer checks as immediate settlement.
    /// The pair's kept source admission is asked again too (FIX 20607).
    fn retry_owner_pair(&self, handle: EntityId) -> Outcome<ContributionForks> {
        let now = self.vault.store.clock.now_recorded_at();
        self.vault.with_write_txn_grouped(|txn| {
            let Some((key, pair)) = owner_pair_in_txn(self.vault, txn, handle)? else {
                return Ok(Err(Unavailable::Unfinished));
            };
            let OwnerPairRoute::Accepted {
                with_passed,
                without_passed,
                judgment,
            } = pair.route
            else {
                return Ok(Err(Unavailable::Unfinished));
            };
            let judged = match judge_owner_pair_in_txn(
                self.vault,
                txn,
                &key,
                with_passed,
                without_passed,
                judgment,
            )? {
                Ok(judged) => judged,
                Err(Unavailable::Unfinished) => return Ok(Err(Unavailable::Unfinished)),
                Err(reason) => {
                    tracing::debug!(
                        reason = reason.as_str(),
                        "an owner-judged pair closes unscored"
                    );
                    close_owner_pair_in_txn(self.vault, txn, &key, judgment.ask, now)?;
                    return Ok(Err(Unavailable::Unfinished));
                }
            };
            record_owner_pair_in_txn(self.vault, txn, &judged, with_passed, without_passed, now)?;
            Ok(Ok(ContributionForks {
                with_skill: ContributionFork {
                    receipt: judged.with_skill.receipt,
                    passed: with_passed,
                },
                without_skill: ContributionFork {
                    receipt: judged.without_skill.receipt,
                    passed: without_passed,
                },
            }))
        })
    }

    /// Keeps this pair's pending pair, once: a fresh blinded mapping, the
    /// owner it asks, its presentation's ids and texts' digests, the frozen
    /// criterion and the Coach's admission to every step (FIX 20607). A
    /// pair another pass kept first is returned as kept. A pair its writer
    /// does not keep is unavailable for that writer's own reason (FIX
    /// 6256). The owner is selected before any text is read, and the texts
    /// are read under that owner's admission (FIX 20607).
    fn reserve_owner_pair(
        &self,
        prepared: &Prepared,
        with_skill: &ContributionForkReceipt,
        without_skill: &ContributionForkReceipt,
        mode: ForkEvidenceMode,
    ) -> Outcome<OwnerPair> {
        if !self.clock.decision_may_start() {
            return Ok(Err(Unavailable::Unfinished));
        }
        let clock = &self.vault.store.clock;
        let criterion = serde_json::to_string(&prepared.anchor.rubric)
            .map_err(|error| Error::InvalidConfig(format!("owner pair criterion: {error}")))?;
        // The mapping is drawn fresh, so neither answer's place tells which
        // fork had the target.
        let shown_first = if blake3::hash(&clock.ulid()?).as_bytes()[0] & 1 == 0 {
            ForkTreatment::WithSkill
        } else {
            ForkTreatment::WithoutSkill
        };
        let (owner, conversation) = {
            let txn = self.vault.store.env.read_txn()?;
            let Some(owner) = crate::policy_model::owners_in_txn(self.vault, &txn)?
                .first()
                .copied()
            else {
                return Ok(Err(Unavailable::Unfinished));
            };
            let conversation =
                crate::task_verb::coach_owner_conversation_in(self.vault, &txn, &owner)?;
            (owner, conversation)
        };
        let texts = match self.owner_pair_texts(
            prepared,
            &criterion,
            shown_first,
            [with_skill, without_skill],
            mode,
            owner,
        )? {
            Ok(texts) => texts,
            Err(reason) => return Ok(Err(reason)),
        };
        let part = |text: &str| -> Result<OwnerPairPart> {
            Ok(OwnerPairPart {
                turn: clock.entity_id()?,
                message: clock.entity_id()?,
                content: text_digest(text),
            })
        };
        let presentation = OwnerPairPresentation {
            conversation: match conversation {
                Some(conversation) => conversation,
                None => clock.entity_id()?,
            },
            question: part(&texts.question)?,
            shown_a: part(&texts.shown_a)?,
            shown_b: part(&texts.shown_b)?,
            at: clock.now_recorded_at(),
        };
        let capsule = &prepared.capsule;
        let pair = OwnerPair {
            handle: clock.entity_id()?,
            owner,
            shown_first,
            with_skill: OwnerPairOutput::of(with_skill),
            without_skill: OwnerPairOutput::of(without_skill),
            run: capsule.run,
            attempt: capsule.attempt,
            lease_generation: capsule.lease_generation,
            step: capsule.step,
            capsule_request: capsule.request_hash,
            exposure_revision: prepared.exposure_revision.clone(),
            source: prepared.source.identity(),
            attempt_receipt: self.candidate.attempt_receipt.clone(),
            skill: self.candidate.skill,
            target: self.candidate.target,
            scoring: ForkScoring::of(self.candidate),
            anchor: prepared.anchor_hash,
            anchor_scoring: prepared.anchor_scoring,
            mode,
            criterion,
            presentation,
            route: OwnerPairRoute::Reserved,
        };
        put_owner_pair(self.vault, &self.pair, &self.provenance, &pair)
    }

    /// The texts `owner` reads, both answers read again from the bodies the
    /// run owns under `owner`'s admission (FIX 20607) and, in the `Executed`
    /// mode, with what each program did.
    fn owner_pair_texts(
        &self,
        prepared: &Prepared,
        criterion: &str,
        shown_first: ForkTreatment,
        [with_skill, without_skill]: [&ContributionForkReceipt; 2],
        mode: ForkEvidenceMode,
        owner: EntityId,
    ) -> Outcome<OwnerPairTexts> {
        let (first, second) = match shown_first {
            ForkTreatment::WithSkill => (with_skill, without_skill),
            ForkTreatment::WithoutSkill => (without_skill, with_skill),
        };
        let reader = PairReader::Consumer { owner: Some(owner) };
        let shown_a = match self.shown_answer(prepared, first, mode, reader)? {
            Ok(text) => text,
            Err(reason) => return Ok(Err(reason)),
        };
        let shown_b = match self.shown_answer(prepared, second, mode, reader)? {
            Ok(text) => text,
            Err(reason) => return Ok(Err(reason)),
        };
        Ok(Ok(OwnerPairTexts {
            question: question_text(criterion, &task_text(&prepared.without_skill)),
            shown_a: format!("Answer A\n\n{shown_a}"),
            shown_b: format!("Answer B\n\n{shown_b}"),
        }))
    }

    /// One fork's answer as the owner reads it, whole, read for `reader`,
    /// the owner the pair asks (FIX 20607).
    fn shown_answer(
        &self,
        prepared: &Prepared,
        fork: &ContributionForkReceipt,
        mode: ForkEvidenceMode,
        reader: PairReader,
    ) -> Outcome<String> {
        let response = match self.read_response(prepared, fork, reader)? {
            Ok(response) => response,
            Err(reason) => return Ok(Err(reason)),
        };
        let executed = match self.executed_view(prepared, fork, mode, reader)? {
            Ok(executed) => executed,
            Err(reason) => return Ok(Err(reason)),
        };
        let mut text = answer_text(&response);
        if let Some(executed) = &executed {
            text.push_str("\n\n");
            text.push_str(&executed_text(executed));
        }
        Ok(Ok(text))
    }
}

/// The question: the criterion both answers are judged against, and the
/// task both answered, with no word of which answer had the target.
fn question_text(criterion: &str, task: &str) -> String {
    format!(
        "The Coach asks you to judge two answers to one task. They follow as answer A and \
         answer B, in no set order. Judge each answer on its own against this criterion, and \
         say which pass.\n\nCriterion: {criterion}\n\nTask:\n{task}"
    )
}

/// What the step asked: its non-system messages' text, in order, whole.
fn task_text(task: &LlmRequest) -> String {
    task.messages
        .iter()
        .filter(|message| message.role != LlmMessageRole::System)
        .flat_map(|message| &message.content)
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// An answer's text, whole.
fn answer_text(response: &LlmResponse) -> String {
    response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// What an answer's program did when run, in the `Executed` mode: how its
/// step ended and each output it left, whole.
fn executed_text(executed: &ExecutedForkView) -> String {
    let ended = match &executed.status {
        ExecutedStepStatus::StepComplete { done: true } => "ran to the step's end and finished",
        ExecutedStepStatus::StepComplete { done: false } => "ran to the step's end",
        ExecutedStepStatus::Failed { .. } => "failed",
    };
    let mut text = format!("When its program ran, it {ended}.");
    if let ExecutedStepStatus::Failed { kind } = &executed.status {
        text.push_str(&format!(" Failure: {kind}."));
    }
    for output in &executed.outputs {
        let state = if output.complete {
            "complete"
        } else {
            "incomplete"
        };
        let bytes = String::from_utf8_lossy(&output.bytes);
        text.push_str(&format!("\n\nOutput {} ({state}):\n{bytes}", output.path));
    }
    text
}
