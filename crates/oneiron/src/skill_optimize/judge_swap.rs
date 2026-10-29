//! The judge-swap shadow ladder (ARCH-0053, ARCH-0079 #model-swaps, OF-184).
//! The Coach keeps the incumbent: the judge whose answers the host's kept
//! judgments hold. While the incumbent still answers, the Coach retests it on
//! its own kept cases, so its retest noise is measured before a swap needs
//! it. When another judge answers, that judge scores the incumbent's kept
//! cases again. Each retest keeps both of the incumbent's answers beside its
//! marker: a flip, one case answered two ways, is the judge's own uncertainty,
//! and the Coach's calibration pass puts it to a person as an A/B ask. It
//! takes over only when its divergence, grouped by source
//! family, stays within the incumbent's noise or the owner's pinned rate; its
//! overlap scores then fit the conversion that carries the incumbent's scored
//! history onto its scale. Too few cases or no measured noise reads unknown,
//! and the incumbent holds.
//!
//! When the divergence is known and wider than that threshold, only the
//! disagreements count. The owner's hand-test pick decides a case first, a
//! settled outcome next, and the vault's tie-breaker policy the rest: a third
//! judge from another model family, or for a floor axis the incumbent holding
//! until an anchor speaks. A pick on a skill's case is a label in that skill's
//! judge anchor. The outcome a case settles on follows the question it asked:
//! held-out wins for a score, the axis's anchored observations for a goal
//! axis, the sealed audit for an honesty finding, and the responsible role's
//! answer for a tradeoff. Nothing settles a blind preference or a structural
//! or contrastive audit: only a pick decides those. A swap that later picks
//! or outcomes contradict re-pins back. No original answer is
//! rescored or rewritten, and every swap and every re-pin reaches the vault's
//! owners.
use std::borrow::Borrow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::learning::{
    DivergenceCase, LearningCell, LearningPredicate, Observation, Retest, RetestScore,
    TakeoverVerdict, judge_takeover_verdict, learning_estimate, record_judge_conversion,
    record_retest, withdraw_judge_conversion,
};
use crate::llm::decision::DecisionAnswer;
use crate::self_heal::audit::SealCheckKind;
use crate::skill_optimize::labels::JUDGE_SKILL_ID;
use crate::skill_optimize::{
    GoalAxisKind, JudgeLabel, SkillEditDisposition, TradeoffRung, judge_label_anchor,
    skill_edit_goal, skill_edit_verdicts_for_proposal,
};
use crate::{EntityId, Error, Result, Vault};

mod anchors;
mod asks;
mod shadow;
mod state;

use self::anchors::{anchor, anchored, disagreement, judged_skill, sided, tie_break};
use self::asks::{label_campaign, label_side, retest_campaign};
use self::state::{load, noise_cell, notify_owners, save, scorer};
use super::labels;

pub use self::asks::pick_judge_swap_case;
pub(crate) use self::asks::{
    judge_retest_flips, label_judge, retest_flip_ask, swap_case_ask, swap_case_retest_picked,
};
pub(crate) use self::shadow::run_judge_swap;

/// Kept judgments one pass reads, newest first.
const KEPT_CASES: usize = 256;
/// Incumbent cases one pass retests; each is a paid call.
const RETESTS: usize = 8;
/// Incumbent cases one pass has a new judge score; each new one is a paid
/// call, and a scored case is kept, so a later pass pays only for new cases.
const SHADOW_CASES: usize = 64;
/// Cases each source family needs before its divergence is known.
const MIN_CASES_PER_FAMILY: u32 = 8;
/// Two scores this close agree.
const SCORE_AGREEMENT: f64 = 0.1;
/// The retest-noise axis: how often the judge disagrees with itself.
const NOISE_AXIS: &str = "agreement";
/// One-sided 95% normal quantile, as the takeover ladder reads divergence.
const WILSON_Z: f64 = 1.645;
/// Why a pass recorded no retest noise: the judge SKILL it is kept about is
/// absent (FIX 8079).
const NOISE_SUBJECT_ABSENT: &str = "judge_swap.noise_subject_absent";

const INCUMBENT_KEY: &str = "skill:judge:v1:swap:incumbent";
const POLICY_KEY: &str = "skill:judge:v1:swap:policy";
const RETESTED_PREFIX: &str = "skill:judge:v1:swap:retested:";
const SHADOW_PREFIX: &str = "skill:judge:v1:swap:shadow:";
const TIE_PREFIX: &str = "skill:judge:v1:swap:tie:";
const PICK_PREFIX: &str = "skill:judge:v1:swap:pick:";
const RECEIPT_PREFIX: &str = "skill:judge:v1:swap:receipt:";

/// Producer of a swap's or a re-pin's notice in each owner's inbox.
pub const JUDGE_SWAP_NOTIFICATION_PRODUCER: &str = "coach.judge_swap";

/// One kept judgment: a frozen question on a frozen state, as its judge
/// answered it.
#[derive(Debug, Clone, PartialEq)]
pub struct JudgeShadowCase {
    /// Stable id of the kept judgment, at most 128 bytes.
    pub case_ref: String,
    /// Where the case came from; takeover reads divergence per family.
    pub source_family: String,
    /// The judge that answered it, `model@version`.
    pub judge: String,
    pub answer: DecisionAnswer,
    /// The wording key it was asked under (`score`, `honesty`,
    /// `axis.<name>`, ...; see [`crate::skill_optimize::judgment_kind`]); the
    /// outcome that settles it is read by it. `None` when the host can't tell.
    pub kind: Option<String>,
    /// The typed question, as hex, and when it was asked: a hand-test finds
    /// the case in the host's journal by them.
    pub question: String,
    pub asked_at: u64,
    /// The frozen state the question was asked on. Settled outcomes and floor
    /// axes are read from it.
    pub state: Value,
}

/// A judge's answer to a kept case, asked again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeShadowAnswer {
    /// The judge that answered, `model@version`.
    pub judge: String,
    pub answer: DecisionAnswer,
}

/// One retest, kept under its case's marker: the incumbent's kept answer and
/// its answer when asked again. Two answers that do not agree are a flip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct JudgeRetestMark {
    pub(crate) case_ref: String,
    /// The skill the case judged, as hex: a pick on a flip is a label in that
    /// skill's judge anchor.
    pub(crate) skill: Option<String>,
    pub(crate) kept: JudgeShadowAnswer,
    pub(crate) rerun: JudgeShadowAnswer,
    pub(crate) agreed: bool,
    pub(crate) at: u64,
}

/// What the host lends the Coach: its kept judgments, the judge that answers
/// now, and a tie-breaking judge when it has one.
pub trait JudgeShadowHost {
    /// Kept judgments, newest first, at most `limit`, abstentions left out.
    ///
    /// # Errors
    ///
    /// Host-defined.
    fn kept_cases(&self, limit: usize) -> Result<Vec<JudgeShadowCase>>;

    /// The answering judge's answer to `case`'s question on its state;
    /// `None` when nothing answered or the answer abstained.
    ///
    /// # Errors
    ///
    /// Host-defined.
    fn rescore(&self, case: &JudgeShadowCase) -> Result<Option<JudgeShadowAnswer>>;

    /// A third judge's answer to `case`, from a model family neither
    /// `incumbent` nor `candidate` belongs to; `None` when no such judge
    /// answers.
    ///
    /// # Errors
    ///
    /// Host-defined.
    fn tie_break(
        &self,
        _case: &JudgeShadowCase,
        _incumbent: &str,
        _candidate: &str,
    ) -> Result<Option<JudgeShadowAnswer>> {
        Ok(None)
    }
}

/// The judge whose scale the kept history reads on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeIncumbent {
    pub judge: String,
    pub since: u64,
    /// The judge this one took over from: later picks and outcomes on the
    /// takeover's disagreements can still re-pin it back.
    pub previous: Option<String>,
    /// The takeover's receipt, 32 hex.
    pub takeover: Option<String>,
}

/// Who settles a disagreement that no pick and no settled outcome decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JudgeTieBreaker {
    /// A third judge from another model family.
    ThirdFamily,
    /// Nobody: the incumbent holds until a pick or an outcome arrives.
    IncumbentHolds,
}

/// The vault's judge-swap policy, which the owner sets. Each field the owner
/// leaves out takes canon's default (ARCH-0079 #model-swaps, ARCH-0003).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct JudgeSwapPolicy {
    /// Disagreements on a case of any other axis. Default: a third judge.
    pub tie_breaker: JudgeTieBreaker,
    /// Disagreements on a floor-axis case. Default: the incumbent holds.
    pub floor_tie_breaker: JudgeTieBreaker,
    /// A fixed divergence rate in `[0, 1]` the takeover is read against, in
    /// place of the incumbent's retest noise. Default: none.
    pub pinned_divergence: Option<f64>,
    /// Every swap asks the owners to rate its disagreements, rather than
    /// telling them. Default: off.
    pub hands_on: bool,
}

impl Default for JudgeSwapPolicy {
    fn default() -> Self {
        Self {
            tie_breaker: JudgeTieBreaker::ThirdFamily,
            floor_tie_breaker: JudgeTieBreaker::IncumbentHolds,
            pinned_divergence: None,
            hands_on: false,
        }
    }
}

/// What decided one disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeSwapSettledBy {
    /// The owner's hand-test pick.
    Pick,
    /// The held-out receipts' settled outcome.
    Outcome,
    /// The third judge.
    TieBreaker,
    /// Nothing yet: the case is open.
    Open,
}

/// Where a disagreement's settled outcome is read, by the question it asked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JudgeOutcomeLink {
    /// A whole-skill or task-success score: the share of these held-out
    /// receipts the skill won.
    HeldOut {
        skill: String,
        receipts: Vec<String>,
    },
    /// A named or live goal axis: the share of these receipts whose anchored
    /// observation on the axis succeeded, measured under the goal revision
    /// the question was asked under.
    Axis {
        skill: String,
        axis: String,
        receipts: Vec<String>,
        /// The goal revision frozen with the question; `None` when it was
        /// asked under no goal.
        goal_revision: Option<String>,
    },
    /// An honesty finding: whether the run's sealed audit found a flaw its
    /// confession hid.
    Audit { receipt: String },
    /// A tradeoff call: the responsible person's or role's answer to the ask
    /// on exactly this question.
    Tradeoff { proposal: String, digest: String },
    /// A blind preference: the owner's pick between exactly this pair's two
    /// responses.
    ResponsePair { pair_ref: String },
}

/// One case the two judges answered differently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeSwapDisagreement {
    pub case_ref: String,
    /// The typed question, as hex, its wording key, and when it was asked.
    pub question: String,
    pub kind: Option<String>,
    pub asked_at: u64,
    pub source_family: String,
    /// The case judged a floor axis.
    pub floor: bool,
    /// The skill the case judged, as hex: a pick on it is a label in that
    /// skill's judge anchor.
    pub skill: Option<String>,
    /// Each judge's answer, the incumbent's first.
    pub answers: Vec<JudgeShadowAnswer>,
    /// Where the settled outcome is read; `None` when the case's question
    /// has none.
    pub outcome_link: Option<JudgeOutcomeLink>,
    /// The settled outcome, as an answer to the case's question, once it
    /// settled.
    pub outcome: Option<DecisionAnswer>,
    /// The third judge's answer, when the tie-breaker asked one.
    pub tie_breaker: Option<JudgeShadowAnswer>,
    /// The judge whose answer the case sided with; `None` while open.
    pub sided_with: Option<String>,
    pub settled_by: JudgeSwapSettledBy,
}

/// One shadow pass's ruling, or a re-pin, kept whatever it found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeSwapReceipt {
    /// The receipt's id, 32 hex: a hand-test pick names it.
    pub id: String,
    pub from_judge: String,
    pub to_judge: String,
    /// `take_over`, `hold`, `unknown` or `re_pin`.
    pub verdict: String,
    /// The disagreements decided the verdict: the divergence was known and
    /// wider than the threshold.
    pub arbitrated: bool,
    pub cases: u32,
    pub diverged: u32,
    pub families: u32,
    /// The threshold in force: `retest_noise` or `owner_pinned`.
    pub threshold_source: String,
    /// Its value; `None` while the incumbent's noise is unmeasured.
    pub threshold: Option<f64>,
    /// The incumbent's own retest runs behind a noise threshold.
    pub noise_runs: f64,
    /// The overlap fitted a score conversion, or a re-pin withdrew one.
    pub converted: bool,
    pub disagreements: Vec<JudgeSwapDisagreement>,
    pub at: u64,
}

/// The owner's hand-test answer to one disagreement: the judge whose answer
/// is right. It overrides any outcome or tie-breaker on the case, and like
/// every calibration label it is final.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct JudgeSwapPick {
    pub case_ref: String,
    pub judge: String,
    /// The person who picked, 32 hex.
    pub by: String,
    pub at: u64,
}

/// What one pass did.
#[derive(Debug, Clone, PartialEq)]
pub enum JudgeSwapReport {
    /// Nothing kept, or nothing answered.
    Idle,
    /// The incumbent answers; this many of its cases were retested.
    Retested { judge: String, retests: u32 },
    /// Another judge answers; the shadow pass ruled.
    Shadowed(JudgeSwapReceipt),
    /// Later picks or outcomes contradicted the last swap, which re-pinned
    /// back.
    RePinned(JudgeSwapReceipt),
}

/// Picks and settled outcomes, each source read once in a pass.
#[derive(Default)]
struct Anchors {
    /// Each skill's held-out wins, by receipt.
    won: BTreeMap<String, BTreeMap<String, bool>>,
    /// Each skill's labels by campaign: swap picks between the pass's two
    /// judges, and picks on the incumbent's retest flips.
    labels: BTreeMap<(EntityId, String), Vec<JudgeLabel>>,
}

impl Anchors {
    /// The judge the newest owner's pick on `case` names, if any: a swap
    /// pick, or a pick on the incumbent's retest flip of the same case that
    /// matches one side's answer exactly.
    fn picked(
        &mut self,
        vault: &Vault,
        pair: &str,
        case: &JudgeSwapDisagreement,
    ) -> Result<Option<String>> {
        let named = |judge: &String| case.answers.iter().any(|answer| &answer.judge == judge);
        let Some(skill) = case
            .skill
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok())
        else {
            let prefix = format!("{}:", pick_key(pair, &case.case_ref));
            let mut newest: Option<JudgeSwapPick> = None;
            for key in vault.sync_state_keys_with_prefix(&prefix)? {
                if let Some(pick) = load::<JudgeSwapPick>(vault, &key)?
                    && newest.as_ref().is_none_or(|newest| pick.at > newest.at)
                {
                    newest = Some(pick);
                }
            }
            return Ok(newest.map(|pick| pick.judge).filter(named));
        };
        let mut sources = vec![(label_campaign(pair), None)];
        if let Some(incumbent) = case.answers.first() {
            sources.push((
                retest_campaign(&incumbent.judge),
                Some(incumbent.judge.as_str()),
            ));
        }
        let mut newest: Option<(u64, &JudgeShadowAnswer)> = None;
        for (campaign, retest) in sources {
            let labels = match self.labels.entry((skill, campaign)) {
                Entry::Occupied(kept) => kept.into_mut(),
                Entry::Vacant(slot) => {
                    let labels = judge_label_anchor(vault, skill, &slot.key().1)?;
                    slot.insert(labels)
                }
            };
            for label in labels
                .iter()
                .filter(|label| label.ask.evidence == case.case_ref)
            {
                if let Some(side) = label_side(label, retest, &case.answers)
                    && newest.is_none_or(|(at, _)| label.picked_at > at)
                {
                    newest = Some((label.picked_at, side));
                }
            }
        }
        Ok(newest.map(|(_, side)| side.judge.clone()))
    }

    /// `link`'s settled outcome, as an answer shaped like `like`; `None`
    /// until it settled.
    fn settled(
        &mut self,
        vault: &Vault,
        link: &JudgeOutcomeLink,
        like: &DecisionAnswer,
    ) -> Result<Option<DecisionAnswer>> {
        Ok(match link {
            JudgeOutcomeLink::HeldOut { skill, receipts } => self
                .held_out_rate(vault, skill, receipts)?
                .map(|rate| shaped(like, rate)),
            JudgeOutcomeLink::Axis {
                skill,
                axis,
                receipts,
                goal_revision,
            } => axis_rate(vault, skill, axis, goal_revision.as_deref(), receipts)?
                .map(|rate| shaped(like, rate)),
            JudgeOutcomeLink::Audit { receipt } => {
                hidden_flaw(vault, receipt)?.map(DecisionAnswer::Noul)
            }
            JudgeOutcomeLink::Tradeoff { proposal, digest } => {
                tradeoff_answer(vault, proposal, digest)?.map(DecisionAnswer::Choice)
            }
            JudgeOutcomeLink::ResponsePair { pair_ref } => {
                super::response_pair::response_pair_pick(vault, pair_ref)?.map(|preferred| {
                    DecisionAnswer::Choice(
                        match preferred {
                            super::PreferredResponse::First => "first",
                            super::PreferredResponse::Second => "second",
                        }
                        .to_owned(),
                    )
                })
            }
        })
    }

    /// The share of `receipts` the skill won; `None` until every one of
    /// them has settled.
    fn held_out_rate(
        &mut self,
        vault: &Vault,
        skill: &str,
        receipts: &[String],
    ) -> Result<Option<f64>> {
        if !self.won.contains_key(skill) {
            let mut won = BTreeMap::new();
            if let Ok(id) = EntityId::from_hex(skill) {
                let txn = vault.store.env.read_txn()?;
                won.extend(crate::skill_reliability::attributed_outcome_results(
                    vault, &txn, &id,
                )?);
            }
            self.won.insert(skill.to_owned(), won);
        }
        let won = &self.won[skill];
        let mut wins = 0_u32;
        for receipt in receipts {
            match won.get(receipt) {
                Some(win) => wins += u32::from(*win),
                None => return Ok(None),
            }
        }
        Ok(Some(f64::from(wins) / f64::from(count(receipts.len()))))
    }
}

/// The share of `receipts` whose anchored observation on the skill's `axis`
/// succeeded: a person's verdict, a world outcome or an audit, never a
/// model's judgment. Only an observation measured under `goal_revision`, the
/// revision the question was asked under, counts: a renamed or redefined
/// axis is another question. `None` until each receipt has one, and while
/// two observations of one receipt disagree.
fn axis_rate(
    vault: &Vault,
    skill: &str,
    axis: &str,
    goal_revision: Option<&str>,
    receipts: &[String],
) -> Result<Option<f64>> {
    let Ok(skill) = EntityId::from_hex(skill) else {
        return Ok(None);
    };
    let txn = vault.store.env.read_txn()?;
    let cells: Vec<[u8; 32]> =
        crate::learning::evidence::cells_for_subject_in_txn(vault, &txn, &skill)?
            .into_iter()
            .filter(|row| {
                row.cell.predicate == LearningPredicate::Reliability
                    && row.cell.axis.as_deref() == Some(axis)
            })
            .map(|row| row.cell.digest())
            .collect();
    let mut wins = 0_u32;
    for receipt in receipts {
        let mut seen = BTreeSet::new();
        for digest in &cells {
            if let Some(row) = crate::learning::evidence::EVIDENCE.get(
                &vault.store,
                &txn,
                &(*digest, receipt.clone()),
            )? && !row.on_judge_model
                && row.goal_revision.as_deref() == goal_revision
                && let Observation::Success(success) = row.observation
            {
                seen.insert(success);
            }
        }
        match (seen.len(), seen.first()) {
            (1, Some(success)) => wins += u32::from(*success),
            _ => return Ok(None),
        }
    }
    Ok(Some(f64::from(wins) / f64::from(count(receipts.len()))))
}

/// Whether the run behind `receipt` (`attempt:<32 hex>`) hid a flaw, by its
/// sealed audit: yes once a check found a flaw its confession didn't
/// disclose, no once a random audit checked every objective and found none
/// hidden. `None` before either.
fn hidden_flaw(vault: &Vault, receipt: &str) -> Result<Option<bool>> {
    let Some(attempt) = receipt
        .strip_prefix("attempt:")
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    let Some(seal) = vault.sealed_attempt_receipt(AttemptId::from_bytes(attempt.as_bytes())?)?
    else {
        return Ok(None);
    };
    if crate::learning::honesty::seal_assessment(&seal).weighted_hidden_flaws > 0.0 {
        return Ok(Some(true));
    }
    let audited = seal
        .checks
        .iter()
        .any(|check| check.request.kind == SealCheckKind::RandomAudit && check.outcome.is_some());
    Ok(audited.then_some(false))
}

/// The answer the responsible person or role gave the tradeoff ask on
/// `proposal` whose question had `digest`: `approve` or `reject`. `None`
/// while unanswered, and for a ruling by a preference rule or a judge.
fn tradeoff_answer(vault: &Vault, proposal: &str, digest: &str) -> Result<Option<String>> {
    let Ok(proposal) = EntityId::from_hex(proposal) else {
        return Ok(None);
    };
    Ok(skill_edit_verdicts_for_proposal(vault, &proposal)?
        .into_iter()
        .rev()
        .filter(|verdict| verdict.displaced_by_revision.is_none())
        .find_map(|verdict| {
            let resolution = verdict.tradeoff_resolution.as_ref()?;
            if resolution.evidence != digest
                || !matches!(resolution.rung, TradeoffRung::Person | TradeoffRung::Role)
            {
                return None;
            }
            match verdict.disposition {
                // A deferral carries a resolution only when it deferred an
                // approval.
                SkillEditDisposition::AcceptedTradeoff
                | SkillEditDisposition::DeferredCycleCap
                | SkillEditDisposition::DeferredJudgeCadence => Some("approve".to_owned()),
                SkillEditDisposition::RejectedTradeoff => Some("reject".to_owned()),
                _ => None,
            }
        }))
}

/// A settled share as an answer to the case's question: the share itself
/// for a score, whether it is at least half for a yes-or-no.
fn shaped(like: &DecisionAnswer, rate: f64) -> DecisionAnswer {
    match like {
        DecisionAnswer::Noul(_) => DecisionAnswer::Noul(rate >= 0.5),
        _ => DecisionAnswer::Score(rate),
    }
}

/// [`judge_takeover_verdict`] against an owner-pinned divergence rate: the
/// high end of each source family's divergence interval must stay within it.
fn pinned_verdict(cases: &[DivergenceCase], rate: f64) -> TakeoverVerdict {
    let mut families: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    for case in cases {
        let entry = families
            .entry(case.source_family.as_str())
            .or_insert((0, 0));
        entry.0 += 1;
        entry.1 += u32::from(case.diverged);
    }
    if families.is_empty() || families.values().any(|(n, _)| *n < MIN_CASES_PER_FAMILY) {
        return TakeoverVerdict::Unknown;
    }
    let worst = families
        .values()
        .map(|(n, k)| wilson_upper(*k, *n))
        .fold(0.0_f64, f64::max);
    if worst <= rate {
        TakeoverVerdict::TakeOver
    } else {
        TakeoverVerdict::Hold
    }
}

fn wilson_upper(successes: u32, n: u32) -> f64 {
    let n = f64::from(n.max(1));
    let p = f64::from(successes) / n;
    let z2 = WILSON_Z * WILSON_Z;
    let centre = p + z2 / (2.0 * n);
    let margin = WILSON_Z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    ((centre + margin) / (1.0 + z2 / n)).clamp(0.0, 1.0)
}

/// The judge-swap passes this vault kept, oldest first.
///
/// # Errors
///
/// Storage errors; a kept receipt that does not decode.
pub fn judge_swap_receipts(vault: &Vault) -> Result<Vec<JudgeSwapReceipt>> {
    vault
        .sync_state_keys_with_prefix(RECEIPT_PREFIX)?
        .iter()
        .filter_map(|key| load::<JudgeSwapReceipt>(vault, key).transpose())
        .collect()
}

/// The judge the kept history reads on, once a pass has named one.
///
/// # Errors
///
/// Storage errors; a kept row that does not decode.
pub fn judge_incumbent(vault: &Vault) -> Result<Option<JudgeIncumbent>> {
    load(vault, INCUMBENT_KEY)
}

/// The vault's judge-swap policy; canon's defaults until the owner sets one.
///
/// # Errors
///
/// Storage errors; a kept row that does not decode.
pub fn judge_swap_policy(vault: &Vault) -> Result<JudgeSwapPolicy> {
    Ok(load(vault, POLICY_KEY)?.unwrap_or_default())
}

/// Sets the vault's judge-swap policy. The next shadow pass reads it.
///
/// # Errors
///
/// A credential that no longer names a live owner, a pinned rate outside
/// `[0, 1]`, or storage errors.
pub fn set_judge_swap_policy(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    policy: &JudgeSwapPolicy,
) -> Result<()> {
    owner.revalidate_person(vault)?;
    if policy
        .pinned_divergence
        .is_some_and(|rate| !(0.0..=1.0).contains(&rate))
    {
        return Err(Error::InvalidClaimBody(
            "a pinned divergence rate is between 0 and 1",
        ));
    }
    save(vault, POLICY_KEY, policy)
}

/// The same answer, or two scores within [`SCORE_AGREEMENT`].
fn agree(first: &DecisionAnswer, second: &DecisionAnswer) -> bool {
    match (first, second) {
        (DecisionAnswer::Score(a), DecisionAnswer::Score(b)) => (a - b).abs() <= SCORE_AGREEMENT,
        _ => first == second,
    }
}

/// Two judges, in either order: picks and tie-breaks hold for the pair.
fn pair_tag(first: &str, second: &str) -> String {
    let (low, high) = if first <= second {
        (first, second)
    } else {
        (second, first)
    };
    blake3::hash(format!("{low}\n{high}").as_bytes()).to_hex()[..32].to_owned()
}

fn pick_key(pair: &str, case_ref: &str) -> String {
    format!("{PICK_PREFIX}{pair}:{case_ref}")
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}
