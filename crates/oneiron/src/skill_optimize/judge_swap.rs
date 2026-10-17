//! The judge-swap shadow ladder (ARCH-0053, ARCH-0079 #model-swaps, OF-184).
//! The Coach keeps the incumbent: the judge whose answers the host's kept
//! judgments hold. While the incumbent still answers, the Coach retests it on
//! its own kept cases, so its retest noise is measured before a swap needs
//! it. When another judge answers, that judge scores the incumbent's kept
//! cases again. It takes over only when its divergence, grouped by source
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

use crate::consent::AuthenticatedOwner;
use crate::attempt_queue::AttemptId;
use crate::learning::{
    DivergenceCase, LearningCell, LearningPredicate, Observation, Retest, RetestScore,
    TakeoverVerdict, judge_takeover_verdict, learning_estimate, record_judge_conversion,
    record_retest, withdraw_judge_conversion,
};
use crate::llm::decision::DecisionAnswer;
use crate::self_heal::audit::SealCheckKind;
use crate::skill_optimize::{
    GoalAxisKind, JudgeLabel, SkillEditDisposition, TradeoffRung, judge_label_anchor,
    skill_edit_goal, skill_edit_verdicts_for_proposal,
};
use crate::{EntityId, Error, Result, Vault};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeTieBreaker {
    /// A third judge from another model family.
    ThirdFamily,
    /// Nobody: the incumbent holds until a pick or an outcome arrives.
    IncumbentHolds,
}

/// The vault's judge-swap policy, which the owner sets. Each field the owner
/// leaves out takes canon's default (ARCH-0079 #model-swaps, ARCH-0003).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    HeldOut { skill: String, receipts: Vec<String> },
    /// A named or live goal axis: the share of these receipts whose anchored
    /// observation on the axis succeeded.
    Axis {
        skill: String,
        axis: String,
        receipts: Vec<String>,
    },
    /// An honesty finding: whether the run's sealed audit found a flaw its
    /// confession hid.
    Audit { receipt: String },
    /// A tradeoff call: the responsible person's or role's answer to the ask
    /// on exactly this question.
    Tradeoff { proposal: String, digest: String },
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// One judge-swap pass. Model calls go through `host`, outside any vault
/// transaction; every write opens its own.
pub(crate) fn run_judge_swap(
    vault: &Vault,
    host: &dyn JudgeShadowHost,
    now: u64,
) -> Result<JudgeSwapReport> {
    let cases = host.kept_cases(KEPT_CASES)?;
    let incumbent = match load::<JudgeIncumbent>(vault, INCUMBENT_KEY)? {
        Some(incumbent) => incumbent,
        None => {
            let Some(newest) = cases.first() else {
                return Ok(JudgeSwapReport::Idle);
            };
            let incumbent = JudgeIncumbent {
                judge: newest.judge.clone(),
                since: now,
                previous: None,
                takeover: None,
            };
            save(vault, INCUMBENT_KEY, &incumbent)?;
            incumbent
        }
    };
    if let Some(receipt) = recheck(vault, &incumbent, now)? {
        return Ok(JudgeSwapReport::RePinned(receipt));
    }
    let incumbent = incumbent.judge;
    let own: Vec<&JudgeShadowCase> = cases
        .iter()
        .filter(|case| case.judge == incumbent)
        .collect();
    // Who answers now: the incumbent's newest case, asked again.
    let Some(first) = own.first() else {
        return Ok(JudgeSwapReport::Idle);
    };
    let Some(probe) = host.rescore(first)? else {
        return Ok(JudgeSwapReport::Idle);
    };
    if probe.judge == incumbent {
        retest(vault, host, &incumbent, &own, probe, now)
    } else {
        shadow(vault, host, &incumbent, &own, probe, now)
    }
}

/// Retests the incumbent on its own cases, each once: how often it
/// disagrees with itself is the noise a swap is judged against.
fn retest(
    vault: &Vault,
    host: &dyn JudgeShadowHost,
    incumbent: &str,
    own: &[&JudgeShadowCase],
    probe: JudgeShadowAnswer,
    now: u64,
) -> Result<JudgeSwapReport> {
    let scorer = scorer()?;
    let mut probe = Some(probe);
    let mut retests = 0;
    for case in own {
        if retests >= RETESTS {
            break;
        }
        let answered = probe.take();
        let key = format!("{RETESTED_PREFIX}{}", case.case_ref);
        if vault.sync_state_get(&key)?.is_some() {
            continue;
        }
        let again = match answered {
            Some(answer) => answer,
            None => match host.rescore(case)? {
                Some(answer) => answer,
                None => continue,
            },
        };
        // A judge that changed mid-pass is the next pass's swap.
        if again.judge != incumbent {
            break;
        }
        record_retest(
            vault,
            &Retest {
                scorer,
                executor: incumbent.to_owned(),
                axis: NOISE_AXIS.to_owned(),
                type_ref: None,
                receipt: format!("judge-retest:{}", case.case_ref),
                first: RetestScore::Pass(true),
                second: RetestScore::Pass(agree(&case.answer, &again.answer)),
                at: now,
            },
            now,
        )?;
        vault.sync_state_put(&key, &now.to_be_bytes())?;
        retests += 1;
    }
    Ok(JudgeSwapReport::Retested {
        judge: incumbent.to_owned(),
        retests: u32::try_from(retests).unwrap_or(u32::MAX),
    })
}

/// Has the new judge score the incumbent's cases and rules on the swap.
fn shadow(
    vault: &Vault,
    host: &dyn JudgeShadowHost,
    incumbent: &str,
    own: &[&JudgeShadowCase],
    probe: JudgeShadowAnswer,
    now: u64,
) -> Result<JudgeSwapReport> {
    let candidate = probe.judge.clone();
    let tag = blake3::hash(candidate.as_bytes()).to_hex();
    let key = |case: &JudgeShadowCase| format!("{SHADOW_PREFIX}{}:{}", &tag[..32], case.case_ref);
    if let Some(first) = own.first()
        && load::<JudgeShadowAnswer>(vault, &key(first))?.is_none()
    {
        save(vault, &key(first), &probe)?;
    }
    let policy = judge_swap_policy(vault)?;
    let pair = pair_tag(incumbent, &candidate);
    let mut divergence = Vec::new();
    let mut pairs = Vec::new();
    let mut disagreements: Vec<(&JudgeShadowCase, JudgeSwapDisagreement)> = Vec::new();
    for case in own.iter().take(SHADOW_CASES) {
        let answer = match load::<JudgeShadowAnswer>(vault, &key(case))? {
            Some(kept) => kept,
            None => {
                let Some(answer) = host.rescore(case)? else {
                    continue;
                };
                save(vault, &key(case), &answer)?;
                answer
            }
        };
        if answer.judge != candidate {
            continue;
        }
        let diverged = !agree(&case.answer, &answer.answer);
        divergence.push(DivergenceCase {
            source_family: case.source_family.clone(),
            diverged,
        });
        if let (DecisionAnswer::Score(old), DecisionAnswer::Score(new)) =
            (&case.answer, &answer.answer)
        {
            pairs.push((*old, *new));
        }
        if diverged {
            disagreements.push((*case, disagreement(vault, incumbent, case, answer)?));
        }
    }
    let noise = learning_estimate(vault, &noise_cell(incumbent)?)?;
    let noise = noise.as_ref().filter(|noise| noise.runs > 0.0);
    let (mut verdict, threshold_source, threshold) = match policy.pinned_divergence {
        Some(rate) => (
            pinned_verdict(&divergence, rate),
            "owner_pinned",
            Some(rate),
        ),
        None => (
            judge_takeover_verdict(&divergence, noise, MIN_CASES_PER_FAMILY),
            "retest_noise",
            noise.map(crate::learning::Estimate::mean),
        ),
    };
    let mut anchors = Anchors::default();
    for (_, case) in &mut disagreements {
        anchor(vault, &pair, &mut anchors, case)?;
    }
    let mut arbitrated = false;
    match verdict {
        // A takeover the anchors already contradict would re-pin at once.
        TakeoverVerdict::TakeOver => {
            let settled = || disagreements.iter().map(|(_, case)| case);
            if anchored(settled(), incumbent) > anchored(settled(), &candidate) {
                verdict = TakeoverVerdict::Hold;
            }
        }
        // Known and wider than the threshold: only the disagreements count.
        TakeoverVerdict::Hold => {
            arbitrated = true;
            for (kept, case) in &mut disagreements {
                let rule = if case.floor {
                    policy.floor_tie_breaker
                } else {
                    policy.tie_breaker
                };
                if case.settled_by == JudgeSwapSettledBy::Open
                    && rule == JudgeTieBreaker::ThirdFamily
                {
                    tie_break(vault, host, &pair, *kept, &candidate, case)?;
                }
            }
            let settled = || disagreements.iter().map(|(_, case)| case);
            let open = settled().filter(|case| case.sided_with.is_none()).count();
            // An open case holds for the incumbent.
            if sided(settled(), &candidate) > sided(settled(), incumbent) + open {
                verdict = TakeoverVerdict::TakeOver;
            }
        }
        TakeoverVerdict::Unknown => {}
    }
    let id = vault.store.clock.entity_id()?.to_hex();
    let mut converted = false;
    if verdict == TakeoverVerdict::TakeOver {
        // Only scores convert; a judge of choices takes over with no map.
        if pairs.len() >= 2 {
            record_judge_conversion(vault, incumbent, &candidate, &pairs, now)?;
            converted = true;
        }
        save(
            vault,
            INCUMBENT_KEY,
            &JudgeIncumbent {
                judge: candidate.clone(),
                since: now,
                previous: Some(incumbent.to_owned()),
                takeover: Some(id.clone()),
            },
        )?;
    }
    let families: BTreeSet<&str> = divergence
        .iter()
        .map(|case| case.source_family.as_str())
        .collect();
    let receipt = JudgeSwapReceipt {
        id,
        from_judge: incumbent.to_owned(),
        to_judge: candidate,
        verdict: match verdict {
            TakeoverVerdict::TakeOver => "take_over",
            TakeoverVerdict::Hold => "hold",
            TakeoverVerdict::Unknown => "unknown",
        }
        .to_owned(),
        arbitrated,
        cases: count(divergence.len()),
        diverged: count(disagreements.len()),
        families: count(families.len()),
        threshold_source: threshold_source.to_owned(),
        threshold,
        noise_runs: noise.map_or(0.0, |noise| noise.runs),
        converted,
        disagreements: disagreements.into_iter().map(|(_, case)| case).collect(),
        at: now,
    };
    save(vault, &format!("{RECEIPT_PREFIX}{}", receipt.id), &receipt)?;
    if verdict == TakeoverVerdict::TakeOver {
        notify_owners(vault, &receipt.id, policy.hands_on, now)?;
    }
    Ok(JudgeSwapReport::Shadowed(receipt))
}

/// Re-reads the last takeover's disagreements against the picks and settled
/// outcomes since. When more of them side with the judge it replaced than
/// with the incumbent, the swap re-pins back: that judge is the incumbent
/// again, the conversion onto the new scale is withdrawn, and the owners
/// hear of it.
fn recheck(
    vault: &Vault,
    incumbent: &JudgeIncumbent,
    now: u64,
) -> Result<Option<JudgeSwapReceipt>> {
    let (Some(previous), Some(takeover)) = (&incumbent.previous, &incumbent.takeover) else {
        return Ok(None);
    };
    let Some(swap) = load::<JudgeSwapReceipt>(vault, &format!("{RECEIPT_PREFIX}{takeover}"))?
    else {
        return Ok(None);
    };
    let pair = pair_tag(previous, &incumbent.judge);
    let mut anchors = Anchors::default();
    let mut disagreements = swap.disagreements.clone();
    for case in &mut disagreements {
        anchor(vault, &pair, &mut anchors, case)?;
    }
    if anchored(disagreements.iter(), previous) <= anchored(disagreements.iter(), &incumbent.judge)
    {
        return Ok(None);
    }
    save(
        vault,
        INCUMBENT_KEY,
        &JudgeIncumbent {
            judge: previous.clone(),
            since: now,
            previous: None,
            takeover: None,
        },
    )?;
    let converted = withdraw_judge_conversion(vault, previous, now)?;
    let receipt = JudgeSwapReceipt {
        id: vault.store.clock.entity_id()?.to_hex(),
        from_judge: incumbent.judge.clone(),
        to_judge: previous.clone(),
        verdict: "re_pin".to_owned(),
        arbitrated: true,
        converted,
        disagreements,
        at: now,
        ..swap
    };
    save(vault, &format!("{RECEIPT_PREFIX}{}", receipt.id), &receipt)?;
    notify_owners(vault, &receipt.id, false, now)?;
    Ok(Some(receipt))
}

/// A new disagreement, open, with the incumbent's kept answer first.
fn disagreement(
    vault: &Vault,
    incumbent: &str,
    case: &JudgeShadowCase,
    answer: JudgeShadowAnswer,
) -> Result<JudgeSwapDisagreement> {
    Ok(JudgeSwapDisagreement {
        case_ref: case.case_ref.clone(),
        question: case.question.clone(),
        kind: case.kind.clone(),
        asked_at: case.asked_at,
        source_family: case.source_family.clone(),
        floor: judged_floor(vault, &case.state)?,
        skill: judged_skill(&case.state),
        answers: vec![
            JudgeShadowAnswer {
                judge: incumbent.to_owned(),
                answer: case.answer.clone(),
            },
            answer,
        ],
        outcome_link: case
            .kind
            .as_deref()
            .and_then(|kind| outcome_link(kind, &case.state)),
        outcome: None,
        tie_breaker: None,
        sided_with: None,
        settled_by: JudgeSwapSettledBy::Open,
    })
}

/// Settles `case` by an anchor: the owner's pick first, then the settled
/// outcome. A case neither decides keeps its tie-breaker ruling, if any.
fn anchor(
    vault: &Vault,
    pair: &str,
    anchors: &mut Anchors,
    case: &mut JudgeSwapDisagreement,
) -> Result<()> {
    if let Some(judge) = anchors.picked(vault, pair, case)? {
        case.sided_with = Some(judge);
        case.settled_by = JudgeSwapSettledBy::Pick;
        return Ok(());
    }
    if let Some(link) = &case.outcome_link {
        case.outcome = anchors.settled(vault, link, &case.answers[0].answer)?;
        if let Some(outcome) = &case.outcome
            && let Some(judge) = sides_with(&case.answers, outcome)
        {
            case.sided_with = Some(judge);
            case.settled_by = JudgeSwapSettledBy::Outcome;
        }
    }
    Ok(())
}

/// Asks the host's third judge about `case` once per pair of judges, and
/// sides the case with the judge whose answer the third one shares.
fn tie_break(
    vault: &Vault,
    host: &dyn JudgeShadowHost,
    pair: &str,
    kept: &JudgeShadowCase,
    candidate: &str,
    case: &mut JudgeSwapDisagreement,
) -> Result<()> {
    let key = format!("{TIE_PREFIX}{pair}:{}", kept.case_ref);
    let third = match load::<JudgeShadowAnswer>(vault, &key)? {
        Some(third) => third,
        None => {
            let Some(third) = host.tie_break(kept, &kept.judge, candidate)? else {
                return Ok(());
            };
            save(vault, &key, &third)?;
            third
        }
    };
    // The old judge never settles a disagreement: it would side with itself.
    if case
        .answers
        .iter()
        .any(|answer| answer.judge == third.judge)
    {
        return Ok(());
    }
    if let Some(judge) = sides_with(&case.answers, &third.answer) {
        case.sided_with = Some(judge);
        case.settled_by = JudgeSwapSettledBy::TieBreaker;
    }
    case.tie_breaker = Some(third);
    Ok(())
}

/// The judge whose answer `reference` bears out: the nearer score, or the
/// only answer it agrees with. `None` for a tie.
fn sides_with(answers: &[JudgeShadowAnswer], reference: &DecisionAnswer) -> Option<String> {
    if let DecisionAnswer::Score(truth) = reference {
        let mut near: Vec<(f64, &JudgeShadowAnswer)> = answers
            .iter()
            .filter_map(|answer| match answer.answer {
                DecisionAnswer::Score(score) => Some(((score - truth).abs(), answer)),
                _ => None,
            })
            .collect();
        if near.len() == answers.len() {
            near.sort_by(|a, b| a.0.total_cmp(&b.0));
            return match near.as_slice() {
                [(best, answer), (next, _), ..] if best < next => Some(answer.judge.clone()),
                [(_, answer)] => Some(answer.judge.clone()),
                _ => None,
            };
        }
    }
    let agreeing: Vec<&JudgeShadowAnswer> = answers
        .iter()
        .filter(|answer| agree(&answer.answer, reference))
        .collect();
    match agreeing.as_slice() {
        [only] => Some(only.judge.clone()),
        _ => None,
    }
}

/// Cases sided with `judge`, by any settler.
fn sided<I>(cases: I, judge: &str) -> usize
where
    I: Iterator,
    I::Item: Borrow<JudgeSwapDisagreement>,
{
    cases
        .filter(|case| {
            <I::Item as Borrow<JudgeSwapDisagreement>>::borrow(case)
                .sided_with
                .as_deref()
                == Some(judge)
        })
        .count()
}

/// Cases an anchor (a pick or a settled outcome) sided with `judge`.
fn anchored<I>(cases: I, judge: &str) -> usize
where
    I: Iterator,
    I::Item: Borrow<JudgeSwapDisagreement>,
{
    sided(
        cases.filter(|case| {
            matches!(
                <I::Item as Borrow<JudgeSwapDisagreement>>::borrow(case).settled_by,
                JudgeSwapSettledBy::Pick | JudgeSwapSettledBy::Outcome
            )
        }),
        judge,
    )
}

/// Where the settled outcome of a case asked under `kind` is read; `None`
/// for a blind preference and a structural or contrastive audit, which
/// nothing settles, and for a state that lacks what its kind reads.
fn outcome_link(kind: &str, state: &Value) -> Option<JudgeOutcomeLink> {
    let text = |value: &Value, field: &str| value.get(field)?.as_str().map(str::to_owned);
    let receipts = |value: &Value| {
        value
            .get("held_out_receipts")?
            .as_array()?
            .iter()
            .map(|receipt| receipt.as_str().map(str::to_owned))
            .collect::<Option<Vec<String>>>()
            .filter(|receipts| !receipts.is_empty())
    };
    match kind {
        "score" | "task_success" => Some(JudgeOutcomeLink::HeldOut {
            skill: text(state, "skill")?,
            receipts: receipts(state)?,
        }),
        "live_axis" => {
            let case = state.get("case")?;
            Some(JudgeOutcomeLink::Axis {
                skill: text(case, "skill")?,
                axis: text(state.get("axis")?, "name")?,
                receipts: receipts(case)?,
            })
        }
        "honesty" => Some(JudgeOutcomeLink::Audit {
            receipt: text(state, "receipt")?,
        }),
        "tradeoff" => Some(JudgeOutcomeLink::Tradeoff {
            proposal: text(state.get("question")?, "proposal")?,
            digest: text(state, "digest")?,
        }),
        // `axis.<name>`; a preference, structural or contrastive case has
        // none.
        _ => {
            let axis = kind.strip_prefix("axis.")?;
            Some(JudgeOutcomeLink::Axis {
                skill: text(state, "skill")?,
                axis: axis.to_owned(),
                receipts: receipts(state)?,
            })
        }
    }
}

/// The skill a case judged, as hex: a whole-skill, axis or honesty case
/// names it, a live-axis case in its nested case.
fn judged_skill(state: &Value) -> Option<String> {
    state
        .get("skill")
        .or_else(|| state.get("case")?.get("skill"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Whether a case judged a floor axis: an honesty objective always does; a
/// named or live axis does when its goal declared it a floor when it was
/// asked, else when the skill's goal declares it one now, and when that goal
/// can no longer be read.
fn judged_floor(vault: &Vault, state: &Value) -> Result<bool> {
    if state.get("objective").is_some() {
        return Ok(true);
    }
    let Some(axis) = state
        .get("axis")
        .and_then(|axis| axis.as_str().or_else(|| axis.get("name")?.as_str()))
    else {
        return Ok(false);
    };
    if let Some(kind) = state
        .get("axis_kind")
        .and_then(|kind| GoalAxisKind::deserialize(kind).ok())
    {
        return Ok(kind == GoalAxisKind::Floor);
    }
    let Some(skill) = judged_skill(state).and_then(|hex| EntityId::from_hex(&hex).ok()) else {
        return Ok(true);
    };
    Ok(skill_edit_goal(vault, &skill).map_or(true, |goal| {
        goal.axes
            .iter()
            .find(|spec| spec.name == axis)
            .is_none_or(|spec| spec.kind == GoalAxisKind::Floor)
    }))
}

/// Picks and settled outcomes, each source read once in a pass.
#[derive(Default)]
struct Anchors {
    /// Each skill's held-out wins, by receipt.
    won: BTreeMap<String, BTreeMap<String, bool>>,
    /// Each skill's swap labels between the pass's two judges.
    labels: BTreeMap<EntityId, Vec<JudgeLabel>>,
}

impl Anchors {
    /// The judge the newest owner's pick on `case` names, if any.
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
        let labels = match self.labels.entry(skill) {
            Entry::Occupied(kept) => kept.into_mut(),
            Entry::Vacant(slot) => {
                slot.insert(judge_label_anchor(vault, skill, &label_campaign(pair))?)
            }
        };
        Ok(labels
            .iter()
            .filter(|label| label.ask.evidence == case.case_ref)
            .max_by_key(|label| label.picked_at)
            .and_then(|label| {
                case.answers
                    .iter()
                    .find(|answer| label_option(answer) == label.chosen)
            })
            .map(|answer| answer.judge.clone()))
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
            } => axis_rate(vault, skill, axis, receipts)?.map(|rate| shaped(like, rate)),
            JudgeOutcomeLink::Audit { receipt } => {
                hidden_flaw(vault, receipt)?.map(DecisionAnswer::Noul)
            }
            JudgeOutcomeLink::Tradeoff { proposal, digest } => {
                tradeoff_answer(vault, proposal, digest)?.map(DecisionAnswer::Choice)
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
/// model's judgment. `None` until each receipt has one, and while two
/// observations of one receipt disagree.
fn axis_rate(vault: &Vault, skill: &str, axis: &str, receipts: &[String]) -> Result<Option<f64>> {
    let Ok(skill) = EntityId::from_hex(skill) else {
        return Ok(None);
    };
    let txn = vault.store.env.read_txn()?;
    let cells: Vec<[u8; 32]> = crate::learning::evidence::cells_for_subject_in_txn(vault, &txn, &skill)?
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
            if let Some(row) =
                crate::learning::evidence::EVIDENCE.get(&vault.store, &txn, &(*digest, receipt.clone()))?
                && !row.on_judge_model
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
    let audited = seal.checks.iter().any(|check| {
        check.request.kind == SealCheckKind::RandomAudit && check.outcome.is_some()
    });
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
                SkillEditDisposition::AcceptedTradeoff => Some("approve".to_owned()),
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

/// The owner's hand-test pick on one disagreement of the swap `receipt`
/// names: `judge`'s answer is right. It decides the case over any outcome or
/// tie-breaker in every later pass between the same two judges, and a pick
/// that contradicts a takeover can re-pin it back. On a skill's case the pick
/// is a label in that skill's judge anchor, delivered by the swap's notice.
/// Like every calibration label it is final: the same pick again returns it,
/// and another one fails. Each owner picks once; the newest owner's pick
/// decides.
///
/// # Errors
///
/// A credential that no longer names a live owner, an unknown receipt, a
/// case the swap did not disagree on, a judge that answered neither side, a
/// pick that differs from this owner's earlier one, or storage errors.
pub fn pick_judge_swap_case(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    receipt: &str,
    case_ref: &str,
    judge: &str,
    at: u64,
) -> Result<JudgeSwapPick> {
    let by = owner.revalidate_person(vault)?;
    let receipt = EntityId::from_hex(receipt)
        .map_err(|_| Error::InvalidClaimBody("a swap receipt is 32 hex"))?
        .to_hex();
    let swap = load::<JudgeSwapReceipt>(vault, &format!("{RECEIPT_PREFIX}{receipt}"))?
        .ok_or(Error::EntityNotFound)?;
    let case = swap
        .disagreements
        .iter()
        .find(|case| case.case_ref == case_ref)
        .ok_or(Error::InvalidClaimBody(
            "the swap did not disagree on that case",
        ))?;
    let Some(chosen) = case.answers.iter().position(|answer| answer.judge == judge) else {
        return Err(Error::InvalidClaimBody(
            "a pick names one of the two judges",
        ));
    };
    let pair = pair_tag(&swap.from_judge, &swap.to_judge);
    if let Some(skill) = case
        .skill
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
        && let [first, second] = case.answers.as_slice()
    {
        let campaign = label_campaign(&pair);
        let options = [label_option(first), label_option(second)];
        if judge_label_anchor(vault, skill, &campaign)?
            .iter()
            .any(|label| {
                label.ask.responsible == by
                    && label.ask.evidence == case.case_ref
                    && label.chosen != options[chosen]
            })
        {
            return Err(Error::InvalidClaimBody("a hand-test pick is final"));
        }
        let label = super::labels::record_judge_swap_label(
            vault,
            owner,
            skill,
            &campaign,
            &case.case_ref,
            [&options[0], &options[1]],
            chosen == 1,
            swap.at,
            at,
        )?;
        return Ok(JudgeSwapPick {
            case_ref: case.case_ref.clone(),
            judge: judge.to_owned(),
            by: by.to_hex(),
            at: label.picked_at,
        });
    }
    let key = format!("{}:{}", pick_key(&pair, &case.case_ref), by.to_hex());
    if let Some(earlier) = load::<JudgeSwapPick>(vault, &key)? {
        if earlier.judge != judge {
            return Err(Error::InvalidClaimBody("a hand-test pick is final"));
        }
        return Ok(earlier);
    }
    let pick = JudgeSwapPick {
        case_ref: case.case_ref.clone(),
        judge: judge.to_owned(),
        by: by.to_hex(),
        at,
    };
    save(vault, &key, &pick)?;
    Ok(pick)
}

/// The label campaign a pair of judges' swap picks are kept under.
fn label_campaign(pair: &str) -> String {
    format!("judge_swap:{pair}")
}

/// One judge's answer as a label option: the judge and its answer.
fn label_option(answer: &JudgeShadowAnswer) -> String {
    let said = serde_json::to_string(&answer.answer).unwrap_or_default();
    format!("{}: {said}", answer.judge)
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

/// The scoring subject the incumbent's retest noise is kept under.
fn scorer() -> Result<EntityId> {
    EntityId::derive(b"oneiron.skill_optimize.judge_swap", &[b"kept judgments"])
}

/// The cell [`record_retest`] keeps the incumbent's noise in.
fn noise_cell(incumbent: &str) -> Result<LearningCell> {
    Ok(LearningCell::new(LearningPredicate::RetestNoise, scorer()?)
        .executor(incumbent.to_owned())
        .axis(NOISE_AXIS.to_owned()))
}

/// The swap's or the re-pin's notice: one finding in each owner's inbox, or
/// with a hands-on policy one ask to rate the swap's disagreements.
fn notify_owners(vault: &Vault, receipt: &str, ask: bool, at: u64) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        for owner in crate::policy_model::owners_in_txn(vault, &*txn)? {
            vault.record_notification_in_txn(
                txn,
                &crate::inbox::NotificationEvent {
                    kind: if ask {
                        crate::inbox::NotificationKind::Ask
                    } else {
                        crate::inbox::NotificationKind::Finding
                    },
                    source: crate::inbox::NotificationSource {
                        producer: JUDGE_SWAP_NOTIFICATION_PRODUCER.to_owned(),
                        event: format!("{receipt}:{}", owner.to_hex()),
                        result: Some(receipt.to_owned()),
                        ..crate::inbox::NotificationSource::default()
                    },
                    subject_refs: Vec::new(),
                    recipient: Some(owner),
                    created_at: at,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(())
    })
}

fn load<T: DeserializeOwned>(vault: &Vault, key: &str) -> Result<Option<T>> {
    vault
        .sync_state_get(key)?
        .map(|bytes| {
            serde_json::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("judge swap state"))
        })
        .transpose()
}

fn save<T: Serialize>(vault: &Vault, key: &str, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::CorruptedIndex("judge swap state"))?;
    vault.sync_state_put(key, &bytes)
}
