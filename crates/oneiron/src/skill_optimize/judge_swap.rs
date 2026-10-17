//! The judge-swap shadow ladder (ARCH-0053, OF-184). The Coach keeps the
//! incumbent: the judge whose answers the host's kept judgments hold. While
//! the incumbent still answers, the Coach retests it on its own kept cases,
//! so its retest noise is measured before a swap needs it. When another judge
//! answers, that judge scores the incumbent's kept cases again. It takes over
//! only when its divergence, grouped by source family, stays within the
//! incumbent's noise; its overlap scores then fit the conversion that carries
//! the incumbent's scored history onto its scale. Too few cases or no
//! measured noise reads unknown, and the incumbent holds. No original answer
//! is rescored or rewritten, and every takeover reaches the vault's owners.
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::learning::{
    DivergenceCase, LearningCell, LearningPredicate, Retest, RetestScore, TakeoverVerdict,
    judge_takeover_verdict, learning_estimate, record_judge_conversion, record_retest,
};
use crate::llm::decision::DecisionAnswer;
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

const INCUMBENT_KEY: &str = "skill:judge:v1:swap:incumbent";
const RETESTED_PREFIX: &str = "skill:judge:v1:swap:retested:";
const SHADOW_PREFIX: &str = "skill:judge:v1:swap:shadow:";
const RECEIPT_PREFIX: &str = "skill:judge:v1:swap:receipt:";

/// Producer of a takeover's notice in each owner's inbox.
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
}

/// A judge's answer to a kept case, asked again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeShadowAnswer {
    /// The judge that answered, `model@version`.
    pub judge: String,
    pub answer: DecisionAnswer,
}

/// What the host lends the Coach: its kept judgments, and the judge that
/// answers now.
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
}

/// The judge whose scale the kept history reads on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeIncumbent {
    pub judge: String,
    pub since: u64,
}

/// One shadow pass's ruling, kept whatever it found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeSwapReceipt {
    pub from_judge: String,
    pub to_judge: String,
    /// `take_over`, `hold` or `unknown`.
    pub verdict: String,
    pub cases: u32,
    pub diverged: u32,
    pub families: u32,
    /// The overlap fitted a score conversion.
    pub converted: bool,
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
        Some(incumbent) => incumbent.judge,
        None => {
            let Some(newest) = cases.first() else {
                return Ok(JudgeSwapReport::Idle);
            };
            save(
                vault,
                INCUMBENT_KEY,
                &JudgeIncumbent {
                    judge: newest.judge.clone(),
                    since: now,
                },
            )?;
            newest.judge.clone()
        }
    };
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
    let mut divergence = Vec::new();
    let mut pairs = Vec::new();
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
        divergence.push(DivergenceCase {
            source_family: case.source_family.clone(),
            diverged: !agree(&case.answer, &answer.answer),
        });
        if let (DecisionAnswer::Score(old), DecisionAnswer::Score(new)) =
            (&case.answer, &answer.answer)
        {
            pairs.push((*old, *new));
        }
    }
    let noise = learning_estimate(vault, &noise_cell(incumbent)?)?;
    let verdict = judge_takeover_verdict(&divergence, noise.as_ref(), MIN_CASES_PER_FAMILY);
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
            },
        )?;
    }
    let families: std::collections::BTreeSet<&str> = divergence
        .iter()
        .map(|case| case.source_family.as_str())
        .collect();
    let receipt = JudgeSwapReceipt {
        from_judge: incumbent.to_owned(),
        to_judge: candidate,
        verdict: match verdict {
            TakeoverVerdict::TakeOver => "take_over",
            TakeoverVerdict::Hold => "hold",
            TakeoverVerdict::Unknown => "unknown",
        }
        .to_owned(),
        cases: u32::try_from(divergence.len()).unwrap_or(u32::MAX),
        diverged: u32::try_from(divergence.iter().filter(|case| case.diverged).count())
            .unwrap_or(u32::MAX),
        families: u32::try_from(families.len()).unwrap_or(u32::MAX),
        converted,
        at: now,
    };
    let id = vault.store.clock.entity_id()?;
    save(vault, &format!("{RECEIPT_PREFIX}{}", id.to_hex()), &receipt)?;
    if verdict == TakeoverVerdict::TakeOver {
        notify_owners(vault, &id, now)?;
    }
    Ok(JudgeSwapReport::Shadowed(receipt))
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

/// The same answer, or two scores within [`SCORE_AGREEMENT`].
fn agree(first: &DecisionAnswer, second: &DecisionAnswer) -> bool {
    match (first, second) {
        (DecisionAnswer::Score(a), DecisionAnswer::Score(b)) => (a - b).abs() <= SCORE_AGREEMENT,
        _ => first == second,
    }
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

/// The takeover's notice: one finding in each owner's inbox.
fn notify_owners(vault: &Vault, receipt: &EntityId, at: u64) -> Result<()> {
    let id = receipt.to_hex();
    vault.with_write_txn_grouped(|txn| {
        for owner in crate::policy_model::owners_in_txn(vault, &*txn)? {
            vault.record_notification_in_txn(
                txn,
                &crate::inbox::NotificationEvent {
                    kind: crate::inbox::NotificationKind::Finding,
                    source: crate::inbox::NotificationSource {
                        producer: JUDGE_SWAP_NOTIFICATION_PRODUCER.to_owned(),
                        event: format!("{id}:{}", owner.to_hex()),
                        result: Some(id.clone()),
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
