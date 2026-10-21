//! Owner picks and calibration asks for judge swaps and retest flips.
//! Entry function: `pick_judge_swap_case`.
//! Case, receipt and pick types remain defined in `super`.

use super::*;

/// The owner's hand-test pick on one disagreement of the swap `receipt`
/// names: `judge`'s answer is right. It decides the case over any outcome or
/// tie-breaker in every later pass between the same two judges, and a pick
/// that contradicts a takeover can re-pin it back. On a skill's case the pick
/// is a label in that skill's judge anchor, delivered by the swap's notice.
/// Like every calibration label it is final: the same pick again returns it,
/// and another one fails, as does one against the side this owner's pick on
/// the incumbent's retest flip of the case named. Each owner picks once; the
/// newest owner's pick decides.
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
        let flips = retest_campaign(&first.judge);
        for (source, retest) in [(&campaign, None), (&flips, Some(first.judge.as_str()))] {
            if judge_label_anchor(vault, skill, source)?
                .iter()
                .any(|label| {
                    label.ask.responsible == by
                        && label.ask.evidence == case.case_ref
                        && label_side(label, retest, &case.answers)
                            .is_some_and(|side| side.judge != judge)
                })
            {
                return Err(Error::InvalidClaimBody("a hand-test pick is final"));
            }
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
pub(super) fn label_campaign(pair: &str) -> String {
    format!("judge_swap:{pair}")
}

/// The label campaign picks on `judge`'s retest flips are kept under.
pub(super) fn retest_campaign(judge: &str) -> String {
    let judge = blake3::hash(judge.as_bytes()).to_hex();
    format!("judge_retest:{}", &judge[..32])
}

/// One judge's answer as a label option: the judge and its answer.
fn label_option(answer: &JudgeShadowAnswer) -> String {
    option_text(&answer.judge, &answer.answer)
}

fn option_text(judge: &str, answer: &DecisionAnswer) -> String {
    let said = serde_json::to_string(answer).unwrap_or_default();
    format!("{judge}: {said}")
}

/// The answer of a swap case's `answers` that `label` picks. A swap label
/// names one by its option. A pick on the incumbent `retest`'s flip names
/// one of its own two answers, so it picks the side whose answer is that
/// one exactly, whichever judge gave it. `None` when it names neither.
pub(super) fn label_side<'a>(
    label: &JudgeLabel,
    retest: Option<&str>,
    answers: &'a [JudgeShadowAnswer],
) -> Option<&'a JudgeShadowAnswer> {
    answers.iter().find(|answer| match retest {
        None => label_option(answer) == label.chosen,
        Some(judge) => option_text(judge, &answer.answer) == label.chosen,
    })
}

/// The calibration ask a pick on `case` answers, the question its hand-test
/// asks: the skill whose anchor the label joins, the pair's label campaign,
/// and the two judges' answers as options, the incumbent's first. Its
/// evidence is the case's ref. `None` when the case names no skill.
pub(crate) fn swap_case_ask(
    swap: &JudgeSwapReceipt,
    case: &JudgeSwapDisagreement,
) -> Option<(EntityId, String, [String; 2])> {
    let skill = case
        .skill
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())?;
    let [first, second] = case.answers.as_slice() else {
        return None;
    };
    let campaign = label_campaign(&pair_tag(&swap.from_judge, &swap.to_judge));
    Some((skill, campaign, [label_option(first), label_option(second)]))
}

/// The judge a label option names: the inverse of [`label_option`]. `None`
/// for an option no judge answer wrote.
pub(crate) fn label_judge(option: &str) -> Option<&str> {
    option.split_once(": ").map(|(judge, _)| judge)
}

/// The incumbent's retest flips, newest first: each a kept case it answered
/// one way and, asked again, another.
///
/// # Errors
///
/// Storage errors; a kept marker that does not decode.
pub(crate) fn judge_retest_flips(vault: &Vault) -> Result<Vec<JudgeRetestMark>> {
    let mut flips = Vec::new();
    for key in vault.sync_state_keys_with_prefix(RETESTED_PREFIX)? {
        if let Some(mark) = load::<JudgeRetestMark>(vault, &key)?
            && !mark.agreed
        {
            flips.push(mark);
        }
    }
    flips.sort_by_key(|mark| std::cmp::Reverse(mark.at));
    Ok(flips)
}

/// The calibration ask a retest flip raises, the judge's uncertainty on one
/// case: the skill whose anchor the pick joins, the judge's retest campaign,
/// and its two answers as options, the kept one first. Its evidence is the
/// case's ref. `None` for an agreeing retest or a case that names no skill.
pub(crate) fn retest_flip_ask(flip: &JudgeRetestMark) -> Option<(EntityId, String, [String; 2])> {
    if flip.agreed {
        return None;
    }
    let skill = flip
        .skill
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())?;
    Some((
        skill,
        retest_campaign(&flip.kept.judge),
        [label_option(&flip.kept), label_option(&flip.rerun)],
    ))
}

/// Whether a pick on the incumbent's retest flip of `case` already names
/// one of the case's answers: the label the next swap pass settles it by.
/// `false` for a case that names no skill or no answers.
///
/// # Errors
///
/// Storage errors reading the skill's judge anchor.
pub(crate) fn swap_case_retest_picked(vault: &Vault, case: &JudgeSwapDisagreement) -> Result<bool> {
    let Some(skill) = case
        .skill
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(false);
    };
    let Some(incumbent) = case.answers.first() else {
        return Ok(false);
    };
    Ok(
        judge_label_anchor(vault, skill, &retest_campaign(&incumbent.judge))?
            .iter()
            .any(|label| {
                label.ask.evidence == case.case_ref
                    && label_side(label, Some(incumbent.judge.as_str()), &case.answers).is_some()
            }),
    )
}
