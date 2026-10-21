//! Judge-swap disagreement construction and anchor settlement.
//! Entry function: `anchor`.
//! The `Anchors` state type remains defined in `super`.

use super::*;

/// A new disagreement, open, with the incumbent's kept answer first.
pub(super) fn disagreement(
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
pub(super) fn anchor(
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
pub(super) fn tie_break(
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
pub(super) fn sided<I>(cases: I, judge: &str) -> usize
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
pub(super) fn anchored<I>(cases: I, judge: &str) -> usize
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
/// for a structural or contrastive audit and for a response score, which
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
            let axis = state.get("axis")?;
            Some(JudgeOutcomeLink::Axis {
                skill: text(case, "skill")?,
                axis: text(axis, "name")?,
                receipts: receipts(case)?,
                goal_revision: text(axis, "goal_revision"),
            })
        }
        "honesty" => Some(JudgeOutcomeLink::Audit {
            receipt: text(state, "receipt")?,
        }),
        "tradeoff" => Some(JudgeOutcomeLink::Tradeoff {
            proposal: text(state.get("question")?, "proposal")?,
            digest: text(state, "digest")?,
        }),
        "preference" => Some(JudgeOutcomeLink::ResponsePair {
            pair_ref: text(state, "pair_ref")?,
        }),
        // `axis.<name>`; a structural, contrastive or response-score case
        // has none.
        _ => {
            let axis = kind.strip_prefix("axis.")?;
            Some(JudgeOutcomeLink::Axis {
                skill: text(state, "skill")?,
                axis: axis.to_owned(),
                receipts: receipts(state)?,
                goal_revision: text(state, "goal_revision"),
            })
        }
    }
}

/// The skill a case judged, as hex: a whole-skill, axis or honesty case
/// names it, a live-axis case in its nested case.
pub(super) fn judged_skill(state: &Value) -> Option<String> {
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
