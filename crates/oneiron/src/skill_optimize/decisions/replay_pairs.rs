//! The blind preference's pairs (FIX 1091). Each reserved response is scored
//! on its own task by the common judge rubric, and the responses whose scores
//! are closest pair: same-task pairs first, then the rest across tasks. The
//! preference question then reads each pair's responses and tasks only:
//! never a score, the rubric, a status or either version's instructions.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::Result;
use crate::llm::decision::{AnswerContract, cut_text, fit_state};
use crate::skill_optimize::{HeldOutReplayNotes, JudgeRubric};

use super::{ask, decided_score, put_rubric};

/// One reserved receipt's response as the host read it, whole: the task its
/// run was given and what it answered. Never its status, verdict, success
/// label or the instructions it ran under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillReplayResponse {
    pub receipt: String,
    pub task: String,
    pub response: String,
}

/// The responses one blind preference pairs, and the common judge rubric
/// (the active shared `judge` skill) each is scored by, read once for the
/// pass. While no rubric is in force, each is scored on its task alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkillReplayResponses {
    pub responses: Vec<SkillReplayResponse>,
    pub rubric: Option<JudgeRubric>,
}

/// One chosen pair: its ref, `first|second` by the two receipts, and the
/// preference question's state.
pub(super) struct BlindPair {
    pub(super) pair_ref: String,
    pub(super) state: Value,
}

/// At most `most` pairs of `receipts`' responses, closest scores first, each
/// with its preference state. Every response is put to the `response_score`
/// question on the scorer's own clock and journal; one that abstains or is
/// escalated has no score and pairs with none.
pub(super) fn blind_pairs<S: HeldOutReplayNotes + ?Sized>(
    scorer: &S,
    task: &str,
    receipts: &[String],
    most: usize,
) -> Result<Vec<BlindPair>> {
    let basis = scorer.replay_responses(receipts)?;
    let mut scores = Vec::with_capacity(basis.responses.len());
    for response in &basis.responses {
        let decision = ask(
            scorer,
            "response_score",
            &[],
            &score_state(response, basis.rubric.as_ref()),
            AnswerContract::Score { min: 0.0, max: 1.0 },
        )?;
        scores.push(decided_score(&decision));
    }
    Ok(closest(&basis.responses, &scores, most)
        .into_iter()
        .map(|[first, second]| pair_state(task, &basis.responses[first], &basis.responses[second]))
        .collect())
}

/// The `response_score` question's state: the response's receipt, task and
/// response, whole while the state fits the ladder's bound (else cut, saying
/// where), and the common rubric's text and pin (its skill, version and
/// digest) when one is in force. No other response and no instructions.
fn score_state(response: &SkillReplayResponse, rubric: Option<&JudgeRubric>) -> Value {
    fit_state(response.task.len().max(response.response.len()), |cut| {
        let mut state = json!({
            "receipt": response.receipt,
            "task": cut_text(&response.task, cut),
            "response": cut_text(&response.response, cut),
        });
        if let Some(rubric) = rubric {
            put_rubric(&mut state, rubric, None);
        }
        if let Some(bytes) = cut {
            state["cut_at_bytes"] = json!(bytes);
        }
        state
    })
}

/// The preference question's state for one pair: the skill's task, the
/// pair's ref, and both responses beside the tasks they answered, whole while
/// the state fits the ladder's bound (else cut, saying where).
fn pair_state(task: &str, first: &SkillReplayResponse, second: &SkillReplayResponse) -> BlindPair {
    let pair_ref = format!("{}|{}", first.receipt, second.receipt);
    let longest = first
        .response
        .len()
        .max(second.response.len())
        .max(first.task.len())
        .max(second.task.len());
    let state = fit_state(longest, |cut| {
        let mut responses = json!({
            "first": cut_text(&first.response, cut),
            "second": cut_text(&second.response, cut),
            "first_task": cut_text(&first.task, cut),
            "second_task": cut_text(&second.task, cut),
        });
        if let Some(bytes) = cut {
            responses["cut_at_bytes"] = json!(bytes);
        }
        json!({"task": task, "pair_ref": pair_ref, "responses": responses})
    });
    BlindPair { pair_ref, state }
}

/// The indices of at most `most` pairs, in the order they were chosen. Only
/// scored responses pair. While a task has two left, the pair taken is the
/// closest pair of neighbours in score order within any one task; then the
/// rest pair across tasks the same way. A tie in the gap goes to the pair
/// with the lesser receipts. No gap is too wide to pair. Each pair keeps
/// its two responses in the order they were given.
fn closest(
    responses: &[SkillReplayResponse],
    scores: &[Option<f32>],
    most: usize,
) -> Vec<[usize; 2]> {
    let mut scored: Vec<(usize, f32)> = scores
        .iter()
        .enumerate()
        .filter_map(|(at, score)| score.map(|score| (at, score)))
        .collect();
    scored.sort_by(|a, b| {
        a.1.total_cmp(&b.1)
            .then_with(|| responses[a.0].receipt.cmp(&responses[b.0].receipt))
    });
    let mut tasks: BTreeMap<&str, Vec<(usize, f32)>> = BTreeMap::new();
    for &(at, score) in &scored {
        tasks
            .entry(responses[at].task.as_str())
            .or_default()
            .push((at, score));
    }
    let same_task: Vec<Vec<(usize, f32)>> = tasks.into_values().collect();
    let mut paired = vec![false; responses.len()];
    let mut pairs = Vec::new();
    take_closest(responses, &same_task, &mut paired, &mut pairs, most);
    take_closest(responses, &[scored], &mut paired, &mut pairs, most);
    pairs
}

/// Until `pairs` holds `most`, takes the unpaired neighbours on any one of
/// `lines` (each in score order) with the least gap, ties to the lesser
/// receipts; stops when no line has two left.
fn take_closest(
    responses: &[SkillReplayResponse],
    lines: &[Vec<(usize, f32)>],
    paired: &mut [bool],
    pairs: &mut Vec<[usize; 2]>,
    most: usize,
) {
    while pairs.len() < most {
        let mut best: Option<(f32, [usize; 2])> = None;
        for line in lines {
            let mut open = line.iter().filter(|(at, _)| !paired[*at]);
            let Some(mut low) = open.next() else {
                continue;
            };
            for high in open {
                let gap = high.1 - low.1;
                let pair = [low.0.min(high.0), low.0.max(high.0)];
                let closer = best.is_none_or(|(least, held)| {
                    gap.total_cmp(&least)
                        .then_with(|| receipts(responses, pair).cmp(&receipts(responses, held)))
                        .is_lt()
                });
                if closer {
                    best = Some((gap, pair));
                }
                low = high;
            }
        }
        let Some((_, pair)) = best else {
            return;
        };
        paired[pair[0]] = true;
        paired[pair[1]] = true;
        pairs.push(pair);
    }
}

/// A pair's two receipts, the lesser first.
fn receipts(responses: &[SkillReplayResponse], [first, second]: [usize; 2]) -> (&str, &str) {
    let (first, second) = (
        responses[first].receipt.as_str(),
        responses[second].receipt.as_str(),
    );
    (first.min(second), first.max(second))
}
