//! A long revision's synthesis (FIX 7549): its answers, in order, joined in
//! batches whose requests each fit the window, level after level, with no
//! total on the levels; and its final answer, assembled from the last level
//! once one answer stands or no batch joins two. An answer too long to join
//! another stands alone and is carried up, never dropped. The answers go to
//! the model as data, never as an instruction.
use oneiron::EntityId;
use oneiron::feedback::{
    FeedbackTriageInput, FeedbackTriageNodeInput, FeedbackTriageOutput, FeedbackTriageSourceRef,
    FeedbackTriageWork, FeedbackTriageWorkNode,
};
use serde::Serialize;

use super::parts::{self, Window};
use super::unavailable;

/// The data one synthesis reads: an ordered batch of answers of the level
/// below, with the ids their findings cite.
#[derive(Serialize)]
struct SynthesisData<'a> {
    source_ref: &'a FeedbackTriageSourceRef,
    evidence: &'a EntityId,
    synthesis: SynthesisLevel,
    answers: &'a [&'a FeedbackTriageOutput],
}

/// The level a synthesis answers at: one above its answers.
#[derive(Serialize)]
struct SynthesisLevel {
    level: u32,
}

fn data(
    source_ref: &FeedbackTriageSourceRef,
    evidence: &EntityId,
    level: u32,
    answers: &[&FeedbackTriageOutput],
) -> oneiron::Result<String> {
    serde_json::to_string(&SynthesisData {
        source_ref,
        evidence,
        synthesis: SynthesisLevel { level },
        answers,
    })
    .map_err(|_| unavailable("a feedback triage synthesis could not be encoded"))
}

/// A synthesis child's data, from its node's input answers.
pub(super) fn node_data(input: &FeedbackTriageNodeInput) -> oneiron::Result<String> {
    let answers: Vec<&FeedbackTriageOutput> = input.answers.iter().collect();
    data(
        &input.source_ref,
        &input.evidence,
        input.node.level,
        &answers,
    )
}

/// Each node's id and answer, in order.
fn answered<'n>(
    nodes: &[&'n FeedbackTriageWorkNode],
) -> oneiron::Result<Vec<(u32, &'n FeedbackTriageOutput)>> {
    nodes
        .iter()
        .map(|node| {
            node.answer
                .as_ref()
                .map(|answer| (node.id, &answer.output))
                .ok_or_else(|| unavailable("a feedback triage level holds an unanswered node"))
        })
        .collect()
}

/// `answers`, in order, in batches whose level-`level` requests each fit
/// the window beside `instruction`: each batch the longest run that fits
/// from where the last ended, an answer that joins none standing alone.
fn batch(
    input: &FeedbackTriageInput,
    answers: &[(u32, &FeedbackTriageOutput)],
    level: u32,
    window: &Window,
    instruction: &str,
) -> oneiron::Result<Vec<Vec<u32>>> {
    let mut batches = Vec::new();
    let mut ids = Vec::new();
    let mut held = Vec::new();
    for &(id, answer) in answers {
        held.push(answer);
        if !ids.is_empty() {
            let data = data(&input.source_ref, &input.evidence, level, &held)?;
            if !parts::fits(window.input_tokens, instruction, &data) {
                batches.push(std::mem::take(&mut ids));
                held.clear();
                held.push(answer);
            }
        }
        ids.push(id);
    }
    if !ids.is_empty() {
        batches.push(ids);
    }
    Ok(batches)
}

/// The current level of a graph that owes nothing, in batches for the
/// next level.
pub(super) fn batches(
    input: &FeedbackTriageInput,
    work: &FeedbackTriageWork,
    nodes: &[&FeedbackTriageWorkNode],
    window: &Window,
    instruction: &str,
) -> oneiron::Result<Vec<Vec<u32>>> {
    let level = work
        .level()
        .checked_add(1)
        .ok_or_else(|| unavailable("a feedback triage graph has no level above its last"))?;
    batch(input, &answered(nodes)?, level, window, instruction)
}

/// An unanswered synthesis node's inputs batched again for a changed
/// window; `None` while they still fit as one.
pub(super) fn split(
    input: &FeedbackTriageInput,
    work: &FeedbackTriageWork,
    node: &FeedbackTriageWorkNode,
    window: &Window,
    instruction: &str,
) -> oneiron::Result<Option<Vec<Vec<u32>>>> {
    let inputs = node
        .inputs
        .iter()
        .map(|id| work.node(*id))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| unavailable("a feedback triage synthesis names a missing input"))?;
    let batches = batch(input, &answered(&inputs)?, node.level, window, instruction)?;
    Ok((batches.len() > 1).then_some(batches))
}

/// The final answer of a level no batch joins: its one answer, or every
/// answer's findings in order; and the models that answered, each once.
pub(super) fn assemble(nodes: &[&FeedbackTriageWorkNode]) -> (FeedbackTriageOutput, String) {
    let mut findings = Vec::new();
    let mut models: Vec<&str> = Vec::new();
    for answer in nodes.iter().filter_map(|node| node.answer.as_ref()) {
        findings.extend(answer.output.findings.iter().cloned());
        if !models.contains(&answer.served_model.as_str()) {
            models.push(&answer.served_model);
        }
    }
    (FeedbackTriageOutput { findings }, models.join(", "))
}
