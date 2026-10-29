//! Deterministic induction for the Coach's browser programs (CUA E8): one
//! candidate program from two solved runs of one exact group, or from one
//! run that repairs a failed program. Alignment is structural, step by step
//! and field by field. An ordinary type's text or select's option that
//! differs whole between the runs takes a `{{name}}` slot; every other part
//! of a step must agree; a check generalizes only where its whole value pair
//! is one slot's. A candidate that does not align, holds a gap or ran short
//! keeps its reasons and is a diagnostic, never complete. A secret slot keeps
//! its name and kind and needs binding again. No model, browser or store.
use std::collections::{BTreeMap, BTreeSet};

use oneiron_browser::{
    BatchStep, DraftGap, ExpectInput, ProposeInput, SecretParam, SlotField, WorkflowProgram,
    validate_replay_args,
};
use serde::Serialize;
use serde_json::Value;

use crate::browser_library::{CANDIDATE_DOMAIN, SolvedRunEvidence};
use crate::entity_id::bytes_to_hex_lower;
use crate::learning::TypeRef;
use crate::{EntityId, Error, Result};

/// The version of this induction, in each candidate's fingerprint and job.
pub(super) const INDUCTION_VERSION: u32 = 1;

/// How far a candidate got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    /// Aligned and verified, every parameter bound.
    Aligned,
    /// Aligned, with secret slots or arguments its admission binds again.
    NeedsBinding,
    /// Did not align, ran short or failed a check: its reasons say why.
    Diagnostic,
}

impl Status {
    /// Whether an admission job may take the candidate.
    pub(super) fn eligible(self) -> bool {
        !matches!(self, Self::Diagnostic)
    }
}

/// The failed program a repair supersedes, as its failure row names it.
#[derive(Debug, Clone, Serialize)]
pub(super) struct Predecessor {
    pub(super) id: String,
    pub(super) failures: u64,
    pub(super) retired: bool,
    pub(super) retire_reason: Option<String>,
    pub(super) supersedes: Option<String>,
    pub(super) successor: Option<String>,
}

/// One candidate program and the finding that proposes it.
#[derive(Debug, Clone)]
pub(super) struct Candidate {
    /// Its input fingerprint in [`CANDIDATE_DOMAIN`]: its seen marker's key.
    pub(super) fingerprint: [u8; 32],
    pub(super) status: Status,
    pub(super) proposal: ProposeInput,
    pub(super) from_runs: Vec<EntityId>,
    pub(super) source_evidence: Vec<EntityId>,
    /// The finding's stable value: no time, attempt or dirty generation.
    pub(super) value: Value,
}

/// One slot the induction made: its step and field, and each run's value.
#[derive(Debug, Clone, Serialize)]
struct SlotDecision {
    name: String,
    step: usize,
    field: SlotField,
    first: String,
    second: String,
}

/// The finding's body, which the fingerprint hashes.
#[derive(Serialize)]
struct Body<'a> {
    version: u32,
    kind: &'static str,
    group: String,
    site: &'a str,
    origin: &'a str,
    subgoal: &'a str,
    type_ref: &'a TypeRef,
    source_evidence: Vec<String>,
    from_runs: Vec<String>,
    spans: Vec<[u64; 2]>,
    status: Status,
    held_out: bool,
    proposal: &'a ProposeInput,
    slots: &'a [SlotDecision],
    secret_slots: &'a [SecretParam],
    gaps: Vec<&'a DraftGap>,
    reasons: &'a [String],
    predecessor: Option<&'a Predecessor>,
}

/// One run's program parts, its secret slots named as the first run's.
struct Side {
    steps: Vec<BatchStep>,
    checks: Vec<ExpectInput>,
    params: Vec<String>,
    args: BTreeMap<String, String>,
}

impl Side {
    fn of(evidence: &SolvedRunEvidence) -> Self {
        let proposal = &evidence.draft.proposal;
        Self {
            steps: proposal.steps.clone(),
            checks: evidence.checks.clone(),
            params: proposal.params.clone(),
            args: proposal.args.clone(),
        }
    }
}

#[derive(Default)]
struct Induction {
    reasons: Vec<String>,
    slots: Vec<SlotDecision>,
    taken: BTreeSet<String>,
}

/// The candidate `first` and `second` make in the group `group`: a pair
/// when `second` is another run, one run's literal program when it is none.
/// `predecessor` makes it a repair that supersedes that program.
///
/// # Errors
///
/// A body that does not encode.
pub(super) fn induce(
    group: &[u8; 32],
    first: &SolvedRunEvidence,
    second: Option<&SolvedRunEvidence>,
    predecessor: Option<&Predecessor>,
) -> Result<Candidate> {
    let mut induction = Induction::default();
    for source in std::iter::once(first).chain(second) {
        induction.source_reasons(source);
    }
    let one = Side::of(first);
    induction.taken.extend(one.params.iter().cloned());
    let two = second.map(|evidence| {
        let rename = induction.secret_names(&first.secret_slots, &evidence.secret_slots);
        induction.renamed(Side::of(evidence), &rename)
    });
    let (steps, checks, params, args, replay_args) = match (second, &two) {
        (Some(evidence), Some(two)) => {
            let steps = induction.align_steps(first, evidence, &one, two);
            let checks = induction.align_checks(&one.checks, &two.checks);
            if one.params != two.params {
                induction.reasons.push("the runs' parameters differ".into());
            }
            let slot_names = induction.slots.iter().map(|slot| slot.name.clone());
            let params: Vec<String> = one.params.iter().cloned().chain(slot_names).collect();
            let mut args = one.args.clone();
            let mut replay_args = BTreeMap::new();
            if !induction.slots.is_empty() {
                replay_args.clone_from(&two.args);
                for slot in &induction.slots {
                    args.insert(slot.name.clone(), slot.first.clone());
                    replay_args.insert(slot.name.clone(), slot.second.clone());
                }
            }
            (steps, checks, params, args, replay_args)
        }
        _ => (
            one.steps.clone(),
            one.checks.clone(),
            one.params.clone(),
            one.args.clone(),
            BTreeMap::new(),
        ),
    };
    let proposal = ProposeInput {
        subgoal: first.subgoal.clone(),
        params,
        steps,
        postcondition: checks,
        args,
        replay_args,
        supersedes: predecessor.map(|program| program.id.clone()),
        seed: None,
        candidate: None,
        secret_args: BTreeMap::new(),
        snapshot_bounds: None,
    };
    let program = WorkflowProgram {
        subgoal: proposal.subgoal.clone(),
        params: proposal.params.clone(),
        secret_params: first.secret_slots.clone(),
        steps: proposal.steps.clone(),
        postcondition: proposal.postcondition.clone(),
    };
    let held_out = induction.verify(&program, &proposal, &one, two.as_ref());
    let unbound = proposal
        .params
        .iter()
        .any(|param| !proposal.args.contains_key(param));
    let status = if !induction.reasons.is_empty() {
        Status::Diagnostic
    } else if !program.secret_params.is_empty() || unbound {
        Status::NeedsBinding
    } else {
        Status::Aligned
    };
    let sources: Vec<&SolvedRunEvidence> = std::iter::once(first).chain(second).collect();
    let source_evidence: Vec<EntityId> = sources.iter().map(|source| source.id).collect();
    let mut from_runs: Vec<EntityId> = Vec::new();
    for source in &sources {
        if !from_runs.contains(&source.run_id) {
            from_runs.push(source.run_id);
        }
    }
    let body = Body {
        version: INDUCTION_VERSION,
        kind: predecessor.map_or("pair", |_| "repair"),
        group: bytes_to_hex_lower(group),
        site: &first.site,
        origin: &first.origin,
        subgoal: &first.subgoal,
        type_ref: &first.type_ref,
        source_evidence: source_evidence.iter().map(EntityId::to_hex).collect(),
        from_runs: from_runs.iter().map(EntityId::to_hex).collect(),
        spans: sources
            .iter()
            .map(|source| [source.draft.after_seq, source.draft.through_seq])
            .collect(),
        status,
        held_out,
        proposal: &proposal,
        slots: &induction.slots,
        secret_slots: &first.secret_slots,
        gaps: sources
            .iter()
            .flat_map(|source| &source.draft.gaps)
            .collect(),
        reasons: &induction.reasons,
        predecessor,
    };
    let encode =
        |_: serde_json::Error| Error::InvariantViolation("browser program finding encode failed");
    let mut value = serde_json::to_value(&body).map_err(encode)?;
    let bytes = serde_json::to_vec(&value).map_err(encode)?;
    let fingerprint = digest(&[&INDUCTION_VERSION.to_be_bytes(), group, &bytes]);
    if let Value::Object(map) = &mut value {
        let hex = bytes_to_hex_lower(&fingerprint);
        map.insert("fingerprint".into(), Value::String(hex));
    }
    Ok(Candidate {
        fingerprint,
        status,
        proposal,
        from_runs,
        source_evidence,
        value,
    })
}

impl Induction {
    /// Why `evidence` cannot stand as it is: a draft short of complete, or
    /// one that pressed through.
    fn source_reasons(&mut self, evidence: &SolvedRunEvidence) {
        let id = evidence.id.to_hex();
        if !evidence.draft.complete {
            self.reasons
                .push(format!("evidence {id} drafted short of complete"));
        }
        if !evidence.draft.pressed_through.is_empty() {
            self.reasons
                .push(format!("evidence {id} drafted past a press"));
        }
    }

    /// The second run's secret slot names as the first's, by occurrence:
    /// the same number of slots, each of the same kind.
    fn secret_names(
        &mut self,
        first: &[SecretParam],
        second: &[SecretParam],
    ) -> BTreeMap<String, String> {
        let kinds = first.len() == second.len()
            && first
                .iter()
                .zip(second)
                .all(|(one, two)| one.kind == two.kind);
        if !kinds {
            self.reasons
                .push("the runs' secret slots differ in number or kind".into());
            return BTreeMap::new();
        }
        first
            .iter()
            .zip(second)
            .filter(|(one, two)| one.name != two.name)
            .map(|(one, two)| (two.name.clone(), one.name.clone()))
            .collect()
    }

    /// `side` with each secret slot `rename` names under its new name.
    fn renamed(&mut self, mut side: Side, rename: &BTreeMap<String, String>) -> Side {
        if rename.is_empty() {
            return side;
        }
        let slots: BTreeMap<String, String> = rename
            .iter()
            .map(|(from, to)| (slot(from), slot(to)))
            .collect();
        let steps = serde_json::to_value(&side.steps)
            .ok()
            .and_then(|mut steps| {
                rename_leaves(&mut steps, &slots);
                serde_json::from_value(steps).ok()
            });
        let checks = serde_json::to_value(&side.checks)
            .ok()
            .and_then(|mut checks| {
                rename_leaves(&mut checks, &slots);
                serde_json::from_value(checks).ok()
            });
        match (steps, checks) {
            (Some(steps), Some(checks)) => {
                side.steps = steps;
                side.checks = checks;
            }
            _ => self
                .reasons
                .push("the second run's secret slots do not rename".into()),
        }
        for param in &mut side.params {
            if let Some(to) = rename.get(param) {
                param.clone_from(to);
            }
        }
        side.args = side
            .args
            .into_iter()
            .map(|(name, value)| (rename.get(&name).cloned().unwrap_or(name), value))
            .collect();
        side
    }

    /// The steps both runs take: equal steps as they are, and each ordinary
    /// text or option that differs whole as a slot.
    fn align_steps(
        &mut self,
        first: &SolvedRunEvidence,
        second: &SolvedRunEvidence,
        one: &Side,
        two: &Side,
    ) -> Vec<BatchStep> {
        if one.steps.len() != two.steps.len() {
            self.reasons.push(format!(
                "the runs take {} and {} steps",
                one.steps.len(),
                two.steps.len()
            ));
            return one.steps.clone();
        }
        let mut steps = Vec::with_capacity(one.steps.len());
        for (step, (a, b)) in one.steps.iter().zip(&two.steps).enumerate() {
            let differing = match (a, b) {
                (
                    BatchStep::Type {
                        target,
                        text: Some(x),
                        secret: None,
                        clear,
                    },
                    BatchStep::Type {
                        target: other,
                        text: Some(y),
                        secret: None,
                        clear: cleared,
                    },
                ) if target == other && clear == cleared => Some((SlotField::Text, x, y)),
                (
                    BatchStep::Select { target, option: x },
                    BatchStep::Select {
                        target: other,
                        option: y,
                    },
                ) if target == other => Some((SlotField::Choice, x, y)),
                _ => None,
            }
            .filter(|(_, x, y)| x != y && !is_slot(x) && !is_slot(y));
            if let Some((field, x, y)) = differing {
                let suggested = first
                    .draft
                    .slot_candidates
                    .iter()
                    .chain(&second.draft.slot_candidates)
                    .find(|candidate| candidate.step == step && candidate.field == field)
                    .map(|candidate| candidate.suggested_param.as_str());
                let name = self.name(step, field, suggested);
                steps.push(templated(a, &name));
                self.slots.push(SlotDecision {
                    name,
                    step,
                    field,
                    first: x.clone(),
                    second: y.clone(),
                });
                continue;
            }
            if serde_json::to_value(a).ok() != serde_json::to_value(b).ok() {
                self.reasons
                    .push(format!("step {step} differs between the runs"));
            }
            steps.push(a.clone());
        }
        steps
    }

    /// A slot name for `step`'s `field`: the draft's suggestion, else one
    /// from the step and field, made distinct with `_2`, `_3` and so on.
    fn name(&mut self, step: usize, field: SlotField, suggested: Option<&str>) -> String {
        let field_name = match field {
            SlotField::Text => "text",
            SlotField::Choice => "option",
        };
        let base = suggested
            .filter(|name| slot_name(name))
            .map_or_else(|| format!("step{step}_{field_name}"), str::to_owned);
        let mut name = base.clone();
        let mut next = 2_u32;
        while self.taken.contains(&name) {
            name = format!("{base}_{next}");
            next += 1;
        }
        self.taken.insert(name.clone());
        name
    }

    /// The checks both runs met, each generalized where it can be.
    fn align_checks(&mut self, one: &[ExpectInput], two: &[ExpectInput]) -> Vec<ExpectInput> {
        if one.len() != two.len() {
            self.reasons.push(format!(
                "the runs met {} and {} checks",
                one.len(),
                two.len()
            ));
            return one.to_vec();
        }
        one.iter()
            .zip(two)
            .enumerate()
            .map(|(at, (a, b))| self.align_check(at, a, b))
            .collect()
    }

    /// Check `at`, every differing field a slot whose whole value pair it
    /// is, and that slot alone.
    fn align_check(&mut self, at: usize, a: &ExpectInput, b: &ExpectInput) -> ExpectInput {
        let (Ok(Value::Object(mut one)), Ok(Value::Object(two))) =
            (serde_json::to_value(a), serde_json::to_value(b))
        else {
            self.reasons.push(format!("check {at} does not encode"));
            return a.clone();
        };
        if one == two {
            return a.clone();
        }
        if one.len() != two.len() || one.keys().any(|key| !two.contains_key(key)) {
            self.reasons
                .push(format!("check {at} differs in its fields"));
            return a.clone();
        }
        for (key, value) in &mut one {
            let other = two.get(key);
            if Some(&*value) == other {
                continue;
            }
            let pair = value.as_str().zip(other.and_then(Value::as_str));
            match pair.and_then(|(x, y)| self.unique_slot(x, y)) {
                Some(name) => *value = Value::String(slot(&name)),
                None => {
                    self.reasons
                        .push(format!("check {at}'s {key} differs with no one slot"));
                    return a.clone();
                }
            }
        }
        match serde_json::from_value(Value::Object(one)) {
            Ok(check) => check,
            Err(_) => {
                self.reasons
                    .push(format!("check {at} does not decode with its slot"));
                a.clone()
            }
        }
    }

    /// The one slot whose values are `x` and `y`, if exactly one is.
    fn unique_slot(&self, x: &str, y: &str) -> Option<String> {
        let mut found = self
            .slots
            .iter()
            .filter(|slot| slot.first == x && slot.second == y);
        let slot = found.next()?;
        found.next().is_none().then(|| slot.name.clone())
    }

    /// Whether `program` holds its shape, holds values out, and, bound,
    /// reproduces each run's steps and checks; returns its held-out claim.
    fn verify(
        &mut self,
        program: &WorkflowProgram,
        proposal: &ProposeInput,
        one: &Side,
        two: Option<&Side>,
    ) -> bool {
        if let Err(error) = program.site() {
            self.reasons.push(format!("the program's shape: {error}"));
        }
        let held_out = match validate_replay_args(program, &proposal.args, &proposal.replay_args) {
            Ok(held_out) => held_out,
            Err(refusal) => {
                self.reasons
                    .push(format!("its held-out values: {refusal:?}"));
                false
            }
        };
        let bound = program
            .params
            .iter()
            .all(|param| proposal.args.contains_key(param));
        if !program.secret_params.is_empty() || !bound {
            return held_out;
        }
        self.reproduces("first", program, &proposal.args, one);
        if let Some(two) = two {
            let replay = if proposal.replay_args.is_empty() {
                &proposal.args
            } else {
                &proposal.replay_args
            };
            self.reproduces("second", program, replay, two);
        }
        held_out
    }

    /// Whether `program` filled from `args` takes `side`'s steps and checks.
    fn reproduces(
        &mut self,
        which: &str,
        program: &WorkflowProgram,
        args: &BTreeMap<String, String>,
        side: &Side,
    ) {
        match program.fill(args) {
            Ok((steps, checks)) => {
                let same = serde_json::to_value(&steps).ok()
                    == serde_json::to_value(&side.steps).ok()
                    && serde_json::to_value(&checks).ok()
                        == serde_json::to_value(&side.checks).ok();
                if !same {
                    self.reasons
                        .push(format!("it does not reproduce the {which} run"));
                }
            }
            Err(error) => self
                .reasons
                .push(format!("filling it for the {which} run: {error}")),
        }
    }
}

/// `step`, a type or select, with its text or option the slot `name`.
fn templated(step: &BatchStep, name: &str) -> BatchStep {
    let mut step = step.clone();
    match &mut step {
        BatchStep::Type { text, .. } => *text = Some(slot(name)),
        BatchStep::Select { option, .. } => *option = slot(name),
        _ => {}
    }
    step
}

/// Each string leaf of `value` that is a key of `slots`, as its value.
fn rename_leaves(value: &mut Value, slots: &BTreeMap<String, String>) {
    match value {
        Value::String(text) => {
            if let Some(to) = slots.get(text.as_str()) {
                text.clone_from(to);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|item| rename_leaves(item, slots)),
        Value::Object(map) => map.values_mut().for_each(|item| rename_leaves(item, slots)),
        _ => {}
    }
}

/// The slot `name`, as a step or check writes it.
fn slot(name: &str) -> String {
    format!("{{{{{name}}}}}")
}

/// Whether `text` is a whole slot.
fn is_slot(text: &str) -> bool {
    text.starts_with("{{") && text.ends_with("}}")
}

/// Whether `name` is a slot name a program takes: a-z, 0-9 and _, from a
/// letter.
fn slot_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// BLAKE3 over `parts` in [`CANDIDATE_DOMAIN`], each part length-delimited.
fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CANDIDATE_DOMAIN);
    for part in parts {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(&len.to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}
