//! Alignment of a candidate's checks and reproduction of its solved runs.
use std::collections::BTreeMap;

use oneiron_browser::{ExpectInput, ProposeInput, WorkflowProgram, validate_replay_args};
use serde_json::Value;

use super::{Induction, Side, slot};

impl Induction {
    /// The checks both runs met, each generalized where it can be.
    pub(super) fn align_checks(
        &mut self,
        one: &[ExpectInput],
        two: &[ExpectInput],
    ) -> Vec<ExpectInput> {
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
    pub(super) fn verify(
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
