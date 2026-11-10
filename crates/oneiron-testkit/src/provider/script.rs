//! The script both scripted model doors answer from: the steps, which of
//! them have answered, every call seen, and every violation. Shared by
//! [`super::ScriptedProvider`] (HTTP) and [`super::ScriptedBackend`] (in
//! process).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde_json::Value;

use super::digest::{PromptDigest, canonical_json, prompt_of};
use super::{Mode, Reply, Step};

/// How much of a missed prompt the report prints.
const REPORT_PROMPT_BYTES: usize = 4096;

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One call a scripted door received.
#[derive(Debug, Clone, PartialEq)]
pub struct SeenCall {
    /// The step that answered it; `None` when none did.
    pub step: Option<String>,
    /// The HTTP method, or `generate` / `stream` for [`super::ScriptedBackend`].
    pub method: String,
    /// The HTTP path, or the model id for [`super::ScriptedBackend`].
    pub path: String,
    /// The prompt digest, for a chat, messages or backend call.
    pub digest: Option<PromptDigest>,
    /// Whether the call asked for a stream.
    pub streamed: bool,
    /// The model the call named.
    pub model: Option<String>,
    /// The request body as JSON (`null` when it was not JSON).
    pub body: Value,
}

/// Everything that went wrong between a script and the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMismatch {
    pub violations: Vec<String>,
}

impl fmt::Display for ProviderMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "oneiron-testkit scripted model: {} violation(s)",
            self.violations.len()
        )?;
        for violation in &self.violations {
            writeln!(f, "- {violation}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ProviderMismatch {}

struct StepState {
    step: Step,
    uses: usize,
}

pub(crate) struct Script {
    steps: Mutex<Vec<StepState>>,
    seen: Mutex<Vec<SeenCall>>,
    violations: Mutex<Vec<String>>,
}

impl Script {
    /// The script of `steps`, with the barrier names they hold at.
    ///
    /// # Errors
    /// Two steps share an id or a barrier.
    pub(crate) fn new(steps: Vec<Step>) -> io::Result<(Self, BTreeSet<String>)> {
        let mut ids = BTreeSet::new();
        let mut barriers = BTreeSet::new();
        for step in &steps {
            if !ids.insert(step.id.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("two steps have the id {:?}", step.id),
                ));
            }
            if let Some(name) = &step.hold {
                if !barriers.insert(name.clone()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("two steps hold at the barrier {name:?}"),
                    ));
                }
            }
        }
        let script = Self {
            steps: Mutex::new(
                steps
                    .into_iter()
                    .map(|step| StepState { step, uses: 0 })
                    .collect(),
            ),
            seen: Mutex::new(Vec::new()),
            violations: Mutex::new(Vec::new()),
        };
        Ok((script, barriers))
    }

    pub(crate) fn violate(&self, violation: String) {
        eprintln!("oneiron-testkit scripted model violation: {violation}");
        lock(&self.violations).push(violation);
    }

    pub(crate) fn see(&self, call: SeenCall) {
        lock(&self.seen).push(call);
    }

    pub(crate) fn seen(&self) -> Vec<SeenCall> {
        lock(&self.seen).clone()
    }

    /// The models the steps pin, sorted and unique.
    pub(crate) fn models(&self) -> Vec<String> {
        let models: BTreeSet<String> = lock(&self.steps)
            .iter()
            .filter_map(|state| state.step.model.clone())
            .collect();
        models.into_iter().collect()
    }

    /// The first step for `digest` that may still answer, marked used.
    pub(crate) fn take(&self, digest: &PromptDigest) -> Option<Step> {
        let mut steps = lock(&self.steps);
        let state = steps.iter_mut().find(|state| {
            state.step.digest == *digest && (state.step.standing || state.uses == 0)
        })?;
        state.uses += 1;
        Some(state.step.clone())
    }

    /// The violations so far, plus every step that answers once and was
    /// never requested.
    pub(crate) fn check(&self) -> Result<(), ProviderMismatch> {
        let mut violations = lock(&self.violations).clone();
        for state in lock(&self.steps).iter() {
            if !state.step.standing && state.uses == 0 {
                violations.push(format!(
                    "step {:?} (prompt digest {}) was never requested",
                    state.step.id, state.step.digest
                ));
            }
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(ProviderMismatch { violations })
        }
    }

    /// The step for `seen`'s prompt, checked against the call's mode and
    /// model; on any mismatch the violation is recorded and returned.
    pub(crate) fn answer(&self, seen: &mut SeenCall, prompt_body: &Value) -> Result<Step, String> {
        let digest = PromptDigest::of_request(prompt_body);
        seen.digest = Some(digest.clone());
        let Some(step) = self.take(&digest) else {
            self.violate(miss_report(&digest, seen, prompt_body));
            return Err(format!("no scripted reply for prompt digest {digest}"));
        };
        seen.step = Some(step.id.clone());
        let mismatch = shape_mismatch(&step, seen.streamed).or_else(|| {
            step.model.as_ref().and_then(|expected| {
                (seen.model.as_deref() != Some(expected.as_str())).then(|| {
                    format!(
                        "step {:?} expects model {expected:?}; the engine asked for {:?}",
                        step.id, seen.model
                    )
                })
            })
        });
        match mismatch {
            Some(mismatch) => {
                self.violate(mismatch.clone());
                Err(mismatch)
            }
            None => Ok(step),
        }
    }
}

fn miss_report(digest: &PromptDigest, seen: &SeenCall, prompt_body: &Value) -> String {
    let prompt = canonical_json(&prompt_of(prompt_body));
    let shown = if prompt.len() > REPORT_PROMPT_BYTES {
        let mut end = REPORT_PROMPT_BYTES;
        while !prompt.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}... ({} bytes)", &prompt[..end], prompt.len())
    } else {
        prompt
    };
    format!(
        "no scripted reply for prompt digest {digest}\n  call: {} {} (model {}, {})\n  prompt: {shown}\n  script it: Step::text(\"<id>\", PromptDigest::from_hex(\"{digest}\").expect(\"digest\"), \"<reply>\")",
        seen.method,
        seen.path,
        seen.model.as_deref().unwrap_or("none"),
        if seen.streamed { "streamed" } else { "buffered" },
    )
}

fn shape_mismatch(step: &Step, streamed: bool) -> Option<String> {
    let wanted = match (step.mode, &step.reply) {
        (Mode::Streamed, _) if !streamed => "a streamed request",
        (Mode::Buffered, _) if streamed => "a buffered request",
        (_, Reply::Json(_) | Reply::Body { .. }) if streamed => {
            "a buffered request (its reply is one JSON body)"
        }
        (_, Reply::Events(_) | Reply::CutStream { .. }) if !streamed => {
            "a streamed request (its reply is an event stream)"
        }
        _ => return None,
    };
    Some(format!(
        "step {:?} expects {wanted}; the engine sent a {} one (\"stream\": {streamed})",
        step.id,
        if streamed { "streamed" } else { "buffered" },
    ))
}

/// The barriers a provider's held steps wait at.
#[derive(Default)]
pub(crate) struct BarrierState {
    pub(crate) reached: bool,
    pub(crate) released: bool,
}

pub(crate) fn barrier_map(names: BTreeSet<String>) -> BTreeMap<String, BarrierState> {
    names
        .into_iter()
        .map(|name| (name, BarrierState::default()))
        .collect()
}
