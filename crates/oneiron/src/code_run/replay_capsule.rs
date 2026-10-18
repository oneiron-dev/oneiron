//! Step replay capsules (FIX 3028, ARCH-0037 #lineage-credit, ARCH-0053):
//! the exact model input of a canonical attempt's first step, captured
//! before it was sent, with each skill body the host put in it tagged where
//! it sits. A contribution check regenerates that step from its capsule with
//! and without one skill's body ([`super::run_contribution_forks`]); nothing
//! is rebuilt from today's skill or today's context.
//!
//! A capture is staged before the call and finalized with the rung that
//! answered it: that rung's model and the route prompt it put first, so the
//! capsule holds what was really sent. The host's ladder names the rung on
//! the thread that made the call ([`note_answering_rung`]), and the capture
//! site finalizes once the call is done ([`finalize_step_captures`]). A
//! capture that fails, or a call no rung answered, leaves no replayable
//! capsule, and the live step goes on as if none was asked.
//!
//! An executor step's capsule also holds the run's state before the step
//! (FIX 3694): its replay row as stored, with the config and teaching it ran
//! under, in a body the run owns. A continuation of a failed run forks from
//! the start of its failing step.

use std::cell::RefCell;

use serde::{Deserialize, Serialize};

use super::codec::encode_code_run_replay_record;
use super::replay::CodeRunReplayRecord;
use super::storage::{finalize_capsule, put_capsule, store_capsule_request, store_capsule_start};
use crate::attempt_queue::AttemptId;
use crate::compaction::output::OutputRef;
use crate::llm::ReasoningEffort;
use crate::vault::VaultId;
use crate::{
    ContentPart, EntityId, LlmMessage, LlmRequest, ModelId, ModelLocality, ModelTierRef, Result,
    Vault,
};

/// The most staged captures one thread holds while their calls are out. A
/// thread that stages more drops its oldest, which then stays unreplayable.
const AWAITING_CAP: usize = 16;

/// One skill body the host put in a run's task, and where it went: the byte
/// span in the task, separator included, and the hash of those bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskExposure {
    /// The entity whose body loaded.
    pub skill: EntityId,
    /// The revision that loaded, `skill_id@version`.
    pub revision: String,
    /// BLAKE3 of the task bytes in `start..end`.
    pub content_hash: [u8; 32],
    pub start: usize,
    pub end: usize,
}

impl TaskExposure {
    /// Appends `body` to `task` after `separator`, as a host puts a skill's
    /// body in a run's task, and returns where it went. A control fork
    /// removes the separator and the body together, leaving the task as it
    /// was before.
    #[must_use]
    pub fn append(
        task: &mut String,
        separator: &str,
        body: &str,
        skill: EntityId,
        revision: String,
    ) -> Self {
        let start = task.len();
        task.push_str(separator);
        task.push_str(body);
        let end = task.len();
        Self {
            skill,
            revision,
            content_hash: *blake3::hash(&task.as_bytes()[start..end]).as_bytes(),
            start,
            end,
        }
    }
}

/// What a capsule's exposure put in front of the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureKind {
    /// A skill's body as knowledge in the model's input.
    Knowledge,
}

/// One exposure in a captured request: the skill, its revision and the hash
/// of its bytes, at a byte span of one text part of one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureSlot {
    pub skill: EntityId,
    pub revision: String,
    pub content_hash: [u8; 32],
    pub kind: ExposureKind,
    pub message: u32,
    pub part: u32,
    pub start: u64,
    pub end: u64,
}

impl ExposureSlot {
    /// The slot's text part in `request` and its byte range there, when the
    /// part is text, the range falls on its character boundaries and its
    /// bytes still hash to the slot's.
    pub(crate) fn locate<'r>(
        &self,
        request: &'r LlmRequest,
    ) -> Option<(&'r str, std::ops::Range<usize>)> {
        let message = request.messages.get(usize::try_from(self.message).ok()?)?;
        let ContentPart::Text { text } = message.content.get(usize::try_from(self.part).ok()?)?
        else {
            return None;
        };
        let range = usize::try_from(self.start).ok()?..usize::try_from(self.end).ok()?;
        let bytes = text.get(range.clone())?;
        (*blake3::hash(bytes.as_bytes()).as_bytes() == self.content_hash).then_some((text, range))
    }
}

/// Which host built the captured step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleHost {
    /// A step of the engine's code executor.
    EngineStep,
    /// A saved-workflow step's single text call.
    WorkflowStep,
}

/// The rung that answered a captured call: its model, where it ran and the
/// route prompt it put first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleRungBinding {
    pub model: ModelId,
    pub locality: ModelLocality,
    pub prompt: Option<String>,
}

/// One captured step of a canonical attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepReplayCapsule {
    pub attempt: EntityId,
    pub lease_generation: u32,
    /// The run the step belongs to; it owns the request's body.
    pub run: EntityId,
    pub step: u64,
    pub host: CapsuleHost,
    /// The request as assembled and bound, before its route's prompt, by its
    /// body ref: its canonical JSON.
    pub request: OutputRef,
    pub request_path: String,
    /// The request's canonical hash.
    pub request_hash: [u8; 32],
    /// The hash of its messages, which the answering rung is matched by.
    pub messages_digest: [u8; 32],
    pub exposures: Vec<ExposureSlot>,
    /// The sampling seed the request carried, if any.
    pub seed: Option<u64>,
    /// The rung that answered; `None` while staged, and for good when no
    /// rung answered it.
    pub binding: Option<CapsuleRungBinding>,
    /// Unix seconds it was captured.
    pub captured_at: u64,
    /// The executor run's state before the step; `None` for a workflow step
    /// and for a start that was not captured.
    pub start: Option<ExecutorStepStart>,
}

/// The executor run's state before the step (FIX 3694): what a
/// continuation forks from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorStepStart {
    /// The start body (its encoded prefix row, its config, its teaching
    /// fingerprint), owned by the run.
    pub body: OutputRef,
    pub path: String,
    /// BLAKE3 of the body bytes.
    pub digest: [u8; 32],
    /// The bridge log's length at the step's start.
    pub bridge_start: u64,
}

/// The body an [`ExecutorStepStart`] names: the run's replay row as stored
/// before the step, with no live-run binding, and what the run ran under.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StepStartBody {
    /// The prefix row, as [`encode_code_run_replay_record`] encodes it.
    pub(crate) record: Vec<u8>,
    pub(crate) task: String,
    pub(crate) model: ModelId,
    pub(crate) model_locality: ModelLocality,
    pub(crate) seat_effort: Option<ReasoningEffort>,
    pub(crate) global_tier: ModelTierRef,
    pub(crate) soft_steps: u32,
    pub(crate) hard_steps: u32,
    /// The resolved teaching the run's provider work was produced under.
    pub(crate) prompt_fingerprint: String,
}

/// One step a capture site is about to send.
pub(crate) struct StepCapture<'a> {
    pub(crate) attempt: AttemptId,
    pub(crate) lease_generation: u32,
    pub(crate) run: EntityId,
    pub(crate) step: u64,
    pub(crate) host: CapsuleHost,
    pub(crate) request: &'a LlmRequest,
    /// The task the request carries, which `exposures` index into.
    pub(crate) task: &'a str,
    pub(crate) exposures: &'a [TaskExposure],
    /// An executor step's run state and config; `None` for a workflow step.
    pub(crate) start: Option<StepStartCapture<'a>>,
}

/// An executor step's run as the step starts: its row as it stands, and the
/// config fields and teaching fingerprint it runs under.
pub(crate) struct StepStartCapture<'a> {
    pub(crate) record: &'a CodeRunReplayRecord,
    pub(crate) model: &'a ModelId,
    pub(crate) model_locality: ModelLocality,
    pub(crate) seat_effort: Option<ReasoningEffort>,
    pub(crate) global_tier: &'a ModelTierRef,
    pub(crate) soft_steps: u32,
    pub(crate) hard_steps: u32,
    pub(crate) prompt_fingerprint: &'a str,
}

/// A staged capture waiting for its call's answering rung.
struct Awaiting {
    vault: VaultId,
    key: (EntityId, u64, u64),
    messages: [u8; 32],
    binding: Option<CapsuleRungBinding>,
}

thread_local! {
    /// The captures this thread staged whose calls are out. A ladder answers
    /// a call on the thread that made it, so the rung that answered is noted
    /// here and written when the capture site finalizes.
    static AWAITING: RefCell<Vec<Awaiting>> = const { RefCell::new(Vec::new()) };
}

/// The hash a captured request and the call a ladder sends for it share:
/// their messages, which admission and a rung's binding leave as they are
/// (the route prompt is a new first message, never a change to these).
fn messages_digest(messages: &[LlmMessage]) -> Option<[u8; 32]> {
    let bytes = serde_json::to_vec(messages).ok()?;
    Some(*blake3::hash(&bytes).as_bytes())
}

/// Notes the rung that answered `request` for the capture on this thread
/// that staged the same messages. A host's ladder calls it once a rung has
/// answered; with no capture waiting on this thread it does nothing.
pub fn note_answering_rung(
    request: &LlmRequest,
    model: &ModelId,
    locality: ModelLocality,
    prompt: Option<&str>,
) {
    AWAITING.with(|awaiting| {
        let mut awaiting = awaiting.borrow_mut();
        if awaiting.is_empty() {
            return;
        }
        let Some(digest) = messages_digest(&request.messages) else {
            return;
        };
        for entry in awaiting.iter_mut().filter(|entry| entry.messages == digest) {
            entry.binding = Some(CapsuleRungBinding {
                model: model.clone(),
                locality,
                prompt: prompt.map(str::to_owned),
            });
        }
    });
}

/// Finalizes this thread's staged captures for `vault`, once their calls are
/// done: each that a rung answered takes that rung, and each that none did
/// stays unreplayable. A capture site calls it after its step's call; a
/// failure is logged and never fails the step.
pub fn finalize_step_captures(vault: &Vault) {
    let id = vault.vault_id();
    let mine: Vec<Awaiting> = AWAITING.with(|awaiting| {
        let mut awaiting = awaiting.borrow_mut();
        let (mine, rest) = std::mem::take(&mut *awaiting)
            .into_iter()
            .partition(|entry| entry.vault == id);
        *awaiting = rest;
        mine
    });
    for entry in mine {
        let Some(binding) = entry.binding else {
            continue;
        };
        if let Err(error) = finalize_capsule(vault, &entry.key, binding) {
            tracing::warn!(kind = ?error.kind(), "a step replay capsule was not finalized");
        }
    }
}

/// Captures a saved-workflow step's admitted request before it is sent: the
/// step is its attempt's only call. Finalize it with
/// [`finalize_step_captures`] once the call is done. A failure is logged and
/// never fails the step.
pub fn capture_workflow_step(
    vault: &Vault,
    attempt: AttemptId,
    lease_generation: u32,
    request: &LlmRequest,
) {
    let Ok(run) = EntityId::from_bytes(*attempt.as_bytes()) else {
        return;
    };
    capture_step(
        vault,
        &StepCapture {
            attempt,
            lease_generation,
            run,
            step: 0,
            host: CapsuleHost::WorkflowStep,
            request,
            task: "",
            exposures: &[],
            start: None,
        },
    );
}

/// Stages `capture` as its attempt's capsule, after finalizing what this
/// thread staged for the vault before. A failure is logged and never fails
/// the step.
pub(crate) fn capture_step(vault: &Vault, capture: &StepCapture<'_>) {
    finalize_step_captures(vault);
    match stage(vault, capture) {
        Ok(Some(awaiting)) => AWAITING.with(|staged| {
            let mut staged = staged.borrow_mut();
            if staged.len() >= AWAITING_CAP {
                staged.remove(0);
            }
            staged.push(awaiting);
        }),
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a step replay capsule was not captured");
        }
    }
}

/// Writes the capsule's request body and its row; `None` for a request
/// whose messages cannot be hashed.
fn stage(vault: &Vault, capture: &StepCapture<'_>) -> Result<Option<Awaiting>> {
    let Some(messages) = messages_digest(&capture.request.messages) else {
        return Ok(None);
    };
    let bytes = capture
        .request
        .canonical_bytes()
        .map_err(|error| crate::Error::InvalidConfig(format!("capsule request: {error}")))?;
    let attempt = EntityId::from_bytes(*capture.attempt.as_bytes())?;
    let path = format!(
        "replay/capsule/{}/{:06}.request.json",
        capture.lease_generation, capture.step
    );
    let request = store_capsule_request(vault, capture.run, path.clone(), &bytes)?;
    // A start that fails is logged, and the capsule goes on without it.
    let start = capture.start.as_ref().and_then(|start| {
        stage_start(vault, capture, start).unwrap_or_else(|error| {
            tracing::warn!(kind = ?error.kind(), "a step start was not captured");
            None
        })
    });
    let capsule = StepReplayCapsule {
        attempt,
        lease_generation: capture.lease_generation,
        run: capture.run,
        step: capture.step,
        host: capture.host,
        request,
        request_path: path,
        request_hash: *blake3::hash(&bytes).as_bytes(),
        messages_digest: messages,
        exposures: slots(capture),
        seed: capture
            .request
            .params
            .get("seed")
            .and_then(serde_json::Value::as_u64),
        binding: None,
        captured_at: crate::unix_seconds_now(),
        start,
    };
    let key = (attempt, u64::from(capture.lease_generation), capture.step);
    put_capsule(vault, &key, &capsule)?;
    Ok(Some(Awaiting {
        vault: vault.vault_id(),
        key,
        messages,
        binding: None,
    }))
}

/// Stores the run's state before the step as a body the run owns: its replay
/// row as stored, which the side-row wall already admitted, with its
/// live-run binding cleared. `None` when no row is stored or the stored row
/// is not the one the step starts from.
fn stage_start(
    vault: &Vault,
    capture: &StepCapture<'_>,
    start: &StepStartCapture<'_>,
) -> Result<Option<ExecutorStepStart>> {
    let Some(mut record) = vault.get_code_run_replay_record(&capture.run)? else {
        return Ok(None);
    };
    if record.generation()? != start.record.generation()? {
        return Ok(None);
    }
    record.live_run = None;
    let body = StepStartBody {
        record: encode_code_run_replay_record(&record)?,
        task: capture.task.to_owned(),
        model: start.model.clone(),
        model_locality: start.model_locality,
        seat_effort: start.seat_effort,
        global_tier: start.global_tier.clone(),
        soft_steps: start.soft_steps,
        hard_steps: start.hard_steps,
        prompt_fingerprint: start.prompt_fingerprint.to_owned(),
    };
    let bytes = rmp_serde::to_vec_named(&body)
        .map_err(|error| crate::Error::InvalidConfig(format!("capsule start: {error}")))?;
    let path = format!(
        "replay/capsule/{}/{:06}.start.msgpack",
        capture.lease_generation, capture.step
    );
    Ok(Some(ExecutorStepStart {
        body: store_capsule_start(vault, capture.run, path.clone(), &bytes)?,
        path,
        digest: *blake3::hash(&bytes).as_bytes(),
        bridge_start: record.bridge_calls.len() as u64,
    }))
}

/// Each task exposure as a slot of the request: the text part the task ends
/// is where the host put it, and an exposure whose bytes there do not hash
/// to its own is left out rather than guessed at.
fn slots(capture: &StepCapture<'_>) -> Vec<ExposureSlot> {
    if capture.task.is_empty() || capture.exposures.is_empty() {
        return Vec::new();
    }
    let located = capture
        .request
        .messages
        .iter()
        .enumerate()
        .find_map(|(message, entry)| {
            entry
                .content
                .iter()
                .enumerate()
                .find_map(|(part, content)| match content {
                    ContentPart::Text { text } if text.ends_with(capture.task) => {
                        Some((message, part, text.len() - capture.task.len()))
                    }
                    _ => None,
                })
        });
    let Some((message, part, base)) = located else {
        return Vec::new();
    };
    let (Ok(message), Ok(part)) = (u32::try_from(message), u32::try_from(part)) else {
        return Vec::new();
    };
    capture
        .exposures
        .iter()
        .map(|exposure| ExposureSlot {
            skill: exposure.skill,
            revision: exposure.revision.clone(),
            content_hash: exposure.content_hash,
            kind: ExposureKind::Knowledge,
            message,
            part,
            start: (base + exposure.start) as u64,
            end: (base + exposure.end) as u64,
        })
        .filter(|slot| slot.locate(capture.request).is_some())
        .collect()
}
