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
//!
//! Each body a capsule names is written as the side-row wall admits it, each
//! secret in it its custody handle, and the capsule names the actor whose
//! step it was, so an erase of that actor releases them (FIX 6144, KEY STORE
//! = A; `storage::replay_capsule`). Staged captures are kept and measured,
//! never capped (FIX 6143).

use std::cell::RefCell;

use serde::{Deserialize, Serialize};

use super::replay::CodeRunReplayRecord;
use super::storage::{finalize_capsule, put_staged_capsule};
use crate::attempt_queue::AttemptId;
use crate::compaction::output::OutputRef;
use crate::llm::ReasoningEffort;
use crate::vault::VaultId;
use crate::{
    ContentPart, EntityId, LlmMessage, LlmRequest, ModelId, ModelLocality, ModelTierRef, Result,
    Vault, WriteActor,
};

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
/// of its bytes as the host put them, in one text part of one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureSlot {
    pub skill: EntityId,
    pub revision: String,
    /// BLAKE3 of its bytes as the host put them in the task, before any
    /// mask.
    pub content_hash: [u8; 32],
    pub kind: ExposureKind,
    pub message: u32,
    pub part: u32,
    /// Where it sits in the request as stored (FIX 6144). `None` when a
    /// secret's handle the wall put there cuts through one of its bounds: no
    /// span of the stored text is the exposure, and none is guessed at.
    pub stored: Option<StoredSpan>,
}

/// Where an exposure sits in a stored request: a byte span of its text part
/// and the hash of the bytes there, each secret in them its handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSpan {
    pub start: u64,
    pub end: u64,
    pub content_hash: [u8; 32],
}

impl ExposureSlot {
    /// The slot's text part in `request` and its byte range there, when it
    /// has a stored span, the part is text, the range falls on its character
    /// boundaries and its bytes still hash to the span's.
    pub(crate) fn locate<'r>(
        &self,
        request: &'r LlmRequest,
    ) -> Option<(&'r str, std::ops::Range<usize>)> {
        let span = self.stored?;
        let message = request.messages.get(usize::try_from(self.message).ok()?)?;
        let ContentPart::Text { text } = message.content.get(usize::try_from(self.part).ok()?)?
        else {
            return None;
        };
        let range = usize::try_from(span.start).ok()?..usize::try_from(span.end).ok()?;
        let bytes = text.get(range.clone())?;
        (*blake3::hash(bytes.as_bytes()).as_bytes() == span.content_hash).then_some((text, range))
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

/// What a capsule holds of the step it captured (FIX 6144, KEY STORE = A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleContent {
    /// Its bodies, each masked as it was written, for `actor`'s step: the
    /// actor its host stamped on the step's writes, which an erase of that
    /// actor finds the capsule by.
    Kept { actor: EntityId },
    /// Its actor was erased. Its request, start and fork answers are
    /// released, its route prompt is cleared and it names no actor; what the
    /// step was stays, and every read of its content is unavailable.
    Erased,
}

impl CapsuleContent {
    /// The actor whose step the capsule holds; `None` once it is erased.
    #[must_use]
    pub const fn actor(self) -> Option<EntityId> {
        match self {
            Self::Kept { actor } => Some(actor),
            Self::Erased => None,
        }
    }
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
    /// body ref: its canonical JSON as stored, each secret in it its custody
    /// handle.
    pub request: OutputRef,
    pub request_path: String,
    /// The canonical hash of the request as it was sent, before any mask:
    /// the identity a sent request is matched by.
    pub request_hash: [u8; 32],
    /// The hash of the request's body as stored, masked (FIX 6144): what a
    /// read of the body checks.
    pub stored_request_hash: [u8; 32],
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
    /// What it holds, and for whose step (FIX 6144).
    pub content: CapsuleContent,
}

impl StepReplayCapsule {
    /// Whether the request as stored is the request as sent (FIX 6144): the
    /// wall placed no handle in it. A replay of a masked copy says so.
    #[must_use]
    pub fn as_sent(&self) -> bool {
        self.stored_request_hash == self.request_hash
    }
}

/// The executor run's state before the step (FIX 3694): what a
/// continuation forks from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorStepStart {
    /// The start body (its encoded prefix row, its config, its teaching
    /// fingerprint), owned by the run, as the wall admitted it.
    pub body: OutputRef,
    pub path: String,
    /// BLAKE3 of the body bytes as stored.
    pub digest: [u8; 32],
    /// The bridge log's length at the step's start.
    pub bridge_start: u64,
}

/// The body an [`ExecutorStepStart`] names: the run's replay row as stored
/// before the step, with no live-run binding, and what the run ran under.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StepStartBody {
    /// The prefix row, as [`super::encode_code_run_replay_record`] encodes it.
    pub(crate) record: Vec<u8>,
    pub(crate) task: String,
    pub(crate) model: ModelId,
    pub(crate) model_locality: ModelLocality,
    pub(crate) seat_effort: Option<ReasoningEffort>,
    pub(crate) global_tier: ModelTierRef,
    pub(crate) soft_steps: u32,
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
    /// The actor its host stamps on the step's writes.
    pub(crate) actor: WriteActor,
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
    pub(crate) prompt_fingerprint: &'a str,
}

/// A capture as its site assembled it, before the side-row wall reads it:
/// what storage admits and writes as the capsule.
pub(crate) struct CapsuleDraft<'a> {
    pub(crate) capture: &'a StepCapture<'a>,
    pub(crate) attempt: EntityId,
    pub(crate) actor: EntityId,
    /// The request's canonical bytes as sent.
    pub(crate) request: Vec<u8>,
    pub(crate) request_path: String,
    pub(crate) start_path: String,
    pub(crate) messages_digest: [u8; 32],
    /// Each exposure where it sits in the request as sent.
    pub(crate) exposures: Vec<ExposureSlot>,
}

impl CapsuleDraft<'_> {
    /// The capsule's key: its attempt, lease generation and step.
    pub(crate) fn key(&self) -> (EntityId, u64, u64) {
        (
            self.attempt,
            u64::from(self.capture.lease_generation),
            self.capture.step,
        )
    }
}

/// A staged capture waiting for its call's answering rung.
struct Awaiting {
    vault: VaultId,
    key: (EntityId, u64, u64),
    messages: [u8; 32],
    binding: Option<CapsuleRungBinding>,
    /// The request bytes it captured.
    bytes: u64,
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
/// failure is logged and never fails the step. The drain is measured: how
/// many took their rung, how many no rung answered and how many failed.
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
    if mine.is_empty() {
        return;
    }
    let (mut finalized, mut unanswered, mut failed) = (0_usize, 0_usize, 0_usize);
    for entry in mine {
        let Some(binding) = entry.binding else {
            unanswered += 1;
            continue;
        };
        match finalize_capsule(vault, &entry.key, binding) {
            Ok(()) => finalized += 1,
            Err(error) => {
                failed += 1;
                tracing::warn!(kind = ?error.kind(), "a step replay capsule was not finalized");
            }
        }
    }
    tracing::debug!(
        finalized,
        unanswered,
        failed,
        "staged step replay captures drained"
    );
}

/// Captures a saved-workflow step's admitted request before it is sent: the
/// step is its attempt's only call, made for `actor`. Finalize it with
/// [`finalize_step_captures`] once the call is done. A failure is logged and
/// never fails the step.
pub fn capture_workflow_step(
    vault: &Vault,
    attempt: AttemptId,
    lease_generation: u32,
    actor: WriteActor,
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
            actor,
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
            staged.push(awaiting);
            measure_staged(&staged);
        }),
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a step replay capsule was not captured");
        }
    }
}

/// What staging does as captures wait on one thread for their calls (FIX
/// 6143, Rule 5): it keeps every one, with no cap and no eviction, and
/// measures how many wait and the request bytes they captured.
fn measure_staged(staged: &[Awaiting]) {
    let bytes = staged
        .iter()
        .fold(0_u64, |total, entry| total.saturating_add(entry.bytes));
    tracing::debug!(
        staged = staged.len(),
        staged_bytes = bytes,
        "a step replay capture is staged"
    );
}

/// Whose step a capsule is (FIX 6144): the actor its host stamped on the
/// step's writes, the gated write's for an executor step and the step's own
/// for a workflow step. An erase of that actor reaches the capsule by it.
const fn capsule_actor(actor: WriteActor) -> EntityId {
    actor.entity_ref()
}

/// Writes the capsule's bodies and its row as the side-row wall admits them;
/// `None` for a request whose messages cannot be hashed, and for a step
/// whose actor is gone by now, which leaves no capsule.
fn stage(vault: &Vault, capture: &StepCapture<'_>) -> Result<Option<Awaiting>> {
    let Some(messages) = messages_digest(&capture.request.messages) else {
        return Ok(None);
    };
    let request = capture
        .request
        .canonical_bytes()
        .map_err(|error| crate::Error::InvalidConfig(format!("capsule request: {error}")))?;
    let draft = CapsuleDraft {
        capture,
        attempt: EntityId::from_bytes(*capture.attempt.as_bytes())?,
        actor: capsule_actor(capture.actor),
        request_path: format!(
            "replay/capsule/{}/{:06}.request.json",
            capture.lease_generation, capture.step
        ),
        start_path: format!(
            "replay/capsule/{}/{:06}.start.msgpack",
            capture.lease_generation, capture.step
        ),
        messages_digest: messages,
        exposures: slots(capture),
        request,
    };
    if put_staged_capsule(vault, &draft)?.is_none() {
        return Ok(None);
    }
    Ok(Some(Awaiting {
        vault: vault.vault_id(),
        key: draft.key(),
        messages,
        binding: None,
        bytes: draft.request.len() as u64,
    }))
}

/// Each task exposure as a slot of the request as sent: the text part the
/// task ends is where the host put it, and an exposure whose bytes there do
/// not hash to its own is left out rather than guessed at. Storage moves
/// each slot to where it sits once the request is masked.
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
            stored: Some(StoredSpan {
                start: (base + exposure.start) as u64,
                end: (base + exposure.end) as u64,
                content_hash: exposure.content_hash,
            }),
        })
        .filter(|slot| slot.locate(capture.request).is_some())
        .collect()
}
