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
//! never capped (FIX 6143). A request the wall refuses outright (a recovery
//! phrase, a key split over members, an opaque codec) is withheld: no copy
//! of it is kept, and the capsule keeps the step's start when that admits,
//! so a continuation still forks from it (FIX 6254, [`CapsuleRequest`]).
//!
//! The answering rung also names the route it went out on
//! ([`note_answering_route_pin`], PR-S1): its route, offer, catalog
//! revision, wire model and route prompt digest, finalized with the rung in
//! the same write. A strict replay checks it goes out on that route again
//! (`shadow_runner`); a capture that pins no route leaves it `None`, and no
//! live step is refused for it.

use std::cell::RefCell;

use serde::{Deserialize, Serialize};

use super::replay::CodeRunReplayRecord;
use super::storage::{finalize_capsule, put_staged_capsule};
use crate::attempt_queue::AttemptId;
use crate::llm::ReasoningEffort;
use crate::vault::VaultId;
use crate::{
    ContentPart, EntityId, LlmMessage, LlmRequest, ModelId, ModelLocality, ModelTierRef, Result,
    Vault, WriteActor,
};

pub use crate::team::task_exposure::TaskExposure;

pub use crate::dreamer_runner::step_replay::{
    CapsuleContent, CapsuleHost, CapsuleRequest, CapsuleRungBinding, ExecutorStepStart,
    ExposureKind, ExposureSlot, ReplayRoutePin, StepReplayCapsule, StoredSpan,
};

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
    /// Every row the request was read from, or `None` when any is unknown.
    pub(crate) source_rows: Option<Vec<EntityId>>,
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
    /// The route the answering rung went out on, beside its binding.
    route_pin: Option<ReplayRoutePin>,
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

/// Notes the route the rung that answered `request` went out on (PR-S1), for
/// the capture on this thread that staged the same messages, matched as
/// [`note_answering_rung`] matches it. A host's ladder calls it beside that
/// note; with no capture waiting on this thread it does nothing. Best
/// effort: a capture with no pin is finalized with its rung all the same.
pub fn note_answering_route_pin(request: &LlmRequest, pin: &ReplayRoutePin) {
    AWAITING.with(|awaiting| {
        let mut awaiting = awaiting.borrow_mut();
        if awaiting.is_empty() {
            return;
        }
        let Some(digest) = messages_digest(&request.messages) else {
            return;
        };
        for entry in awaiting.iter_mut().filter(|entry| entry.messages == digest) {
            entry.route_pin = Some(pin.clone());
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
        match finalize_capsule(vault, &entry.key, binding, entry.route_pin) {
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
    source_rows: Option<Vec<EntityId>>,
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
            source_rows,
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
        route_pin: None,
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
