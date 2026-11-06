use crate::Result;
use crate::compaction::output::OutputRef;
use crate::side_table::ErasedForm;
use crate::{ContentPart, EntityId, LlmRequest, ModelId, ModelLocality};
use serde::{Deserialize, Serialize};

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

/// The route the rung that answered a captured call went out on (PR-S1):
/// what a strict replay of the call checks it goes out on again. Taken from
/// the answering rung as it answered, never rebuilt from a later catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRoutePin {
    /// The rung's route, `adapter@origin`.
    pub route_id: String,
    /// The offer the call was admitted under.
    pub offer_id: String,
    /// The provider catalog's revision the offer was bound at, if it names one.
    pub catalog_revision: Option<String>,
    /// The model id the provider was sent.
    pub wire_model: String,
    /// BLAKE3 of the rung's route prompt as JSON: `null` for a rung that
    /// puts none, so no prompt and an empty one differ.
    pub route_prompt_digest: [u8; 32],
}

/// What a capsule keeps of its step's request (FIX 6254).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleRequest {
    /// Its canonical JSON as stored, each secret in it its custody handle,
    /// by its body ref, its path and the hash of the stored bytes, which a
    /// read of the body checks.
    Kept {
        body: OutputRef,
        path: String,
        stored_hash: [u8; 32],
        /// Whether restore explicitly marked this request body as erased.
        erased: bool,
    },
    /// The side-row wall refused the request outright, for these reasons
    /// (a recovery phrase, a key split over members, an opaque codec): no
    /// copy of it is kept, raw or masked, and every read of it is
    /// unavailable. The capsule holds the step's start in its place.
    Withheld { reasons: Vec<String> },
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
    /// The request as assembled and bound, before its route's prompt: its
    /// body as stored (FIX 6144), or withheld when the wall refused it
    /// outright (FIX 6254).
    pub request: CapsuleRequest,
    /// The canonical hash of the request as it was sent, before any mask:
    /// the identity a sent request is matched by.
    pub request_hash: [u8; 32],
    /// The hash of its messages, which the answering rung is matched by.
    pub messages_digest: [u8; 32],
    /// Every row the captured request was read from; `None` when any
    /// constituent is unknown (FIX 7104). Older capsules keep unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rows: Option<Vec<EntityId>>,
    pub exposures: Vec<ExposureSlot>,
    /// The sampling seed the request carried, if any.
    pub seed: Option<u64>,
    /// The rung that answered; `None` while staged, and for good when no
    /// rung answered it.
    pub binding: Option<CapsuleRungBinding>,
    /// The route that rung went out on (PR-S1), written with it; `None`
    /// while staged, and for good when no rung pinned its route.
    pub route_pin: Option<ReplayRoutePin>,
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
    /// wall placed no handle in it. A replay of a masked copy says so, and a
    /// withheld request has no copy (FIX 6254).
    #[must_use]
    pub fn as_sent(&self) -> bool {
        matches!(
            &self.request,
            CapsuleRequest::Kept { stored_hash, .. } if *stored_hash == self.request_hash
        )
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
    /// Whether restore explicitly marked this start body as erased.
    pub erased: bool,
}

/// What an erase leaves of a capsule (FIX 6144): what the step was (its
/// attempt, run, step and lease generation, its host, the model and
/// locality that answered it, both request hashes and its messages digest,
/// its exposures' skills, revisions and spans, its seed, its time, its
/// start's ref, digest and bridge count, and the route its rung went out on,
/// which holds the route prompt's digest only), its content Erased, naming
/// no actor, with its route prompt cleared. Its bodies are released beside it;
/// its fork receipts and scores stay in their own rows.
pub(crate) fn erased(mut capsule: StepReplayCapsule) -> StepReplayCapsule {
    capsule.content = CapsuleContent::Erased;
    if let Some(binding) = &mut capsule.binding {
        binding.prompt = None;
    }
    capsule
}

/// A capsule's erased form is [`erased`]'s: the scrub writes it past the
/// side-row wall, so no wall ever fails an erase (FIX 5718).
impl ErasedForm for StepReplayCapsule {
    fn into_erased(self) -> Result<Self> {
        Ok(erased(self))
    }
}
