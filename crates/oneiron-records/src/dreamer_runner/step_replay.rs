//! Moved from `crates/oneiron/src/dreamer_runner/step_replay.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::compaction::output::OutputRef;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::ContentPart;
use oneiron_model::llm::LlmRequest;
use oneiron_model::llm::ModelId;
use oneiron_model::llm::ModelLocality;
use oneiron_model::model_binding::ModelRole;
use serde::Deserialize;
use serde::Serialize;

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
    pub fn locate<'r>(&self, request: &'r LlmRequest) -> Option<(&'r str, std::ops::Range<usize>)> {
        locate_span(request, self.message, self.part, self.stored)
    }
}

/// Where the console of the step before sits in a captured engine step's
/// request (FIX 3608): the user message the request builder rendered that
/// step's observation into, whole and at the full tier, as one text part.
/// A callable's counterfactual renders each branch's observation through
/// the same formatter and puts it there. A console the builder showed any
/// other way (an overview, a stub, a fold or a frame) has no slot. Nor has
/// a console in a request that lists the run's results in a brief.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleSlot {
    /// The step whose observation the message renders.
    pub step: u64,
    pub message: u32,
    pub part: u32,
    /// The whole text part as stored (FIX 6144). `None` when a secret's
    /// handle the wall put there cuts through one of its bounds.
    pub stored: Option<StoredSpan>,
}

impl ConsoleSlot {
    /// The slot of `text`, the whole first part of message `message`, which
    /// renders step `step`'s console; `None` past the index a slot holds.
    pub fn whole(step: u64, message: usize, text: &str) -> Option<Self> {
        Some(Self {
            step,
            message: u32::try_from(message).ok()?,
            part: 0,
            stored: Some(StoredSpan {
                start: 0,
                end: text.len() as u64,
                content_hash: *blake3::hash(text.as_bytes()).as_bytes(),
            }),
        })
    }

    /// The slot's text part in `request`, when its stored span is that whole
    /// part and its bytes still hash to the span's.
    pub fn locate<'r>(&self, request: &'r LlmRequest) -> Option<&'r str> {
        let (text, range) = locate_span(request, self.message, self.part, self.stored)?;
        (range == (0..text.len())).then_some(text)
    }
}

/// Part `part` of message `message` in `request` and the byte range `span`
/// names there, when the part is text, the range falls on its character
/// boundaries and its bytes still hash to the span's.
pub fn locate_span(
    request: &LlmRequest,
    message: u32,
    part: u32,
    span: Option<StoredSpan>,
) -> Option<(&str, std::ops::Range<usize>)> {
    let span = span?;
    let message = request.messages.get(usize::try_from(message).ok()?)?;
    let ContentPart::Text { text, .. } = message.content.get(usize::try_from(part).ok()?)? else {
        return None;
    };
    let range = usize::try_from(span.start).ok()?..usize::try_from(span.end).ok()?;
    let bytes = text.get(range.clone())?;
    (*blake3::hash(bytes.as_bytes()).as_bytes() == span.content_hash).then_some((text, range))
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

/// The rung that answered a call, as it answered: its model, where it ran
/// and the route prompt it put first. A live value: a capsule keeps its
/// rung as a [`StoredRungBinding`], its prompt in a body (FIX 6255).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleRungBinding {
    pub model: ModelId,
    pub locality: ModelLocality,
    pub prompt: Option<String>,
}

/// The rung that answered a captured call, as its capsule keeps it (FIX
/// 6255): its model, where it ran, and its route prompt as a body the run
/// owns, by ref. `prompt` is `None` when the rung put no prompt. Its `Kept`
/// body is the prompt's canonical JSON string as the side-row wall admitted
/// it, each secret in it its custody handle; `Withheld` keeps no copy, for
/// the wall's reasons. `prompt_digest` is the digest of the prompt as it
/// was sent ([`route_prompt_digest`], FIX 6356): a replay checks the route
/// configured now against it before the stored prompt takes its place.
/// `role` is the role whose admission sent the call (FIX 6359): a replay is
/// admitted through that role's route clamp, and through no other role's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRungBinding {
    pub model: ModelId,
    pub locality: ModelLocality,
    pub prompt: Option<CapsuleRequest>,
    pub prompt_digest: [u8; 32],
    pub role: ModelRole,
}

impl StoredRungBinding {
    /// Whether the route prompt as stored is the prompt as sent: the rung
    /// put none, or the wall placed no handle in it, so its stored JSON
    /// hashes to the digest it was sent under. A withheld prompt has no
    /// copy.
    #[must_use]
    pub fn prompt_as_sent(&self) -> bool {
        match &self.prompt {
            None => true,
            Some(CapsuleRequest::Kept { stored_hash, .. }) => *stored_hash == self.prompt_digest,
            Some(CapsuleRequest::Withheld { .. }) => false,
        }
    }

    /// The hash of the route prompt's body as stored (FIX 6255): what a
    /// contribution fork's receipt names its prompt by, and what its proof
    /// reads back. `None` for a rung that put no prompt, and for a withheld
    /// one, which no fork is sent under.
    #[must_use]
    pub fn stored_prompt_hash(&self) -> Option<[u8; 32]> {
        match &self.prompt {
            Some(CapsuleRequest::Kept { stored_hash, .. }) => Some(*stored_hash),
            None | Some(CapsuleRequest::Withheld { .. }) => None,
        }
    }
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
    /// puts none, so no prompt and an empty one differ
    /// ([`route_prompt_digest`]).
    pub route_prompt_digest: [u8; 32],
}

/// What a capsule keeps of its step's request (FIX 6254), and of its
/// answering rung's route prompt (FIX 6255): there the body is the prompt's
/// canonical JSON string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleRequest {
    /// Its canonical JSON as stored, each secret in it its custody handle,
    /// by its body ref, its path and the hash of the stored bytes, which a
    /// read of the body checks. For a step's request, the body is the
    /// manifest of its shared pieces (FIX 4192), and the hash is the whole
    /// request's they put together.
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
    /// Its actor was erased. Its request, start, route prompt and fork
    /// answers are released and it names no actor; what the step was stays,
    /// and every read of its content is unavailable.
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

/// The executor run's state before the step (FIX 3694): what a
/// continuation forks from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorStepStart {
    /// The start body (its encoded prefix row, its config, its teaching
    /// fingerprint), owned by the run, as the wall admitted it. FIX 4192:
    /// this is the body's manifest; the run holds the body as shared
    /// pieces the manifest names.
    pub body: OutputRef,
    pub path: String,
    /// BLAKE3 of the whole body bytes as stored, its pieces put together.
    pub digest: [u8; 32],
    /// The bridge log's length at the step's start.
    pub bridge_start: u64,
    /// Whether restore explicitly marked this start body as erased.
    pub erased: bool,
}

/// The replay context a step's checkpoint committed (FIX 6351): a body the
/// run owns, as the wall admitted it, beside the step's capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepContextRef {
    pub body: OutputRef,
    pub path: String,
    /// BLAKE3 of the body bytes as stored.
    pub digest: [u8; 32],
    /// Whether restore explicitly marked this context body as erased.
    pub erased: bool,
}
