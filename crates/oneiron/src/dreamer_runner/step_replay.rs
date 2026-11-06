use crate::Result;
use crate::compaction::output::OutputRef;
use crate::model_binding::ModelRole;
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
    pub(crate) fn whole(step: u64, message: usize, text: &str) -> Option<Self> {
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
    pub(crate) fn locate<'r>(&self, request: &'r LlmRequest) -> Option<&'r str> {
        let (text, range) = locate_span(request, self.message, self.part, self.stored)?;
        (range == (0..text.len())).then_some(text)
    }
}

/// Part `part` of message `message` in `request` and the byte range `span`
/// names there, when the part is text, the range falls on its character
/// boundaries and its bytes still hash to the span's.
fn locate_span(
    request: &LlmRequest,
    message: u32,
    part: u32,
    span: Option<StoredSpan>,
) -> Option<(&str, std::ops::Range<usize>)> {
    let span = span?;
    let message = request.messages.get(usize::try_from(message).ok()?)?;
    let ContentPart::Text { text } = message.content.get(usize::try_from(part).ok()?)? else {
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

/// A capsule's answering rung as a replay sends on it again (FIX 6255):
/// the rung with the route prompt read from the capsule's body, each secret
/// in it its custody handle, and the digest of the prompt as it was sent,
/// which the route configured now must match before the stored prompt
/// takes its place. `role` is the role whose admission sent the captured
/// call (FIX 6359), which admits the replay. It lives for one call and is
/// never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRung {
    pub binding: CapsuleRungBinding,
    pub prompt_digest: [u8; 32],
    pub role: ModelRole,
}

impl ReplayRung {
    /// `stored`'s rung with `prompt`, the route prompt its body holds.
    #[must_use]
    pub fn of(stored: &StoredRungBinding, prompt: Option<String>) -> Self {
        Self {
            binding: CapsuleRungBinding {
                model: stored.model.clone(),
                locality: stored.locality,
                prompt,
            },
            prompt_digest: stored.prompt_digest,
            role: stored.role,
        }
    }
}

/// The digest a route prompt is pinned by (FIX 6356, CALLS "route prompt
/// digest"): BLAKE3 of the prompt as JSON, `null` for a rung that puts
/// none, so no prompt and an empty one differ. The one producer: a route
/// pin and a capsule's stored rung both take it from here.
#[must_use]
pub fn route_prompt_digest(prompt: Option<&str>) -> [u8; 32] {
    // A string always encodes as JSON; nothing here can fail.
    let json = serde_json::to_vec(&prompt).unwrap_or_default();
    *blake3::hash(&json).as_bytes()
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
    /// Where the step before's console sits in the request (FIX 3608);
    /// `None` when the builder showed none of it whole.
    pub console: Option<ConsoleSlot>,
    /// The sampling seed the request carried, if any.
    pub seed: Option<u64>,
    /// The rung that answered, its route prompt by its body (FIX 6255);
    /// `None` while staged, and for good when no rung answered it.
    pub binding: Option<StoredRungBinding>,
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
    /// The replay context its step's checkpoint committed beside it (FIX
    /// 6351): the guest responses the step's bridge handed out. `None`
    /// until that checkpoint commits one, and for good when it did not.
    pub context: Option<StepContextRef>,
    /// The answer of a single-call workflow step (FIX 3611): the digest and
    /// length of the text its one call returned, which is the step's durable
    /// result. No copy of the text is kept here. `None` until the step binds
    /// it, and for good for a step that ran tool rounds and for an engine
    /// step.
    pub answer: Option<OutputRef>,
}

impl StepReplayCapsule {
    /// Whether the request as stored is the request as sent (FIX 6144): the
    /// wall placed no handle in it. A replay of a masked copy says so, and a
    /// withheld request has no copy (FIX 6254). Its answering rung's route
    /// prompt counts too (FIX 6255): a replay that sends a masked prompt is
    /// no call as sent, though its request is.
    #[must_use]
    pub fn as_sent(&self) -> bool {
        let request = matches!(
            &self.request,
            CapsuleRequest::Kept { stored_hash, .. } if *stored_hash == self.request_hash
        );
        request
            && self
                .binding
                .as_ref()
                .is_none_or(StoredRungBinding::prompt_as_sent)
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

/// What an erase leaves of a capsule (FIX 6144): what the step was (its
/// attempt, run, step and lease generation, its host, the model and
/// locality that answered it and the role that admitted it (FIX 6359),
/// both request hashes and its messages digest, its exposures' skills,
/// revisions and spans, its console slot (FIX 3608), its seed, its time, its start's ref, digest and
/// bridge count, its replay context's ref and digest, its route prompt's
/// ref and digest (FIX 6255), the route its rung went out on, which holds
/// the route prompt's digest only, and its answer's digest and length (FIX
/// 3611)), its content Erased, naming no actor. Its bodies are released beside it, its route prompt's among them;
/// its fork receipts and scores stay in their own rows.
pub(crate) fn erased(mut capsule: StepReplayCapsule) -> StepReplayCapsule {
    capsule.content = CapsuleContent::Erased;
    capsule
}

/// A capsule's erased form is [`erased`]'s: the scrub writes it past the
/// side-row wall, so no wall ever fails an erase (FIX 5718).
impl ErasedForm for StepReplayCapsule {
    fn into_erased(self) -> Result<Self> {
        Ok(erased(self))
    }
}
