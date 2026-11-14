use crate::Result;
use crate::code_run::FoldWordRef;
use crate::compaction::output::OutputRef;
use crate::model_binding::ModelRole;
use crate::side_table::ErasedForm;
use crate::{ContentPart, EntityId, LlmRequest, ModelId, ModelLocality};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
use oneiron_records::dreamer_runner::step_replay::locate_span;
#[doc(hidden)]
pub use oneiron_records::dreamer_runner::step_replay::{
    CapsuleContent, CapsuleHost, CapsuleRequest, CapsuleRungBinding, ConsoleSlot,
    ExecutorStepStart, ExposureKind, ExposureSlot, ReplayRoutePin, StepContextRef,
    StoredRungBinding, StoredSpan,
};

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
    /// outright (FIX 6254). A kept request's body is the manifest of the
    /// pieces its run holds once for the actor (FIX 4192).
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
    /// The folds whose accepted summaries its bodies copy (FIX 18924). Every
    /// capsule keeps it. It is apart from `source_rows` and claims no list
    /// of inputs is complete.
    pub(crate) fold_words: CapsuleFoldWords,
}

/// The folds whose accepted summaries a capsule's bodies copy (FIX 18924),
/// one list for each body, each fold once. A list names what was put in its
/// body, never folds read from an id. A withdrawal of one fold's words
/// retires each body whose list names that fold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CapsuleFoldWords {
    /// The stubs the request shows and the answers its consoles may print.
    pub(crate) request: Vec<FoldWordRef>,
    /// The answers the start's prefix row records.
    pub(crate) start: Vec<FoldWordRef>,
    /// The answers a hook view in the replay context shows.
    pub(crate) context: Vec<FoldWordRef>,
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
