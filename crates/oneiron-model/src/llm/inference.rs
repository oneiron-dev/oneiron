//! What a model worker is and what one physical call to it reported (FIX
//! 8314, INFERENCE R1): the worker's kind, its mode, the identity it answered
//! with and how that identity is known, its readiness, and one receipt per
//! physical backend request.
//!
//! The identity is the ONE existing tuple, [`CacheIdentity`]: its `model`,
//! `runtime`, `template` and `backend_epoch` are the observed weights, build,
//! rendered template and answering incarnation. A [`WorkerDescriptor`] only
//! holds it beside the worker's kind and the provenance of its build; it is
//! never a second identity. A configured revision, a URL or a returned label
//! is not identity.
//!
//! A receipt holds counts, closed enums, fixed-width hex and a validated
//! model id only: never prompt text, a path, a provider's free string or raw
//! provider JSON, so a run receipt may log it. A count or time no native
//! source reported is absent, never zero; an empty `passes` list means no
//! native cache-pass evidence, not a cold cache.
//!
//! A backend's usage object carries its receipts as a list under
//! [`INFERENCE_CALLS_KEY`], one entry per physical request in order; the
//! adapters keep that object as [`LlmUsage::raw_provider`], and
//! [`LlmUsage::inference_calls`] reads them back.
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

use super::cache::{CacheIdentity, CachePassUsage};
use super::media::MediaUsage;
use super::scheduling::{SchedulingReceipt, WorkPhysical};
use super::{LlmUsage, ModelId};

/// The key in a provider's usage object that holds its inference receipts.
pub const INFERENCE_CALLS_KEY: &str = "inference_calls";

/// What kind of worker answered, named by what its reply carries, never by a
/// provider's name or URL. `Unknown` for a backend no reply names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerKind {
    LlamaCpp,
    Exl3,
    Embedder,
    Oneironer,
    VoxCpm2,
    Asr,
    Unknown,
}

/// Who runs a worker's process. `Managed` is the default of a NEW worker
/// declaration; an existing endpoint is `External`, which is probed and routed
/// to and never installed, started, stopped, restarted or unloaded. Mode is
/// not locality: a supervised loopback worker is still an own server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerMode {
    #[default]
    Managed,
    External,
}

/// How the build a worker answered with is known. `VerifiedArtifacts` is a
/// content-addressed record of what the worker loaded and runs, checked
/// against the answer that named it; a digest of a reported version string is
/// `ReportedVersion`, never verified; anything else is `Unknown`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerBuildEvidence {
    VerifiedArtifacts,
    ReportedVersion,
    #[default]
    Unknown,
}

/// One worker as an answer or a probe observed it: its kind, the one
/// identity it answered with, and how its build is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerDescriptor {
    pub kind: WorkerKind,
    #[serde(default, skip_serializing_if = "CacheIdentity::is_empty")]
    pub identity: CacheIdentity,
    #[serde(default)]
    pub build_evidence: WorkerBuildEvidence,
}

/// The waits one physical request spent before it ran, in whole
/// microseconds, each a separate interval and never a promised sum: device
/// admission (`device_us`), the worker's ingress to its admission
/// (`worker_us`), and the native engine's enqueue to start, an answer pass's
/// wait for pages included (`engine_us`). A wait no source measured is
/// absent; prefill time is never a queue wait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueueWait {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_us: Option<u64>,
}

impl QueueWait {
    /// True when no wait was measured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// How a physical request ended, as its native finish names it. `Other` is
/// a closed category that keeps no provider text; an absent end is unknown.
/// `Error` and `Cancelled` imply no token count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceEndReason {
    Stop,
    Length,
    ToolCalls,
    ContentFiltered,
    Cancelled,
    Error,
    Other,
}

/// One physical backend request: the engine model it was admitted for, the
/// worker that answered, and what that worker measured. A thinking request's
/// reasoning, re-encode and answer are passes of ONE receipt; a retry or a
/// second native request is its own receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceCallReceipt {
    /// The validated engine model the call was admitted for, stamped by the
    /// adapter that sent it. Not a digest and no proof of the loaded bytes;
    /// absent on a worker's own wire record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelId>,
    pub worker: WorkerDescriptor,
    /// The request's own prompt, in tokens, as the worker counted it before
    /// any pass re-encoded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_prompt_tokens: Option<u64>,
    /// Each pass the worker made over an input, in order. Empty: no native
    /// cache-pass evidence.
    #[serde(default)]
    pub passes: Vec<CachePassUsage>,
    #[serde(default, skip_serializing_if = "QueueWait::is_empty")]
    pub queue_wait: QueueWait,
    /// The worker's acceptance of the request to its first generated token,
    /// reasoning or answer, measured at the worker; never a client's
    /// end-to-end time, wall time or prefill time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttft_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<InferenceEndReason>,
    /// The native count of generated tokens, never a zero-filled default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    /// Draft tokens proposed over the request's passes, only when every pass
    /// reported its count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drafts_proposed: Option<u64>,
    /// Draft tokens accepted over the request's passes, as `drafts_proposed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drafts_accepted: Option<u64>,
    /// The worker's scheduling context and executor rounds at this call's end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduling: Option<SchedulingReceipt>,
    /// Host-stamped custody of this native physical call (FIX 11893). Absent
    /// means Paid/unknown; worker JSON is never the source of this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical: Option<WorkPhysical>,
}

impl InferenceCallReceipt {
    /// A request's receipt naming `worker` and, when known, the admitted
    /// `model`, with every count, pass and time absent.
    #[must_use]
    pub fn unmeasured(model: Option<ModelId>, worker: WorkerDescriptor) -> Self {
        Self {
            model,
            worker,
            logical_prompt_tokens: None,
            passes: Vec::new(),
            queue_wait: QueueWait::default(),
            ttft_us: None,
            end_reason: None,
            output_tokens: None,
            drafts_proposed: None,
            drafts_accepted: None,
            scheduling: None,
            physical: None,
        }
    }
}

/// Why a worker is not ready: what an actual answer or a probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerFailure {
    Unreachable,
    InvalidReply,
    KindMismatch,
    ModelMismatch,
    BuildMismatch,
    TemplateMismatch,
    LoadFailed,
}

/// Whether a worker serves its named model and build. `Ready` needs an
/// actual answer naming the expected model on its route, with the pinned
/// model and build observed, a present epoch, verified artifacts and a
/// matching template where the worker renders one; an open port, a listing
/// or a provider's availability is not readiness. Missing evidence is
/// `Unverified`; contradicting evidence is `Failed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WorkerReadiness {
    Unchecked,
    Starting,
    Unverified {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        observed: Option<WorkerDescriptor>,
    },
    Ready {
        observed: WorkerDescriptor,
    },
    Failed {
        failure: WorkerFailure,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        observed: Option<WorkerDescriptor>,
    },
}

/// The lifecycle phase a worker failure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerPhase {
    Install,
    Launch,
    Qualify,
    Serve,
    Drain,
}

/// A sanitized failure that keeps the model and phase even before
/// qualification produced a descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerFailureDetail {
    pub model: ModelId,
    pub phase: WorkerPhase,
    pub reason: String,
}

/// One worker's status: its stable config key, the engine model it serves,
/// its mode, the physical machine it runs on when known, its readiness, and
/// what it last reported. Not a provider's or a seat's availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub worker_id: String,
    pub model: ModelId,
    #[serde(default)]
    pub mode: WorkerMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<EntityId>,
    pub readiness: WorkerReadiness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resident_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_receipt: Option<InferenceCallReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_detail: Option<WorkerFailureDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_queued: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_active: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused: Option<u64>,
}

/// The receipts in a usage object: the list under [`INFERENCE_CALLS_KEY`] in
/// it, or in the provider usage a ladder's served receipt holds under
/// `usage`. A record that does not read as an [`InferenceCallReceipt`] is no
/// evidence and is left out. No other nesting is read.
fn receipts_in(raw: &JsonValue) -> Vec<InferenceCallReceipt> {
    let served = || match raw.get("rung") {
        Some(rung) if rung.is_u64() => raw.get("usage")?.get(INFERENCE_CALLS_KEY),
        _ => None,
    };
    raw.get(INFERENCE_CALLS_KEY)
        .or_else(served)
        .and_then(JsonValue::as_array)
        .map(|records| {
            records
                .iter()
                .filter_map(|record| InferenceCallReceipt::deserialize(record).ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

impl LlmUsage {
    /// The receipts the backend reported for this call, one per physical
    /// request, in order: from its usage, or from the provider usage a
    /// ladder's served receipt holds. Empty when it reported none.
    #[must_use]
    pub fn inference_calls(&self) -> Vec<InferenceCallReceipt> {
        receipts_in(&self.raw_provider)
    }

    /// Binds every receipt in this usage object to `model`, the engine model
    /// the adapter's request was admitted for. A worker's wire names no
    /// engine model, and one it names is not taken on its word. Only the
    /// direct usage object is bound: an adapter binds before any ladder
    /// wraps it.
    pub fn bind_inference_model(&mut self, model: &ModelId) {
        let Some(JsonValue::Array(records)) = self.raw_provider.get_mut(INFERENCE_CALLS_KEY) else {
            return;
        };
        for record in records {
            if let JsonValue::Object(record) = record {
                record.insert(
                    "model".to_owned(),
                    JsonValue::String(model.as_str().to_owned()),
                );
            }
        }
    }
}

impl MediaUsage {
    /// The receipts the media call's backend reported, as
    /// [`LlmUsage::inference_calls`] reads them.
    #[must_use]
    pub fn inference_calls(&self) -> Vec<InferenceCallReceipt> {
        receipts_in(&self.raw_provider)
    }

    /// Appends `calls` to the list under [`INFERENCE_CALLS_KEY`] in this
    /// usage's provider object, which an absent object becomes. A provider
    /// usage that is some other value is left as it came.
    pub fn put_inference_calls(&mut self, calls: &[InferenceCallReceipt]) {
        if calls.is_empty() {
            return;
        }
        if self.raw_provider.is_null() {
            self.raw_provider = JsonValue::Object(JsonMap::new());
        }
        let Some(usage) = self.raw_provider.as_object_mut() else {
            return;
        };
        if let JsonValue::Array(list) = usage
            .entry(INFERENCE_CALLS_KEY)
            .or_insert_with(|| JsonValue::Array(Vec::new()))
        {
            list.extend(
                calls
                    .iter()
                    .filter_map(|call| serde_json::to_value(call).ok()),
            );
        }
    }
}
