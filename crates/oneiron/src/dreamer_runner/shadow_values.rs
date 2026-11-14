//! Immutable shadow-run artifact, request-part and evidence vocabulary.

use crate::compaction::output::OutputRef;
use crate::dreamer_runner::step_replay::{
    CapsuleRequest, ExecutorStepStart, ReplayRoutePin, StepReplayCapsule, StoredRungBinding,
};
use crate::store::result_manifest::CodeRunRawOutput;
use crate::{EntityId, LlmUsage};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::dreamer_runner::shadow_values::{
    ArtifactDigest, ArtifactDigestAlgorithm, EngineArtifactPin, SHADOW_PROTOCOL_VERSION,
    ShadowBridgeWindow, ShadowIsolation, ShadowIsolationRequired, ShadowMeterContext,
    ShadowModelPin, ShadowSandboxBinding, ShadowScope, ShadowTarget, ShadowTraceEntry,
    ShadowTraceKind, ShadowUnavailable, ShadowUnavailableReason, ShadowUsage,
};

/// One captured step of a canonical attempt: the key its capsule is kept
/// under, and the run it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShadowStepIdentity {
    pub attempt: EntityId,
    pub lease_generation: u32,
    pub run: EntityId,
    pub step: u64,
}

impl ShadowStepIdentity {
    /// The step `capsule` captured.
    #[must_use]
    pub const fn of(capsule: &StepReplayCapsule) -> Self {
        Self {
            attempt: capsule.attempt,
            lease_generation: capsule.lease_generation,
            run: capsule.run,
            step: capsule.step,
        }
    }
}

/// A captured request's digest, saying which copy it is of (FIX 6144): the
/// request as it was sent, or its copy as stored, each secret in it masked
/// into its custody handle. A replay of a masked copy is never "as sent",
/// nor is one whose route prompt is masked (FIX 6255).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "of", content = "digest", rename_all = "snake_case")]
pub enum ShadowRequestDigest {
    AsSent([u8; 32]),
    AsStored([u8; 32]),
}

/// What an arm runs from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ShadowSource {
    /// A captured request by its body ref and digest, and the step it was
    /// captured at: the shape a candidate process is handed (PR-S2).
    CapturedRequest {
        request: OutputRef,
        request_digest: ShadowRequestDigest,
        step: ShadowStepIdentity,
    },
    /// A step replay capsule by its key, with the request digest it must
    /// hold and, when the caller names it, the start it must hold.
    Capsule {
        step: ShadowStepIdentity,
        request_digest: ShadowRequestDigest,
        start: Option<ExecutorStepStart>,
    },
}

/// One whole body an arm holds or was granted, by its path and ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowBodyRef {
    /// Its path, as its run names its outputs.
    pub path: String,
    pub body: OutputRef,
    /// Whether its producer finished it; a partial body says so.
    pub complete: bool,
    /// The secret scan's reason when it marked the body: no read shows it.
    pub secret: Option<String>,
}

impl ShadowBodyRef {
    /// The ref of `output`, which the scan marked with `secret` if it did.
    #[must_use]
    pub(crate) fn of(output: &CodeRunRawOutput, secret: Option<&str>) -> Self {
        Self {
            path: output.path.clone(),
            body: output.output_ref(),
            complete: output.complete,
            secret: secret.map(str::to_owned),
        }
    }
}

/// One model call of an arm, as the host admitted, sent and settled it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowModelReceipt {
    pub call_id: u32,
    /// The request as sent, in the arm's store, once the host built it.
    pub request: Option<ShadowBodyRef>,
    pub request_digest: ShadowRequestDigest,
    /// The pins the call had to go out on.
    pub expected: ShadowModelPin,
    /// The route the host's model would have sent it on, when it had one.
    pub served: Option<ReplayRoutePin>,
    /// The answer, in the arm's store.
    pub response: Option<ShadowBodyRef>,
    /// The run admission's receipts for the call, as they serialize.
    pub receipts: Vec<serde_json::Value>,
    pub usage: ShadowUsage,
    pub unavailable: Option<ShadowUnavailable>,
}

/// An opaque hold on an arm's bodies at its host: reads need it, and
/// releasing it frees them. A host gives one with every result that ran,
/// a failed or cancelled one too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShadowArmLease(EntityId);

impl ShadowArmLease {
    /// A fresh lease.
    #[must_use]
    pub fn mint() -> Self {
        Self(EntityId::now())
    }

    /// Its name, for the host's own bookkeeping.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl ShadowRequestDigest {
    /// The digest of the copy of its request `capsule` keeps: the request as
    /// sent, or its masked copy as stored; `None` for a request the wall
    /// withheld (FIX 6254). A capsule whose route prompt is masked keeps no
    /// call as sent ([`StepReplayCapsule::as_sent`], FIX 6255), so its
    /// request's digest is the stored copy's, though it is the sent one.
    #[must_use]
    pub fn of_capsule(capsule: &StepReplayCapsule) -> Option<Self> {
        match &capsule.request {
            CapsuleRequest::Kept { .. } if capsule.as_sent() => {
                Some(Self::AsSent(capsule.request_hash))
            }
            CapsuleRequest::Kept { stored_hash, .. } => Some(Self::AsStored(*stored_hash)),
            CapsuleRequest::Withheld { .. } => None,
        }
    }
}
