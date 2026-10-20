//! The shadow runner (PR-S1; FIX 1661/2144, the runner side of L07-B's
//! B2b): one captured step of a canonical run, run again in an arm of its
//! own, so a candidate engine's step can be compared with the baseline's on
//! the same input. An arm runs from immutable identity only: a step replay
//! capsule's request as stored and its start, the run's earlier results
//! frozen before the arm starts, a guest clock and seed, the model and route
//! the captured call went out on, and a protocol version.
//!
//! What PR-S1 runs is the trusted baseline, in its host's process: the
//! captured request goes to the pinned model through the host's metered
//! gateway, the reply is healed as a run's is, and its program runs on a
//! fresh runtime against a replay-only bridge (`ShadowBridgeHost`): each
//! call it makes is collected as a proposed effect and answered with the
//! step's recorded outcome, nothing is applied, and its results stay in the
//! arm's own store ([`ShadowBodyStore`]). A candidate engine (a build or a
//! patch) is unavailable before any of its code is loaded, until the
//! sandboxed candidate process lands (PR-S2), and a whole run is
//! unavailable: an arm ends after its captured step. This is not B2b's
//! completion.
//!
//! [`ShadowRunner`] is the seam a host implements and L07-B's comparison
//! calls; [`ShadowFrame`]s are the protocol PR-S2's process speaks.
//! An unavailable arm is a result with a typed reason
//! ([`ShadowUnavailableReason`]), never a loss or a fix; `Err` is a runner
//! or storage failure.

mod admit;
mod bridge;
mod frames;
mod source;
mod store;
mod types;

use std::future::Future;
use std::pin::Pin;

pub use self::admit::admit_published_inline;
pub(crate) use self::bridge::{ArmReads, ShadowBridgeHost};
pub use self::frames::{ShadowFrame, ShadowFrameBody, ShadowModelAnswer, ShadowReceiptFrame};
pub use self::source::{PreparedShadowStep, prepare_shadow_step_source, shadow_source_gone};
pub use self::store::{ShadowBodyStore, ShadowSourceHold};
pub use self::types::{
    ArtifactDigest, ArtifactDigestAlgorithm, EngineArtifactPin, ShadowArmLease, ShadowBodyRef,
    ShadowBridgeWindow, ShadowDeterminism, ShadowIsolation, ShadowIsolationRequired,
    ShadowMeterContext, ShadowModelPin, ShadowModelReceipt, ShadowRequestDigest, ShadowRunRequest,
    ShadowRunResult, ShadowSandboxBinding, ShadowScope, ShadowSource, ShadowStatus,
    ShadowStepIdentity, ShadowStepRun, ShadowTarget, ShadowTraceEntry, ShadowTraceKind,
    ShadowUnavailable, ShadowUnavailableReason, ShadowUsage, ShadowWindowFullReason,
};
use crate::Result;

/// The shadow protocol's version: a request or frame of another is
/// unavailable (`ProtocolUnsupported`). CALLS "shadow protocol version 1".
pub const SHADOW_PROTOCOL_VERSION: u32 = 1;

/// One arm's run, as a runner answers it.
pub type ShadowRunFuture<'a> = Pin<Box<dyn Future<Output = Result<ShadowRunResult>> + Send + 'a>>;

/// A host that runs shadow arms.
pub trait ShadowRunner: Send + Sync {
    /// Runs one arm of `request`, to its result: run, or unavailable for a
    /// typed reason. `Err` is a runner or storage failure.
    fn run<'a>(&'a self, request: ShadowRunRequest) -> ShadowRunFuture<'a>;
}
