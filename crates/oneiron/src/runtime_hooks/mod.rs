//! Runtime hooks (ARCH-0080). Slice 1: fact hooks that run after a write
//! commits, on their own runner. Slice 2 (`verb`): verb hooks inside a call.
//!
//! The runner follows the claim changelog and the settlement feed through
//! typed per-binding cursors. Rust filters each fact, under the hook's own
//! grant, before any sandbox starts. Each run is keyed by its derivation
//! envelope: its memo row, local outcomes, Hook receipt, saved intents and
//! cursor commit in one write, and queued work lands afterwards through the
//! existing doors, as the hook's author with source Generated.

mod apply;
mod block;
mod body;
mod dial;
mod filter;
mod grant;
mod lineage;
mod outcome;
mod read;
mod replay;
mod runner;
#[cfg(feature = "code-sandbox-wasmtime")]
pub mod sandbox;
mod source;
mod store;
pub mod verb;

pub use block::{HookBlock, HookBlockLifetime};
pub use body::{HookBodyRun, HookBodyRuntime};
pub use grant::HookGrant;
pub use lineage::{HookCheck, HookCheckReason, LineageLink};
pub use outcome::{
    BlockRequest, EnqueuedDreamer, EnqueuedTask, HookOutcome, ProposedClaim, ProposedEdge,
    ProposedNote,
};
pub use replay::{HookReplayEntry, HookReplayResult};
pub use runner::{FactHookRunner, HOOK_PASS_ENTRIES, HOOK_RUNNER_TICK, HookPassReport};
#[allow(
    unused_imports,
    reason = "the gate's settlement doors call it once their seam lands"
)]
pub(crate) use source::record_settlement_in_txn;
pub use source::{
    ClaimChangelogPosition, FactKind, FactPosition, FactPositionHex, FactSource, SettledFact,
    SettledOutcome, SettlementKind, SettlementPosition,
};
pub(crate) use store::hook_receipts;
pub use verb::{
    InvocationId, VerbCall, VerbDomain, VerbHookPre, VerbHookStop, hook_class,
};
