//! Runtime hooks (ARCH-0080). Slice 1: fact hooks that run after a write
//! commits, on their own runner. Slice 2 (`verb`): verb hooks inside a call.
//!
//! The runner follows the claim changelog, the settlement feed, the tick
//! feed of due TASKs and the inbound surface-event feed (FIX 4749) through
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
mod host;
pub mod host_doors;
mod lineage;
mod outcome;
mod pack_line;
mod read;
mod regen;
mod replay;
mod runner;
#[cfg(feature = "code-sandbox-wasmtime")]
pub mod sandbox;
mod scope;
mod source;
mod store;
pub mod verb;

pub use block::{HookBlock, HookBlockLifetime, HookTurnTarget};
pub use body::{
    HookBodyRun, HookBodyRuntime, HookBodyUsage, HookBudgetOverrun, HookPreparation,
    HookRunContext, HookSettledCallRef, HookVerdict, HookVerdictCall, HookVerdictContext,
    HookVerdictReply,
};
pub use grant::HookGrant;
pub(crate) use grant::carry_hook_grant_in_txn;
pub use host::{BudgetHit, HOST_BUDGET_HIT};
pub use lineage::{HookCheck, HookCheckReason, LineageLink};
pub use outcome::{
    BlockRequest, EnqueuedDreamer, EnqueuedTask, HookOutcome, ProposedClaim, ProposedEdge,
    ProposedNote,
};
pub use read::grant_view::{hook_evidence_views, hook_pull_image};
pub(crate) use regen::note_bound_hook_in_txn;
pub use regen::{
    HookContractStamp, HookGoldenDiff, HookGoldenFingerprint, HookRegenFailure,
    HookRegenFailurePhase, HookRegenOutcome, HookRegenRecord, HookRegenRequest, HookRegenerator,
};
pub use replay::{
    HookReplayCase, HookReplayCompare, HookReplayCursor, HookReplayEntry, HookReplayEntryPage,
    HookReplayResult,
};
pub use runner::{
    FactHookRunner, HOOK_PASS_ENTRIES, HOOK_RUNNER_TICK, HookPassAdmission, HookPassReport,
};
pub(crate) use scope::HookScope;
#[allow(
    unused_imports,
    reason = "the gate's settlement doors call it once their seam lands"
)]
pub(crate) use source::record_settlement_in_txn;
pub(crate) use source::record_timeout_demotion_in_txn;
pub use source::{
    ClaimChangelogPosition, FactKind, FactPosition, FactPositionHex, FactSource, SchedulePosition,
    SettledFact, SettledOutcome, SettlementKind, SettlementPosition, SurfaceInboundPosition,
};
pub(crate) use source::{index_task_due_in_txn, record_surface_inbound_in_txn};
pub(crate) use store::{
    hook_receipts, hook_run_read_rows, scrub_hook_source_in_txn, sync_binding_cursor_in_txn,
};
pub use verb::{
    InvocationId, VerbCall, VerbCallScope, VerbDomain, VerbHookPre, VerbHookPreSnapshot,
    VerbHookStop, hook_class,
};
pub(crate) use verb::{VerbResume, verb_ask_settled_in_txn};

// The lift sweep's typed acceptance for this module's authored side
// tables (FIX 2680), named by their declarations.
pub(crate) use self::block::hooks_block_accepts_masked;
pub(crate) use self::regen::hooks_regen_accepts_masked;
pub(crate) use self::store::hooks_intent_accepts_masked;
pub(crate) use self::store::hooks_memo_accepts_masked;
pub(crate) use self::store::hooks_receipt_accepts_masked;
pub(crate) use self::verb::hooks_verb_run_accepts_masked;
