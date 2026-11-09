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
pub(crate) mod tables;
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
    HOOK_REGEN_CALL_PURPOSE_NAME, HookContractStamp, HookContractText, HookGoldenDiff,
    HookGoldenFingerprint, HookGoldenManifest, HookRegenActor, HookRegenCancel, HookRegenDecision,
    HookRegenEvent, HookRegenFailure, HookRegenFailurePhase, HookRegenOutcome, HookRegenPassReport,
    HookRegenPrior, HookRegenReceipt, HookRegenRecord, HookRegenRequest, HookRegenerator,
    MAX_HOOK_CONTRACT_DECLARATIONS, MAX_HOOK_REGEN_HISTORY,
};
pub use replay::{
    HookReplayCase, HookReplayCompare, HookReplayCursor, HookReplayEntry, HookReplayEntryPage,
    HookReplayResult,
};
pub(crate) use runner::prune_hook_feeds;
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
// Untangle slice 6.8: change feed subscriptions read the hooks' positions, heads and settlement
// feed, and filter claims with the hooks' glob.
pub(crate) use filter::glob_match;
pub(crate) use source::head_in_txn as fact_source_head_in_txn;
pub(crate) use source::settled_feed_facts_after_in_txn;
pub use source::{
    ClaimChangelogPosition, FactKind, FactPosition, FactPositionHex, FactSource, SchedulePosition,
    SettledFact, SettledOutcome, SettlementKind, SettlementPosition, SurfaceInboundPosition,
};
pub(crate) use source::{
    index_task_due_in_txn, next_tick_release_at, record_surface_inbound_in_txn, release_due_ticks,
};
pub(crate) use store::{
    forget_scrubbed_source_in_txn, hook_receipts, hook_run_read_rows, scrub_erased_hook_sources,
    scrub_erased_in_session_stores, scrub_hook_source_in_txn, sync_binding_cursor_in_txn,
};
pub use verb::{
    InvocationId, VerbCall, VerbCallScope, VerbDomain, VerbHookPre, VerbHookPreSnapshot,
    VerbHookStop, hook_class,
};
pub(crate) use verb::{VerbResume, verb_ask_settled_in_txn};

// The lift sweep's typed acceptance for this module's authored side
// tables (FIX 2680), named by their declarations.
pub(crate) use self::block::hooks_block_accepts_masked;
pub(crate) use self::regen::{hooks_regen_accepts_masked, hooks_regen_receipt_accepts_masked};
pub(crate) use self::store::hooks_intent_accepts_masked;
pub(crate) use self::store::hooks_memo_accepts_masked;
pub(crate) use self::store::hooks_receipt_accepts_masked;
pub(crate) use self::verb::hooks_verb_run_accepts_masked;
