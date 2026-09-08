mod emission;
mod envelope;
mod human_speech;
mod memory_verbs;

use std::cell::Cell;

use crate::code_run::consent;
use crate::code_run::replay::CodeRunBridgeCall;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    SelfCall, SelfContextCall, SelfContextResult, SelfDispatchOutcome, SelfDispatcher,
    SelfDurableWaitReason, SelfEffect,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::TrapRef;
use crate::off_record::OffRecordSession;
use crate::store::Store;
use crate::{ClaimSource, Vault, WriteActor};

pub(crate) use self::envelope::check_write_gate_against_vault;
#[cfg(test)]
pub(super) use self::envelope::{SELF_PROVENANCE_CALL_KEY, edge_operation_gate_id};
pub(super) use self::envelope::{SELF_PROVENANCE_SURFACE_KEY, lineage_for_run};
use self::human_speech::HumanWaitDispatchTarget;
pub use self::memory_verbs::SELF_MEMORY_SEARCH_MAX_RESULTS;

/// Host-bound dispatcher for one first-party code run.
///
/// The actor and source are bound at construction time by the host. Individual
/// [`SelfCall`] values carry only operation arguments, so guest-authored code
/// cannot spoof actor, source, or approval fields through this skeleton.
pub struct HostSelfDispatcher<'a> {
    pub(super) storage: ExecutorStorage<'a>,
    pub(super) actor: WriteActor,
    pub(super) run_ref: String,
    pub(super) human_wait_target: Option<HumanWaitDispatchTarget>,
    pub(super) code_emission:
        Option<(consent::CodeEmissionContext, Option<consent::ReviewContext>)>,
    /// ONE-1314. Whether this run's effect history is already known to carry
    /// an EXTERNAL effect, so the memory writes it seals afterwards must be
    /// stamped with tool-output lineage rather than bare `Generated`.
    ///
    /// Host-internal by construction: the only way to set it is
    /// [`Self::observe_bridge_history`], which takes a recorded bridge-call
    /// history (never a lineage value), and no `SelfCall` payload, public
    /// constructor, or API argument reaches it. It is a `Cell` because the
    /// executor holds the dispatcher by SHARED reference and the observation
    /// has to land before the write it describes dispatches. Monotone: once
    /// set it is never cleared, so a later step cannot launder an earlier
    /// external effect out of the run.
    pub(super) external_effect_seen: Cell<bool>,
}

/// Explicit first-party GatedActorWrite trap surface for engine-native code.
///
/// This is a type alias for [`HostSelfDispatcher`], whose public `self.memory.*`
/// variants stamp host-owned actor/provenance and run per-operation gate checks
/// before any write commits.
pub type GatedActorWrite<'a> = HostSelfDispatcher<'a>;

impl<'a> HostSelfDispatcher<'a> {
    /// Creates a dispatcher for a first-party run.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidClaimBody`] when `run_ref` is blank.
    pub fn new(vault: &'a Vault, actor: WriteActor, run_ref: impl Into<String>) -> Result<Self> {
        Self::bound(ExecutorStorage::Canonical(vault), actor, run_ref)
    }

    pub fn with_code_emission_context(
        vault: &'a Vault,
        actor: WriteActor,
        run_ref: impl Into<String>,
        emission: consent::CodeEmissionContext,
        review: Option<consent::ReviewContext>,
    ) -> Result<Self> {
        let mut dispatcher = Self::bound(ExecutorStorage::Canonical(vault), actor, run_ref)?;
        dispatcher.code_emission = Some((emission, review));
        Ok(dispatcher)
    }

    /// Creates the canonical dispatcher for a workflow step waiting on a real,
    /// human-assigned TASK. The task body remains authoritative for responder
    /// identity; dispatch resolves it when `self.ask_human` mints the wait.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidClaimBody`] when `run_ref` is blank.
    pub fn for_human_task(
        vault: &'a Vault,
        actor: WriteActor,
        run_ref: impl Into<String>,
        task_ref: EntityId,
        trap: TrapRef,
    ) -> Result<Self> {
        let mut dispatcher = Self::new(vault, actor, run_ref)?;
        dispatcher.human_wait_target = Some(HumanWaitDispatchTarget { task_ref, trap });
        Ok(dispatcher)
    }

    /// Creates a dispatcher bound to an already-acquired live off-record
    /// session (ONE-1729/P4b).
    ///
    /// This is RUN ENTRY for the session path: the run's one
    /// `SessionWriteRoute` and its conversation shell are captured here,
    /// before any read or write, and every later apply goes through them.
    /// The host binds `off_record_session_ref` once, upstream; what arrives
    /// here is the typed handle, never an unchecked string and never a second
    /// [`Vault`] clone.
    ///
    /// # Errors
    ///
    /// Propagates the session's own typed refusals when the room is closing
    /// or gone, plus [`crate::Error::InvalidClaimBody`] for a blank
    /// `run_ref`.
    pub fn for_off_record_session(
        session: &'a OffRecordSession<'a>,
        actor: WriteActor,
        run_ref: impl Into<String>,
    ) -> Result<Self> {
        Self::bound(ExecutorStorage::for_session(session)?, actor, run_ref)
    }

    fn bound(
        storage: ExecutorStorage<'a>,
        actor: WriteActor,
        run_ref: impl Into<String>,
    ) -> Result<Self> {
        let run_ref = run_ref.into();
        if run_ref.trim().is_empty() {
            return Err(crate::Error::InvalidClaimBody(
                "self dispatcher missing run ref",
            ));
        }

        Ok(Self {
            storage,
            actor,
            run_ref,
            human_wait_target: None,
            code_emission: None,
            external_effect_seen: Cell::new(false),
        })
    }

    /// Records what this run's effect history already contains.
    ///
    /// The HOST calls this with the run's recorded bridge calls — the durable
    /// replay record's history plus the current step's — before dispatching a
    /// write. It accepts a bridge-call history, never a lineage: the mapping
    /// from history to lineage is [`lineage_for_run`], owned here, so no
    /// caller can assert a narrower history than the one it recorded.
    pub(crate) fn observe_bridge_history(&self, bridge_calls: &[CodeRunBridgeCall]) {
        if lineage_for_run(bridge_calls).contains(ClaimSource::ToolOutput) {
            self.external_effect_seen.set(true);
        }
    }

    /// The bound session ref, or `None` for a canonical run.
    pub(crate) fn session_ref(&self) -> Option<&str> {
        self.storage.session_ref()
    }

    /// Identity-only projection of the store this dispatcher writes into.
    pub(crate) fn store_identity(&self) -> *const Store {
        self.storage.store_identity()
    }

    /// The session-owned conversation container for K-EXEC turns, created by
    /// the session machinery at session ENTRY (one shell per live session,
    /// enforced there — R-20260807-02 rider 1) and read from the session's
    /// in-memory registry entry. Never minted per bind; never `session_ref`.
    #[allow(
        dead_code,
        reason = "the identity pin's consumer is the branch-store oracle; an executor turn takes \
                  the container from the binding it already holds, never through a second lookup"
    )]
    pub(crate) fn session_container_id(&self) -> Option<&EntityId> {
        match &self.storage {
            ExecutorStorage::Canonical(_) => None,
            ExecutorStorage::Session(binding) => Some(&binding.container),
        }
    }

    /// Host-stamped actor for writes from this dispatcher.
    #[must_use]
    pub const fn actor(&self) -> WriteActor {
        self.actor
    }

    /// Host-stamped source for first-party generated code effects.
    #[must_use]
    pub const fn source(&self) -> ClaimSource {
        ClaimSource::Generated
    }

    /// Stable host run reference included in write provenance.
    #[must_use]
    pub fn run_ref(&self) -> &str {
        &self.run_ref
    }

    /// Dispatches one call on behalf of a durable engine-executor replay run.
    ///
    /// The ordinary [`SelfDispatcher`] implementation intentionally has no run
    /// id and preserves the standalone run-ref-only speech identity. The engine
    /// executor owns the durable id, so it enters through this crate-private
    /// door and binds that id only to transcript identity; guest payloads still
    /// cannot name or forge it.
    pub(crate) fn dispatch_for_executor_run(
        &self,
        run_id: EntityId,
        call: SelfCall,
    ) -> Result<SelfDispatchOutcome> {
        self.dispatch_bound(call, Some(run_id))
    }

    fn dispatch_bound(
        &self,
        call: SelfCall,
        run_id: Option<EntityId>,
    ) -> Result<SelfDispatchOutcome> {
        // The descriptor bridge answers before the policy probe: that probe is
        // itself a vault read, and `self.context` must perform none.
        if !matches!(call, SelfCall::Context(_)) {
            self.enforce_off_record_effect_policy(call.effect())?;
        }
        match call {
            SelfCall::MemorySearch(call) => self.dispatch_memory_search(call),
            SelfCall::MemoryWriteFixture(call) => self.dispatch_memory_write_fixture(call),
            SelfCall::MemoryPutClaim(call) => self.dispatch_memory_put_claim(call),
            SelfCall::MemorySupersedeClaim(call) => self.dispatch_memory_supersede_claim(call),
            SelfCall::MemoryPutEdge(call) => self.dispatch_memory_put_edge(call),
            SelfCall::AskHuman(call) => self.dispatch_ask_human(call),
            SelfCall::DestructiveFixture(call) => Ok(self.durable_wait(
                SelfEffect::DestructiveFixture,
                SelfDurableWaitReason::DestructiveEffect,
                Some(call.label),
            )),
            SelfCall::OutboundFixture(call) => Ok(self.durable_wait(
                SelfEffect::OutboundFixture,
                SelfDurableWaitReason::OutboundEffect,
                Some(call.label),
            )),
            SelfCall::Context(call) => dispatch_self_context(call),
            SelfCall::Speak(call) => self.dispatch_speech(SelfEffect::Speak, call, run_id),
            SelfCall::Think(call) => self.dispatch_speech(SelfEffect::Think, call, run_id),
            SelfCall::Express(call) => self.dispatch_speech(SelfEffect::Express, call, run_id),
        }
    }
}

impl SelfDispatcher for HostSelfDispatcher<'_> {
    /// Dispatch ordering on the session-bound path (ARCH-0052 §D6):
    ///
    /// 0. the run's `SessionWriteRoute` was captured at RUN ENTRY, in
    ///    [`HostSelfDispatcher::for_off_record_session`] — not here, and never
    ///    per dispatch;
    /// 1. mode-scoped effect policy, below, before anything else;
    /// 2. host envelope, then the write gate;
    /// 3. for on-record supersede only, ONE-1936's stale-target guard inside
    ///    its own transaction;
    /// 4. the apply, through the STORED route, which revalidates itself.
    ///
    /// Canonical dispatch keeps its existing path and captures no route.
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome> {
        self.dispatch_bound(call, None)
    }
}

/// `self.context(spec)` — validate, normalize, hand the descriptor back.
///
/// Deliberately a free function, not a `HostSelfDispatcher` method: it has no
/// access to the vault, which is the strongest available statement that the
/// call performs no read.
fn dispatch_self_context(call: SelfContextCall) -> Result<SelfDispatchOutcome> {
    let spec = crate::context_projection::normalize_context_spec(call.spec);
    crate::context_projection::validate_context_spec(&spec)?;
    Ok(SelfDispatchOutcome::Context(SelfContextResult {
        spec: crate::context_projection::context(spec),
    }))
}
