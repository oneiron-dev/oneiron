//! Host construction, binding and captured identity for a dispatcher.
//! Entry: `HostSelfDispatcher::new`.
//! `HostSelfDispatcher` state is defined by `code_run::dispatcher`.

use super::*;

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
    /// identity; dispatch resolves it when `ask` mints the wait.
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
    /// or gone, or `actor` is not in the stretch's room, plus
    /// [`crate::Error::InvalidClaimBody`] for a blank `run_ref`.
    pub fn for_off_record_session(
        session: &'a OffRecordSession<'a>,
        actor: WriteActor,
        run_ref: impl Into<String>,
    ) -> Result<Self> {
        Self::bound(
            ExecutorStorage::for_session(session, actor.entity_ref())?,
            actor,
            run_ref,
        )
    }

    pub(super) fn bound(
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
            agent_parent: None,
            agent_lease: None,
            activity: None,
            skill_vault: None,
            storage,
            actor,
            run_ref,
            human_wait_target: None,
            code_emission: None,
            owner_proof: None,
            owner_surface: None,
            opener_lineage: Vec::new(),
            external_effect_seen: Cell::new(false),
            agent_verbs: None,
            hook_view: RefCell::new(None),
            parked_hooks: RefCell::new(Vec::new()),
            reader_spawn: None,
            reader_child: None,
            scoped_ports: None,
            bound_run: None,
            planner: None,
            slip_issuer: None,
            replay_exposures: Vec::new(),
            model_provider: RefCell::new(None),
            run_request: RefCell::new(None),
            fold_log: fold_verbs::FoldLog::Site,
            program: None,
            read_worlds: Cell::default(),
            caller_task: false,
            repo_review_policy: None,
        })
    }

    /// Binds the host's door onto the SDK verb table, so each verb-table call
    /// runs each verb with that host's ceiling and gate.
    ///
    /// A host that binds a door runs one attempt of a run at a time, as the
    /// MCP code host's single-flight does: the door's rulings on a step's kept
    /// answers and that step's checkpoint are separate records, so two
    /// attempts of one step at once could close it past a refusal.
    #[must_use]
    pub fn with_agent_verb_door(
        mut self,
        door: std::sync::Arc<dyn crate::code_run::AgentVerbDoor>,
    ) -> Self {
        self.agent_verbs = Some(door);
        self
    }

    /// The skill bodies the host put in the run's task, each where it went
    /// (FIX 3028): the run's first step is captured with them tagged, for a
    /// later contribution check.
    #[must_use]
    pub fn with_replay_exposures(mut self, exposures: Vec<crate::code_run::TaskExposure>) -> Self {
        self.replay_exposures = exposures;
        self
    }

    /// The leased attempt this run serves, its lease generation and the
    /// exposures its task holds, for the run's step replay capsule; `None`
    /// for a run no attempt lease binds.
    pub(crate) fn replay_capture(
        &self,
    ) -> Option<(
        crate::attempt_queue::AttemptId,
        u32,
        &[crate::code_run::TaskExposure],
    )> {
        self.agent_lease.as_ref().map(|lease| {
            (
                lease.attempt,
                lease.generation,
                self.replay_exposures.as_slice(),
            )
        })
    }

    /// The write token of the leased run this dispatcher serves, from its
    /// lease, for a write the run makes outside a verb call's envelope (FIX
    /// 3103); `None` for a run no attempt lease binds.
    pub(crate) fn run_write_token(&self) -> Option<crate::skill_attribution::RunWriteToken> {
        self.agent_lease
            .as_ref()
            .map(crate::skill_attribution::RunWriteToken::from_lease)
    }

    /// Binds a host-authenticated owner proof to one agent action dispatch.
    /// The guest payload has no field from which it could construct this.
    pub(crate) fn with_authenticated_owner(
        mut self,
        owner: &'a crate::consent::AuthenticatedOwner,
    ) -> Self {
        self.owner_proof = Some(owner);
        self
    }

    /// Where the bound owner's say-so reached the host (WILL-PLAN L13 row
    /// 01): an owner setting records it in the owner's act. Audit only; no
    /// admission reads it.
    pub(crate) fn with_owner_surface(
        mut self,
        surface: Option<crate::authority::ActSurface>,
    ) -> Self {
        self.owner_surface = surface;
        self
    }

    /// Binds the credential the host admitted the run's caller under (FIX
    /// 4705): its slip and that slip's parent become the run's own lineage,
    /// which with its forks never settles a request the run opens. The ids
    /// come from the verified slip itself, never from a guest or wire value.
    #[must_use]
    pub fn with_opener_credential(mut self, credential: &crate::authority::VerifiedSlip) -> Self {
        let claims = credential.claims();
        self.opener_lineage = std::iter::once(claims.slip_id)
            .chain(claims.parent_id)
            .collect();
        self
    }

    /// Records what this run's effect history already contains.
    ///
    /// The HOST calls this with the run's recorded bridge calls — the durable
    /// replay record's history plus the current step's — before dispatching a
    /// write. It accepts a bridge-call history, never a lineage: the mapping
    /// from history to lineage is [`lineage_for_run`], owned here, so no
    /// caller can assert a narrower history than the one it recorded.
    ///
    /// The same history names the calls a verb hook's ask parked, so the
    /// same call made again resumes its ask.
    pub(crate) fn observe_bridge_history(&self, bridge_calls: &[CodeRunBridgeCall]) {
        if lineage_for_run(bridge_calls).contains(ClaimSource::ToolOutput) {
            self.external_effect_seen.set(true);
        }
        self.observe_parked_hooks(bridge_calls);
    }

    /// The HOST calls this with each turn's answer before its program runs:
    /// the provider its ladder served the turn from, or `None` when no ladder
    /// stamped it. Each verb call the program makes carries it on its origin.
    pub(crate) fn observe_model_provider(&self, provider: Option<&str>) {
        *self.model_provider.borrow_mut() = provider.map(str::to_owned);
    }

    /// The provider [`Self::observe_model_provider`] last recorded.
    pub(in crate::code_run) fn model_provider(&self) -> Option<String> {
        self.model_provider.borrow().clone()
    }

    /// The bound session ref, or `None` for a canonical run.
    pub(crate) fn session_ref(&self) -> Option<&str> {
        self.storage.session_ref()
    }

    /// Identity of the vault this dispatcher writes into.
    pub(crate) fn vault_id(&self) -> VaultId {
        self.storage.vault_id()
    }

    /// The participant a session-bound dispatcher acts as, or `None` for a
    /// canonical run.
    pub(crate) fn participant(&self) -> Option<EntityId> {
        self.storage.participant()
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
}
