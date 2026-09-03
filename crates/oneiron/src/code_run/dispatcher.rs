use rmpv::Value;
use sha2::{Digest, Sha256};
use xxhash_rust::xxh3::xxh3_128;

use crate::code_sandbox::SandboxGuestTier;
use crate::llm::TrapRef;
use crate::off_record::OffRecordSession;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::store::Store;
use crate::vault::LiveEntityRow;
use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EdgeKind,
    EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};

use super::consent;
use super::consent::CodeSourceTrust;
use super::storage::ExecutorStorage;
use super::types::{
    SelfAskHumanCall, SelfCall, SelfContextCall, SelfContextResult, SelfDispatchOutcome,
    SelfDispatcher, SelfDurableWait, SelfDurableWaitReason, SelfEffect, SelfMemoryEdgeWriteResult,
    SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall, SelfMemorySearchCall, SelfMemorySearchResult,
    SelfMemorySupersedeClaimCall, SelfMemoryWriteFixtureCall, SelfMemoryWriteResult,
    SelfSpeechCall, SelfSpeechResult,
};

const SELF_SURFACE_NAME: &str = "self.*";
pub(super) const SELF_PROVENANCE_SURFACE_KEY: &str = "surface";
const SELF_PROVENANCE_RUN_KEY: &str = "run";
pub(super) const SELF_PROVENANCE_CALL_KEY: &str = "call";
const SELF_MEMORY_EDGE_OPERATION_ID_DOMAIN: &[u8] = b"oneiron:self-memory-edge-operation:v1";
/// Domain of the code-emission admission record's id, kept separate from the
/// emission's own identity so a record handle can never collide with — or be
/// mistaken for — the claim, edge or gate ids of the write it witnesses.
const CODE_EMISSION_RECORD_ID_DOMAIN: &[u8] = b"oneiron:self-code-emission-record:v1";
/// Body keys of the code-emission admission record: what the host DECIDED
/// (lane inputs) and which run it decided for.
const CODE_EMISSION_RECORD_KEYS: [&str; 5] =
    ["kind", "tier", "source_trust", "dreamer_run_id", "run_ref"];

/// Maximum results a first-party `self.memory.search` call can request.
pub const SELF_MEMORY_SEARCH_MAX_RESULTS: usize = 16;

#[derive(Debug, Clone, Copy)]
struct HumanWaitDispatchTarget {
    task_ref: EntityId,
    trap: TrapRef,
}

/// Host-bound dispatcher for one first-party code run.
///
/// The actor and source are bound at construction time by the host. Individual
/// [`SelfCall`] values carry only operation arguments, so guest-authored code
/// cannot spoof actor, source, or approval fields through this skeleton.
pub struct HostSelfDispatcher<'a> {
    storage: ExecutorStorage<'a>,
    actor: WriteActor,
    run_ref: String,
    human_wait_target: Option<HumanWaitDispatchTarget>,
    code_emission: Option<(consent::CodeEmissionContext, Option<consent::ReviewContext>)>,
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
        })
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

    /// Effect-level off-record policy — the FIRST check on the session path.
    ///
    /// While the bound room is off record, the four durable memory-write
    /// verbs are refused before `write_envelope`, policy/gate evaluation,
    /// transaction acquisition, decision append, ONE-1936's stale-target
    /// guard, or any overlay/base mutation. Off-record is TALK-ONLY: a
    /// durable write is not made acceptable by being made ephemeral, so the
    /// answer is refusal, not redirection.
    ///
    /// The rejection is mode-scoped POLICY, never inferred from where a row
    /// would route: after the same live session flips `OnRecord` the ordinary
    /// verb path is available again to a run that binds after the flip. A run
    /// that was already in flight keeps its run-entry route, whose
    /// `revalidate` refuses the write instead of splitting the record across
    /// the flip.
    ///
    /// The match is exhaustive so a new effect cannot default into either
    /// answer — it has to be ruled on here.
    fn enforce_off_record_effect_policy(&self, effect: SelfEffect) -> Result<()> {
        if !self.storage.off_record_policy_active()? {
            return Ok(());
        }
        match effect {
            // Delegation mints a synced TASK entity, so it lands on the
            // durable-record side of the talk-only line with the memory writes.
            SelfEffect::MemoryPutClaim
            | SelfEffect::MemorySupersedeClaim
            | SelfEffect::MemoryPutEdge
            | SelfEffect::MemoryWriteFixture
            | SelfEffect::TaskDelegate => Err(Error::OffRecordTalkOnly {
                session_ref: self.storage.session_ref().unwrap_or_default().to_owned(),
            }),
            // `self.context` stores nothing and reads nothing — a descriptor
            // round-trip has no durable-record side for the talk-only line to
            // protect.
            //
            // The speech family is what TALK-ONLY means: a room that is off
            // record is still a room somebody is speaking in, and its
            // utterances ride the session's own route into the overlay, where
            // they evaporate with it. Refusing them here would make an
            // off-record room mute rather than private.
            SelfEffect::MemorySearch
            | SelfEffect::AskHuman
            | SelfEffect::DestructiveFixture
            | SelfEffect::OutboundFixture
            | SelfEffect::Context
            | SelfEffect::Speak
            | SelfEffect::Think
            | SelfEffect::Express => Ok(()),
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

    fn code_emission_admission(&self) -> Result<Option<consent::CodeEmissionAdmission>> {
        let Some((emission, review)) = &self.code_emission else {
            return Ok(None);
        };
        let review_input = review
            .as_ref()
            .map(consent::ReviewContext::as_input)
            .transpose()?;
        let emission_record = self.ensure_code_emission_record(emission)?;
        consent::admit_code_emission(
            emission.tier,
            emission.source_trust,
            emission.dreamer_run_id.as_deref(),
            &emission.touched_symbols,
            review_input.as_ref(),
            emission_record,
        )
        .map(Some)
    }

    /// Persists the free lane's evidence — the host's own admission decision —
    /// and returns the record's handle.
    ///
    /// The free lane has no model-authored evidence to cite, but it does have a
    /// truthful host fact: THIS run, at THIS tier and source trust, was admitted
    /// to write. That fact lives only in memory until it is persisted here, as
    /// one typed entity with a deterministic domain-separated id, in its OWN
    /// transaction — committed before `dispatch_memory_put_claim` or
    /// `dispatch_memory_write_fixture` opens the gate that cites it, so the
    /// door's in-transaction resolver always sees it.
    ///
    /// Minting is idempotent by construction: the id is a function of the
    /// admission identity, so a second dispatch of the same admission finds the
    /// record already there and cites it rather than writing a duplicate. What
    /// it cites is VERIFIED, never assumed from a surviving row: reuse requires
    /// a live entity (not an ARCH-0038 soft-delete shell) of exactly
    /// `ENTITY_TYPE_ASSET` whose body is byte-equal to this admission's own
    /// record body. Any other occupant of the id — deleted, foreign type, or
    /// divergent body — is a host-invariant refusal here, never a citation and
    /// never a remint over the id. The put is a direct typed entity write,
    /// NEVER a claim or batch candidate, so it adds no gate decision and no
    /// pending-consent row.
    ///
    /// The review lane returns `None`: its evidence is the blast-radius walk's
    /// own artifact refs, and a record it would never cite is a write nobody
    /// asked for.
    fn ensure_code_emission_record(
        &self,
        emission: &consent::CodeEmissionContext,
    ) -> Result<Option<EntityId>> {
        if consent::consent_lane_for(emission.tier, emission.source_trust)
            != consent::ConsentLane::Free
        {
            return Ok(None);
        }
        // Same trim and same refusal the admission itself makes, so a run
        // without a handle is refused before anything is written.
        let dreamer_run_id = emission
            .dreamer_run_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .ok_or(Error::CodeEmissionMissingDreamerRunId)?;
        // A code-emission context is bound at construction to the canonical
        // vault (`with_code_emission_context`), and the session arm hands out
        // no entity door: an admission arriving on it would be a binding this
        // dispatcher never made.
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(Error::InvariantViolation(
                "code emission admission requires canonical storage",
            ));
        };
        let record_id = code_emission_record_id(
            emission.tier,
            emission.source_trust,
            dreamer_run_id,
            &self.run_ref,
        )?;
        // The record's identity IS its body, so the expected bytes are
        // computed once: they verify an occupant of the deterministic id, and
        // they are what an absent id is minted with.
        let expected_body = code_emission_record_body(
            emission.tier,
            emission.source_trust,
            dreamer_run_id,
            &self.run_ref,
        )?;
        match vault.live_entity_row(&record_id)? {
            // Nothing occupies the id: mint, exactly as before.
            LiveEntityRow::Absent => {}
            // The record this admission would have written is already there,
            // proven by its own bytes rather than by a surviving header.
            LiveEntityRow::Live { entity_type, body }
                if entity_type == ENTITY_TYPE_ASSET && body == expected_body =>
            {
                return Ok(Some(record_id));
            }
            // A soft-delete shell, a foreign entity type, or a divergent body
            // is NOT this admission's record. Citing it would make the free
            // lane's only evidence a lie, and reminting over it would
            // resurrect a tombstoned entity (ARCH-0038) or overwrite an
            // entity nobody asked to lose — so the dispatch fails closed here,
            // before any claim, Proposed row, pending consent or gate receipt
            // exists.
            LiveEntityRow::Live { .. } | LiveEntityRow::DeletedShell => {
                return Err(Error::InvariantViolation(
                    "code emission record id holds a deleted or divergent entity",
                ));
            }
        }
        let now = crate::unix_seconds_now();
        vault.put_entity(
            &record_id,
            ENTITY_TYPE_ASSET,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &expected_body,
        )?;
        Ok(Some(record_id))
    }

    fn non_candidate_code_emission_admission(
        &self,
    ) -> Result<Option<consent::CodeEmissionAdmission>> {
        let Some((emission, _)) = &self.code_emission else {
            return Ok(None);
        };
        let dreamer_run_id = emission
            .dreamer_run_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .ok_or(Error::CodeEmissionMissingDreamerRunId)?;
        Ok(Some(consent::CodeEmissionAdmission {
            lane: consent::consent_lane_for(emission.tier, emission.source_trust),
            dreamer_run_id: dreamer_run_id.to_owned(),
            candidate_evidence: None,
            // The memory VERBS this admission stamps persist no claim
            // candidate, so there is no candidate evidence for a record to be
            // cited by, and nothing to mint.
            emission_record: None,
        }))
    }

    fn write_envelope(
        &self,
        effect: SelfEffect,
        admission: Option<&consent::CodeEmissionAdmission>,
    ) -> Result<WriteEnvelope> {
        let mut provenance = vec![
            (
                Value::from(SELF_PROVENANCE_SURFACE_KEY),
                Value::from(SELF_SURFACE_NAME),
            ),
            (
                Value::from(SELF_PROVENANCE_RUN_KEY),
                Value::from(self.run_ref.clone()),
            ),
            (
                Value::from(SELF_PROVENANCE_CALL_KEY),
                Value::from(effect.as_str()),
            ),
        ];
        if let Some(admission) = admission {
            provenance.push((Value::from("runner"), Value::from("dreamer")));
            provenance.push((
                Value::from("run_id"),
                Value::from(admission.dreamer_run_id.as_str()),
            ));
        }
        Ok(WriteEnvelope::new(
            self.actor,
            self.source(),
            WriteProvenance::new(Value::Map(provenance))?,
            ClaimApprovalStatus::Proposed,
        ))
    }

    fn dispatch_memory_search(&self, call: SelfMemorySearchCall) -> Result<SelfDispatchOutcome> {
        let limit = call.limit.min(SELF_MEMORY_SEARCH_MAX_RESULTS);
        let results = self.storage.search_text(&call.query, limit)?;
        Ok(SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
            query: call.query,
            results,
        }))
    }

    fn dispatch_memory_write_fixture(
        &self,
        call: SelfMemoryWriteFixtureCall,
    ) -> Result<SelfDispatchOutcome> {
        let admission = self.code_emission_admission()?;
        let candidate = match admission
            .as_ref()
            .and_then(|admission| admission.candidate_evidence.clone())
        {
            Some(evidence) => (*call.candidate).clone().with_evidence(evidence),
            None => *call.candidate,
        };
        let envelope = self.write_envelope(SelfEffect::MemoryWriteFixture, admission.as_ref())?;
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault
                .batch()
                .claim_candidate(
                    &call.id,
                    candidate,
                    &envelope,
                    call.occurred,
                    call.learned_at,
                )
                .commit()?,
            ExecutorStorage::Session(binding) => {
                binding.session.executor_batch_claim_candidate(
                    &binding.route,
                    &call.id,
                    candidate,
                    &envelope,
                    call.occurred,
                    call.learned_at,
                )?;
            }
        }

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.id,
        }))
    }

    fn dispatch_memory_put_claim(
        &self,
        call: SelfMemoryPutClaimCall,
    ) -> Result<SelfDispatchOutcome> {
        let admission = self.code_emission_admission()?;
        let candidate = match admission
            .as_ref()
            .and_then(|admission| admission.candidate_evidence.clone())
        {
            Some(evidence) => (*call.candidate).clone().with_evidence(evidence),
            None => *call.candidate,
        };
        let envelope = self.write_envelope(SelfEffect::MemoryPutClaim, admission.as_ref())?;
        let gate_body = candidate.clone().into_claim_body(&envelope);
        self.check_write_gate(call.id, &gate_body, &envelope, true)?;
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault
                .put_claim_candidate_without_lexical_query_reconcile(
                    &call.id,
                    candidate,
                    &envelope,
                    call.occurred,
                    call.learned_at,
                )?,
            ExecutorStorage::Session(binding) => binding.session.executor_put_claim_candidate(
                &binding.route,
                &call.id,
                candidate,
                &envelope,
                call.occurred,
                call.learned_at,
            )?,
        }

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.id,
        }))
    }

    fn dispatch_memory_supersede_claim(
        &self,
        call: SelfMemorySupersedeClaimCall,
    ) -> Result<SelfDispatchOutcome> {
        let admission = self.non_candidate_code_emission_admission()?;
        if matches!(
            admission.as_ref().map(|admission| admission.lane),
            Some(consent::ConsentLane::Review)
        ) {
            return Err(Error::CodeReviewUnsupportedOperation);
        }
        let envelope = self.write_envelope(SelfEffect::MemorySupersedeClaim, admission.as_ref())?;
        let claim_gate_body = self.operation_gate_body(
            SelfEffect::MemorySupersedeClaim,
            ClaimSubject::Entity(call.old_id),
            Value::Binary(call.new_id.as_bytes().to_vec()),
            &envelope,
        );

        let supersedes_weight =
            EdgeKind::Supersedes
                .default_weight()
                .ok_or(Error::InvariantViolation(
                    "Supersedes edge missing default weight",
                ))?;
        let edge_gate_body = self.operation_gate_body(
            SelfEffect::MemorySupersedeClaim,
            ClaimSubject::Edge {
                source: call.new_id,
                kind: EdgeKind::Supersedes,
                target: call.old_id,
            },
            Value::F32(supersedes_weight),
            &envelope,
        );
        let edge_gate_id = edge_operation_gate_id(
            SelfEffect::MemorySupersedeClaim,
            call.new_id,
            EdgeKind::Supersedes,
            call.old_id,
        )?;
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault.supersede_claim_for_code_run_trap(
                &call.new_id,
                &call.old_id,
                call.now,
                &envelope,
                call.old_id,
                &claim_gate_body,
                edge_gate_id,
                &edge_gate_body,
            )?,
            ExecutorStorage::Session(binding) => binding.session.executor_supersede_claim(
                &binding.route,
                &call.new_id,
                &call.old_id,
                call.now,
                &envelope,
                call.old_id,
                &claim_gate_body,
                edge_gate_id,
                &edge_gate_body,
            )?,
        }

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.new_id,
        }))
    }

    fn dispatch_memory_put_edge(&self, call: SelfMemoryPutEdgeCall) -> Result<SelfDispatchOutcome> {
        ensure_public_memory_edge_kind(call.kind)?;
        let admission = self.non_candidate_code_emission_admission()?;
        if matches!(
            admission.as_ref().map(|admission| admission.lane),
            Some(consent::ConsentLane::Review)
        ) {
            return Err(Error::CodeReviewUnsupportedOperation);
        }
        let envelope = self.write_envelope(SelfEffect::MemoryPutEdge, admission.as_ref())?;
        let gate_body = self.operation_gate_body(
            SelfEffect::MemoryPutEdge,
            ClaimSubject::Edge {
                source: call.src,
                kind: call.kind,
                target: call.tgt,
            },
            Value::F32(call.weight),
            &envelope,
        );
        let gate_id =
            edge_operation_gate_id(SelfEffect::MemoryPutEdge, call.src, call.kind, call.tgt)?;
        match &self.storage {
            ExecutorStorage::Canonical(vault) => vault.put_edge_for_code_run_trap(
                &call.src,
                call.kind,
                &call.tgt,
                call.weight,
                &envelope,
                gate_id,
                &gate_body,
            )?,
            ExecutorStorage::Session(binding) => binding.session.executor_put_edge(
                &binding.route,
                &call.src,
                call.kind,
                &call.tgt,
                call.weight,
                &envelope,
                gate_id,
                &gate_body,
            )?,
        }

        Ok(SelfDispatchOutcome::MemoryEdgeWrite(
            SelfMemoryEdgeWriteResult {
                src: call.src,
                kind: call.kind,
                tgt: call.tgt,
            },
        ))
    }

    fn operation_gate_body(
        &self,
        effect: SelfEffect,
        subject: ClaimSubject,
        value: Value,
        envelope: &WriteEnvelope,
    ) -> ClaimBody {
        let mut body = ClaimBody::new(
            effect.as_str(),
            subject,
            value,
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(crate::write_envelope::write_envelope_evidence(
            envelope, None,
        ));
        body.source = Some(envelope.source());
        body
    }

    /// Executor-path gate routing: DECISIONS FOLLOW THEIR CONTENT.
    ///
    /// `Canonical` takes the unchanged vault-store path. A session run reaches
    /// here only after [`Self::enforce_off_record_effect_policy`] passed,
    /// which — for the four durable memory verbs — means the room is ON
    /// RECORD; its decision is a decision about base content and lands in
    /// base with it.
    ///
    /// The `Overlay` arm is the ordering assertion made structural: an
    /// off-record durable write must never arrive here at all, and if one
    /// ever did, the answer would still be refusal rather than an ephemeral
    /// decision. [`OffRecordSession::executor_check_write_gate`] routes on the
    /// captured route and raises the talk-only refusal for `Overlay`.
    fn check_write_gate(
        &self,
        id: EntityId,
        body: &ClaimBody,
        envelope: &WriteEnvelope,
        can_resolve_pending_consent: bool,
    ) -> Result<()> {
        match &self.storage {
            ExecutorStorage::Canonical(vault) => check_write_gate_against_vault(
                vault,
                id,
                body,
                envelope,
                can_resolve_pending_consent,
            ),
            ExecutorStorage::Session(binding) => binding.session.executor_check_write_gate(
                &binding.route,
                id,
                body,
                envelope,
                can_resolve_pending_consent,
            ),
        }
    }

    fn dispatch_ask_human(&self, call: SelfAskHumanCall) -> Result<SelfDispatchOutcome> {
        if let Some(target) = self.human_wait_target {
            let ExecutorStorage::Canonical(vault) = &self.storage else {
                return Err(Error::InvalidClaimBody(
                    "self.ask_human task wait requires canonical storage",
                ));
            };
            let responder_ref = crate::task_verb::task_human_assignee(vault, target.task_ref)?
                .ok_or(Error::InvalidClaimBody(
                    "self.ask_human task is not assigned to a human",
                ))?;
            crate::human_task::bind_human_wait(vault, target.task_ref, responder_ref, &target.trap)
                .map_err(|error| match error {
                    crate::human_task::HumanTaskError::Engine(error) => error,
                    _ => Error::InvalidClaimBody("self.ask_human wait binding was refused"),
                })?;
            return Ok(SelfDispatchOutcome::DurableWait(SelfDurableWait {
                wait_id: target.task_ref,
                effect: SelfEffect::AskHuman,
                reason: SelfDurableWaitReason::HumanInput,
                prompt: Some(call.prompt),
            }));
        }

        // Unit fixtures exercise generic replay/wait encoding without creating a
        // TASK. Production dispatch fails closed unless the host supplied the
        // real task and trap through `for_human_task`.
        #[cfg(test)]
        {
            Ok(self.durable_wait(
                SelfEffect::AskHuman,
                SelfDurableWaitReason::HumanInput,
                Some(call.prompt),
            ))
        }
        #[cfg(not(test))]
        {
            let _ = call;
            Err(Error::InvalidClaimBody(
                "self.ask_human missing human task wait target",
            ))
        }
    }

    /// One speech call — one durable MESSAGE bubble (ONE-1686, RT-04).
    ///
    /// Speech is an EFFECT, dispatched where every other `self.*` effect is
    /// dispatched, at the moment the guest calls it. Nothing is buffered for a
    /// final response, so a step that speaks, searches, speaks again and then
    /// writes lands those four things in that order.
    ///
    /// The bubble's author, message type and visibility are the host's: the
    /// actor is the one bound at construction, the type comes from the
    /// utterance the effect names, and `is_visible` is
    /// [`ExecutorUtterance::is_visible`]. Only the text is the guest's.
    ///
    /// A `Speech` OUTCOME therefore means one thing and nothing else: the
    /// bubble exists. Both storage arms materialize it, and a refusal — a
    /// stale route after a mid-run mode flip, a ceiling denial — leaves through
    /// `Err`, which the bridge records as the `Denied`/`Failed` row the
    /// fail-closed barrier already understands. `emitted` is `true` on every
    /// value this constructor can build; the decoder refuses any other
    /// combination, so no replay row can claim speech that never happened.
    ///
    /// # Replay identity (ONE-1929)
    ///
    /// The bubble's TURN and MESSAGE ids are DERIVED from the run's host ref,
    /// the durable run id, and the bridge position the host stamped — never
    /// minted fresh per dispatch. Explicit speech commits at the moment the
    /// guest calls it, so a step whose replay append then fails (a generation
    /// conflict, an output-recording error, a crash between the two) is retried
    /// from a replay state that still names the same bridge position. Under
    /// fresh ids that retry minted a SECOND bubble for one utterance; under the
    /// derived ids the witness door recognizes the row it already wrote and the
    /// retry converges on it. A retry that would put DIFFERENT bytes at that
    /// position is a divergence, not a duplicate, and the door refuses it typed
    /// rather than speaking twice.
    fn dispatch_speech(
        &self,
        effect: SelfEffect,
        call: SelfSpeechCall,
        run_id: Option<EntityId>,
    ) -> Result<SelfDispatchOutcome> {
        let kind = effect.speech_utterance().ok_or(Error::InvariantViolation(
            "speech dispatch on a non-speech effect",
        ))?;
        let _receipt = self.storage.witness_executor_utterance(
            &self.run_ref,
            run_id,
            kind,
            &call.text,
            call.occurred_at,
            call.order,
            self.actor,
        )?;
        Ok(SelfDispatchOutcome::Speech(SelfSpeechResult {
            effect,
            order: call.order,
            is_visible: kind.is_visible(),
            emitted: true,
        }))
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

    fn durable_wait(
        &self,
        effect: SelfEffect,
        reason: SelfDurableWaitReason,
        prompt: Option<String>,
    ) -> SelfDispatchOutcome {
        SelfDispatchOutcome::DurableWait(SelfDurableWait {
            wait_id: EntityId::now(),
            effect,
            reason,
            prompt,
        })
    }
}

/// The write-path gate check both executor routes share.
///
/// Lives here, beside the dispatcher that decides WHICH vault runs it, so the
/// canonical and post-flip session paths cannot drift into two gate bodies.
/// The session side reaches it through
/// [`OffRecordSession::executor_check_write_gate`], which owns the routing.
pub(crate) fn check_write_gate_against_vault(
    vault: &Vault,
    id: EntityId,
    body: &ClaimBody,
    envelope: &WriteEnvelope,
    can_resolve_pending_consent: bool,
) -> Result<()> {
    validate_write_actor_binding(vault, envelope)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?;
    let gate_result = crate::gate::check_claim_policy_for_write(
        &vault.store,
        &mut wtxn,
        &id,
        body,
        Some(envelope),
        &policy,
        crate::gate::GateWriteMode {
            record_decision: true,
            persist_pending_consent: false,
            resolve_pending: false,
            can_resolve_pending_consent,
            include_source_in_gate_input: true,
        },
        // This door pre-checks a PERSISTED claim candidate, so it keeps the
        // full GATE-12 floor: the synthetic-operation mode belongs only to the
        // memory verbs' own gate bodies in `claim/put.rs`.
        false,
    );
    wtxn.commit()?;
    gate_result
}

fn validate_write_actor_binding(vault: &Vault, envelope: &WriteEnvelope) -> Result<()> {
    crate::gate::validate_write_envelope(envelope)?;
    let actor = envelope.actor();
    let rtxn = vault.store.env.read_txn()?;
    let actor_raw = vault
        .store
        .entities
        .get(&rtxn, actor.entity_ref().as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let actor_header = crate::batch::EntityMetadataHeader::parse(&actor_raw)
        .ok_or(Error::CorruptedIndex("entity header"))?;
    crate::provenance::validate_actor_class(actor_header.entity_type, actor.actor_class())
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

/// The code-emission admission record's id: a domain-separated digest over the
/// admission identity (tier, source trust, Dreamer run, host run ref).
///
/// Deterministic so the record is minted at most once per admission, and
/// length-prefixed so two different identities can never hash to the same
/// material. A digest that lands on a reserved sentinel is re-salted rather
/// than truncated into one.
fn code_emission_record_id(
    tier: SandboxGuestTier,
    source_trust: CodeSourceTrust,
    dreamer_run_id: &str,
    run_ref: &str,
) -> Result<EntityId> {
    for salt in 0..=u8::MAX {
        let mut hasher = Sha256::new();
        hasher.update(CODE_EMISSION_RECORD_ID_DOMAIN);
        hasher.update([salt]);
        for part in [
            tier.as_str().as_bytes(),
            source_trust.as_str().as_bytes(),
            dreamer_run_id.as_bytes(),
            run_ref.as_bytes(),
        ] {
            let len = u64::try_from(part.len())
                .map_err(|_| Error::ArithmeticOverflow("code emission record id material"))?;
            hasher.update(len.to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "code emission record id derivation failed",
    ))
}

/// The record body: exactly the admission identity its id is derived from, so
/// a reader of the entity can check what the host decided rather than trust the
/// handle.
fn code_emission_record_body(
    tier: SandboxGuestTier,
    source_trust: CodeSourceTrust,
    dreamer_run_id: &str,
    run_ref: &str,
) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(CODE_EMISSION_RECORD_KEYS[0]),
            Value::from(consent::CODE_EMISSION_EVIDENCE_KIND),
        ),
        (
            Value::from(CODE_EMISSION_RECORD_KEYS[1]),
            Value::from(tier.as_str()),
        ),
        (
            Value::from(CODE_EMISSION_RECORD_KEYS[2]),
            Value::from(source_trust.as_str()),
        ),
        (
            Value::from(CODE_EMISSION_RECORD_KEYS[3]),
            Value::from(dreamer_run_id),
        ),
        (
            Value::from(CODE_EMISSION_RECORD_KEYS[4]),
            Value::from(run_ref),
        ),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &value)
        .map_err(|_| Error::InvariantViolation("code emission record encode failed"))?;
    Ok(encoded)
}

pub(super) fn edge_operation_gate_id(
    effect: SelfEffect,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
) -> Result<EntityId> {
    let mut material = Vec::with_capacity(
        SELF_MEMORY_EDGE_OPERATION_ID_DOMAIN.len()
            + effect.as_str().len()
            + src.as_bytes().len()
            + 1
            + tgt.as_bytes().len(),
    );
    material.extend_from_slice(SELF_MEMORY_EDGE_OPERATION_ID_DOMAIN);
    material.extend_from_slice(effect.as_str().as_bytes());
    material.extend_from_slice(src.as_bytes());
    material.push(kind as u8);
    material.extend_from_slice(tgt.as_bytes());

    let bytes = xxh3_128(&material).to_le_bytes();
    for tweak in 0..=u8::MAX {
        let mut candidate = bytes;
        candidate[0] ^= tweak;
        if let Ok(id) = EntityId::from_bytes(candidate) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "edge operation gate id derivation failed",
    ))
}

fn ensure_public_memory_edge_kind(kind: EdgeKind) -> Result<()> {
    match kind {
        EdgeKind::Mentions
        | EdgeKind::About
        | EdgeKind::Supports
        | EdgeKind::Opposes
        | EdgeKind::ParticipatesIn
        | EdgeKind::Attached
        | EdgeKind::EmployedBy
        | EdgeKind::HasFacet
        | EdgeKind::FacetOf
        | EdgeKind::InWorld
        | EdgeKind::SetIn => Ok(()),
        EdgeKind::AuthoredBy
        | EdgeKind::ScopedTo
        | EdgeKind::PartOf
        | EdgeKind::Supersedes
        | EdgeKind::BelongsTo
        | EdgeKind::ClaimOf
        | EdgeKind::ChildOf
        | EdgeKind::AssignedTo
        | EdgeKind::DerivedFrom
        | EdgeKind::MergedInto
        | EdgeKind::SplitInto
        | EdgeKind::BlockedBy
        // ONE-1608: `blocks` is the L2 code-memory readiness edge. Its
        // dedicated door binds the actor entity to its asserted class and
        // proves acyclicity; a guest `self.memory.put_edge` carries neither,
        // so guest code may not mint readiness dependencies.
        | EdgeKind::Blocks
        // ONE-1414: `same_as` is structural and its writes belong to the
        // federation coreference door (`put_coreference_link`), which writes
        // the link and its status Claim in ONE transaction under an actor
        // gate. A raw link here would assert identity with no status, no
        // consent surface, and no actor — so it lands on the refusal side
        // with the rest of the structural kinds.
        | EdgeKind::SameAs => Err(Error::InvalidClaimBody(
            "self.memory.put_edge rejects structural edge kinds",
        )),
    }
}
