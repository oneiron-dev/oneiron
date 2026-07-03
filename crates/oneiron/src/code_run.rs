//! Host-side skeleton for first-party `self.*` code-mode calls.
//!
//! This module does not execute guest code. It gives the host a typed dispatch
//! boundary that binds WHO/source outside the guest call payload, then routes
//! first-party memory writes through the existing batch/gate chokepoint. The
//! sandbox link-time boundary contract lives in [`crate::code_sandbox`].

use rmpv::Value;

use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimCandidate, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, EdgeKind, EntityId, Error, Result, ScoredEntity, TimeRange, Vault, WriteActor,
    WriteEnvelope, WriteProvenance,
};

const SELF_SURFACE_NAME: &str = "self.*";
const SELF_PROVENANCE_SURFACE_KEY: &str = "surface";
const SELF_PROVENANCE_RUN_KEY: &str = "run";
const SELF_PROVENANCE_CALL_KEY: &str = "call";

/// Dispatcher for host-side `self.*` calls emitted by a first-party runtime.
pub trait SelfDispatcher {
    /// Routes one typed call through the host-owned dispatcher.
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome>;
}

/// Host-bound dispatcher for one first-party code run.
///
/// The actor and source are bound at construction time by the host. Individual
/// [`SelfCall`] values carry only operation arguments, so guest-authored code
/// cannot spoof actor, source, or approval fields through this skeleton.
pub struct HostSelfDispatcher<'a> {
    vault: &'a Vault,
    actor: WriteActor,
    run_ref: String,
}

impl<'a> HostSelfDispatcher<'a> {
    /// Creates a dispatcher for a first-party run.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidClaimBody`] when `run_ref` is blank.
    pub fn new(vault: &'a Vault, actor: WriteActor, run_ref: impl Into<String>) -> Result<Self> {
        let run_ref = run_ref.into();
        if run_ref.trim().is_empty() {
            return Err(crate::Error::InvalidClaimBody(
                "self dispatcher missing run ref",
            ));
        }

        Ok(Self {
            vault,
            actor,
            run_ref,
        })
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

    fn write_envelope(&self, effect: SelfEffect) -> Result<WriteEnvelope> {
        Ok(WriteEnvelope::new(
            self.actor,
            self.source(),
            WriteProvenance::new(Value::Map(vec![
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
            ]))?,
            ClaimApprovalStatus::Proposed,
        ))
    }

    fn dispatch_memory_search(&self, call: SelfMemorySearchCall) -> Result<SelfDispatchOutcome> {
        let results = self.vault.search_text(&call.query, call.limit)?;
        Ok(SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
            query: call.query,
            results,
        }))
    }

    fn dispatch_memory_write_fixture(
        &self,
        call: SelfMemoryWriteFixtureCall,
    ) -> Result<SelfDispatchOutcome> {
        let envelope = self.write_envelope(SelfEffect::MemoryWriteFixture)?;
        self.vault
            .batch()
            .claim_candidate(
                &call.id,
                *call.candidate,
                &envelope,
                call.occurred,
                call.learned_at,
            )
            .commit()?;

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.id,
        }))
    }

    fn dispatch_memory_put_claim(
        &self,
        call: SelfMemoryPutClaimCall,
    ) -> Result<SelfDispatchOutcome> {
        let envelope = self.write_envelope(SelfEffect::MemoryPutClaim)?;
        self.vault
            .batch()
            .claim_candidate(
                &call.id,
                *call.candidate,
                &envelope,
                call.occurred,
                call.learned_at,
            )
            .commit()?;

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.id,
        }))
    }

    fn dispatch_memory_supersede_claim(
        &self,
        call: SelfMemorySupersedeClaimCall,
    ) -> Result<SelfDispatchOutcome> {
        let envelope = self.write_envelope(SelfEffect::MemorySupersedeClaim)?;
        let gate_body = self.operation_gate_body(
            SelfEffect::MemorySupersedeClaim,
            ClaimSubject::Entity(call.new_id),
            Value::Binary(call.old_id.as_bytes().to_vec()),
            &envelope,
        );
        self.check_write_gate(EntityId::now(), &gate_body, &envelope)?;
        self.vault
            .supersede_claim(&call.new_id, &call.old_id, call.now)?;

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.new_id,
        }))
    }

    fn dispatch_memory_put_edge(&self, call: SelfMemoryPutEdgeCall) -> Result<SelfDispatchOutcome> {
        let envelope = self.write_envelope(SelfEffect::MemoryPutEdge)?;
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
        self.check_write_gate(EntityId::now(), &gate_body, &envelope)?;
        self.vault
            .put_edge(&call.src, call.kind, &call.tgt, call.weight)?;

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
            envelope.approval(),
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(crate::types::write_envelope_evidence(envelope, None));
        body.source = Some(envelope.source());
        body
    }

    fn check_write_gate(
        &self,
        id: EntityId,
        body: &ClaimBody,
        envelope: &WriteEnvelope,
    ) -> Result<()> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &wtxn)?;
        crate::gate::check_claim_policy_for_write(
            &self.vault.store,
            &mut wtxn,
            &id,
            body,
            Some(envelope),
            &policy,
            crate::gate::GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent: true,
            },
        )?;
        wtxn.commit().map_err(Error::from)
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

impl SelfDispatcher for HostSelfDispatcher<'_> {
    fn dispatch(&self, call: SelfCall) -> Result<SelfDispatchOutcome> {
        match call {
            SelfCall::MemorySearch(call) => self.dispatch_memory_search(call),
            SelfCall::MemoryWriteFixture(call) => self.dispatch_memory_write_fixture(call),
            SelfCall::MemoryPutClaim(call) => self.dispatch_memory_put_claim(call),
            SelfCall::MemorySupersedeClaim(call) => self.dispatch_memory_supersede_claim(call),
            SelfCall::MemoryPutEdge(call) => self.dispatch_memory_put_edge(call),
            SelfCall::AskHuman(call) => Ok(self.durable_wait(
                SelfEffect::AskHuman,
                SelfDurableWaitReason::HumanInput,
                Some(call.prompt),
            )),
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
        }
    }
}

/// Typed first-party host call.
#[derive(Debug, Clone, PartialEq)]
pub enum SelfCall {
    /// Fixture for `self.memory.search(...)`.
    MemorySearch(SelfMemorySearchCall),
    /// Internal fixture proving dispatcher-stamped writes use the batch/gate path.
    ///
    /// This is not the CODE-007a public `self.memory.put_claim` trap surface.
    MemoryWriteFixture(SelfMemoryWriteFixtureCall),
    /// Public first-party `self.memory.put_claim(...)` trap.
    MemoryPutClaim(SelfMemoryPutClaimCall),
    /// Public first-party `self.memory.supersede_claim(...)` trap.
    MemorySupersedeClaim(SelfMemorySupersedeClaimCall),
    /// Public first-party `self.memory.put_edge(...)` trap.
    MemoryPutEdge(SelfMemoryPutEdgeCall),
    /// Fixture for `self.ask_human(...)`.
    AskHuman(SelfAskHumanCall),
    /// Fixture for destructive effects, which must park as durable waits.
    DestructiveFixture(SelfFixtureEffectCall),
    /// Fixture for outbound effects, which must park as durable waits.
    OutboundFixture(SelfFixtureEffectCall),
}

impl SelfCall {
    /// Returns the host effect class for this call.
    #[must_use]
    pub const fn effect(&self) -> SelfEffect {
        match self {
            Self::MemorySearch(_) => SelfEffect::MemorySearch,
            Self::MemoryWriteFixture(_) => SelfEffect::MemoryWriteFixture,
            Self::MemoryPutClaim(_) => SelfEffect::MemoryPutClaim,
            Self::MemorySupersedeClaim(_) => SelfEffect::MemorySupersedeClaim,
            Self::MemoryPutEdge(_) => SelfEffect::MemoryPutEdge,
            Self::AskHuman(_) => SelfEffect::AskHuman,
            Self::DestructiveFixture(_) => SelfEffect::DestructiveFixture,
            Self::OutboundFixture(_) => SelfEffect::OutboundFixture,
        }
    }
}

/// Host effect class routed by the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfEffect {
    MemorySearch,
    MemoryWriteFixture,
    MemoryPutClaim,
    MemorySupersedeClaim,
    MemoryPutEdge,
    AskHuman,
    DestructiveFixture,
    OutboundFixture,
}

impl SelfEffect {
    /// Stable effect label used in host-generated provenance.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemorySearch => "self.memory.search",
            Self::MemoryWriteFixture => "self.memory.write_fixture",
            Self::MemoryPutClaim => "self.memory.put_claim",
            Self::MemorySupersedeClaim => "self.memory.supersede_claim",
            Self::MemoryPutEdge => "self.memory.put_edge",
            Self::AskHuman => "self.ask_human",
            Self::DestructiveFixture => "self.fixture.destructive",
            Self::OutboundFixture => "self.fixture.outbound",
        }
    }
}

/// Arguments for the `self.memory.search` fixture call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfMemorySearchCall {
    pub query: String,
    pub limit: usize,
}

impl SelfMemorySearchCall {
    #[must_use]
    pub fn new(query: impl Into<String>, limit: usize) -> Self {
        Self {
            query: query.into(),
            limit,
        }
    }
}

/// Internal fixture write routed through [`Vault::batch`].
#[derive(Debug, Clone, PartialEq)]
pub struct SelfMemoryWriteFixtureCall {
    pub id: EntityId,
    pub candidate: Box<ClaimCandidate>,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

impl SelfMemoryWriteFixtureCall {
    #[must_use]
    pub fn new(
        id: EntityId,
        candidate: ClaimCandidate,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        Self {
            id,
            candidate: Box::new(candidate),
            occurred,
            learned_at,
        }
    }
}

/// Arguments for the public `self.memory.put_claim` trap.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfMemoryPutClaimCall {
    pub id: EntityId,
    pub candidate: Box<ClaimCandidate>,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

impl SelfMemoryPutClaimCall {
    #[must_use]
    pub fn new(
        id: EntityId,
        candidate: ClaimCandidate,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Self {
        Self {
            id,
            candidate: Box::new(candidate),
            occurred,
            learned_at,
        }
    }
}

/// Arguments for the public `self.memory.supersede_claim` trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfMemorySupersedeClaimCall {
    pub new_id: EntityId,
    pub old_id: EntityId,
    pub now: u64,
}

impl SelfMemorySupersedeClaimCall {
    #[must_use]
    pub const fn new(new_id: EntityId, old_id: EntityId, now: u64) -> Self {
        Self {
            new_id,
            old_id,
            now,
        }
    }
}

/// Arguments for the public `self.memory.put_edge` trap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelfMemoryPutEdgeCall {
    pub src: EntityId,
    pub kind: EdgeKind,
    pub tgt: EntityId,
    pub weight: f32,
}

impl SelfMemoryPutEdgeCall {
    #[must_use]
    pub const fn new(src: EntityId, kind: EdgeKind, tgt: EntityId, weight: f32) -> Self {
        Self {
            src,
            kind,
            tgt,
            weight,
        }
    }
}

/// Arguments for the `self.ask_human` fixture call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfAskHumanCall {
    pub prompt: String,
}

impl SelfAskHumanCall {
    #[must_use]
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
        }
    }
}

/// Arguments for destructive/outbound fixture effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfFixtureEffectCall {
    pub label: String,
}

impl SelfFixtureEffectCall {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

/// Result of dispatching a `self.*` call.
#[derive(Debug, Clone, PartialEq)]
pub enum SelfDispatchOutcome {
    MemorySearch(SelfMemorySearchResult),
    MemoryWrite(SelfMemoryWriteResult),
    MemoryEdgeWrite(SelfMemoryEdgeWriteResult),
    DurableWait(SelfDurableWait),
}

/// Result of a `self.memory.search` fixture dispatch.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfMemorySearchResult {
    pub query: String,
    pub results: Vec<ScoredEntity>,
}

/// Result of an internal fixture memory write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfMemoryWriteResult {
    pub id: EntityId,
}

/// Result of a public `self.memory.put_edge` trap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelfMemoryEdgeWriteResult {
    pub src: EntityId,
    pub kind: EdgeKind,
    pub tgt: EntityId,
}

/// Durable wait produced for effects that need human/external resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfDurableWait {
    pub wait_id: EntityId,
    pub effect: SelfEffect,
    pub reason: SelfDurableWaitReason,
    pub prompt: Option<String>,
}

/// Why a dispatched effect parked instead of committing immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfDurableWaitReason {
    HumanInput,
    DestructiveEffect,
    OutboundEffect,
}

#[cfg(test)]
mod tests {
    use rmpv::Value;

    use super::*;
    use crate::{
        ClaimSubject, EdgeActorClass, HnswConfig, VaultConfig, WriteActor,
        types::{
            ENTITY_TYPE_PERSON, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
            WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY,
        },
    };

    fn test_config() -> VaultConfig {
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = Some("test-model-v1".to_owned());
        config.max_readers = 16;
        config.hnsw = HnswConfig::default();
        config
    }

    fn open_test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), test_config()).expect("open vault");
        (dir, vault)
    }

    fn range(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    fn seed_person(vault: &Vault, seed: u8) -> EntityId {
        let id = EntityId::from_bytes([seed; 16]).expect("entity id");
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
            .expect("seed person");
        id
    }

    fn gate_decision_count(vault: &Vault) -> Result<usize> {
        Ok(vault.store.gate_decisions(100)?.len())
    }

    fn assert_latest_gate_decision(vault: &Vault, expected_id: EntityId) -> Result<()> {
        let decisions = vault.store.gate_decisions(1)?;
        let latest = decisions.first().expect("latest gate decision");
        assert_eq!(latest.content_kind, "claim");
        assert_eq!(latest.claim_id, Some(*expected_id.as_bytes()));
        assert!(latest.actor_ref.is_some());
        assert!(
            latest
                .reason_codes
                .iter()
                .all(|code| code.starts_with("gate."))
        );
        Ok(())
    }

    fn map_value<'a>(entries: &'a [(Value, Value)], key: &str) -> &'a Value {
        entries
            .iter()
            .find_map(|(entry_key, entry_value)| {
                (entry_key.as_str() == Some(key)).then_some(entry_value)
            })
            .expect("map entry")
    }

    #[test]
    fn code_run_memory_search_routes_through_dispatcher() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA1);
        let memory = EntityId::from_bytes([0xB1; 16]).expect("memory id");
        vault
            .batch()
            .put(&memory, ENTITY_TYPE_PERSON, range(2), 2, b"matcha note")
            .text(&memory, &[("body", "matcha preference")])
            .commit()?;

        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-search",
        )?;
        let outcome = dispatcher.dispatch(SelfCall::MemorySearch(SelfMemorySearchCall::new(
            "matcha", 5,
        )))?;

        let SelfDispatchOutcome::MemorySearch(result) = outcome else {
            panic!("expected memory search outcome");
        };
        assert_eq!(result.query, "matcha");
        assert!(result.results.iter().any(|hit| hit.id == memory));
        Ok(())
    }

    #[test]
    fn code_run_fixture_write_stamps_actor_source_and_approval() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA2);
        let subject = seed_person(&vault, 0xB2);
        let claim = EntityId::from_bytes([0xC2; 16]).expect("claim id");
        let candidate = ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("matcha"),
            0.8,
        )
        .with_evidence(Value::Map(vec![(
            Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            Value::from("guest-spoof-attempt"),
        )]));

        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-write",
        )?;
        let outcome = dispatcher.dispatch(SelfCall::MemoryWriteFixture(
            SelfMemoryWriteFixtureCall::new(claim, candidate, range(3), 4),
        ))?;

        assert_eq!(
            outcome,
            SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: claim })
        );
        let stored = vault.get_claim(&claim)?.expect("stored claim");
        assert_eq!(stored.source, Some(ClaimSource::Generated));
        assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);

        let Some(Value::Map(evidence)) = stored.evidence else {
            panic!("expected write envelope evidence");
        };
        let stamped_actor = evidence
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)).then_some(value)
            })
            .expect("stamped actor");
        assert_eq!(stamped_actor, &Value::Binary(actor.as_bytes().to_vec()));

        let provenance = evidence
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY)).then_some(value)
            })
            .expect("stamped provenance");
        let Value::Map(provenance) = provenance else {
            panic!("expected provenance map");
        };
        let call = provenance
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some(SELF_PROVENANCE_CALL_KEY)).then_some(value)
            })
            .expect("call provenance");
        assert_eq!(call.as_str(), Some(SelfEffect::MemoryWriteFixture.as_str()));

        let candidate_evidence = evidence
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY)).then_some(value)
            })
            .expect("nested candidate evidence");
        let Value::Map(candidate_evidence) = candidate_evidence else {
            panic!("expected candidate evidence map");
        };
        let spoofed_actor = candidate_evidence
            .iter()
            .find_map(|(key, value)| {
                (key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)).then_some(value)
            })
            .expect("spoofed actor remains nested");
        assert_eq!(spoofed_actor.as_str(), Some("guest-spoof-attempt"));
        Ok(())
    }

    #[test]
    fn code_run_public_put_claim_trap_stamps_host_fields() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA4);
        let subject = seed_person(&vault, 0xB4);
        let claim = EntityId::from_bytes([0xC4; 16]).expect("claim id");
        let candidate = ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("sencha"),
            0.9,
        )
        .with_evidence(Value::Map(vec![(
            Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            Value::from("guest-spoof-attempt"),
        )]));

        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-put-claim",
        )?;
        let outcome = dispatcher.dispatch(SelfCall::MemoryPutClaim(
            SelfMemoryPutClaimCall::new(claim, candidate, range(5), 6),
        ))?;

        assert_eq!(
            outcome,
            SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: claim })
        );
        assert_latest_gate_decision(&vault, claim)?;
        let stored = vault.get_claim(&claim)?.expect("stored claim");
        assert_eq!(stored.source, Some(ClaimSource::Generated));
        assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);

        let Some(Value::Map(evidence)) = stored.evidence else {
            panic!("expected write envelope evidence");
        };
        assert_eq!(
            map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            &Value::Binary(actor.as_bytes().to_vec())
        );

        let provenance = map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY);
        let Value::Map(provenance) = provenance else {
            panic!("expected provenance map");
        };
        assert_eq!(
            map_value(provenance, SELF_PROVENANCE_CALL_KEY).as_str(),
            Some(SelfEffect::MemoryPutClaim.as_str())
        );

        let candidate_evidence = map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY);
        let Value::Map(candidate_evidence) = candidate_evidence else {
            panic!("expected candidate evidence map");
        };
        assert_eq!(
            map_value(candidate_evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY).as_str(),
            Some("guest-spoof-attempt")
        );
        Ok(())
    }

    #[test]
    fn code_run_public_write_traps_route_per_op_through_gate() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA5);
        let subject = seed_person(&vault, 0xB5);
        let edge_target = seed_person(&vault, 0xC5);
        let old = EntityId::from_bytes([0xD5; 16]).expect("old claim id");
        let new = EntityId::from_bytes([0xE5; 16]).expect("new claim id");
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-write-traps",
        )?;

        let before_old = gate_decision_count(&vault)?;
        dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            old,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from("sencha"),
                0.8,
            ),
            range(10),
            11,
        )))?;
        assert_eq!(gate_decision_count(&vault)?, before_old + 1);
        assert_latest_gate_decision(&vault, old)?;

        let before_new = gate_decision_count(&vault)?;
        dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            new,
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from("matcha"),
                0.9,
            ),
            range(12),
            13,
        )))?;
        assert_eq!(gate_decision_count(&vault)?, before_new + 1);
        assert_latest_gate_decision(&vault, new)?;

        let before_supersede = gate_decision_count(&vault)?;
        let supersede_outcome = dispatcher.dispatch(SelfCall::MemorySupersedeClaim(
            SelfMemorySupersedeClaimCall::new(new, old, 20),
        ))?;
        assert_eq!(
            supersede_outcome,
            SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: new })
        );
        assert_eq!(gate_decision_count(&vault)?, before_supersede + 1);
        let old_read = vault.get_claim(&old)?.expect("superseded claim");
        assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Superseded);
        assert_eq!(old_read.valid_to, Some(20));
        assert_eq!(vault.targets(&new, EdgeKind::Supersedes, None)?, vec![old]);

        let before_edge = gate_decision_count(&vault)?;
        let edge_outcome = dispatcher.dispatch(SelfCall::MemoryPutEdge(
            SelfMemoryPutEdgeCall::new(subject, EdgeKind::Mentions, edge_target, 0.7),
        ))?;
        assert_eq!(
            edge_outcome,
            SelfDispatchOutcome::MemoryEdgeWrite(SelfMemoryEdgeWriteResult {
                src: subject,
                kind: EdgeKind::Mentions,
                tgt: edge_target,
            })
        );
        assert_eq!(gate_decision_count(&vault)?, before_edge + 1);
        assert_eq!(
            vault.targets(&subject, EdgeKind::Mentions, None)?,
            vec![edge_target]
        );

        let read_after_write = vault.get_claim(&new)?.expect("new claim after traps");
        assert_eq!(read_after_write.value, Value::from("matcha"));
        assert_eq!(read_after_write.lifecycle, ClaimLifecycleStatus::Active);
        Ok(())
    }

    #[test]
    fn code_run_human_destructive_and_outbound_effects_become_durable_waits() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA3);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-waits",
        )?;

        let cases = [
            (
                SelfCall::AskHuman(SelfAskHumanCall::new("continue?")),
                SelfEffect::AskHuman,
                SelfDurableWaitReason::HumanInput,
            ),
            (
                SelfCall::DestructiveFixture(SelfFixtureEffectCall::new("delete memory")),
                SelfEffect::DestructiveFixture,
                SelfDurableWaitReason::DestructiveEffect,
            ),
            (
                SelfCall::OutboundFixture(SelfFixtureEffectCall::new("send message")),
                SelfEffect::OutboundFixture,
                SelfDurableWaitReason::OutboundEffect,
            ),
        ];

        for (call, effect, reason) in cases {
            let outcome = dispatcher.dispatch(call)?;
            let SelfDispatchOutcome::DurableWait(wait) = outcome else {
                panic!("expected durable wait");
            };
            assert_eq!(wait.effect, effect);
            assert_eq!(wait.reason, reason);
            assert!(wait.prompt.is_some());
        }

        Ok(())
    }
}
