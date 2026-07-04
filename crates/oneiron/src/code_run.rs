//! Host-side skeleton for first-party `self.*` code-mode calls.
//!
//! This module does not execute guest code. It gives the host a typed dispatch
//! boundary that binds WHO/source outside the guest call payload, then routes
//! first-party memory writes through the existing batch/gate chokepoint. The
//! sandbox link-time boundary contract lives in [`crate::code_sandbox`].

use rmpv::Value;
use xxhash_rust::xxh3::xxh3_128;

use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimCandidate, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, EdgeKind, EntityId, Error, Result, ScoredEntity, TimeRange, Vault, WriteActor,
    WriteEnvelope, WriteProvenance,
};

const SELF_SURFACE_NAME: &str = "self.*";
const SELF_PROVENANCE_SURFACE_KEY: &str = "surface";
const SELF_PROVENANCE_RUN_KEY: &str = "run";
const SELF_PROVENANCE_CALL_KEY: &str = "call";
const SELF_MEMORY_EDGE_OPERATION_ID_DOMAIN: &[u8] = b"oneiron:self-memory-edge-operation:v1";

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
        let gate_body = (*call.candidate).clone().into_claim_body(&envelope);
        self.check_write_gate(call.id, &gate_body, &envelope, true)?;
        self.vault
            .put_claim_candidate_without_lexical_query_reconcile(
                &call.id,
                *call.candidate,
                &envelope,
                call.occurred,
                call.learned_at,
            )?;

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.id,
        }))
    }

    fn dispatch_memory_supersede_claim(
        &self,
        call: SelfMemorySupersedeClaimCall,
    ) -> Result<SelfDispatchOutcome> {
        let envelope = self.write_envelope(SelfEffect::MemorySupersedeClaim)?;
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
        self.vault.supersede_claim_for_code_run_trap(
            &call.new_id,
            &call.old_id,
            call.now,
            &envelope,
            call.old_id,
            &claim_gate_body,
            edge_gate_id,
            &edge_gate_body,
        )?;

        Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: call.new_id,
        }))
    }

    fn dispatch_memory_put_edge(&self, call: SelfMemoryPutEdgeCall) -> Result<SelfDispatchOutcome> {
        ensure_public_memory_edge_kind(call.kind)?;
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
        self.vault.put_edge_for_code_run_trap(
            &call.src,
            call.kind,
            &call.tgt,
            call.weight,
            &envelope,
            edge_operation_gate_id(SelfEffect::MemoryPutEdge, call.src, call.kind, call.tgt)?,
            &gate_body,
        )?;

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
        body.evidence = Some(crate::types::write_envelope_evidence(envelope, None));
        body.source = Some(envelope.source());
        body
    }

    fn validate_write_actor_binding(&self, envelope: &WriteEnvelope) -> Result<()> {
        crate::gate::validate_write_envelope(envelope)?;
        let actor = envelope.actor();
        let rtxn = self.vault.store.env.read_txn()?;
        let actor_raw = self
            .vault
            .store
            .entities
            .get(&rtxn, actor.entity_ref().as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let actor_header = crate::batch::EntityMetadataHeader::parse(actor_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        crate::provenance::validate_actor_class(actor_header.entity_type, actor.actor_class())
    }

    fn check_write_gate(
        &self,
        id: EntityId,
        body: &ClaimBody,
        envelope: &WriteEnvelope,
        can_resolve_pending_consent: bool,
    ) -> Result<()> {
        self.validate_write_actor_binding(envelope)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, &wtxn)?;
        let gate_result = crate::gate::check_claim_policy_for_write(
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
                can_resolve_pending_consent,
                include_source_in_gate_input: true,
            },
        );
        wtxn.commit().map_err(Error::from)?;
        gate_result
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

fn edge_operation_gate_id(
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
        | EdgeKind::DerivedFrom => Err(Error::InvalidClaimBody(
            "self.memory.put_edge rejects structural edge kinds",
        )),
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
            ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST,
            WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
            WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY,
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

    fn seed_machine(vault: &Vault, seed: u8) -> EntityId {
        let id = EntityId::from_bytes([seed; 16]).expect("entity id");
        vault
            .put_entity(&id, ENTITY_TYPE_MACHINE, range(1), 1, b"machine")
            .expect("seed machine");
        id
    }

    fn seed_first_party_actor(vault: &Vault) -> EntityId {
        let id = EntityId::from_bytes(crate::gate::FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
            .expect("first-party actor id");
        vault
            .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"first-party actor")
            .expect("seed first-party actor");
        id
    }

    fn clear_policy_manifests_for_test(vault: &Vault) -> Result<()> {
        vault.with_write_txn(|wtxn| {
            let mut ids = Vec::new();
            for row in vault
                .store
                .type_index
                .prefix_iter(wtxn, &[ENTITY_TYPE_POLICY_MANIFEST])?
            {
                let (key, _) = row?;
                let id = EntityId::from_bytes(
                    key[1..]
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("type index key"))?,
                )
                .map_err(|_| Error::CorruptedIndex("type index key"))?;
                ids.push(id);
            }
            for id in ids {
                crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
            }
            Ok(())
        })
    }

    fn put_policy_manifest_bytes(vault: &Vault, seed: u8, data: &[u8]) -> Result<()> {
        let id = EntityId::from_bytes([seed; 16])?;
        let learned_at = 2_u64;
        let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(ENTITY_TYPE_POLICY_MANIFEST);
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(data);

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .entities
            .put(&mut wtxn, id.as_bytes(), &payload)?;
        let type_key = crate::store::Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
        let temporal_key = crate::store::Store::encode_temporal_key(learned_at, &id);
        vault
            .store
            .temporal_occurred_start
            .put(&mut wtxn, &temporal_key, &[])?;
        vault
            .store
            .temporal_learned
            .put(&mut wtxn, &temporal_key, &[])?;
        wtxn.commit().map_err(Error::from)
    }

    fn put_malformed_policy_manifest(vault: &Vault, seed: u8) -> Result<()> {
        put_policy_manifest_bytes(vault, seed, b"not-msgpack")
    }

    fn install_self_memory_allow_policy(vault: &Vault, actor: EntityId) -> Result<()> {
        install_self_memory_policy_trusting_source(vault, actor, ClaimSource::Generated)
    }

    fn install_self_memory_policy_trusting_source(
        vault: &Vault,
        actor: EntityId,
        source: ClaimSource,
    ) -> Result<()> {
        clear_policy_manifests_for_test(vault)?;
        let manifest = Value::Map(vec![
            (Value::from("schema_version"), Value::from("1.1")),
            (Value::from("pack_id"), Value::from("code-run-test")),
            (Value::from("pack_version"), Value::from("v1")),
            (
                Value::from("min_engine_version"),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                Value::from("defaults"),
                Value::Map(vec![
                    (Value::from("criticality"), Value::from("normal")),
                    (Value::from("sensitivity"), Value::from("normal")),
                ]),
            ),
            (
                Value::from("rules"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("prefix"), Value::from("self.memory.")),
                    (
                        Value::from("axes"),
                        Value::Map(vec![
                            (Value::from("criticality"), Value::from("normal")),
                            (Value::from("sensitivity"), Value::from("normal")),
                        ]),
                    ),
                ])]),
            ),
            (
                Value::from("actor_ceilings"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("actor_class"), Value::from("agent")),
                    (Value::from("actor_ref"), Value::from(actor.to_hex())),
                    (Value::from("ceiling"), Value::from("auto")),
                ])]),
            ),
            (
                Value::from("source_trust"),
                Value::Map(vec![(
                    Value::from(source.as_str()),
                    Value::Map(vec![
                        (Value::from("max_auto_sensitivity"), Value::from(0_u64)),
                        (Value::from("receipted"), Value::Boolean(true)),
                        (Value::from("warned"), Value::Boolean(true)),
                    ]),
                )]),
            ),
        ]);
        let mut data = Vec::new();
        rmpv::encode::write_value(&mut data, &manifest)
            .map_err(|_| Error::InvariantViolation("failed to encode policy manifest fixture"))?;
        put_policy_manifest_bytes(vault, 0xE8, &data)
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

    fn assert_latest_gate_decision_reasons(
        vault: &Vault,
        expected_id: EntityId,
        expected_outcome: &str,
        expected_reasons: &[&str],
    ) -> Result<()> {
        let decisions = vault.store.gate_decisions(1)?;
        let latest = decisions.first().expect("latest gate decision");
        assert_eq!(latest.outcome, expected_outcome);
        assert_eq!(latest.claim_id, Some(*expected_id.as_bytes()));
        assert_eq!(
            latest.reason_codes,
            expected_reasons
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    fn assert_source_trust_gate_rejection(err: Error) {
        match err {
            Error::GateWriteRejected {
                outcome,
                reason_codes,
            } => {
                assert_eq!(outcome, "pending");
                assert_eq!(reason_codes, vec!["gate.pending.source_trust"]);
            }
            other => panic!("expected source-trust gate rejection, got {other:?}"),
        }
    }

    fn assert_recent_gate_decision_ids(vault: &Vault, expected: &[EntityId]) -> Result<()> {
        let decisions = vault.store.gate_decisions(expected.len())?;
        let actual = decisions
            .iter()
            .map(|decision| decision.claim_id.expect("gate decision claim id"))
            .collect::<Vec<_>>();
        let expected = expected.iter().map(|id| *id.as_bytes()).collect::<Vec<_>>();
        assert_eq!(actual, expected);
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
    fn code_run_put_claim_trap_ignores_guest_source_and_g2_sees_generated() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xAA);
        install_self_memory_policy_trusting_source(&vault, actor, ClaimSource::UserStated)?;
        let subject = seed_person(&vault, 0xBA);
        let claim = EntityId::from_bytes([0xCA; 16]).expect("claim id");
        let candidate = ClaimCandidate::new(
            "profile.favorite_drink",
            ClaimSubject::Entity(subject),
            Value::from("gyokuro"),
            0.9,
        )
        .with_evidence(Value::Map(vec![(
            Value::from("source"),
            Value::from(ClaimSource::UserStated.as_str()),
        )]));

        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-guest-source-spoof",
        )?;
        dispatcher.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            claim,
            candidate,
            range(7),
            8,
        )))?;

        assert_latest_gate_decision_reasons(
            &vault,
            claim,
            "pending",
            &["gate.pending.source_trust"],
        )?;
        let stored = vault.get_claim(&claim)?.expect("stored claim");
        assert_eq!(stored.source, Some(ClaimSource::Generated));
        let pending = vault.pending_gate_consents(10)?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].claim_id, *claim.as_bytes());
        assert_eq!(pending[0].reason_codes, vec!["gate.pending.source_trust"]);

        let Some(Value::Map(evidence)) = stored.evidence else {
            panic!("expected write envelope evidence");
        };
        let candidate_evidence = map_value(&evidence, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY);
        let Value::Map(candidate_evidence) = candidate_evidence else {
            panic!("expected candidate evidence map");
        };
        assert_eq!(
            map_value(candidate_evidence, "source").as_str(),
            Some(ClaimSource::UserStated.as_str())
        );
        Ok(())
    }

    #[test]
    fn code_run_public_write_traps_route_per_op_through_gate() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_first_party_actor(&vault);
        install_self_memory_allow_policy(&vault, actor)?;
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
        let supersedes_edge_gate_id = edge_operation_gate_id(
            SelfEffect::MemorySupersedeClaim,
            new,
            EdgeKind::Supersedes,
            old,
        )?;
        let supersede_outcome = dispatcher.dispatch(SelfCall::MemorySupersedeClaim(
            SelfMemorySupersedeClaimCall::new(new, old, 20),
        ))?;
        assert_eq!(
            supersede_outcome,
            SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult { id: new })
        );
        assert_eq!(gate_decision_count(&vault)?, before_supersede + 2);
        assert_recent_gate_decision_ids(&vault, &[supersedes_edge_gate_id, old])?;
        let old_read = vault.get_claim(&old)?.expect("superseded claim");
        assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Superseded);
        assert_eq!(old_read.valid_to, Some(20));
        assert_eq!(vault.targets(&new, EdgeKind::Supersedes, None)?, vec![old]);

        let before_edge = gate_decision_count(&vault)?;
        let edge_gate_id = edge_operation_gate_id(
            SelfEffect::MemoryPutEdge,
            subject,
            EdgeKind::Mentions,
            edge_target,
        )?;
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
        assert_latest_gate_decision(&vault, edge_gate_id)?;
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
    fn code_run_edge_and_supersede_traps_force_generated_source_into_g2() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xAB);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-generated-source-g2",
        )?;
        let subject = seed_person(&vault, 0xBB);
        let edge_target = seed_person(&vault, 0xCB);
        let old = EntityId::from_bytes([0xDB; 16]).expect("old claim id");
        let new = EntityId::from_bytes([0xEB; 16]).expect("new claim id");

        install_self_memory_allow_policy(&vault, actor)?;
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

        install_self_memory_policy_trusting_source(&vault, actor, ClaimSource::UserStated)?;
        let edge_gate_id = edge_operation_gate_id(
            SelfEffect::MemoryPutEdge,
            subject,
            EdgeKind::Mentions,
            edge_target,
        )?;
        let edge_err = dispatcher
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                subject,
                EdgeKind::Mentions,
                edge_target,
                0.7,
            )))
            .expect_err("generated source must be evaluated by G2");
        assert_source_trust_gate_rejection(edge_err);
        assert_latest_gate_decision_reasons(
            &vault,
            edge_gate_id,
            "pending",
            &["gate.pending.source_trust"],
        )?;
        assert!(
            vault
                .targets(&subject, EdgeKind::Mentions, None)?
                .is_empty()
        );

        let supersede_err = dispatcher
            .dispatch(SelfCall::MemorySupersedeClaim(
                SelfMemorySupersedeClaimCall::new(new, old, 20),
            ))
            .expect_err("generated source must be evaluated by G2");
        assert_source_trust_gate_rejection(supersede_err);
        assert_latest_gate_decision_reasons(
            &vault,
            old,
            "pending",
            &["gate.pending.source_trust"],
        )?;
        let old_read = vault.get_claim(&old)?.expect("old claim remains");
        assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Active);
        assert!(vault.targets(&new, EdgeKind::Supersedes, None)?.is_empty());
        Ok(())
    }

    #[test]
    fn code_run_immediate_write_traps_reject_pending_gate() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_person(&vault, 0xA6);
        let src = seed_person(&vault, 0xB6);
        let tgt = seed_person(&vault, 0xC6);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-pending-write",
        )?;
        let gate_id =
            edge_operation_gate_id(SelfEffect::MemoryPutEdge, src, EdgeKind::Mentions, tgt)?;
        let before = gate_decision_count(&vault)?;

        let _err = dispatcher
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::Mentions,
                tgt,
                0.7,
            )))
            .expect_err("pending immediate write must not commit");

        assert_eq!(gate_decision_count(&vault)?, before + 1);
        let decisions = vault.store.gate_decisions(1)?;
        let latest = decisions.first().expect("latest gate decision");
        assert_eq!(latest.outcome, "pending");
        assert_eq!(latest.claim_id, Some(*gate_id.as_bytes()));
        assert!(
            latest
                .reason_codes
                .iter()
                .any(|code| code.starts_with("gate.pending."))
        );
        assert!(vault.targets(&src, EdgeKind::Mentions, None)?.is_empty());
        Ok(())
    }

    #[test]
    fn code_run_write_traps_validate_bound_actor() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_machine(&vault, 0xA8);
        let src = seed_person(&vault, 0xB8);
        let tgt = seed_person(&vault, 0xC8);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-invalid-actor",
        )?;
        let before = gate_decision_count(&vault)?;

        let _err = dispatcher
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::Mentions,
                tgt,
                0.7,
            )))
            .expect_err("wrong actor class must reject before write");

        assert_eq!(gate_decision_count(&vault)?, before);
        assert!(vault.targets(&src, EdgeKind::Mentions, None)?.is_empty());
        Ok(())
    }

    #[test]
    fn code_run_put_edge_rejects_structural_edge_kinds() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let actor = seed_first_party_actor(&vault);
        let src = seed_person(&vault, 0xB9);
        let tgt = seed_person(&vault, 0xC9);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-structural-edge",
        )?;
        let before = gate_decision_count(&vault)?;

        let err = dispatcher
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::ClaimOf,
                tgt,
                1.0,
            )))
            .expect_err("structural edge kind must reject");
        assert!(
            matches!(
                err,
                Error::InvalidClaimBody("self.memory.put_edge rejects structural edge kinds")
            ),
            "{err:?}"
        );

        assert_eq!(gate_decision_count(&vault)?, before);
        assert!(vault.targets(&src, EdgeKind::ClaimOf, None)?.is_empty());
        Ok(())
    }

    #[test]
    fn code_run_write_gate_denial_persists_decision() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        put_malformed_policy_manifest(&vault, 0xE7)?;
        let actor = seed_person(&vault, 0xA7);
        let src = seed_person(&vault, 0xB7);
        let tgt = seed_person(&vault, 0xC7);
        let dispatcher = HostSelfDispatcher::new(
            &vault,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-denied-write",
        )?;
        let gate_id =
            edge_operation_gate_id(SelfEffect::MemoryPutEdge, src, EdgeKind::Mentions, tgt)?;
        let before = gate_decision_count(&vault)?;

        let _err = dispatcher
            .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::Mentions,
                tgt,
                0.7,
            )))
            .expect_err("fail-closed policy must reject write");

        assert_eq!(gate_decision_count(&vault)?, before + 1);
        let decisions = vault.store.gate_decisions(1)?;
        let latest = decisions.first().expect("latest gate decision");
        assert_eq!(latest.outcome, "deny");
        assert_eq!(latest.claim_id, Some(*gate_id.as_bytes()));
        assert_eq!(latest.reason_codes, vec!["gate.deny.policy_fail_closed"]);
        assert!(vault.targets(&src, EdgeKind::Mentions, None)?.is_empty());
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
