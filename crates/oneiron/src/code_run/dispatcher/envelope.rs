//! Write-envelope construction, gate bodies and the write-gate checks every memory verb clears.

use rmpv::Value;
use xxhash_rust::xxh3::xxh3_128;

use crate::code_run::consent;
use crate::code_run::replay::CodeRunBridgeCall;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::SelfEffect;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EdgeKind,
    SourceLineage, Vault, WriteEnvelope, WriteProvenance,
};

use super::HostSelfDispatcher;

const SELF_SURFACE_NAME: &str = "self.*";

pub(crate) const SELF_PROVENANCE_SURFACE_KEY: &str = "surface";

const SELF_PROVENANCE_RUN_KEY: &str = "run";

pub(crate) const SELF_PROVENANCE_CALL_KEY: &str = "call";

const SELF_MEMORY_EDGE_OPERATION_ID_DOMAIN: &[u8] = b"oneiron:self-memory-edge-operation:v1";

impl HostSelfDispatcher<'_> {
    pub(super) fn write_envelope(
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
        // ONE-1314. Actor and source stay host-bound exactly as before; what
        // is added is the run's OBSERVED history. Only the memory-write
        // effects that persist a claim/edge carry it — the fixture effect
        // persists nothing a lineage could qualify — and only when the host
        // has actually observed an external effect, so an unobserved run
        // builds the byte-identical trivial envelope it built before.
        let lineage = match effect {
            SelfEffect::MemoryPutClaim
            | SelfEffect::MemorySupersedeClaim
            | SelfEffect::MemoryPutEdge
                if self.external_effect_seen.get() =>
            {
                SourceLineage::of(self.source()).with(ClaimSource::ToolOutput)
            }
            _ => SourceLineage::of(self.source()),
        };
        Ok(WriteEnvelope::with_lineage(
            self.actor,
            self.source(),
            WriteProvenance::new(Value::Map(provenance))?,
            ClaimApprovalStatus::Proposed,
            lineage,
        ))
    }

    pub(super) fn operation_gate_body(
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
    pub(super) fn check_write_gate(
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
        crate::gate::ClaimGateWrite::plain(body, Some(envelope)),
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

pub(crate) fn edge_operation_gate_id(
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

/// Whether one recorded bridge call reached OUTSIDE this vault.
///
/// The match is exhaustive on purpose: a new `SelfEffect` variant fails this
/// compile until someone states which side of the boundary it sits on, so the
/// external-effect vocabulary extends mechanically instead of silently
/// defaulting to "internal".
const fn bridge_call_is_external_effect(effect: SelfEffect) -> bool {
    match effect {
        // Reaches a counterparty outside the vault; the durable wait it parks
        // on is exactly the boundary crossing lineage records.
        SelfEffect::OutboundFixture => true,
        // Vault-local: memory access is not a tool effect, the destructive
        // fixture and delegation park on authority rather than on leaving the
        // vault, and the speech/context family never leaves the run.
        SelfEffect::MemorySearch
        | SelfEffect::MemoryWriteFixture
        | SelfEffect::MemoryPutClaim
        | SelfEffect::MemorySupersedeClaim
        | SelfEffect::MemoryPutEdge
        | SelfEffect::AskHuman
        | SelfEffect::DestructiveFixture
        | SelfEffect::TaskDelegate
        | SelfEffect::Context
        | SelfEffect::Speak
        | SelfEffect::Think
        | SelfEffect::Express => false,
    }
}

/// The lineage a run's recorded effect history implies.
///
/// PURE: history in, lineage out. The base is `Generated` — first-party code
/// wrote the call — and an external effect anywhere in the history adds
/// `ToolOutput`, because everything the run produced after that hop may carry
/// what the outside world said. Reads and searches add nothing: memory access
/// is not a tool effect.
pub(crate) fn lineage_for_run(bridge_calls: &[CodeRunBridgeCall]) -> SourceLineage {
    let lineage = SourceLineage::of(ClaimSource::Generated);
    if bridge_calls
        .iter()
        .any(|call| bridge_call_is_external_effect(call.effect))
    {
        return lineage.with(ClaimSource::ToolOutput);
    }
    lineage
}
