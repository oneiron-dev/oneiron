//! Doors to the derivation floor (untangle 6.7a, decision C-3): write a claim
//! an agent stamped `surface = vault.derive` through the shared claim gate,
//! as any write door does, and see whether the derivation floors (GATE-12,
//! GATE-13, the checker) held it. Built only on the claim write path, so the
//! same door runs on a tree with no derivation commit.

use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::error::{Error, GateError, Result};
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use crate::{ClaimCandidate, EdgeActorClass, EntityId, TimeRange, Vault};

/// Writes a minimal human-authored agent definition with a Proposed
/// ceiling, as the owner's own agent; its id.
///
/// # Errors
///
/// The vault's.
pub fn define_agent(vault: &Vault) -> Result<EntityId> {
    use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
    use crate::claim::ClaimLifecycleStatus;
    let definition = AgentDefinition::new(
        "oneiron.agent.derivation-fixture",
        "Derivation fixture agent",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    );
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

/// Writes, as the agent `agent`, a proposed `Generated` claim about
/// `subject` citing `evidence`, stamped `surface = vault.derive` as a
/// derivation commit stamps it. `Ok(Ok(id))` when it landed; `Ok(Err(..))`
/// with the gate's reason tokens when the gate refused it.
///
/// # Errors
///
/// Any error other than the gate's refusal.
pub fn write_derived_claim(
    vault: &Vault,
    agent: EntityId,
    subject: EntityId,
    evidence: &[EntityId],
) -> Result<std::result::Result<EntityId, Vec<String>>> {
    let id = EntityId::now();
    let candidate = ClaimCandidate::new(
        "preference.coffee",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("an oat milk flat white"),
        0.9,
    )
    .with_evidence(encode_consolidation_evidence(
        &ConsolidationEvidenceEnvelope {
            refs: evidence.to_vec(),
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    ));
    let envelope = WriteEnvelope::new(
        WriteActor::new(agent, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(rmpv::Value::Map(vec![
            (rmpv::Value::from("surface"), rmpv::Value::from("vault.derive")),
            (rmpv::Value::from("run"), rmpv::Value::from("derivation-floor")),
        ]))?,
        ClaimApprovalStatus::Proposed,
    );
    let now = vault.now_recorded_at();
    let written = vault.with_write_txn_grouped(|txn| {
        vault
            .batch_in()
            .claim_candidate(&id, candidate, &envelope, TimeRange { start: now, end: now }, now)
            .apply_recording_gate_decisions(txn)
    });
    match written {
        Ok(()) => Ok(Ok(id)),
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => Ok(Err(reason_codes
            .iter()
            .map(|code| (*code).to_owned())
            .collect())),
        Err(error) => Err(error),
    }
}
