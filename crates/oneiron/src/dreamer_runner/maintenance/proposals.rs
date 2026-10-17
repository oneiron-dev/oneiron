//! The shared Generated writer for deterministic maintenance findings. A
//! Coach finding lands Proposed in the owner's run tray (`/v1/owner/runs`)
//! under the attempt that wrote it, so one review approves or declines a
//! night's batch. A Dreamer finding applies at once (OF-023, owner ruling
//! 10-18: "autoapply + revert rather than holdout"): it lands Auto with its
//! effect, a receipt and a typed inverse the owner reverts, and waits in the
//! run tray only when the Gate parks it. Every finding cites the records it
//! was read from: GATE-12 refuses a Dreamer claim with no live evidence ref.
use super::applied::{self, MaintenanceInverse};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::authority::{BaseAgent, base_agent_for_facet};
use crate::provenance::birth::{MAX_BIRTH_INPUTS, RowBirth};
use crate::provenance::made_by::MadeByClass;
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSubject, EntityId, Error, Result, TimeRange, Vault,
};
use rmpv::Value;

/// The facet's shared proposal envelope plus the Gate's run-tray keys
/// (`runner=dreamer`, `run=<attempt>`), the same keys a representation
/// proposal carries. The authority stamp is unchanged.
pub(super) fn run_tray_envelope(
    vault: &Vault,
    facet: &str,
    attempt: AttemptId,
) -> Result<WriteEnvelope> {
    let shared = vault.dreamer_proposal_envelope(facet, attempt)?;
    let run = crate::entity_id::bytes_to_hex_lower(attempt.as_bytes());
    let mut provenance = shared
        .provenance()
        .value()
        .as_map()
        .ok_or_else(super::invalid)?
        .clone();
    if provenance
        .iter()
        .any(|(key, _)| matches!(key.as_str(), Some("runner" | "run")))
    {
        return Err(super::invalid());
    }
    provenance.push((Value::from("runner"), Value::from("dreamer")));
    provenance.push((Value::from("run"), Value::from(run)));
    Ok(WriteEnvelope::new(
        shared.actor(),
        shared.source(),
        WriteProvenance::new(Value::Map(provenance))?,
        shared.approval(),
    ))
}
#[expect(
    clippy::too_many_arguments,
    reason = "one finding's facet, subject, claim and evidence"
)]
pub(super) fn emit(
    vault: &Vault,
    attempt: AttemptId,
    facet: &str,
    subject: EntityId,
    predicate: &str,
    value: &serde_json::Value,
    evidence: &[EntityId],
    now: u64,
) -> Result<EntityId> {
    let envelope = run_tray_envelope(vault, facet, attempt)?;
    vault.with_write_txn_grouped(|txn| {
        emit_in_txn(
            vault, txn, subject, predicate, value, evidence, &envelope, now,
        )
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "one finding's subject, claim, evidence and write envelope"
)]
pub(super) fn emit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: EntityId,
    predicate: &str,
    value: &serde_json::Value,
    evidence: &[EntityId],
    envelope: &crate::WriteEnvelope,
    now: u64,
) -> Result<EntityId> {
    write_in_txn(
        vault,
        txn,
        &Finding {
            subject,
            predicate,
            value,
            evidence,
        },
        envelope,
        now,
    )
    .map(|(id, _)| id)
}

/// Lands one finding under `envelope`, or returns the one already landed
/// with the same content; the flag is true only for a fresh landing.
fn write_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    finding: &Finding<'_>,
    envelope: &crate::WriteEnvelope,
    now: u64,
) -> Result<(EntityId, bool)> {
    let Finding {
        subject,
        predicate,
        value,
        evidence,
    } = *finding;
    let bytes = serde_json::to_vec(value).map_err(|_| super::invalid())?;
    let id = crate::codebase::entity_id_from_hash_material(
        b"oneiron:dreamer-maintenance-proposal:v1",
        &[subject.as_bytes(), predicate.as_bytes(), &bytes],
    )?;
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &*txn, &id)? {
        let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or_else(super::invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(super::invalid());
        }
        let body = crate::claim::decode_claim_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            true,
        )?;
        if body.subject != ClaimSubject::Entity(subject)
            || body.predicate != predicate
            || body.value.as_str() != std::str::from_utf8(&bytes).ok()
            || body.source != Some(crate::ClaimSource::Generated)
            || crate::claim::session_claim_producer(&body) != Some(envelope.actor().entity_ref())
        {
            return Err(super::invalid());
        }
        return Ok((id, false));
    }
    let candidate = ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(String::from_utf8(bytes).map_err(|_| super::invalid())?),
        1.0,
    )
    .with_evidence(crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: evidence.to_vec(),
            chain: Vec::new(),
            source_meet: crate::ClaimSource::Generated,
        },
    ));
    let mut envelope = envelope.clone();
    vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
    // Rule A: the finding is concluded from the records it cites, the first
    // MAX_BIRTH_INPUTS of them.
    let birth = RowBirth::written(
        envelope.actor(),
        MadeByClass::Concluded,
        "dreamer.finding",
        &evidence[..evidence.len().min(MAX_BIRTH_INPUTS)],
        &[],
        now,
    );
    vault
        .batch_in()
        .claim_candidate(
            &id,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .made_by(&id, birth)
        .apply_recording_gate_decisions(txn)?;
    vault.record_finding_notification_in_txn(txn, id, subject, now)?;
    Ok((id, true))
}

/// One finding's subject, predicate, value and the records it cites.
#[derive(Clone, Copy)]
pub(super) struct Finding<'a> {
    pub(super) subject: EntityId,
    pub(super) predicate: &'a str,
    pub(super) value: &'a serde_json::Value,
    pub(super) evidence: &'a [EntityId],
}

/// Where a Dreamer facet's findings land: applied at Auto under the run-tray
/// envelope's provenance, or held Proposed in the run tray as before.
pub(super) struct Landing {
    envelope: WriteEnvelope,
    attempt: AttemptId,
    facet: String,
    applied: bool,
}

impl Landing {
    /// Lands one finding in the caller's write. Applied, a fresh finding runs
    /// `effect` after it lands and records the inverse `effect` returns with
    /// its receipt; a replay of the same content returns the finding already
    /// landed and runs nothing, so a reverted finding is never applied again.
    /// Held, `effect` never runs.
    pub(super) fn land_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        finding: &Finding<'_>,
        now: u64,
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<MaintenanceInverse>,
    ) -> Result<EntityId> {
        let (id, fresh) = write_in_txn(vault, txn, finding, &self.envelope, now)?;
        if self.applied && fresh {
            let inverse = effect(txn)?;
            applied::record_in_txn(
                vault,
                txn,
                id,
                self.attempt,
                &self.facet,
                self.envelope.actor(),
                inverse,
                now,
            )?;
        }
        Ok(id)
    }
}

/// Runs `write` with the Dreamer facet's applied landing, and once more with
/// its held landing when the Gate parks the applied write (a critical class,
/// a policy that keeps the Dreamer at Proposed): such a finding keeps the run
/// tray. A Coach facet is refused: its findings never apply on their own.
pub(super) fn land<T>(
    vault: &Vault,
    facet: &str,
    attempt: AttemptId,
    write: impl Fn(&Landing) -> Result<T>,
) -> Result<T> {
    if base_agent_for_facet(facet) != BaseAgent::Dreamer {
        return Err(super::invalid());
    }
    let tray = run_tray_envelope(vault, facet, attempt)?;
    let apply = Landing {
        envelope: WriteEnvelope::new(
            tray.actor(),
            tray.source(),
            WriteProvenance::new(tray.provenance().value().clone())?,
            ClaimApprovalStatus::Auto,
        ),
        attempt,
        facet: facet.to_owned(),
        applied: true,
    };
    match write(&apply) {
        Err(error) if parked(&error) => write(&Landing {
            envelope: tray,
            attempt,
            facet: facet.to_owned(),
            applied: false,
        }),
        landed => landed,
    }
}

/// Whether the Gate parked a write rather than refusing it.
fn parked(error: &Error) -> bool {
    matches!(
        error,
        Error::Gate(crate::error::GateError::GateWriteRejected {
            outcome: "pending",
            ..
        })
    )
}
