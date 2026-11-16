//! Doors for `tests/conflict_settle_restriction.rs`.
//! - [`emit_retract_finding`] lands the Dreamer's curator finding that
//!   retracts a stored claim, as the curator lands a finding over a critical
//!   target (`maintenance::curator::run`, then `proposals::emit`): Active,
//!   Proposed, Generated, produced by the Dreamer and citing its target. The
//!   curator grades only the Dreamer's own aged consolidations, and its
//!   writers are private to it; the door lands the finding over any stored
//!   claim, so a test can settle it.
//! - [`land_stale_consolidation`] lands a claim as the Dreamer's own
//!   consolidation on its last curator rung, a target the curator grades.
//! - [`run_curator_once`] runs one curator pass, as the wake driver runs it.
//! - [`open_conflict_with_retract_finding`] opens a conflict whose retained
//!   alternative is such a finding, for
//!   `tests/retained_curator_keep_restriction.rs`.
//! - [`approve_finding_unapplied`] approves such a finding as the owner with
//!   its rung unapplied, for `tests/curator_approved_apply_restriction.rs`.

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::error::{Error, Result};
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
use crate::{ClaimCandidate, ClaimSubject, EntityId, TimeRange, Vault};
use rmpv::Value;

/// Lands the Dreamer's Proposed finding that retracts `target`, graded on
/// the body `target` holds now (its `source_hash`). Returns its id.
///
/// # Errors
///
/// The vault's, and a `target` that is no stored row.
pub fn emit_retract_finding(vault: &Vault, target: EntityId) -> Result<EntityId> {
    let dreamer = vault.dreamer_authority()?;
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        let value = retract_value_in(vault, txn, target)?;
        let candidate = ClaimCandidate::new(
            crate::dreamer_runner::maintenance::CURATOR_PROPOSAL_PREDICATE,
            ClaimSubject::Entity(target),
            Value::from(value),
            1.0,
        )
        .with_evidence(crate::dreamer_consolidation::encode_consolidation_evidence(
            &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
                refs: vec![target],
                chain: Vec::new(),
                source_meet: ClaimSource::Generated,
            },
        ));
        let mut envelope = WriteEnvelope::new(
            dreamer,
            ClaimSource::Generated,
            WriteProvenance::new(Value::Map(vec![(
                Value::from("surface"),
                Value::from("test.curator_finding"),
            )]))?,
            ClaimApprovalStatus::Proposed,
        );
        vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
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
            .apply_recording_gate_decisions(txn)
    })?;
    Ok(id)
}

/// The value of the curator finding that retracts `target`, graded on the
/// body `target` holds in `txn`: its rung, `target` and `source_hash`, as
/// JSON text.
fn retract_value_in(vault: &Vault, txn: &heed::RoTxn<'_>, target: EntityId) -> Result<String> {
    let revision = crate::dreamer_runner::maintenance::claim_revision_in_txn(vault, txn, &target)?
        .ok_or(Error::EntityNotFound)?;
    Ok(serde_json::json!({
        "target": target.to_hex(),
        "source_hash": blake3::Hash::from(revision).to_hex().to_string(),
        "action": { "kind": "retract" },
    })
    .to_string())
}

/// Approves the curator finding `finding` as the owner, with its rung
/// unapplied: the state an approval leaves when the rung does not apply with
/// it (`Vault::apply_approved_curator_in_savepoint` logs the failure, or
/// finds a demotion parked on the target), which the nightly pass then
/// applies. The approval lands as an owner's approval lands
/// (`ClaimMaterialization::apply_owner_approval`); nothing else of the
/// settlement runs.
///
/// # Errors
///
/// The vault's, and a `finding` that is no stored proposal.
pub fn approve_finding_unapplied(vault: &Vault, finding: EntityId) -> Result<()> {
    use crate::batch::{BatchOp, ClaimMaterialization, ENTITY_METADATA_HEADER_LEN};

    let owner = crate::write_envelope::WriteActor::new(
        crate::vault::embedded_owner_actor_id()?,
        crate::edge::EdgeActorClass::Human,
    );
    vault.with_write_txn_grouped(|txn| {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &*txn, &finding)?
            .ok_or(Error::EntityNotFound)?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        let mut body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.approval != ClaimApprovalStatus::Proposed {
            return Err(Error::InvalidClaimBody("the finding is no proposal"));
        }
        body.approval = ClaimApprovalStatus::Approved;
        let put = BatchOp::Put {
            id: finding,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at,
            row_version: None,
            data: crate::claim::encode_claim_body(&body)?,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        };
        ClaimMaterialization::apply_owner_approval(vault, txn, put, true, owner, None)
    })
}

/// Opens a conflict over `member` whose one retained alternative is the
/// Dreamer's curator finding that retracts `target`, graded on the body
/// `target` holds now, about `member`'s subject and citing `member`: a
/// finding a Keep lands and, approving it, applies. The marker is written
/// as `super::derive::open_conflict_with_alternative` writes its own.
/// Returns the marker and the alternative's selector.
///
/// # Errors
///
/// The vault's, a `member` that is no claim or no admissible evidence, and
/// a `target` that is no stored row.
pub fn open_conflict_with_retract_finding(
    vault: &Vault,
    member: EntityId,
    target: EntityId,
) -> Result<(EntityId, EntityId)> {
    use crate::attempt_queue::AttemptId;
    use crate::dreamer_consolidation::evidence::{VerifiedCandidate, VerifiedEvidenceSet};
    use crate::dreamer_consolidation::{PromotionCandidate, retained_alternatives_entry_for_test};

    let body = vault.get_claim(&member)?.ok_or(Error::EntityNotFound)?;
    let actor = vault.dreamer_authority()?;
    let key = crate::claim::ScopedReadActorKey::for_engine_actor(actor)
        .ok_or(Error::InvalidClaimBody("an actor with no read"))?;
    let (evidence, value) = {
        let read = vault.scoped_read(key);
        let txn = vault.store.env.read_txn()?;
        (
            VerifiedEvidenceSet::verify_whole_in_txn(
                vault,
                &read,
                &txn,
                &[member],
                ClaimSource::Generated,
            )?,
            retract_value_in(vault, &txn, target)?,
        )
    };
    let alternative = EntityId::now();
    let now = vault.now_recorded_at();
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let retained = VerifiedCandidate {
        proposal: PromotionCandidate {
            claim_id: alternative,
            candidate: ClaimCandidate::new(
                crate::dreamer_runner::maintenance::CURATOR_PROPOSAL_PREDICATE,
                body.subject,
                Value::from(value),
                1.0,
            ),
            evidence_turn_refs: evidence.refs(),
            provenance_chain: Vec::new(),
            supersedes: None,
            evidence_meet: evidence.meet(),
            occurred,
            learned_at: now,
            decisions: Vec::new(),
        },
        evidence,
        answers: Vec::new(),
        sources: None,
        contested: true,
    };
    let alternatives = retained_alternatives_entry_for_test(&[&retained], AttemptId::now())?;
    let candidate = ClaimCandidate::new(
        crate::claim::PREDICATE_CONFLICT_OPEN,
        body.subject,
        Value::Map(vec![
            (Value::from("predicate"), Value::from(body.predicate)),
            (
                Value::from("prior_head"),
                Value::Binary(member.as_bytes().to_vec()),
            ),
            (
                Value::from("candidates"),
                Value::Array(vec![Value::Binary(alternative.as_bytes().to_vec())]),
            ),
            alternatives,
        ]),
        1.0,
    )
    .with_evidence(retained.evidence.envelope(Vec::new()));
    let marker = EntityId::now();
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from("surface"),
            Value::from("test.open_conflict_with_retract_finding"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    );
    vault.with_write_txn_grouped(|txn| {
        let mut envelope = envelope.clone();
        vault.sign_retained_machine_claim_in_txn(txn, &marker, &candidate, &mut envelope)?;
        vault
            .batch_in()
            .claim_candidate(&marker, candidate, &envelope, occurred, now)
            .apply_recording_gate_decisions(txn)
    })?;
    Ok((marker, alternative))
}

/// Lands `predicate` about `subject` holding `value` as the Dreamer's own
/// consolidation on its last curator rung, learned at `learned_at`: a
/// signed Generated Auto write whose evidence cites `subject` and names the
/// Dreamer under the surface `dreamer`, and whose scope holds the `stale`
/// demotion rung. A curator pass past its minimum age grades it for a
/// retract. Returns its id.
///
/// # Errors
///
/// The vault's, and the write door's.
pub fn land_stale_consolidation(
    vault: &Vault,
    subject: EntityId,
    predicate: &str,
    value: Value,
    learned_at: u64,
) -> Result<EntityId> {
    let dreamer = vault.dreamer_authority()?;
    let id = EntityId::now();
    let candidate = ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, 1.0)
        .with_scope(Value::Map(vec![(
            Value::from(crate::claim::CLAIM_SCOPE_DEMOTION_RUNG_KEY),
            Value::from("stale"),
        )]))
        .with_evidence(crate::dreamer_consolidation::encode_consolidation_evidence(
            &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
                refs: vec![subject],
                chain: Vec::new(),
                source_meet: ClaimSource::Generated,
            },
        ));
    vault.with_write_txn_grouped(|txn| {
        let mut envelope = WriteEnvelope::new(
            dreamer,
            ClaimSource::Generated,
            WriteProvenance::new(Value::Map(vec![(
                Value::from("surface"),
                Value::from("dreamer"),
            )]))?,
            ClaimApprovalStatus::Auto,
        );
        vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
        vault
            .batch_in()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
            )
            .apply_recording_gate_decisions(txn)
    })?;
    Ok(id)
}

/// Runs one curator pass at `now` (Unix seconds), as the wake driver runs
/// it: a maintenance attempt for the curator facet, admitted on the
/// maintenance lane and graded under the Dreamer's authority stamp. Answers
/// the findings the pass landed, held for a person or applied.
///
/// # Errors
///
/// The vault's, the pass's own, or an attempt that is not admitted.
pub fn run_curator_once(vault: &Vault, now: u64) -> Result<Vec<EntityId>> {
    use crate::dreamer_runner::maintenance::{CURATOR_FACET, MAINTENANCE_QUEUE_KIND, run_curator};
    use crate::dreamer_runner::{
        AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAttemptPayload, DreamerRunnerStore,
    };

    let store = DreamerRunnerStore::new(vault);
    vault.with_write_txn(|txn| {
        store
            .enqueue_kind_in_txn(
                txn,
                MAINTENANCE_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: CURATOR_FACET.to_owned(),
                    input: Value::from("nightly"),
                    parent_attempt: None,
                },
                Some(format!("test.curator_pass:{now}")),
                None,
                now,
            )
            .map(|_| ())
    })?;
    let DreamerAdmissionOutcome::Admitted(admitted) =
        store.admit_next_maintenance(AdmitDreamerAttempt {
            lease_owner: "test-door".to_owned(),
            now,
            budget_id: "wake".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        })?
    else {
        return Err(Error::InvalidConfig(
            "the curator attempt was not admitted".into(),
        ));
    };
    run_curator(vault, &admitted, now)
}
