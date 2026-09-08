//! Dreamer precommit: evidence floor, shell and live rows, degeneracy, and denial codes.

use super::*;
use crate::gate::doors::dreamer_run_id_from_write_envelope;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

pub(super) const PRECOMMIT_RUN_ID: &str = "gate12-precommit-run";

/// `refs` key of the consolidation evidence envelope
/// (`dreamer_consolidation/provenance.rs`). Spelled out here only so a test
/// can corrupt one ref inside an otherwise well-formed envelope.
pub(super) const PRECOMMIT_EVIDENCE_REFS_KEY: &str = "refs";

/// A vault whose manifest lets the Dreamer's `agent` actor land Auto writes,
/// so pre-commit validation is the only thing that can refuse the write.
fn precommit_vault() -> Result<(tempfile::TempDir, crate::Vault)> {
    let (tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::Generated, 0),
        signatures_entry(),
    ]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &first_party_connector_actor_ref(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0x22), &data)?;
    Ok((tmp, vault))
}

pub(super) fn precommit_evidence(refs: Vec<EntityId>) -> Value {
    crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs,
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    )
}

/// The evidence-map shape the door-level validator input carries: the
/// envelope-encoded payload rides under the pinned `candidate_evidence` key
/// (`write_envelope_evidence` composes exactly this map on real writes).
fn precommit_evidence_map(refs: Vec<EntityId>) -> Value {
    Value::Map(vec![(
        Value::from(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY),
        precommit_evidence(refs),
    )])
}

pub(super) fn precommit_body(value: Value, evidence: Option<Value>) -> ClaimBody {
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.value = value;
    body.evidence = evidence;
    body
}

pub(super) fn seed_precommit_evidence_entity(vault: &crate::Vault, id: &EntityId) -> Result<()> {
    vault.put_entity(id, ENTITY_TYPE_PERSON, test_time(1), 1, b"evidence ref")
}

fn attempt_precommit_write(
    vault: &crate::Vault,
    claim_id: &EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(
        vault,
        body,
        first_party_connector_actor_id(),
        PRECOMMIT_RUN_ID,
    )?;
    vault
        .batch()
        .claim_candidate(claim_id, candidate, &envelope, test_time(3), 3)
        .commit()
}

/// A pre-commit denial is a DENY carrying exactly the pinned code, and it
/// leaves nothing claim-side behind: no claim entity, no Proposed row, no
/// pending-consent row.
fn assert_precommit_denied(
    vault: &crate::Vault,
    err: Error,
    claim_id: &EntityId,
    reason_code: &'static str,
) -> Result<()> {
    match err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert_eq!(outcome, "deny", "validity failures deny, never downgrade");
            assert_eq!(reason_codes, vec![reason_code]);
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
    assert!(
        vault.get_raw(claim_id)?.is_none(),
        "a denied Dreamer write must land no claim"
    );
    assert!(
        !has_pending_gate_consent(vault, claim_id)?,
        "a validity denial must not mint a pending-consent row"
    );
    Ok(())
}

fn stub_resolver(resolves: bool) -> impl Fn(&EntityId) -> Result<bool> {
    move |_: &EntityId| Ok(resolves)
}

#[test]
fn invalid_dreamer_write_rejected_precommit() -> Result<()> {
    let (_tmp, vault) = precommit_vault()?;
    let evidence_ref = test_id(0x31);
    seed_precommit_evidence_entity(&vault, &evidence_ref)?;

    // Check 1 — every degenerate narration form, matched case-insensitively.
    // The claim codec accepts these values, so the pre-commit validator is
    // the only thing standing between them and the vault.
    for (seed, value) in [
        (0x40_u8, ""),
        (0x41, "   "),
        (0x4A, "I will remember this later"),
        (0x43, "I'll get to it"),
        (0x44, "Working on it"),
        (0x45, "IN PROGRESS"),
        (0x46, "todo: ask the owner"),
        (0x4B, "TBD"),
        (0x48, "Placeholder"),
        (0x49, "As an AI, I cannot"),
    ] {
        let claim_id = test_id(seed);
        let body = precommit_body(
            Value::from(value),
            Some(precommit_evidence(vec![evidence_ref])),
        );
        let err = attempt_precommit_write(&vault, &claim_id, &body)
            .expect_err("degenerate Dreamer narration must be refused");
        assert_precommit_denied(
            &vault,
            err,
            &claim_id,
            "gate.deny.dreamer_precommit.degenerate_output",
        )?;
    }
    Ok(())
}

#[test]
fn invalid_dreamer_write_rejected_precommit_evidence_floor() -> Result<()> {
    let (_tmp, vault) = precommit_vault()?;
    let resolving = test_id(0x32);
    seed_precommit_evidence_entity(&vault, &resolving)?;

    // A well-formed envelope whose single ref is 4 bytes rather than 16: the
    // decode breaks, which counts as no admissible evidence, never an abort.
    let mut malformed = precommit_evidence(vec![resolving]);
    if let Value::Map(entries) = &mut malformed {
        for (key, value) in entries {
            if key.as_str() == Some(PRECOMMIT_EVIDENCE_REFS_KEY) {
                *value = Value::Array(vec![Value::Binary(vec![0x01, 0x02, 0x03, 0x04])]);
            }
        }
    }

    // Check 3 — no candidate_evidence key at all; a legacy (non-envelope)
    // payload; a malformed ref; and a well-formed ref that resolves to
    // nothing. `test_id(0x33)` is deliberately never seeded.
    for (seed, evidence) in [
        (0x50_u8, None),
        (0x51, Some(Value::Array(Vec::new()))),
        (0x52, Some(malformed)),
        (0x53, Some(precommit_evidence(vec![test_id(0x33)]))),
    ] {
        let claim_id = test_id(seed);
        let body = precommit_body(Value::from("Ada Lovelace"), evidence);
        let err = attempt_precommit_write(&vault, &claim_id, &body)
            .expect_err("a non-runtime-record claim must cite resolving evidence");
        assert_precommit_denied(
            &vault,
            err,
            &claim_id,
            "gate.deny.dreamer_precommit.no_evidence",
        )?;
    }

    // The same claim with one resolving ref lands.
    let claim_id = test_id(0x54);
    let body = precommit_body(
        Value::from("Ada Lovelace"),
        Some(precommit_evidence(vec![resolving])),
    );
    attempt_precommit_write(&vault, &claim_id, &body)?;
    assert_eq!(
        stored_claim_body(&vault, &claim_id)?.approval,
        ClaimApprovalStatus::Auto
    );
    Ok(())
}

/// `DeleteReason::UserDelete` deliberately keeps a parseable 25-byte header
/// shell, and that shell is exactly what the floor must refuse: the ticket
/// pins evidence as an EXISTING, NON-ERASED entity, so however well the
/// header still reads, an erased ref cannot carry a Dreamer write.
#[test]
fn dreamer_precommit_evidence_floor_denies_soft_deleted_ref() -> Result<()> {
    let (_tmp, vault) = precommit_vault()?;
    let evidence_ref = test_id(0x56);
    seed_precommit_evidence_entity(&vault, &evidence_ref)?;
    assert!(
        vault
            .delete_entity_with_reason(&evidence_ref, crate::deletion::DeleteReason::UserDelete)?
            .existed,
        "the seeded evidence entity was there to delete"
    );
    let shell = vault
        .get_raw(&evidence_ref)?
        .expect("a soft delete keeps the shell");
    assert_eq!(
        shell.len(),
        crate::batch::ENTITY_METADATA_HEADER_LEN,
        "the surviving row is the bodyless header shell"
    );
    assert!(vault.is_deleted_shell(&evidence_ref)?);

    let claim_id = test_id(0x57);
    let body = precommit_body(
        Value::from("Ada Lovelace"),
        Some(precommit_evidence(vec![evidence_ref])),
    );
    let err = attempt_precommit_write(&vault, &claim_id, &body)
        .expect_err("an erased shell is not evidence");
    assert_precommit_denied(
        &vault,
        err,
        &claim_id,
        "gate.deny.dreamer_precommit.no_evidence",
    )?;
    Ok(())
}

/// Fail-closed is per-REF, never a wedge on the writer: the same Dreamer run
/// that was denied on an erased ref lands as soon as it cites a live one.
#[test]
fn dreamer_precommit_evidence_floor_retry_after_shell_denial() -> Result<()> {
    let (_tmp, vault) = precommit_vault()?;
    let deleted = test_id(0x58);
    seed_precommit_evidence_entity(&vault, &deleted)?;
    assert!(
        vault
            .delete_entity_with_reason(&deleted, crate::deletion::DeleteReason::UserDelete)?
            .existed
    );

    let denied_claim = test_id(0x59);
    let body = precommit_body(
        Value::from("Ada Lovelace"),
        Some(precommit_evidence(vec![deleted])),
    );
    let err = attempt_precommit_write(&vault, &denied_claim, &body)
        .expect_err("the erased ref is refused");
    assert_precommit_denied(
        &vault,
        err,
        &denied_claim,
        "gate.deny.dreamer_precommit.no_evidence",
    )?;

    // Same writer, same shape, one LIVE ref.
    let live = test_id(0x5B);
    seed_precommit_evidence_entity(&vault, &live)?;
    let retry_claim = test_id(0x5C);
    let body = precommit_body(
        Value::from("Ada Lovelace"),
        Some(precommit_evidence(vec![live])),
    );
    attempt_precommit_write(&vault, &retry_claim, &body)?;
    assert_eq!(
        stored_claim_body(&vault, &retry_claim)?.approval,
        ClaimApprovalStatus::Auto,
        "a per-ref denial never wedges the writer"
    );
    Ok(())
}

/// The shared liveness body both repaired call sites read, at the vault
/// level: a deleted shell and a live zero-byte payload have the SAME row
/// shape, and only the deletion metadata tells them apart. Body-bearing rows
/// and same-write-transaction visibility (the miner's write-then-gate order)
/// are pinned here too, because the resolver may never open a transaction of
/// its own to answer.
#[test]
fn live_entity_rows_separate_shells_from_live_zero_byte_payloads() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let shell = test_id(0x5D);
    vault.put_entity(&shell, ENTITY_TYPE_PERSON, test_time(1), 1, b"deleted body")?;
    assert!(
        vault
            .delete_entity_with_reason(&shell, crate::deletion::DeleteReason::UserDelete)?
            .existed
    );
    assert_eq!(
        vault
            .get_raw(&shell)?
            .expect("a soft delete keeps the shell")
            .len(),
        crate::batch::ENTITY_METADATA_HEADER_LEN
    );
    let body_bearing = test_id(0x5E);
    vault.put_entity(
        &body_bearing,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"live body",
    )?;

    let mut wtxn = vault.store.env.write_txn()?;
    // A live zero-byte payload: the shell's exact row shape, with no deletion
    // metadata anywhere.
    let zero_byte = test_id(0x60);
    vault.store.entities.put(
        &mut wtxn,
        zero_byte.as_bytes(),
        &entity_record(ENTITY_TYPE_PERSON, test_time(1), 1, b""),
    )?;
    // Written in THIS transaction and never committed: the miner's evidence
    // record is exactly this case.
    let in_txn = test_id(0x61);
    vault.store.entities.put(
        &mut wtxn,
        in_txn.as_bytes(),
        &entity_record(ENTITY_TYPE_PERSON, test_time(1), 1, b"in-txn body"),
    )?;
    // Shorter than the metadata header: unparseable.
    let truncated = test_id(0x62);
    vault
        .store
        .entities
        .put(&mut wtxn, truncated.as_bytes(), b"short")?;

    assert!(live_entity_row_in_txn(&vault.store, &wtxn, &body_bearing)?.is_live());
    assert!(
        live_entity_row_in_txn(&vault.store, &wtxn, &in_txn)?.is_live(),
        "a row written in the caller's own write transaction still resolves"
    );
    assert!(
        live_entity_row_in_txn(&vault.store, &wtxn, &zero_byte)?.is_live(),
        "a header-only row with no deletion metadata is a live zero-byte payload"
    );
    assert_eq!(
        live_entity_row_in_txn(&vault.store, &wtxn, &shell)?,
        LiveEntityRow::DeletedShell,
        "the same row shape WITH deletion metadata is an erased shell"
    );
    assert_eq!(
        live_entity_row_in_txn(&vault.store, &wtxn, &test_id(0x63))?,
        LiveEntityRow::Absent
    );
    assert!(
        live_entity_row_in_txn(&vault.store, &wtxn, &truncated).is_err(),
        "an unparseable header fails closed rather than resolving"
    );
    wtxn.abort();
    Ok(())
}

/// A deletion-metadata read that cannot be decoded is fail-closed: no live
/// answer comes out of an unreadable window, so the floor is not met.
#[cfg(feature = "sync")]
#[test]
fn live_entity_rows_fail_closed_on_unreadable_deletion_metadata() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let zero_byte = test_id(0x64);
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.entities.put(
        &mut wtxn,
        zero_byte.as_bytes(),
        &entity_record(ENTITY_TYPE_PERSON, test_time(1), 1, b""),
    )?;
    vault.store.sync_state.put(
        &mut wtxn,
        &format!("d:w:{}", crate::deletion::window_label_from_timestamp(1)),
        b"not a loro snapshot",
    )?;
    assert!(
        live_entity_row_in_txn(&vault.store, &wtxn, &zero_byte).is_err(),
        "an undecodable published-tombstone window never resolves"
    );
    wtxn.abort();
    Ok(())
}

#[test]
fn invalid_dreamer_write_precommit_denial_leaves_no_proposed_row() -> Result<()> {
    let (_tmp, vault) = precommit_vault()?;
    let claim_id = test_id(0x55);
    // A Proposed request is exactly the lane a validity failure must NOT be
    // downgraded into.
    let mut body = precommit_body(Value::from("todo"), None);
    body.approval = ClaimApprovalStatus::Proposed;

    let err = attempt_precommit_write(&vault, &claim_id, &body)
        .expect_err("a degenerate Proposed candidate is denied, not queued");
    assert_precommit_denied(
        &vault,
        err,
        &claim_id,
        "gate.deny.dreamer_precommit.degenerate_output",
    )?;
    assert!(
        vault.pending_gate_consents(10)?.is_empty(),
        "no pending-consent row anywhere"
    );
    Ok(())
}

#[test]
fn runtime_record_predicates_exempt_from_evidence_floor() -> Result<()> {
    let (_tmp, vault) = precommit_vault()?;

    // The Dreamer's own runtime record cannot cite evidence for itself, so
    // the floor is skipped for exactly these three predicates.
    for (seed, predicate) in [
        (0x60_u8, crate::dreamer_runner::DREAMER_MILESTONE_PREDICATE),
        (0x61, crate::llm::DREAMER_STEP_PREDICATE),
        (0x62, crate::llm::DREAMER_TRAP_PREDICATE),
    ] {
        let claim_id = test_id(seed);
        let mut body = precommit_body(Value::from("checkpoint reached"), None);
        body.predicate = predicate.to_owned();
        attempt_precommit_write(&vault, &claim_id, &body)?;
        assert_eq!(
            stored_claim_body(&vault, &claim_id)?.approval,
            ClaimApprovalStatus::Auto,
            "{predicate} is exempt from the evidence floor"
        );
    }

    // Exemption is from the FLOOR only: a degenerate runtime record still
    // fails check 1.
    let claim_id = test_id(0x63);
    let mut body = precommit_body(Value::from("  "), None);
    body.predicate = crate::llm::DREAMER_STEP_PREDICATE.to_owned();
    let err = attempt_precommit_write(&vault, &claim_id, &body)
        .expect_err("an exempt predicate is still refused a degenerate value");
    assert_precommit_denied(
        &vault,
        err,
        &claim_id,
        "gate.deny.dreamer_precommit.degenerate_output",
    )
}

#[test]
fn runtime_record_exemption_table_is_built_from_the_writers_constants() {
    assert_eq!(
        DREAMER_RUNTIME_RECORD_PREDICATES,
        [
            crate::dreamer_runner::DREAMER_MILESTONE_PREDICATE,
            crate::llm::DREAMER_STEP_PREDICATE,
            crate::llm::DREAMER_TRAP_PREDICATE,
        ],
        "the exemption table must stay composed from the writers' constants"
    );
}

#[test]
fn non_dreamer_writes_unaffected() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::UserStated, 0),
        signatures_entry(),
    ]);
    append_actor_ceiling(&mut data, actor_ceiling_row("human", "auto"));
    put_policy_manifest_bytes(&vault, test_id(0x12), &data)?;

    // An owner write with an empty-like value and no candidate evidence:
    // both would be refused if this claim were Dreamer-authored. The Dreamer
    // branch is never entered, so it passes exactly as before.
    let claim_id = test_id(0x64);
    let mut body = public_stamped(source_trust_claim(ClaimSource::UserStated));
    body.value = Value::from("   ");
    let (candidate, envelope) =
        claim_candidate_write_parts_for_actor(&vault, &body, test_id(0x65), EdgeActorClass::Human)?;
    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    assert_eq!(
        stored_claim_body(&vault, &claim_id)?.approval,
        ClaimApprovalStatus::Auto
    );
    Ok(())
}

#[test]
fn replay_path_skips_dreamer_precommit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x13), &encode_policy_manifest(vec![]))?;

    // A Dreamer-shaped, degenerate, evidence-free claim arriving over
    // replication: replay stays trust-blind and must not consult the
    // validator.
    let id = test_id(0x66);
    let body = precommit_body(Value::from("I will do it later"), None);
    let data = crate::claim::encode_claim_body(&body)?;
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time(5),
            5,
            &data,
        )
        .commit()?;

    assert!(
        vault.get_raw(&id)?.is_some(),
        "replicated replay must not call the Dreamer pre-commit validator"
    );
    Ok(())
}

#[test]
fn dreamer_precommit_refuses_malformed_shape() {
    let resolves = stub_resolver(true);
    let evidence = precommit_evidence_map(vec![test_id(0x34)]);
    let value = Value::from("Ada");

    // Check 2 restates bounds the claim codec also owns, so these are pinned
    // against the validator directly: a body carrying them cannot reach the
    // door in the first place.
    let base = DreamerPrecommitInput {
        predicate: "profile.name",
        value: &value,
        confidence: 0.7,
        subject_present: true,
        evidence: Some(&evidence),
    };
    let long_predicate = format!("profile.{}", "n".repeat(crate::claim::MAX_PREDICATE_BYTES));
    let nil = Value::Nil;

    let cases: [DreamerPrecommitInput<'_>; 7] = [
        DreamerPrecommitInput {
            predicate: "",
            ..base
        },
        DreamerPrecommitInput {
            predicate: &long_predicate,
            ..base
        },
        DreamerPrecommitInput {
            predicate: "edge.provenance",
            ..base
        },
        DreamerPrecommitInput {
            confidence: f32::NAN,
            ..base
        },
        DreamerPrecommitInput {
            confidence: 1.5,
            ..base
        },
        DreamerPrecommitInput {
            subject_present: false,
            ..base
        },
        DreamerPrecommitInput {
            value: &nil,
            ..base
        },
    ];
    for case in &cases {
        assert_eq!(
            validate_dreamer_precommit(case, &resolves),
            Err(GateReasonCode::DenyDreamerMalformed),
            "predicate {:?} confidence {} must be refused as malformed",
            case.predicate,
            case.confidence
        );
    }

    assert_eq!(validate_dreamer_precommit(&base, &resolves), Ok(()));
}

#[test]
fn dreamer_precommit_first_failure_wins_pinned_order() {
    let resolves = stub_resolver(false);
    let degenerate = Value::from("TODO");
    let sound = Value::from("Ada");

    // Degenerate value + reserved predicate + no evidence: check 1 wins.
    assert_eq!(
        validate_dreamer_precommit(
            &DreamerPrecommitInput {
                predicate: "edge.provenance",
                value: &degenerate,
                confidence: 2.0,
                subject_present: false,
                evidence: None,
            },
            &resolves,
        ),
        Err(GateReasonCode::DenyDreamerDegenerateOutput)
    );

    // Sound value, reserved predicate, no evidence: check 2 wins.
    assert_eq!(
        validate_dreamer_precommit(
            &DreamerPrecommitInput {
                predicate: "edge.provenance",
                value: &sound,
                confidence: 0.5,
                subject_present: true,
                evidence: None,
            },
            &resolves,
        ),
        Err(GateReasonCode::DenyDreamerMalformed)
    );

    // Sound value and shape, unresolvable evidence: check 3 wins.
    assert_eq!(
        validate_dreamer_precommit(
            &DreamerPrecommitInput {
                predicate: "profile.name",
                value: &sound,
                confidence: 0.5,
                subject_present: true,
                evidence: None,
            },
            &resolves,
        ),
        Err(GateReasonCode::DenyDreamerNoEvidence)
    );
}

#[test]
fn dreamer_precommit_degenerate_prefixes_are_matched_case_insensitively() {
    let resolves = stub_resolver(true);
    let evidence = precommit_evidence(vec![test_id(0x35)]);

    for prefix in DREAMER_DEGENERATE_VALUE_PREFIXES {
        let value = Value::from(format!("  {} the rest", prefix.to_uppercase()));
        assert_eq!(
            validate_dreamer_precommit(
                &DreamerPrecommitInput {
                    predicate: "profile.name",
                    value: &value,
                    confidence: 0.5,
                    subject_present: true,
                    evidence: Some(&evidence),
                },
                &resolves,
            ),
            Err(GateReasonCode::DenyDreamerDegenerateOutput),
            "{prefix} must match case-insensitively after trimming"
        );
    }
}

#[test]
fn dreamer_precommit_skips_degeneracy_for_non_string_values() {
    let resolves = stub_resolver(true);
    let evidence = precommit_evidence_map(vec![test_id(0x36)]);
    let value = Value::from(7_u64);

    // Only strings can be degenerate narration; other value shapes are
    // judged structurally and pass.
    assert_eq!(
        validate_dreamer_precommit(
            &DreamerPrecommitInput {
                predicate: "profile.age",
                value: &value,
                confidence: 0.5,
                subject_present: true,
                evidence: Some(&evidence),
            },
            &resolves,
        ),
        Ok(())
    );
}

/// Pre-commit validation is claim VALIDITY, so an absent manifest must not
/// buy a way around it.
///
/// The validator used to be computed inside the `enforces_write_gate()` arm,
/// which a vault with no manifest skips wholesale. `Proposed` is the sharp
/// case: the door's tail source-trust check returns early for anything that is
/// not `Auto`, so on the bootstrap path nothing else looked at the claim at
/// all and a degenerate Dreamer candidate simply landed.
#[test]
fn absent_manifest_cannot_bypass_dreamer_precommit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    assert!(
        !resolve(&vault)?.enforces_write_gate(),
        "this fixture must exercise the absent-manifest bootstrap path"
    );
    let evidence_ref = test_id(0x36);
    seed_precommit_evidence_entity(&vault, &evidence_ref)?;

    // Check 1 on the path that used to skip the validator entirely.
    let proposed_id = test_id(0x37);
    let mut proposed = precommit_body(
        Value::from("I will remember this later"),
        Some(precommit_evidence(vec![evidence_ref])),
    );
    proposed.approval = ClaimApprovalStatus::Proposed;
    let err = attempt_precommit_write(&vault, &proposed_id, &proposed)
        .expect_err("an absent manifest must not smuggle a degenerate Dreamer claim past GATE-12");
    assert_precommit_denied(
        &vault,
        err,
        &proposed_id,
        "gate.deny.dreamer_precommit.degenerate_output",
    )?;

    // An Auto candidate denies with the pinned GATE-12 code, rather than
    // falling through to the unrelated source-trust refusal at the door tail.
    let auto_id = test_id(0x38);
    let auto = precommit_body(
        Value::from("   "),
        Some(precommit_evidence(vec![evidence_ref])),
    );
    let err = attempt_precommit_write(&vault, &auto_id, &auto)
        .expect_err("a degenerate Auto Dreamer claim is refused without a manifest too");
    assert_precommit_denied(
        &vault,
        err,
        &auto_id,
        "gate.deny.dreamer_precommit.degenerate_output",
    )?;

    // The evidence floor is part of the same validator, so it holds here too.
    let no_evidence_id = test_id(0x39);
    let mut no_evidence = precommit_body(Value::from("Ada"), None);
    no_evidence.approval = ClaimApprovalStatus::Proposed;
    let err = attempt_precommit_write(&vault, &no_evidence_id, &no_evidence)
        .expect_err("the evidence floor still applies without a manifest");
    assert_precommit_denied(
        &vault,
        err,
        &no_evidence_id,
        "gate.deny.dreamer_precommit.no_evidence",
    )?;

    // Control: only INVALID candidates are refused. The bootstrap path still
    // lands a well-formed Dreamer candidate exactly as it did before.
    let valid_id = test_id(0x3A);
    let mut valid = precommit_body(
        Value::from("Ada"),
        Some(precommit_evidence(vec![evidence_ref])),
    );
    valid.approval = ClaimApprovalStatus::Proposed;
    attempt_precommit_write(&vault, &valid_id, &valid)?;
    assert!(
        vault.get_raw(&valid_id)?.is_some(),
        "an absent manifest must still land a valid Dreamer candidate"
    );
    Ok(())
}

/// The three GATE-12 codes reach callers through `Error::GateWriteRejected`,
/// so they must parse back through the public typed taxonomy.
///
/// `Error::gate_denial()` returns `None` for the WHOLE denial as soon as one
/// reason code is unknown to `GateDenialReason`, so an unmapped code does not
/// degrade gracefully — it silently erases the reason a caller was given.
#[test]
fn dreamer_precommit_codes_round_trip_through_the_typed_denial_taxonomy() {
    for (emitted, typed) in [
        (
            GateReasonCode::DenyDreamerDegenerateOutput,
            GateDenialReason::DenyDreamerPrecommitDegenerateOutput,
        ),
        (
            GateReasonCode::DenyDreamerMalformed,
            GateDenialReason::DenyDreamerPrecommitMalformed,
        ),
        (
            GateReasonCode::DenyDreamerNoEvidence,
            GateDenialReason::DenyDreamerPrecommitNoEvidence,
        ),
    ] {
        // The door emits the internal code; the public taxonomy must spell the
        // exact same string or the two enums have silently drifted apart.
        assert_eq!(emitted.as_str(), typed.as_str());
        assert_eq!(GateDenialReason::from_code(emitted.as_str()), Some(typed));
        assert_eq!(
            typed.outcome(),
            GateDenialOutcome::Deny,
            "validity failures deny, never pend"
        );

        let err = Error::GateWriteRejected {
            outcome: GateDenialOutcome::Deny.as_str(),
            reason_codes: vec![emitted.as_str()],
        };
        let denial = err
            .gate_denial()
            .expect("a Dreamer pre-commit denial must parse into the typed taxonomy");
        assert_eq!(denial.outcome(), GateDenialOutcome::Deny);
        assert_eq!(denial.reason_codes(), &[typed]);
    }
}

/// Every `ClaimSource` the engine can compute as an evidence meet.
///
/// The Dreamer's promotion writer stamps the COMPUTED meet on its envelope
/// (`effective_evidence_source`), so a `ToolOutput`, `Imported` or `Observed`
/// Dreamer write is the ordinary case rather than a forgery.
const ALL_CLAIM_SOURCES: [ClaimSource; 6] = [
    ClaimSource::UserStated,
    ClaimSource::Observed,
    ClaimSource::Inferred,
    ClaimSource::Imported,
    ClaimSource::ToolOutput,
    ClaimSource::Generated,
];

/// Names each source explicitly, so adding a `ClaimSource` variant is a
/// COMPILE error here rather than a silent hole in the pins below: whoever
/// adds one has to decide what the source-agnostic detector does with it.
fn claim_source_pin_label(source: ClaimSource) -> &'static str {
    match source {
        ClaimSource::UserStated => "user_stated",
        ClaimSource::Observed => "observed",
        ClaimSource::Inferred => "inferred",
        ClaimSource::Imported => "imported",
        ClaimSource::ToolOutput => "tool_output",
        ClaimSource::Generated => "generated",
    }
}

/// A Dreamer-shaped provenance map: the surface marker, plus an optional
/// run handle under either accepted key.
fn dreamer_surface_provenance(surface: &str, run: Option<(&str, &str)>) -> Value {
    let mut entries = vec![(
        Value::from(DREAMER_PROVENANCE_SURFACE_KEY),
        Value::from(surface),
    )];
    if let Some((run_key, run_id)) = run {
        entries.push((Value::from(run_key), Value::from(run_id)));
    }
    Value::Map(entries)
}

fn dreamer_detector_envelope(
    actor_class: EdgeActorClass,
    source: ClaimSource,
    provenance: Value,
) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(first_party_connector_actor_id(), actor_class),
        source,
        WriteProvenance::new(provenance)?,
        ClaimApprovalStatus::Proposed,
    ))
}

/// GATE-12 candidacy is exactly `Agent` class + the Dreamer run surface + a
/// non-empty run id, and NOTHING else.
///
/// Pinned on the detector itself, because the two ways to get this wrong are
/// both invisible from a single door test: a source allowlist (which lets a
/// truthful non-`Generated` meet disable the deny-first floor) and
/// surface-only detection (which would sweep the dormant-magistrate bridge
/// writes, surface marker with no run id, into GATE-12).
#[test]
fn dreamer_detector_is_source_agnostic_provenance() -> Result<()> {
    // 1. Authorship holds across EVERY evidence meet. `source` is epistemic
    //    taint computed FROM the candidate's evidence; it says how well the
    //    claim is known, never who wrote it.
    for source in ALL_CLAIM_SOURCES {
        // The label is spelled independently of the enum, so a renamed
        // on-disk source string cannot drift past this pin either.
        let label = claim_source_pin_label(source);
        assert_eq!(label, source.as_str());
        for run_key in [DREAMER_PROVENANCE_RUN_ID_KEY, DREAMER_PROVENANCE_RUN_KEY] {
            let envelope = dreamer_detector_envelope(
                EdgeActorClass::Agent,
                source,
                dreamer_surface_provenance(
                    DREAMER_RUNNER_ATTEMPT_KIND,
                    Some((run_key, PRECOMMIT_RUN_ID)),
                ),
            )?;
            assert_eq!(
                dreamer_run_id_from_write_envelope(&envelope).as_deref(),
                Some(PRECOMMIT_RUN_ID),
                "a {label} meet under `{run_key}` is still Dreamer-authored"
            );
        }
    }

    // 2. The run id stays REQUIRED. Blank, whitespace-only and absent are
    //    all outside GATE-12, so the magistrate bridge (surface marker, no
    //    run) keeps its ONE-1888 behaviour.
    for run in [
        Some((DREAMER_PROVENANCE_RUN_ID_KEY, "")),
        Some((DREAMER_PROVENANCE_RUN_KEY, "   ")),
        None,
    ] {
        let envelope = dreamer_detector_envelope(
            EdgeActorClass::Agent,
            ClaimSource::Generated,
            dreamer_surface_provenance(DREAMER_RUNNER_ATTEMPT_KIND, run),
        )?;
        assert_eq!(
            dreamer_run_id_from_write_envelope(&envelope),
            None,
            "a surface marker with no run handle is not a GATE-12 candidate"
        );
    }

    // 3. A different surface is a different author, run id or not.
    let other_surface = dreamer_detector_envelope(
        EdgeActorClass::Agent,
        ClaimSource::Generated,
        dreamer_surface_provenance(
            "agent.dispatch",
            Some((DREAMER_PROVENANCE_RUN_ID_KEY, PRECOMMIT_RUN_ID)),
        ),
    )?;
    assert_eq!(
        dreamer_run_id_from_write_envelope(&other_surface),
        None,
        "only the Dreamer run surface carries Dreamer authorship"
    );

    // 4. The `Agent` class requirement holds: owner writes and the
    //    System-actor projection shape stay outside GATE-12 on a fully valid
    //    Dreamer provenance map, whatever their meet.
    for actor_class in [EdgeActorClass::Human, EdgeActorClass::System] {
        for source in ALL_CLAIM_SOURCES {
            let envelope = dreamer_detector_envelope(
                actor_class,
                source,
                dreamer_surface_provenance(
                    DREAMER_RUNNER_ATTEMPT_KIND,
                    Some((DREAMER_PROVENANCE_RUN_ID_KEY, PRECOMMIT_RUN_ID)),
                ),
            )?;
            assert_eq!(
                dreamer_run_id_from_write_envelope(&envelope),
                None,
                "{actor_class:?} is not the Dreamer, whatever the {} meet",
                claim_source_pin_label(source)
            );
        }
    }
    Ok(())
}

/// `dreamer_claim_candidate_write_parts`, with the evidence meet under test
/// instead of its hardcoded `Generated`. Seeding is shared with that helper
/// so these writes differ from the pinned `Generated` fixtures on exactly
/// one axis.
fn dreamer_write_parts_with_source(
    vault: &crate::Vault,
    body: &ClaimBody,
    source: ClaimSource,
) -> Result<(ClaimCandidate, WriteEnvelope)> {
    let actor = first_party_connector_actor_id();
    let (candidate, _) = dreamer_claim_candidate_write_parts(vault, body, actor, PRECOMMIT_RUN_ID)?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        source,
        WriteProvenance::new(dreamer_surface_provenance(
            DREAMER_RUNNER_ATTEMPT_KIND,
            Some((DREAMER_PROVENANCE_RUN_ID_KEY, PRECOMMIT_RUN_ID)),
        ))?,
        body.approval,
    );
    Ok((candidate, envelope))
}

fn attempt_dreamer_write_with_source(
    vault: &crate::Vault,
    claim_id: &EntityId,
    body: &ClaimBody,
    source: ClaimSource,
) -> Result<()> {
    let (candidate, envelope) = dreamer_write_parts_with_source(vault, body, source)?;
    vault
        .batch()
        .claim_candidate(claim_id, candidate, &envelope, test_time(3), 3)
        .commit()
}

/// The deny-first floor is not an allowlist: a degenerate Dreamer value is
/// refused under EVERY evidence meet, including the `ToolOutput`,
/// `Imported` and `Observed` meets a truthful promotion stamps.
#[test]
fn dreamer_precommit_denies_degenerate_output_under_every_evidence_meet() -> Result<()> {
    let (_tmp, vault) = precommit_vault()?;
    let evidence_ref = test_id(0x70);
    seed_precommit_evidence_entity(&vault, &evidence_ref)?;

    for (index, source) in ALL_CLAIM_SOURCES.into_iter().enumerate() {
        let seed = u8::try_from(index).expect("source index fits a byte");
        let claim_id = test_id(0x71 + seed);
        // Evidence resolves and the value is the only defect, so this
        // discriminates check 1 rather than the evidence floor.
        let mut body = precommit_body(
            Value::from("I will remember this next pass"),
            Some(precommit_evidence(vec![evidence_ref])),
        );
        body.approval = ClaimApprovalStatus::Proposed;
        let err = attempt_dreamer_write_with_source(&vault, &claim_id, &body, source)
            .expect_err("a degenerate Dreamer value is refused whatever its meet");
        assert_precommit_denied(
            &vault,
            err,
            &claim_id,
            "gate.deny.dreamer_precommit.degenerate_output",
        )?;
        assert!(
            vault.pending_gate_consents(10)?.is_empty(),
            "a {} meet must not mint an owner-review row behind the deny",
            claim_source_pin_label(source)
        );
    }
    Ok(())
}

/// The evidence floor holds for a non-`Generated` meet too: a well-formed
/// `ToolOutput` Dreamer value that cites nothing is still refused.
#[test]
fn dreamer_precommit_evidence_floor_holds_for_a_tool_output_meet() -> Result<()> {
    let (_tmp, vault) = precommit_vault()?;
    let claim_id = test_id(0x78);
    let mut body = precommit_body(Value::from("Ada Lovelace"), None);
    body.approval = ClaimApprovalStatus::Proposed;

    let err = attempt_dreamer_write_with_source(&vault, &claim_id, &body, ClaimSource::ToolOutput)
        .expect_err("a tool-output Dreamer claim must cite resolving evidence too");
    assert_precommit_denied(
        &vault,
        err,
        &claim_id,
        "gate.deny.dreamer_precommit.no_evidence",
    )
}

/// Detection widened; GROUPING did not.
///
/// A valid `ToolOutput` Dreamer candidate clears GATE-12 and pends on its own
/// (unrelated) source-trust posture. The pending row it mints carries
/// `dreamer_run_id == None`, because `pending_consent_dreamer_run_id` keeps
/// its `Proposed` + `Generated` pre-filter exactly as narrow as before.
#[test]
fn valid_tool_output_dreamer_write_pends_without_joining_a_run_group() -> Result<()> {
    let (_tmp, vault) = precommit_vault()?;
    let evidence_ref = test_id(0x79);
    seed_precommit_evidence_entity(&vault, &evidence_ref)?;

    let claim_id = test_id(0x7A);
    let mut body = precommit_body(
        Value::from("Ada Lovelace"),
        Some(precommit_evidence(vec![evidence_ref])),
    );
    body.approval = ClaimApprovalStatus::Proposed;
    // The source-trust posture is only reachable on a door that FEEDS the
    // meet to the evaluator: `claim_gate_input` drops `source` (and the
    // sensitivity band with it) for anything that is not `Auto` unless the
    // caller asked for `include_source_in_gate_input`. The public batch
    // `claim_candidate` door does not, so a `Proposed` candidate can never
    // pend on source trust there whatever the manifest says. This is the same
    // door the `Generated` source-trust pend is already pinned on by
    // `allowed_gate_consent_resolution_rejects_drifted_source_trust_pending`,
    // so the two meets differ on exactly one axis here too.
    let (candidate, envelope) =
        dreamer_write_parts_with_source(&vault, &body, ClaimSource::ToolOutput)?;
    vault.put_claim_candidate_without_lexical_query_reconcile(
        &claim_id,
        candidate,
        &envelope,
        test_time(3),
        3,
    )?;

    let stored = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(
        stored.source,
        Some(ClaimSource::ToolOutput),
        "the computed meet is stamped truthfully, never rewritten to pass"
    );

    let pending = vault.pending_gate_consents(10)?;
    assert_eq!(pending.len(), 1, "the write pends for owner review");
    let row = &pending[0];
    assert_eq!(row.claim_id, *claim_id.as_bytes());
    assert_eq!(
        row.dreamer_run_id, None,
        "run grouping stays Proposed + Generated only"
    );
    // The pend is the unrelated source-trust posture, and it is the ONLY
    // reason: no GATE-12 denial rides along on a valid candidate.
    assert_eq!(
        row.reason_codes,
        vec!["gate.pending.source_trust"],
        "a valid Dreamer candidate pends on source trust alone"
    );
    Ok(())
}
