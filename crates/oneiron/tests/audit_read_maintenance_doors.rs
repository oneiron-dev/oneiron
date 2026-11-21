//! [AUDIT-READ-POWER] maintenance and work doors (RULING AUDIT-READ-POWER-LIST
//! = B; Engine RULING AUDITREAD-DOOR-LIST = A): PR 2 group 3 covers
//! `vault.seal.receipt`, `vault.code.secrets.purge.get`,
//! `vault.code.checks.get`, `vault.owner_work.get` and
//! `vault.secrets.lift_history` (`vault.usage.repair.receipts` is server-side,
//! in `oneiron-server/tests/audit_read_host_door.rs`).
//!
//! Each door reads for the owner or a live audit_read holder, checked in its
//! own read, so a revoke refuses at the next read. A holder gets only the
//! read part: the lift sweep's close and start stay the owner's.
//!
//! Every call goes through the generated verb dispatch
//! (`task_verb::sdk::invoke`), JSON in and out, as a transport calls it. A
//! holder is a PERSON bound to its own live credential, minted from the host
//! root's claims and verified as a transport verifies the slip a request
//! presents. Public paths only.
//!
//! `cargo test --locked -p oneiron --all-features --test audit_read_maintenance_doors`

use oneiron::EntityId;
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptResultRef, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    EnqueueAttempt, EnqueueOutcome, SetAttemptResult,
};
use oneiron::learning::TypeRef;
use oneiron::memory::MEMORY_CODE_NOT_FOUND;
use oneiron::self_heal::audit::doors::confess_as_owner;
use oneiron::self_heal::audit::{AttemptConfession, ObjectiveConfession};
use oneiron::store::GateDecisionId;
use serde_json::{Value, json};

mod audit_read_support;

use audit_read_support::*;

fn assert_not_found(error: &oneiron::memory::MemoryError, what: &str) {
    assert_eq!(
        error.code, MEMORY_CODE_NOT_FOUND,
        "{what} reads as not found: {error:?}"
    );
}

/// `vault.seal.receipt`: the stored receipt reads for a live audit_read
/// holder too, and for no one else. Not-found shape: an attempt that names
/// nothing reads as none after the grant.
#[test]
fn the_seal_receipt_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let missing = json!({ "attempt": AttemptId::now() });

    assert_forbidden(
        &refused(&as_holder, "vault.seal.receipt", missing.clone()),
        "the seal receipt before any grant",
    );

    grant(&fixture, holder, None);
    assert_eq!(
        call(&as_holder, "vault.seal.receipt", missing.clone()),
        Value::Null,
        "the holder is admitted and reads none for an attempt that names nothing"
    );
    assert_forbidden(
        &refused(&as_stranger, "vault.seal.receipt", missing.clone()),
        "the seal receipt for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.seal.receipt", missing),
        "the seal receipt at the next read after the revoke",
    );
    Ok(())
}

/// `vault.code.secrets.purge.get`: a purge plan reads for a live audit_read
/// holder whatever its owner, and for no one else. Not-found shape: a plan
/// that names nothing reads as not found after the grant.
#[test]
fn the_secret_purge_plan_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let missing = json!({ "plan": EntityId::now().to_hex() });

    assert_forbidden(
        &refused(&as_holder, "vault.code.secrets.purge.get", missing.clone()),
        "the purge plan before any grant",
    );

    grant(&fixture, holder, None);
    assert_not_found(
        &refused(&as_holder, "vault.code.secrets.purge.get", missing.clone()),
        "the holder is admitted and a plan that names nothing",
    );
    assert_forbidden(
        &refused(
            &as_stranger,
            "vault.code.secrets.purge.get",
            missing.clone(),
        ),
        "the purge plan for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.code.secrets.purge.get", missing),
        "the purge plan at the next read after the revoke",
    );
    Ok(())
}

/// `vault.code.checks.get`: retained checker receipts read for a live
/// audit_read holder too, and for no one else. Not-found shape: a repo that
/// names nothing reads as not found after the grant.
#[test]
fn the_code_check_receipts_read_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let missing = json!({
        "repo": EntityId::now().to_hex(),
        "work_ref": "cd".repeat(32),
        "receipt_ref": format!("queue-check:v1:{}", "ab".repeat(32)),
    });

    assert_forbidden(
        &refused(&as_holder, "vault.code.checks.get", missing.clone()),
        "the check receipts before any grant",
    );

    grant(&fixture, holder, None);
    assert_not_found(
        &refused(&as_holder, "vault.code.checks.get", missing.clone()),
        "the holder is admitted and a repo that names nothing",
    );
    assert_forbidden(
        &refused(&as_stranger, "vault.code.checks.get", missing.clone()),
        "the check receipts for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.code.checks.get", missing),
        "the check receipts at the next read after the revoke",
    );
    Ok(())
}

/// `vault.owner_work.get`: where an owner work request stands reads for a
/// live audit_read holder too, and for no one else. Not-found shape: an
/// entry that names nothing reads as not found after the grant.
#[test]
fn the_owner_work_receipt_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let missing = json!({ "request": "ab".repeat(32) });

    assert_forbidden(
        &refused(&as_holder, "vault.owner_work.get", missing.clone()),
        "the owner work receipt before any grant",
    );

    grant(&fixture, holder, None);
    assert_not_found(
        &refused(&as_holder, "vault.owner_work.get", missing.clone()),
        "the holder is admitted and an entry that names nothing",
    );
    assert_forbidden(
        &refused(&as_stranger, "vault.owner_work.get", missing.clone()),
        "the owner work receipt for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.owner_work.get", missing),
        "the owner work receipt at the next read after the revoke",
    );
    Ok(())
}

/// `vault.secrets.lift_history`: the sweep's state reads for a live
/// audit_read holder too, and for no one else. Record shape: the status
/// always answers. Close and start stay the owner's: a holder asking for
/// either is refused.
#[test]
fn the_lift_history_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);

    assert_forbidden(
        &refused(&as_holder, "vault.secrets.lift_history", json!({})),
        "the lift history before any grant",
    );

    grant(&fixture, holder, None);
    let status = call(&as_holder, "vault.secrets.lift_history", json!({}));
    assert!(
        status.get("open_proposals").is_some(),
        "the holder reads the sweep's state: {status}"
    );
    assert_forbidden(
        &refused(&as_stranger, "vault.secrets.lift_history", json!({})),
        "the lift history for a person without the power",
    );
    assert_forbidden(
        &refused(
            &as_holder,
            "vault.secrets.lift_history",
            json!({ "start": true }),
        ),
        "a holder's start stays the owner's",
    );
    assert_forbidden(
        &refused(
            &as_holder,
            "vault.secrets.lift_history",
            json!({ "close": { "proposal": "ab".repeat(16), "reason": "rotated" } }),
        ),
        "a holder's close stays the owner's",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.secrets.lift_history", json!({})),
        "the lift history at the next read after the revoke",
    );
    Ok(())
}

/// `vault.seal.receipt`: a sourced receipt is withheld whole from a live
/// audit_read holder whose own lane misses a source row. The sealed attempt's
/// confession names the owner's private diary NOTE, which no holder reads,
/// while its result NOTE stays vault-readable; the owner reads the receipt,
/// and the granted holder reads none.
#[test]
fn the_seal_receipt_is_withheld_from_a_holder_whose_lane_misses_a_source_row() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let as_owner = owner(&fixture);

    let subject = as_owner
        .create_note(
            "diary",
            "The owner's private seal subject, no holder reads.",
        )
        .expect("the owner's private diary NOTE");
    let subject = EntityId::from_hex(&subject.id_hex).expect("the private subject's id");
    let result = as_owner
        .create_note(
            "research",
            "The sealed attempt's durable result, readable to every lane.",
        )
        .expect("the vault-readable result NOTE");

    let queue = AttemptQueue::new(&fixture.vault);
    let now = fixture.vault.now_recorded_at();
    let EnqueueOutcome::Enqueued(_) = queue
        .enqueue(EnqueueAttempt {
            kind: "test.seal_receipt".to_owned(),
            payload: b"seal-receipt-red-test".to_vec(),
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("enqueue the seal attempt")
    else {
        panic!("a fresh seal attempt enqueues");
    };
    let ClaimOutcome::Claimed(leased) = queue
        .claim_kind(
            "test.seal_receipt",
            ClaimAttempt {
                lease_owner: "seal-receipt-red-test".to_owned(),
                now: u64::MAX,
            },
        )
        .expect("claim the seal attempt")
    else {
        panic!("the seal attempt claims");
    };
    queue
        .set_executor_model(
            leased.id,
            "seal-receipt-red-test",
            leased.attempt_count,
            "fixture/seal-model@rev-a",
        )
        .expect("stamp the seal attempt's executor");
    queue
        .set_result(SetAttemptResult {
            id: leased.id,
            lease_owner: "seal-receipt-red-test".to_owned(),
            attempt_count: leased.attempt_count,
            result_ref: AttemptResultRef::new(result.id_hex.clone()).expect("the result reference"),
            now: leased.updated_at,
        })
        .expect("attach the seal attempt's result");
    queue
        .complete(CompleteAttempt {
            id: leased.id,
            lease_owner: "seal-receipt-red-test".to_owned(),
            attempt_count: leased.attempt_count,
            now: leased.updated_at,
        })
        .expect("complete the seal attempt");

    let proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the owner's proof");
    confess_as_owner(
        &fixture.vault,
        &proof,
        &AttemptConfession {
            attempt: leased.id,
            subject,
            type_ref: TypeRef::root(1),
            objectives: vec![ObjectiveConfession {
                objective: "summarize the week's notes".to_owned(),
                met: Some(true),
                flaw: None,
                uncertainty: None,
            }],
        },
    )
    .expect("the owner seals the attempt");

    let input = json!({ "attempt": leased.id });
    let owned = call(&as_owner, "vault.seal.receipt", input.clone());
    assert!(
        owned["receipt"].is_object(),
        "the owner reads the receipt: {owned}"
    );
    assert_forbidden(
        &refused(&as_holder, "vault.seal.receipt", input.clone()),
        "the seal receipt before any grant",
    );

    grant(&fixture, holder, None);
    assert_eq!(
        call(&as_holder, "vault.seal.receipt", input.clone()),
        Value::Null,
        "the holder reads none for a receipt its lane cannot read"
    );
    assert_forbidden(
        &refused(&as_stranger, "vault.seal.receipt", input.clone()),
        "the seal receipt for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.seal.receipt", input),
        "the seal receipt at the next read after the revoke",
    );
    Ok(())
}
