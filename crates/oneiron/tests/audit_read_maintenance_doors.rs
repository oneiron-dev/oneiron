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
use oneiron::attempt_queue::AttemptId;
use oneiron::memory::MEMORY_CODE_NOT_FOUND;
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
