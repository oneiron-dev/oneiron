//! [AUDIT-READ-POWER] group 2, the owner record doors (RULING
//! AUDIT-READ-POWER-LIST = B, the lead 15 Nov 21:1x; Engine RULING
//! AUDITREAD-DOOR-LIST = A): six doors that read the owner's records for the
//! owner or a live audit_read holder, checked at each read.
//!
//! - `vault.authority.history.export` and `vault.sieve.receipts` answer their
//!   lists; the holder reads the owner's own answer.
//! - `vault.skills.receipts` answers a skill's hub sources and admission; an
//!   unknown skill reads as an empty answer, not as none.
//! - `vault.writes.critical_confirm.receipt`, `vault.hooks.regen.history` and
//!   `vault.skills.pack_receipt` answer one record by id; an id that names
//!   nothing reads as not-found once admitted, which is how these tests show
//!   admission without a large fixture.
//!
//! Every call goes through the generated verb dispatch
//! (`task_verb::sdk::invoke`), JSON in and out, as a transport calls it. A
//! holder is a PERSON bound to its own live credential, minted from the host
//! root's claims and verified as a transport verifies the slip a request
//! presents. Public paths only.
//!
//! `cargo test --locked -p oneiron --all-features --test audit_read_owner_record_doors`

use oneiron::EntityId;
use oneiron::memory::MEMORY_CODE_NOT_FOUND;
use serde_json::json;

mod audit_read_support;

use audit_read_support::*;

/// `vault.authority.history.export`: the signed history export reads for a live
/// audit_read holder too, and for no one else.
#[test]
fn the_authority_history_export_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);

    let owned = call(
        &owner(&fixture),
        "vault.authority.history.export",
        json!({}),
    );
    assert!(
        owned["entries"].is_array(),
        "the owner reads an export: {owned}"
    );
    assert_forbidden(
        &refused(&as_holder, "vault.authority.history.export", json!({})),
        "the export before any grant",
    );

    grant(&fixture, holder, None);
    let read = call(&as_holder, "vault.authority.history.export", json!({}));
    assert_eq!(read, owned, "the holder reads the owner's export: {read}");
    assert_forbidden(
        &refused(&as_stranger, "vault.authority.history.export", json!({})),
        "the export for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.authority.history.export", json!({})),
        "the export at the next read after the revoke",
    );
    Ok(())
}

/// `vault.writes.critical_confirm.receipt`: a confirmation receipt reads for a
/// live audit_read holder too; an id that names nothing reads as not-found
/// once admitted, and as forbidden before the grant and after the revoke.
#[test]
fn the_critical_confirm_receipt_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let missing = json!({ "confirm_id": "00".repeat(32) });

    assert_eq!(
        refused(
            &owner(&fixture),
            "vault.writes.critical_confirm.receipt",
            missing.clone()
        )
        .code,
        MEMORY_CODE_NOT_FOUND,
        "the id names nothing"
    );
    assert_forbidden(
        &refused(
            &as_holder,
            "vault.writes.critical_confirm.receipt",
            missing.clone(),
        ),
        "the receipt before any grant",
    );

    grant(&fixture, holder, None);
    assert_eq!(
        refused(
            &as_holder,
            "vault.writes.critical_confirm.receipt",
            missing.clone()
        )
        .code,
        MEMORY_CODE_NOT_FOUND,
        "the holder is admitted past the gate and finds none"
    );
    assert_forbidden(
        &refused(
            &as_stranger,
            "vault.writes.critical_confirm.receipt",
            missing.clone(),
        ),
        "the receipt for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.writes.critical_confirm.receipt", missing),
        "the receipt at the next read after the revoke",
    );
    Ok(())
}

/// `vault.hooks.regen.history`: a binding's regen history reads for a live
/// audit_read holder too; an id that names nothing reads as not-found once
/// admitted, and as forbidden before the grant and after the revoke.
#[test]
fn the_hook_regen_history_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let missing = json!({ "binding": EntityId::now().to_hex() });

    assert_eq!(
        refused(
            &owner(&fixture),
            "vault.hooks.regen.history",
            missing.clone()
        )
        .code,
        MEMORY_CODE_NOT_FOUND,
        "the id names nothing"
    );
    assert_forbidden(
        &refused(&as_holder, "vault.hooks.regen.history", missing.clone()),
        "the history before any grant",
    );

    grant(&fixture, holder, None);
    assert_eq!(
        refused(&as_holder, "vault.hooks.regen.history", missing.clone()).code,
        MEMORY_CODE_NOT_FOUND,
        "the holder is admitted past the gate and finds none"
    );
    assert_forbidden(
        &refused(&as_stranger, "vault.hooks.regen.history", missing.clone()),
        "the history for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.hooks.regen.history", missing),
        "the history at the next read after the revoke",
    );
    Ok(())
}

/// `vault.sieve.receipts`: the consumed-span receipts read for a live
/// audit_read holder too, and for no one else.
#[test]
fn the_sieve_receipts_read_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);

    let owned = call(&owner(&fixture), "vault.sieve.receipts", json!({}));
    assert!(
        owned["receipts"].is_array(),
        "the owner reads receipts: {owned}"
    );
    assert_forbidden(
        &refused(&as_holder, "vault.sieve.receipts", json!({})),
        "the receipts before any grant",
    );

    grant(&fixture, holder, None);
    let read = call(&as_holder, "vault.sieve.receipts", json!({}));
    assert_eq!(read, owned, "the holder reads the owner's receipts: {read}");
    assert_forbidden(
        &refused(&as_stranger, "vault.sieve.receipts", json!({})),
        "the receipts for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.sieve.receipts", json!({})),
        "the receipts at the next read after the revoke",
    );
    Ok(())
}

/// `vault.skills.pack_receipt`: a pack receipt reads for a live audit_read
/// holder too; an id that names nothing reads as not-found once admitted, and
/// as forbidden before the grant and after the revoke.
#[test]
fn the_skill_pack_receipt_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let missing = json!({ "attempt_receipt": format!("attempt:{}", "00".repeat(32)) });

    assert_eq!(
        refused(
            &owner(&fixture),
            "vault.skills.pack_receipt",
            missing.clone()
        )
        .code,
        MEMORY_CODE_NOT_FOUND,
        "the id names nothing"
    );
    assert_forbidden(
        &refused(&as_holder, "vault.skills.pack_receipt", missing.clone()),
        "the receipt before any grant",
    );

    grant(&fixture, holder, None);
    assert_eq!(
        refused(&as_holder, "vault.skills.pack_receipt", missing.clone()).code,
        MEMORY_CODE_NOT_FOUND,
        "the holder is admitted past the gate and finds none"
    );
    assert_forbidden(
        &refused(&as_stranger, "vault.skills.pack_receipt", missing.clone()),
        "the receipt for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.skills.pack_receipt", missing),
        "the receipt at the next read after the revoke",
    );
    Ok(())
}

/// `vault.skills.receipts`: a skill's hub receipts read for a live audit_read
/// holder too, and for no one else.
#[test]
fn the_hub_skill_receipts_read_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let input = json!({ "entity": EntityId::now().to_hex() });

    let owned = call(&owner(&fixture), "vault.skills.receipts", input.clone());
    assert!(
        owned["sources"].is_array(),
        "the owner reads receipts: {owned}"
    );
    assert_forbidden(
        &refused(&as_holder, "vault.skills.receipts", input.clone()),
        "the receipts before any grant",
    );

    grant(&fixture, holder, None);
    let read = call(&as_holder, "vault.skills.receipts", input.clone());
    assert_eq!(read, owned, "the holder reads the owner's receipts: {read}");
    assert_forbidden(
        &refused(&as_stranger, "vault.skills.receipts", input.clone()),
        "the receipts for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.skills.receipts", input),
        "the receipts at the next read after the revoke",
    );
    Ok(())
}
