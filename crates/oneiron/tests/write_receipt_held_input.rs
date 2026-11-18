//! FIX RECEIPT-RECORDS-CALL-HELD-INPUT (follow-up of FIX
//! REPLAY-COMPARE-KNOWN-OTHER-CALLERS): a verb write's receipt row is stored
//! through the side-row wall, which places a shaped secret, and a value base
//! custody holds (a passphrase no shape rule places), as a handle in the
//! input text the row keeps. A resumed step makes the write again with the
//! same input and compares it with that row twice
//! (`code_run/dispatcher/agent_verb/receipts.rs`): when the write is answered
//! from its receipt (`records_call`) and when the step closes (`meets`).
//! Before, both compares read the identity of the input as the row keeps it,
//! the handle in place of the value, so the identical write failed with "a
//! resumed step changed a write it already made" and the step never closed.
//! Now each compare reads the offered input in the form the wall planned the
//! row, first without and then with the values base custody holds, as the
//! replay compare does (`admitted_from_known`), and still reads an input's
//! object keys in any order. With those values, each reads as its record's
//! handle on both sides, so a passphrase another custody record holds still
//! changed the write (FIX REPLAY-COMPARE-KNOWN-OTHER-CALLERS).
//!
//! Red on the base (#9500's head 1507c44a73d): the three held-value tests
//! fail at their meet asserts, after their FIXTURE asserts; the two guards
//! and the other-held-passphrase test pass. That test fails where the known
//! arm read every value custody holds as one stand-in (this PR's tip before
//! its last fix), and the others pass there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test write_receipt_held_input`.
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::sync::Arc;

use oneiron::code_run::SelfAgentVerbCall;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::test_doors::code_run_write_identity::{
    StoredReceiptMeet, resumed_write_meets_its_stored_receipt,
};
use oneiron::{Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret. Custody holds the first.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const UNHELD_PASSPHRASE: &str = "summer harbour pencil compass";
/// A passphrase a second custody record holds.
const OTHER_HELD_PASSPHRASE: &str = "autumn meadow candle ribbon";

/// A token a shape rule places, whether custody holds it or not.
const SHAPED_TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

fn vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    vault.register_test_secret(
        "orchard passphrase",
        HELD_PASSPHRASE.as_bytes(),
        Vec::new(),
        1,
    )?;
    vault.register_test_secret(
        "meadow passphrase",
        OTHER_HELD_PASSPHRASE.as_bytes(),
        Vec::new(),
        1,
    )?;
    Ok((directory, vault))
}

fn task_create(input: serde_json::Value) -> SelfAgentVerbCall {
    SelfAgentVerbCall {
        verb: AgentVerb::TasksCreate,
        input,
    }
}

/// A task whose description holds `value`, its fields in one order.
fn task_holding(value: &str) -> SelfAgentVerbCall {
    task_create(json!({
        "title": "unlock the archive",
        "description": format!("the archive opens with {value}"),
    }))
}

/// The same task, its fields in the other order.
fn task_holding_reordered(value: &str) -> SelfAgentVerbCall {
    task_create(json!({
        "description": format!("the archive opens with {value}"),
        "title": "unlock the archive",
    }))
}

fn assert_meets(meet: &StoredReceiptMeet) {
    assert!(
        meet.write_meets,
        "the resumed write meets its receipt when it is answered from it: {meet:?}"
    );
    assert!(
        meet.close_meets,
        "the resumed write meets its receipt when its step closes: {meet:?}"
    );
}

#[test]
fn a_resumed_write_holding_a_passphrase_custody_holds_meets_its_receipt() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = task_holding(HELD_PASSPHRASE);

    let meet = resumed_write_meets_its_stored_receipt(&vault, &call, &call)?;

    assert!(
        !meet.kept_input.contains(HELD_PASSPHRASE),
        "FIXTURE: the wall placed the held passphrase as a handle in the receipt: {meet:?}"
    );
    assert_meets(&meet);
    Ok(())
}

#[test]
fn a_resumed_write_holding_a_shaped_token_meets_its_receipt() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = task_holding(SHAPED_TOKEN);

    let meet = resumed_write_meets_its_stored_receipt(&vault, &call, &call)?;

    assert!(
        !meet.kept_input.contains(SHAPED_TOKEN),
        "FIXTURE: the wall placed the shaped token as a handle in the receipt: {meet:?}"
    );
    assert_meets(&meet);
    Ok(())
}

/// A write receipt reads its input's object keys in any order (the custody
/// value rows' `input_identity` says so too), so the planned compare reads
/// the inputs as JSON, never as the text each was written in.
#[test]
fn a_resumed_write_holding_a_held_passphrase_with_its_keys_reordered_meets_its_receipt()
-> TestResult {
    let (_directory, vault) = vault()?;
    let first = task_holding(HELD_PASSPHRASE);
    let again = task_holding_reordered(HELD_PASSPHRASE);
    assert_ne!(
        first.input.to_string(),
        again.input.to_string(),
        "FIXTURE: the two inputs are written in different key orders"
    );

    let meet = resumed_write_meets_its_stored_receipt(&vault, &first, &again)?;

    assert!(
        !meet.kept_input.contains(HELD_PASSPHRASE),
        "FIXTURE: the wall placed the held passphrase as a handle in the receipt: {meet:?}"
    );
    assert_meets(&meet);
    Ok(())
}

/// Guard: a passphrase no custody record holds stays as written in the
/// receipt, and the resumed write meets it on the base and the head.
#[test]
fn a_resumed_write_holding_a_passphrase_no_custody_holds_meets_its_receipt() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = task_holding(UNHELD_PASSPHRASE);

    let meet = resumed_write_meets_its_stored_receipt(&vault, &call, &call)?;

    assert!(
        meet.kept_input.contains(UNHELD_PASSPHRASE),
        "FIXTURE: the receipt keeps a passphrase no custody holds as written: {meet:?}"
    );
    assert_meets(&meet);
    Ok(())
}

/// Guard: a resumed write that holds another value where its receipt held
/// the custody-held passphrase changed the write, and both compares refuse
/// it, on the base and the head.
#[test]
fn a_resumed_write_holding_another_passphrase_does_not_meet_its_receipt() -> TestResult {
    let (_directory, vault) = vault()?;

    let meet = resumed_write_meets_its_stored_receipt(
        &vault,
        &task_holding(HELD_PASSPHRASE),
        &task_holding(UNHELD_PASSPHRASE),
    )?;

    assert!(
        !meet.write_meets,
        "a changed write is refused when it is answered from its receipt: {meet:?}"
    );
    assert!(
        !meet.close_meets,
        "a changed write is refused when its step closes: {meet:?}"
    );
    Ok(())
}

/// A resumed write that holds a passphrase another custody record holds,
/// where its receipt held the first one's handle, changed the write: both
/// compares refuse it, as for a passphrase no custody holds, and never read
/// the two records' values as one.
#[test]
fn a_resumed_write_holding_another_held_passphrase_does_not_meet_its_receipt() -> TestResult {
    let (_directory, vault) = vault()?;

    let meet = resumed_write_meets_its_stored_receipt(
        &vault,
        &task_holding(HELD_PASSPHRASE),
        &task_holding(OTHER_HELD_PASSPHRASE),
    )?;

    assert!(
        !meet.kept_input.contains(HELD_PASSPHRASE),
        "FIXTURE: the wall placed the held passphrase as a handle in the receipt: {meet:?}"
    );
    assert!(
        !meet.write_meets,
        "a write with another held passphrase is refused when it is answered from its receipt: \
         {meet:?}"
    );
    assert!(
        !meet.close_meets,
        "a write with another held passphrase is refused when its step closes: {meet:?}"
    );
    Ok(())
}
