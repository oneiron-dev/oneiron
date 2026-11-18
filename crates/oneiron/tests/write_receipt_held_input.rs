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
//! row, with the values base custody holds, and still reads an input's
//! object keys in any order. With those values, each reads as its record's
//! handle on both sides, so a passphrase another custody record holds still
//! changed the write (FIX REPLAY-COMPARE-KNOWN-OTHER-CALLERS), and so does
//! another token of the shape the wall minted a record for. The receipt is
//! read for those values alone, never for a shape (a key the wall kept as
//! written with its switch off stays so) and never inside a handle it holds.
//! Only a custody that knows no value reads every handle and shaped token as
//! the plan's one stand-in, as the replay compare does (`admitted_from_known`).
//!
//! Red on the base (#9500's head 1507c44a73d): the three held-value tests
//! fail at their meet asserts, after their FIXTURE asserts; the two guards,
//! the other-held-passphrase test and the other-shaped-token test pass. The
//! other-held-passphrase test fails where the known arm read every value
//! custody holds as one stand-in (8ed4fa51188). The other-shaped-token test
//! fails where each compare read the plan's one stand-in before custody's
//! values (9f76b08b8b9 with that test), and the others pass there. The
//! word-of-its-handle and other-shaped-key tests fail where the receipt was
//! planned as an offer is, shapes and handles read too (the merge of #9500's
//! 3e6f08a37c0 with those tests).
//!
//! Blind review round 1 of #9503: each compare now reads the verb names
//! first and plans the input texts alone, for the values of the records the
//! receipt's handles name alone, with no stand-in. The word-input,
//! unnamed-handle (both vaults) and longer-value tests are red at the merge
//! of #9500's 3ca83fe3f29 (0abff894971); the offered-handle test is red at
//! dd8a176dcd6 and green from that merge on.
//!
//! Blind review round 2 of #9503: a held receipt is read as a template.
//! Each handle it holds that names a record custody knows meets the same
//! handle, or one value of that record at any generation whose length lets
//! the text after it match as written; every other byte meets only itself,
//! and nothing is masked again. The wall reads text spelled as a handle
//! that names no record like any other text. The rotated-value test, the
//! longer-generation test and the handle-spelled passphrase test are red at
//! e8dcab0e9fd; the rotation guard is green there and here.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test write_receipt_held_input`.
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use std::sync::Arc;

use oneiron::code_run::SelfAgentVerbCall;
use oneiron::policy_model::SecretScanMode;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::test_doors::code_run_write_identity::{
    StoredReceiptMeet, resumed_write_meets_its_stored_receipt,
    resumed_write_meets_its_stored_receipt_after,
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
/// Another token of the same shape.
const OTHER_SHAPED_TOKEN: &str = "ghp_zyxwvutsrqponmlkjihgfedcba9876543210";
/// Two keys of one shape, which the wall keeps as written with its switch off.
const SHAPED_KEY: &str = "AKIA1234567890123456";
const OTHER_SHAPED_KEY: &str = "AKIA1234567890123457";
/// Texts that spell handles no custody record names, written as words.
const UNNAMED_HANDLE: &str = "[secret sc908070]";
const OTHER_UNNAMED_HANDLE: &str = "[secret sc908071]";
/// Values custody takes in the review's cases, no shape rule placing any.
const RIVER: &str = "river meadow";
const ORCHARD: &str = "amber orchard";
const ORCHARD_TODAY: &str = "amber orchard today";
/// The value the review's rotation takes.
const BLUE_HARBOR: &str = "blue harbor";
/// A passphrase spelled as a handle no custody record has.
const HANDLE_SPELLED_PASSPHRASE: &str = "[secret sc99999999999999999999]";

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

/// A vault whose custody holds no value the tests register.
fn bare_vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    Ok((directory, vault))
}

/// The owner rotates the custody record named `name` to `value`.
fn rotate(vault: &Vault, name: &str, value: &str) -> oneiron::Result<()> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|_| oneiron::Error::InvariantViolation("embedded owner"))?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault
        .rotate_secret_as_owner(&owner, name, value.as_bytes(), 5)
        .map(drop)
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

fn assert_refused(meet: &StoredReceiptMeet) {
    assert!(
        !meet.write_meets,
        "a changed write is refused when it is answered from its receipt: {meet:?}"
    );
    assert!(
        !meet.close_meets,
        "a changed write is refused when its step closes: {meet:?}"
    );
}

/// The first handle `text` holds, `[secret sc12]`.
fn first_handle(text: &str) -> Option<&str> {
    let open = text.find("[secret ")?;
    let close = open + text[open..].find(']')?;
    Some(&text[open..=close])
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

/// A resumed write that holds another token of the same shape, where its
/// receipt held the handle of the record the wall minted for the first
/// token, changed the write: both compares refuse it. Reading every handle
/// and every shaped token as the plan's one stand-in reads the two tokens
/// as one, so custody decides once it knows a value: the minted record
/// holds only the first token.
#[test]
fn a_resumed_write_holding_another_shaped_token_does_not_meet_its_receipt() -> TestResult {
    let (_directory, vault) = vault()?;

    let meet = resumed_write_meets_its_stored_receipt(
        &vault,
        &task_holding(SHAPED_TOKEN),
        &task_holding(OTHER_SHAPED_TOKEN),
    )?;

    assert!(
        !meet.kept_input.contains(SHAPED_TOKEN),
        "FIXTURE: the wall placed the shaped token as a handle in the receipt: {meet:?}"
    );
    assert!(
        !meet.write_meets,
        "a write with another shaped token is refused when it is answered from its receipt: \
         {meet:?}"
    );
    assert!(
        !meet.close_meets,
        "a write with another shaped token is refused when its step closes: {meet:?}"
    );
    Ok(())
}

/// Custody holds a value, `secret`, that spells part of the handle the wall
/// placed in the receipt (`[secret sc12]`). The handle names its record and
/// holds no value, so the receipt is never read inside it, and the identical
/// write meets it.
#[test]
fn a_resumed_write_meets_its_receipt_while_custody_holds_a_word_of_its_handle() -> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret("handle word", b"secret", Vec::new(), 1)?;
    let call = task_holding(HELD_PASSPHRASE);

    let meet = resumed_write_meets_its_stored_receipt(&vault, &call, &call)?;

    assert!(
        !meet.kept_input.contains(HELD_PASSPHRASE),
        "FIXTURE: the wall placed the held passphrase as a handle in the receipt: {meet:?}"
    );
    assert_meets(&meet);
    Ok(())
}

/// With the owner's switch off the wall seeks no shape (FIX 8644), so the
/// receipt keeps a key a shape rule reads as written. A resumed write with
/// another key of that shape changed the write: the receipt is read for the
/// values custody holds alone, never for a shape, so both compares refuse
/// it and never read the two keys as one stand-in.
#[test]
fn a_resumed_write_holding_another_shaped_key_kept_as_written_does_not_meet_its_receipt()
-> TestResult {
    let (_directory, vault) = vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.set_secret_scan_mode(&owner, SecretScanMode::Off, 1)?;

    let meet = resumed_write_meets_its_stored_receipt(
        &vault,
        &task_holding(SHAPED_KEY),
        &task_holding(OTHER_SHAPED_KEY),
    )?;

    assert!(
        meet.kept_input.contains(SHAPED_KEY),
        "FIXTURE: with the switch off the receipt keeps the key as written: {meet:?}"
    );
    assert!(
        !meet.write_meets,
        "a write with another key is refused when it is answered from its receipt: {meet:?}"
    );
    assert!(
        !meet.close_meets,
        "a write with another key is refused when its step closes: {meet:?}"
    );
    Ok(())
}

/// Custody takes the word `input` after the receipt is stored. Each compare
/// reads the verb names and the input texts out of the two requests first,
/// and plans the input texts alone, so the request's own `input` key is
/// never read as a value and the identical write meets its receipt. Red at
/// the merge of #9500's 3ca83fe3f29 (0abff894971): both plans placed a
/// handle on the MessagePack key `input`, no input was found, and both
/// compares refused the identical write.
#[test]
fn a_resumed_write_meets_its_receipt_after_custody_takes_the_word_input() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = task_holding(HELD_PASSPHRASE);

    let meet = resumed_write_meets_its_stored_receipt_after(&vault, &call, &call, |vault| {
        vault
            .register_test_secret("input word", b"input", Vec::new(), 3)
            .map(drop)
    })?;

    assert!(
        !meet.kept_input.contains(HELD_PASSPHRASE),
        "FIXTURE: the wall placed the held passphrase as a handle in the receipt: {meet:?}"
    );
    assert_meets(&meet);
    Ok(())
}

/// A write whose input spells a handle no custody record names keeps that
/// text as written, and a resumed write that spells another such handle
/// changed the write. A handle no record custody knows names reads only as
/// written, never as the plan's one stand-in, so both compares refuse it.
/// Red at 0abff894971: both read as the stand-in and the changed write met.
#[test]
fn a_resumed_write_holding_another_unnamed_handle_does_not_meet_its_receipt() -> TestResult {
    let (_directory, vault) = vault()?;

    let meet = resumed_write_meets_its_stored_receipt(
        &vault,
        &task_holding(UNNAMED_HANDLE),
        &task_holding(OTHER_UNNAMED_HANDLE),
    )?;

    assert!(
        meet.kept_input.contains(UNNAMED_HANDLE),
        "FIXTURE: the receipt keeps the handle text as written: {meet:?}"
    );
    assert_refused(&meet);
    Ok(())
}

/// `a_resumed_write_holding_another_unnamed_handle_does_not_meet_its_receipt`
/// where custody holds no value the test registers: a custody that knows
/// none leaves the two inputs to meet as written. Red at 0abff894971, which
/// read both handles as the stand-in there.
#[test]
fn a_resumed_write_holding_another_unnamed_handle_does_not_meet_its_receipt_in_a_bare_vault()
-> TestResult {
    let (_directory, vault) = bare_vault()?;

    let meet = resumed_write_meets_its_stored_receipt(
        &vault,
        &task_holding(UNNAMED_HANDLE),
        &task_holding(OTHER_UNNAMED_HANDLE),
    )?;

    assert_refused(&meet);
    Ok(())
}

/// Custody holds `amber orchard`, so the receipt of a write holding `amber
/// orchard today` keeps `[secret scN] today`. Custody then takes `amber
/// orchard today` as another record. The compare reads the inputs for the
/// values of the records the receipt names alone, so the longer value
/// never hides the one its handle names, and the identical write meets its
/// receipt. Red at 0abff894971: the offer took the longer value's handle
/// and both compares refused the identical write.
#[test]
fn a_resumed_write_meets_its_receipt_after_custody_takes_a_longer_value_over_its_handle()
-> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret("orchard", ORCHARD.as_bytes(), Vec::new(), 1)?;
    let call = task_holding(ORCHARD_TODAY);

    let meet = resumed_write_meets_its_stored_receipt_after(&vault, &call, &call, |vault| {
        vault
            .register_test_secret("orchard today", ORCHARD_TODAY.as_bytes(), Vec::new(), 3)
            .map(drop)
    })?;

    assert!(
        !meet.kept_input.contains(ORCHARD) && meet.kept_input.contains("] today"),
        "FIXTURE: the receipt keeps the shorter value's handle before ` today`: {meet:?}"
    );
    assert_meets(&meet);
    Ok(())
}

/// Custody holds `river meadow`, `amber orchard` and `secret`, so the
/// receipt of a write holding `river meadow / amber orchard` keeps two
/// handles. A resumed write that offers the first handle as written, and
/// the second value, is the same write: a handle names its record, and no
/// compare reads a value inside a handle, on either side. Red at dd8a176dcd6
/// (the offer read `secret` inside the handle); green from 0abff894971 on,
/// whose merge of #9500 reads no handle for a value in any pass.
#[test]
fn a_resumed_write_offering_the_handle_its_receipt_holds_meets_its_receipt() -> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret("river", RIVER.as_bytes(), Vec::new(), 1)?;
    vault.register_test_secret("orchard", ORCHARD.as_bytes(), Vec::new(), 1)?;
    vault.register_test_secret("handle word", b"secret", Vec::new(), 1)?;
    let call = task_holding(&format!("{RIVER} / {ORCHARD}"));

    let kept = resumed_write_meets_its_stored_receipt(&vault, &call, &call)?;
    assert_meets(&kept);
    let river_handle = first_handle(&kept.kept_input)
        .ok_or_else(|| format!("FIXTURE: the receipt holds a handle: {kept:?}"))?;
    let again = task_holding(&format!("{river_handle} / {ORCHARD}"));

    let meet = resumed_write_meets_its_stored_receipt(&vault, &call, &again)?;

    assert_meets(&meet);
    Ok(())
}

/// Custody holds `river meadow`, so the receipt of a write holding `river
/// meadow / blue harbor` keeps `[secret scN] / blue harbor`. The owner then
/// rotates that record to `blue harbor`. A resumed write holding `river
/// meadow / river meadow` changed the write: the receipt's text after its
/// handle meets only itself, never the rotated value, so both compares
/// refuse it. Red at e8dcab0e9fd, which read the receipt for the record's
/// values too, so both sides read `[secret scN] / [secret scN]` and met.
#[test]
fn a_resumed_write_changed_into_its_record_s_rotated_value_does_not_meet_its_receipt() -> TestResult
{
    let (_directory, vault) = vault()?;
    vault.register_test_secret("river", RIVER.as_bytes(), Vec::new(), 1)?;
    let first = task_holding(&format!("{RIVER} / {BLUE_HARBOR}"));
    let again = task_holding(&format!("{RIVER} / {RIVER}"));

    let meet = resumed_write_meets_its_stored_receipt_after(&vault, &first, &again, |vault| {
        rotate(vault, "river", BLUE_HARBOR)
    })?;

    assert!(
        !meet.kept_input.contains(RIVER) && meet.kept_input.contains(&format!("] / {BLUE_HARBOR}")),
        "FIXTURE: the receipt keeps the handle, then `blue harbor` as written: {meet:?}"
    );
    assert_refused(&meet);
    Ok(())
}

/// Guard for the test above: after the same rotation, the identical write
/// meets its receipt, its first value under the record's handle at the
/// generation it held, and `blue harbor` as written. Green at e8dcab0e9fd
/// and at this head.
#[test]
fn a_resumed_write_meets_its_receipt_after_its_record_rotates_into_its_written_text() -> TestResult
{
    let (_directory, vault) = vault()?;
    vault.register_test_secret("river", RIVER.as_bytes(), Vec::new(), 1)?;
    let call = task_holding(&format!("{RIVER} / {BLUE_HARBOR}"));

    let meet = resumed_write_meets_its_stored_receipt_after(&vault, &call, &call, |vault| {
        rotate(vault, "river", BLUE_HARBOR)
    })?;

    assert!(
        !meet.kept_input.contains(RIVER) && meet.kept_input.contains(&format!("] / {BLUE_HARBOR}")),
        "FIXTURE: the receipt keeps the handle, then `blue harbor` as written: {meet:?}"
    );
    assert_meets(&meet);
    Ok(())
}

/// Custody holds `amber orchard`, so the receipt of a write holding `amber
/// orchard today` keeps `[secret scN] today`. The owner then rotates that
/// record to `amber orchard today`. Both generations are the record's, and
/// its handle meets the one whose length lets ` today` follow as written,
/// so the identical write meets its receipt. Red at e8dcab0e9fd: the offer
/// took the longer generation whole, `[secret scN]`, and both compares
/// refused the identical write.
#[test]
fn a_resumed_write_meets_its_receipt_after_its_record_rotates_to_a_longer_value() -> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret("orchard", ORCHARD.as_bytes(), Vec::new(), 1)?;
    let call = task_holding(ORCHARD_TODAY);

    let meet = resumed_write_meets_its_stored_receipt_after(&vault, &call, &call, |vault| {
        rotate(vault, "orchard", ORCHARD_TODAY)
    })?;

    assert!(
        !meet.kept_input.contains(ORCHARD) && meet.kept_input.contains("] today"),
        "FIXTURE: the receipt keeps the record's handle before ` today`: {meet:?}"
    );
    assert_meets(&meet);
    Ok(())
}

/// Custody holds a passphrase spelled as a handle no record has. A write
/// holding it keeps no plaintext of it in its receipt: the wall reads text
/// spelled as a handle that names no record like any other text, so the
/// passphrase takes its own record's handle, and the identical write meets
/// that receipt. Red at e8dcab0e9fd: the wall read the passphrase as a
/// handle and the receipt kept it as written.
#[test]
fn a_write_holding_a_passphrase_spelled_as_a_handle_keeps_it_out_of_its_receipt() -> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret(
        "handle-spelled passphrase",
        HANDLE_SPELLED_PASSPHRASE.as_bytes(),
        Vec::new(),
        1,
    )?;
    let call = task_holding(HANDLE_SPELLED_PASSPHRASE);

    let meet = resumed_write_meets_its_stored_receipt(&vault, &call, &call)?;

    assert!(
        !meet.kept_input.contains(HANDLE_SPELLED_PASSPHRASE),
        "the receipt keeps no plaintext of the passphrase: {meet:?}"
    );
    assert_meets(&meet);
    Ok(())
}
