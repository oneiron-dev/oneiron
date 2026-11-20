//! FIX ERASED-IDENTITY-ONE-STAND-IN (Engine ANSWER 19 Nov 02:54 = B): an
//! erase of a run's replies keeps each bridge request's identity alone, a
//! digest of the request with every handle the side-row wall placed read as
//! one stand-in (FIX 6534). A call made again met that identity with each
//! value base custody holds read as the stand-in too (FIX
//! REPLAY-COMPARE-KNOWN-MATCHER), so any value custody holds, or any key of
//! the same shape, at the place of the erased row's handle read as the same
//! call: the call made again with another passphrase was answered from the
//! erased row, and ran nothing.
//!
//! The erase now also keeps the records the request named, by their
//! handles, and the digest of the request read for those records' values
//! alone, each as its record's handle. A call made again meets the erased
//! row only when its values name the same records. A value custody took
//! after the row was stored, before its erase, is one of them (the mixed
//! era); a value custody takes after the erase changes nothing. With no
//! custody read in reach the row reads by its stand-in identity, as before.
//!
//! Each case stores one call in an agent's replay record through the wall,
//! erases it with the agent's replies by the agent's delete, and reads it
//! against the call made again, as the replay cursor reads an erased row.
//! A room's run stages its record in the room's overlay, where the delete's
//! sweep erases it, or the room's put fence erases it when its agent is
//! gone before the put: each reads base custody in its writer, as the
//! wall does for a room (FIX 2329). A value in a body the call holds as
//! bytes is read as the wall reads that body.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test erased_request_custody_identity`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::off_record::OffRecordBackendClass;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::erased_request_identity::{
    custody_handle, room_stored_call_erased, room_stored_call_is, store_note_body, store_note_call,
    store_note_call_in_room, stored_body_call_is, stored_call_erased, stored_call_is,
};
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret, two custody records hold.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const OTHER_HELD_PASSPHRASE: &str = "autumn meadow candle ribbon";
/// A passphrase custody takes only after a row holds it as written.
const LATER_PASSPHRASE: &str = "spring valley mirror basket";
/// A passphrase whose record shows which handle custody gives next.
const PROBE_PASSPHRASE: &str = "harbor compass lighthouse ribbon";
/// Keys of one shape a shape rule reads as a secret: the first two custody
/// records hold, the third none.
const FIRST_SHAPED_KEY: &str = "AKIA1234567890123456";
const SECOND_SHAPED_KEY: &str = "AKIA1234567890123457";
const UNHELD_SHAPED_KEY: &str = "AKIA1234567890123458";
/// A value the first shaped key's record rotates to: the key and the words
/// before it in [`words`].
const SHAPED_KEY_WITH_WORDS: &str = "archive with AKIA1234567890123456";
/// A short value, and a text holding it as written and inside a base64 run
/// longer than that value's reach (its length times six), where `Zm94`
/// spells it.
const SHORT_VALUE: &str = "fox";
const SHORT_VALUE_AND_RUN: &str = "fox ! AAAAAAAAZm94AAAAAAAA";
/// A longer value an unrelated record takes: its reach spans that run.
const UNRELATED_VALUE: &str = "violet ledger";

fn vault() -> TestResult<(tempfile::TempDir, Vault)> {
    vault_holding(&[
        ("orchard passphrase", HELD_PASSPHRASE),
        ("meadow passphrase", OTHER_HELD_PASSPHRASE),
        ("first key", FIRST_SHAPED_KEY),
        ("second key", SECOND_SHAPED_KEY),
    ])
}

/// A vault whose custody holds each named value in its own record.
fn vault_holding(values: &[(&str, &str)]) -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    for &(name, value) in values {
        vault.register_test_secret(name, value.as_bytes(), Vec::new(), 1)?;
    }
    Ok((directory, vault))
}

/// The owner rotates the custody record named `name` to `value`.
fn rotate(vault: &Vault, name: &str, value: &str) -> TestResult {
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.rotate_secret_as_owner(&owner, name, value.as_bytes(), 5)?;
    Ok(())
}

fn words(value: &str) -> String {
    format!("unlock the archive with {value}")
}

/// Stores the call writing `words`, runs `between`, then erases the call
/// with its agent's replies by the agent's delete: the agent and the run.
fn erased_call(
    vault: &Vault,
    words: &str,
    between: impl FnOnce(&Vault) -> TestResult,
) -> TestResult<[EntityId; 2]> {
    let [agent, run] = store_note_call(vault, words)?;
    assert!(
        !stored_call_erased(vault, run)?,
        "the call is stored live before its agent's delete"
    );
    between(vault)?;
    vault.delete_entity(&agent)?;
    assert!(
        stored_call_erased(vault, run)?,
        "the agent's delete erases the call's request"
    );
    Ok([agent, run])
}

/// Guard: the call made again with the passphrase its erased row held meets
/// the row, on the base and the head.
#[test]
fn an_erased_call_made_again_with_the_passphrase_it_held_meets_its_row() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = erased_call(&vault, &words(HELD_PASSPHRASE), |_| Ok(()))?;
    assert!(stored_call_is(&vault, call, &words(HELD_PASSPHRASE), true)?);
    Ok(())
}

/// Guard: the same for a shaped key custody holds.
#[test]
fn an_erased_call_made_again_with_the_shaped_key_it_held_meets_its_row() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = erased_call(&vault, &words(FIRST_SHAPED_KEY), |_| Ok(()))?;
    assert!(stored_call_is(
        &vault,
        call,
        &words(FIRST_SHAPED_KEY),
        true
    )?);
    Ok(())
}

/// The call made again with a passphrase another custody record holds is
/// another call: it never meets the erased row that held the first one's
/// handle. On the base both read as the stand-in, and it met the row.
#[test]
fn an_erased_call_made_again_with_another_passphrase_custody_holds_is_another_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = erased_call(&vault, &words(HELD_PASSPHRASE), |_| Ok(()))?;
    assert!(
        !stored_call_is(&vault, call, &words(OTHER_HELD_PASSPHRASE), true)?,
        "a value another record holds names another record"
    );
    Ok(())
}

/// The call made again with another key of the same shape, one custody
/// holds and one it does not, is another call each time. On the base the
/// key read as the stand-in, and it met the row.
#[test]
fn an_erased_call_made_again_with_another_shaped_key_is_another_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = erased_call(&vault, &words(FIRST_SHAPED_KEY), |_| Ok(()))?;
    for other in [SECOND_SHAPED_KEY, UNHELD_SHAPED_KEY] {
        assert!(
            !stored_call_is(&vault, call, &words(other), true)?,
            "another key of the same shape is another call: {other}"
        );
    }
    Ok(())
}

/// A row stored while custody held one of its passphrases, and before it
/// took the other, holds the first one's handle and the second as written.
/// Erased once custody holds both, it meets the call made again with both.
/// On the base its identity kept the second as written, the call made again
/// read it as the stand-in, and the call drifted (FIX-LIST
/// [REPLAY-COMPARE-MIXED-ERA], the erased part).
#[test]
fn an_erased_call_held_before_custody_took_one_of_its_passphrases_meets_its_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let held = format!("{HELD_PASSPHRASE} then {LATER_PASSPHRASE}");
    let call = erased_call(&vault, &words(&held), |vault| {
        vault.register_test_secret(
            "valley passphrase",
            LATER_PASSPHRASE.as_bytes(),
            Vec::new(),
            2,
        )?;
        Ok(())
    })?;
    assert!(stored_call_is(&vault, call, &words(&held), true)?);
    Ok(())
}

/// Custody takes a word the erased row held as written after the erase:
/// the records the erase kept decide, so the call made again still meets
/// its row. On the base the call made again read the new value as the
/// stand-in too, and drifted from the identity the erase took.
#[test]
fn an_erased_call_meets_its_call_after_custody_took_a_word_it_held() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = erased_call(&vault, &words(HELD_PASSPHRASE), |_| Ok(()))?;
    vault.register_test_secret("archive word", b"archive", Vec::new(), 2)?;
    assert!(stored_call_is(&vault, call, &words(HELD_PASSPHRASE), true)?);
    Ok(())
}

/// Guard: with no custody read in reach the erased row reads by its
/// stand-in identity, as before: a key of the same shape meets it.
#[test]
fn an_erased_call_read_with_no_custody_in_reach_meets_by_its_stand_in() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = erased_call(&vault, &words(FIRST_SHAPED_KEY), |_| Ok(()))?;
    assert!(stored_call_is(
        &vault,
        call,
        &words(SECOND_SHAPED_KEY),
        false
    )?);
    Ok(())
}

/// `{"password":"<value>"}`: a body a call holds as bytes, its value under a
/// credential name.
fn password_body(value: &str) -> Vec<u8> {
    format!(r#"{{"password":"{value}"}}"#).into_bytes()
}

/// A call holding a body as bytes: the wall read that body and placed the
/// passphrase's handle under its credential name. The erase reads the body
/// as the wall does, so the identical call made again meets its row. On the
/// base, and at the first fix (3802475905d), the erase and the call made
/// again read the bytes as one text: the row's bare handle never met the
/// passphrase, and the call drifted.
#[test]
fn an_erased_call_holding_a_passphrase_in_a_body_meets_its_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let body = password_body(HELD_PASSPHRASE);
    let [agent, run] = store_note_body(&vault, &body)?;
    vault.delete_entity(&agent)?;
    assert!(
        stored_call_erased(&vault, run)?,
        "the agent's delete erases the call's request"
    );
    assert!(stored_body_call_is(&vault, [agent, run], &body, true)?);
    Ok(())
}

/// Guard: another passphrase custody holds in the same body is another
/// call, on the base and the head.
#[test]
fn an_erased_call_holding_another_passphrase_in_a_body_is_another_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let [agent, run] = store_note_body(&vault, &password_body(HELD_PASSPHRASE))?;
    vault.delete_entity(&agent)?;
    assert!(
        stored_call_erased(&vault, run)?,
        "the agent's delete erases the call's request"
    );
    assert!(!stored_body_call_is(
        &vault,
        [agent, run],
        &password_body(OTHER_HELD_PASSPHRASE),
        true
    )?);
    Ok(())
}

/// A room's run stages the call live; the agent's delete then sweeps the
/// room's overlay and erases it there. Red on the base and at the first fix
/// (3802475905d): the sweep kept the stand-in identity alone, and another
/// passphrase custody holds met the row.
#[test]
fn a_rooms_erased_call_made_again_with_another_passphrase_custody_holds_is_another_call()
-> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-erased-identity-sweep", OffRecordBackendClass::Local)?;
    let [agent, run] = store_note_call_in_room(&vault, &session, &words(HELD_PASSPHRASE), false)?;
    assert!(
        !room_stored_call_erased(&session, run)?,
        "the room stages the call live before its agent's delete"
    );
    vault.delete_entity(&agent)?;
    assert!(
        room_stored_call_erased(&session, run)?,
        "the agent's delete erases the call the room holds"
    );
    assert!(!room_stored_call_is(
        &vault,
        &session,
        [agent, run],
        &words(OTHER_HELD_PASSPHRASE),
        true
    )?);
    Ok(())
}

/// Guard for the test above: the call made again with the passphrase the
/// room's erased row held meets it, on the base and the head.
#[test]
fn a_rooms_erased_call_made_again_with_the_passphrase_it_held_meets_its_row() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault.off_record_session_vault().enter(
        "sess-erased-identity-sweep-guard",
        OffRecordBackendClass::Local,
    )?;
    let [agent, run] = store_note_call_in_room(&vault, &session, &words(HELD_PASSPHRASE), false)?;
    vault.delete_entity(&agent)?;
    assert!(
        room_stored_call_erased(&session, run)?,
        "the agent's delete erases the call the room holds"
    );
    assert!(room_stored_call_is(
        &vault,
        &session,
        [agent, run],
        &words(HELD_PASSPHRASE),
        true
    )?);
    Ok(())
}

/// The agent is gone before the room's run puts its record: the room's put
/// fence erases the call in its writer, before the wall reads it. The call
/// made again with the key it held meets the row; another key of the same
/// shape, one custody holds or one it holds not, is another call. Red on
/// the base and at the first fix (3802475905d): the fence kept the stand-in
/// identity alone, where every key of that shape reads as the stand-in.
#[test]
fn a_rooms_call_put_after_its_agent_is_gone_meets_only_a_call_naming_its_records() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-erased-identity-fence", OffRecordBackendClass::Local)?;
    let call = store_note_call_in_room(&vault, &session, &words(FIRST_SHAPED_KEY), true)?;
    assert!(
        room_stored_call_erased(&session, call[1])?,
        "the room's put fence erases the call of a gone agent"
    );
    assert!(room_stored_call_is(
        &vault,
        &session,
        call,
        &words(FIRST_SHAPED_KEY),
        true
    )?);
    for other in [SECOND_SHAPED_KEY, UNHELD_SHAPED_KEY] {
        assert!(
            !room_stored_call_is(&vault, &session, call, &words(other), true)?,
            "{other} is another call"
        );
    }
    Ok(())
}

/// The number a custody handle (`sc` and digits) carries.
fn handle_number(handle: &str) -> TestResult<u64> {
    Ok(handle
        .strip_prefix("sc")
        .ok_or("a custody handle opens with sc")?
        .parse()?)
}

/// The handle custody gives `record`.
fn handle_of(vault: &Vault, record: EntityId) -> TestResult<String> {
    Ok(custody_handle(vault, record)?.ok_or("custody gives the record a handle")?)
}

/// A record holds, as its value, the handle custody gives the record after
/// it, spelled as a handle, while no record has that handle: the wall and
/// the erase read the spelling as the value it is. Custody then takes that
/// next record. The call made again still meets its row: its erase named
/// one record, and a read for that record knows that record's handle alone.
/// Red at 6058748001c (blind review round 1 of #9528): the read took the
/// spelling for the handle of the record custody took since, and drifted.
#[test]
fn an_erased_call_spelling_the_handle_of_a_record_custody_takes_later_meets_its_call() -> TestResult
{
    let (_directory, vault) = vault()?;
    let probe = vault.register_test_secret(
        "harbor passphrase",
        PROBE_PASSPHRASE.as_bytes(),
        Vec::new(),
        2,
    )?;
    let next = handle_number(&handle_of(&vault, probe)?)? + 2;
    let spelled = format!("[secret sc{next}]");
    let holder = vault.register_test_secret("spelled handle", spelled.as_bytes(), Vec::new(), 2)?;
    assert_eq!(handle_of(&vault, holder)?, format!("sc{}", next - 1));
    let call = erased_call(&vault, &words(&spelled), |_| Ok(()))?;
    let later = vault.register_test_secret(
        "valley passphrase",
        LATER_PASSPHRASE.as_bytes(),
        Vec::new(),
        3,
    )?;
    assert_eq!(
        handle_of(&vault, later)?,
        format!("sc{next}"),
        "custody gives its handles in order"
    );
    assert!(stored_call_is(&vault, call, &words(&spelled), true)?);
    Ok(())
}

/// Custody holds, as a value, the word an erased form once named its
/// custody identity by. The room's put fence erases the call of a gone
/// agent before the wall reads the record, so the wall reads the erased
/// form too: it names no such word, and its records are bare handles the
/// wall leaves as they are. The call made again with the key it held meets
/// the row, and another key of the same shape is another call. Red at
/// 6058748001c (blind review round 1 of #9528): the wall took the word for
/// that value and placed its handle, and the row no longer read as erased.
#[test]
fn a_rooms_call_put_after_its_agent_is_gone_keeps_its_records_when_custody_holds_a_form_word()
-> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret("erased form word", b"custody", Vec::new(), 2)?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-erased-identity-word", OffRecordBackendClass::Local)?;
    let call = store_note_call_in_room(&vault, &session, &words(FIRST_SHAPED_KEY), true)?;
    assert!(
        room_stored_call_erased(&session, call[1])?,
        "the room's put fence erases the call of a gone agent"
    );
    assert!(room_stored_call_is(
        &vault,
        &session,
        call,
        &words(FIRST_SHAPED_KEY),
        true
    )?);
    assert!(
        !room_stored_call_is(&vault, &session, call, &words(SECOND_SHAPED_KEY), true)?,
        "another key of the same shape is another call"
    );
    Ok(())
}

/// Custody holds a key of a shape a rule reads, and an erased row held it
/// after other words. The owner then rotates its record to a value that
/// spans the key and the words before it. The call made again still meets
/// its row: the record's shorter generation reads it as the erase did. Red
/// at 2cf8949a021 (blind review round 2 of #9528): the read took the longer
/// generation whole, `unlock the [secret scN]`, and drifted from the row
/// the base still met by its stand-in identity.
#[test]
fn an_erased_call_meets_its_call_after_its_record_rotates_to_a_value_spanning_its_words()
-> TestResult {
    let (_directory, vault) = vault()?;
    let call = erased_call(&vault, &words(FIRST_SHAPED_KEY), |_| Ok(()))?;
    rotate(&vault, "first key", SHAPED_KEY_WITH_WORDS)?;
    assert!(stored_call_is(
        &vault,
        call,
        &words(FIRST_SHAPED_KEY),
        true
    )?);
    assert!(
        !stored_call_is(&vault, call, &words(SECOND_SHAPED_KEY), true)?,
        "another key custody holds is another call"
    );
    Ok(())
}

/// Custody holds a short value alone; an erased row held it as written and
/// spelled in a base64 run longer than that value's reach, so the erase
/// read the run as text. An unrelated record then takes a longer value,
/// whose reach spans the run. The call made again still meets its row: a
/// read for the records the erase named reaches as far as their values
/// alone. Red at 2cf8949a021 (blind review round 2 of #9528): the read
/// reached as far as every value custody holds, took `Zm94` for the short
/// value, and drifted.
#[test]
fn an_erased_call_meets_its_call_after_an_unrelated_record_takes_a_longer_value() -> TestResult {
    let (_directory, vault) = vault_holding(&[("short value", SHORT_VALUE)])?;
    let call = erased_call(&vault, &words(SHORT_VALUE_AND_RUN), |_| Ok(()))?;
    vault.register_test_secret("unrelated value", UNRELATED_VALUE.as_bytes(), Vec::new(), 2)?;
    assert!(stored_call_is(
        &vault,
        call,
        &words(SHORT_VALUE_AND_RUN),
        true
    )?);
    Ok(())
}
