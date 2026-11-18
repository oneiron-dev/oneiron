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
use oneiron::test_doors::erased_request_identity::{
    room_stored_call_erased, room_stored_call_is, store_note_body, store_note_call,
    store_note_call_in_room, stored_body_call_is, stored_call_erased, stored_call_is,
};
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret, two custody records hold.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const OTHER_HELD_PASSPHRASE: &str = "autumn meadow candle ribbon";
/// A passphrase custody takes only after a row holds it as written.
const LATER_PASSPHRASE: &str = "spring valley mirror basket";
/// Keys of one shape a shape rule reads as a secret: the first two custody
/// records hold, the third none.
const FIRST_SHAPED_KEY: &str = "AKIA1234567890123456";
const SECOND_SHAPED_KEY: &str = "AKIA1234567890123457";
const UNHELD_SHAPED_KEY: &str = "AKIA1234567890123458";

fn vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    for (name, value) in [
        ("orchard passphrase", HELD_PASSPHRASE),
        ("meadow passphrase", OTHER_HELD_PASSPHRASE),
        ("first key", FIRST_SHAPED_KEY),
        ("second key", SECOND_SHAPED_KEY),
    ] {
        vault.register_test_secret(name, value.as_bytes(), Vec::new(), 1)?;
    }
    Ok((directory, vault))
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
/// fence erases the call in its writer. The call made again with the
/// passphrase it held meets the row; another passphrase custody holds is
/// another call. Red on the base and at the first fix (3802475905d): the
/// fence kept the stand-in identity alone, and the other passphrase met.
#[test]
fn a_rooms_call_put_after_its_agent_is_gone_meets_only_a_call_naming_its_records() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-erased-identity-fence", OffRecordBackendClass::Local)?;
    let call = store_note_call_in_room(&vault, &session, &words(HELD_PASSPHRASE), true)?;
    assert!(
        room_stored_call_erased(&session, call[1])?,
        "the room's put fence erases the call of a gone agent"
    );
    assert!(room_stored_call_is(
        &vault,
        &session,
        call,
        &words(HELD_PASSPHRASE),
        true
    )?);
    assert!(!room_stored_call_is(
        &vault,
        &session,
        call,
        &words(OTHER_HELD_PASSPHRASE),
        true
    )?);
    Ok(())
}
