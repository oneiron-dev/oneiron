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
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test erased_request_custody_identity`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::test_doors::erased_request_identity::{
    store_note_call, stored_call_erased, stored_call_is,
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
