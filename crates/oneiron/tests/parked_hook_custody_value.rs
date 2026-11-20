//! FIX PARKED-HOOK-LIVE-EXACT-COMPARE: a call a verb pre-hook's ask parked
//! leaves a note in its durable run's history, and the same call made again
//! resumes that ask under the ask's invocation. The note keeps the row as
//! the side-row wall stored it: each value base custody holds, a shaped key
//! or a passphrase, as its handle. The call made again holds the value
//! itself. The base compared the two exactly, so a parked call holding such
//! a value never met its note: it took a fresh invocation, and the hook
//! asked the owner a second time.
//!
//! The call made again now resumes the ask when it meets the row as the
//! replay cursor reads a row (FIX REPLAY-COMPARE-KNOWN-MATCHER), each value
//! custody holds meeting the handle the wall placed for it, and the ask saved
//! the call's own args. A handle meets every generation its record keeps, so
//! the saved args, the request as the guest made it, tell the value the owner
//! was asked about from one the record took since (blind review round 1 of
//! #9676): a call made again with the rotated value, or under an ask that
//! saved other args, is another call.
//!
//! Red on the base: the two "resumes its ask" cases with a value custody
//! holds. Green on the base and the head: the guards.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test parked_hook_custody_value`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::store::GateDecisionId;
use oneiron::test_doors::parked_hook_custody::{parked_note_resumed, store_parked_note_call};
use oneiron::{Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret, two custody records hold.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const OTHER_HELD_PASSPHRASE: &str = "autumn meadow candle ribbon";
/// The value the first passphrase's record rotates to.
const ROTATED_PASSPHRASE: &str = "spring valley mirror basket";
/// Keys of one shape a shape rule reads as a secret: the first two custody
/// records hold, the third none.
const FIRST_SHAPED_KEY: &str = "AKIA1234567890123456";
const SECOND_SHAPED_KEY: &str = "AKIA1234567890123457";
const UNHELD_SHAPED_KEY: &str = "AKIA1234567890123458";

/// A vault whose custody holds both passphrases and the first two keys,
/// each in its own record.
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

/// A parked call holding a shaped key custody holds, made again, resumes its
/// ask. On the base its row held the key's handle, the call made again held
/// the key, and the two never met.
#[test]
fn a_parked_call_made_again_with_the_shaped_key_it_held_resumes_its_ask() -> TestResult {
    let (_directory, vault) = vault()?;
    let held = words(FIRST_SHAPED_KEY);
    let [agent, run] = store_parked_note_call(&vault, &held)?;
    assert!(
        parked_note_resumed(&vault, run, agent, &held, &held)?,
        "the same call made again resumes the ask it parked on"
    );
    Ok(())
}

/// The same for a passphrase custody holds, which no shape rule reads.
#[test]
fn a_parked_call_made_again_with_the_passphrase_it_held_resumes_its_ask() -> TestResult {
    let (_directory, vault) = vault()?;
    let held = words(HELD_PASSPHRASE);
    let [agent, run] = store_parked_note_call(&vault, &held)?;
    assert!(
        parked_note_resumed(&vault, run, agent, &held, &held)?,
        "the same call made again resumes the ask it parked on"
    );
    Ok(())
}

/// Guard: a call made again with another key of the same shape, held by
/// custody or not, is another call, on the base and the head.
#[test]
fn a_parked_call_made_again_with_another_shaped_key_is_another_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let held = words(FIRST_SHAPED_KEY);
    let [agent, run] = store_parked_note_call(&vault, &held)?;
    for other in [SECOND_SHAPED_KEY, UNHELD_SHAPED_KEY] {
        assert!(
            !parked_note_resumed(&vault, run, agent, &held, &words(other))?,
            "another key of the same shape is another call: {other}"
        );
    }
    Ok(())
}

/// Guard: a call made again with another passphrase custody holds is
/// another call, on the base and the head.
#[test]
fn a_parked_call_made_again_with_another_held_passphrase_is_another_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let held = words(HELD_PASSPHRASE);
    let [agent, run] = store_parked_note_call(&vault, &held)?;
    assert!(
        !parked_note_resumed(&vault, run, agent, &held, &words(OTHER_HELD_PASSPHRASE))?,
        "another passphrase custody holds is another call"
    );
    Ok(())
}

/// Guard: once the passphrase's record rotates, the call made again with
/// its new value is another call. The row's handle meets every generation of
/// that record, but the ask saved the first value, the one the owner was
/// asked about, so the call never resumes that ask, on the base and the head.
#[test]
fn a_parked_call_made_again_with_its_records_rotated_value_is_another_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let held = words(HELD_PASSPHRASE);
    let [agent, run] = store_parked_note_call(&vault, &held)?;
    rotate(&vault, "orchard passphrase", ROTATED_PASSPHRASE)?;
    assert!(
        !parked_note_resumed(&vault, run, agent, &held, &words(ROTATED_PASSPHRASE))?,
        "the record's rotated value never resumes the ask about its first one"
    );
    Ok(())
}

/// Guard: a call whose row it meets through custody, under an ask that saved
/// another call's args, never resumes that ask, on the base and the head.
#[test]
fn a_parked_call_under_an_ask_that_saved_other_args_is_another_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let held = words(HELD_PASSPHRASE);
    let [agent, run] = store_parked_note_call(&vault, &held)?;
    let other = words(OTHER_HELD_PASSPHRASE);
    assert!(
        !parked_note_resumed(&vault, run, agent, &other, &held)?,
        "an ask that saved other args is not this call's"
    );
    Ok(())
}

/// Guard: a parked call holding no value custody holds resumes its ask when
/// made again with the same words, and not with other words, on the base and
/// the head.
#[test]
fn a_parked_call_holding_plain_words_resumes_only_for_the_same_words() -> TestResult {
    let (_directory, vault) = vault()?;
    let (held, other) = ("file the quarterly report", "file the yearly report");
    let [agent, run] = store_parked_note_call(&vault, held)?;
    assert!(parked_note_resumed(&vault, run, agent, held, held)?);
    assert!(!parked_note_resumed(&vault, run, agent, held, other)?);
    Ok(())
}
