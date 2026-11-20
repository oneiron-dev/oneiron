//! FIX PARKED-HOOK-LIVE-EXACT-COMPARE: a call a verb pre-hook's ask parked
//! leaves a note in its durable run's history, and the same call made again
//! resumes that ask under the ask's invocation. The note keeps the row as
//! the side-row wall stored it: each value base custody holds, a shaped key
//! or a passphrase, as its handle. The call made again holds the value
//! itself. The base compared the two exactly, so a parked call holding such
//! a value never met its note: it took a fresh invocation, and the hook
//! asked the owner a second time.
//!
//! The note now meets the call made again as the replay cursor reads a row
//! (FIX REPLAY-COMPARE-KNOWN-MATCHER): each value custody holds meets the
//! handle the wall placed for it, and only that one, so a call made again
//! with another key of the same shape, or with another passphrase custody
//! holds, stays another call.
//!
//! Red on the base: the two "meets its note" cases with a value custody
//! holds. Green on the base and the head: the guards.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test parked_hook_custody_value`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::test_doors::parked_hook_custody::{parked_note_meets, store_parked_note_call};
use oneiron::{Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret, two custody records hold.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const OTHER_HELD_PASSPHRASE: &str = "autumn meadow candle ribbon";
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

fn words(value: &str) -> String {
    format!("unlock the archive with {value}")
}

/// A parked call holding a shaped key custody holds, made again, meets its
/// note and resumes its ask. On the base its row held the key's handle, the
/// call made again held the key, and the two never met.
#[test]
fn a_parked_call_made_again_with_the_shaped_key_it_held_meets_its_note() -> TestResult {
    let (_directory, vault) = vault()?;
    let [agent, run] = store_parked_note_call(&vault, &words(FIRST_SHAPED_KEY))?;
    assert!(
        parked_note_meets(&vault, run, agent, &words(FIRST_SHAPED_KEY))?,
        "the same call made again resumes the ask it parked on"
    );
    Ok(())
}

/// The same for a passphrase custody holds, which no shape rule reads.
#[test]
fn a_parked_call_made_again_with_the_passphrase_it_held_meets_its_note() -> TestResult {
    let (_directory, vault) = vault()?;
    let [agent, run] = store_parked_note_call(&vault, &words(HELD_PASSPHRASE))?;
    assert!(
        parked_note_meets(&vault, run, agent, &words(HELD_PASSPHRASE))?,
        "the same call made again resumes the ask it parked on"
    );
    Ok(())
}

/// Guard: a call made again with another key of the same shape, held by
/// custody or not, is another call, on the base and the head.
#[test]
fn a_parked_call_made_again_with_another_shaped_key_is_another_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let [agent, run] = store_parked_note_call(&vault, &words(FIRST_SHAPED_KEY))?;
    for other in [SECOND_SHAPED_KEY, UNHELD_SHAPED_KEY] {
        assert!(
            !parked_note_meets(&vault, run, agent, &words(other))?,
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
    let [agent, run] = store_parked_note_call(&vault, &words(HELD_PASSPHRASE))?;
    assert!(
        !parked_note_meets(&vault, run, agent, &words(OTHER_HELD_PASSPHRASE))?,
        "another passphrase custody holds is another call"
    );
    Ok(())
}

/// Guard: a parked call holding no value custody holds meets the same call
/// made again, and not a call with other words, on the base and the head.
#[test]
fn a_parked_call_holding_plain_words_meets_only_the_same_words() -> TestResult {
    let (_directory, vault) = vault()?;
    let (held, other) = ("file the quarterly report", "file the yearly report");
    let [agent, run] = store_parked_note_call(&vault, held)?;
    assert!(parked_note_meets(&vault, run, agent, held)?);
    assert!(!parked_note_meets(&vault, run, agent, other)?);
    Ok(())
}
