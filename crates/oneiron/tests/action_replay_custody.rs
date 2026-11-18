//! FIX REPLAY-COMPARE-KNOWN-MATCHER (Engine RULING FIX-2329-REPLAY-KNOWN =
//! C, then A, 15 Nov 22:05): the side-row wall gives a value base custody
//! holds its record's handle in a code run's replay row, a value no shape
//! rule places too (a passphrase). The call made again with that value meets
//! its row: the replay compare plans the offered request with the values base
//! custody holds, as the wall planned the row. Before, it planned the request
//! with none of them, so the identical call drifted from its own row ("code-run
//! replay request mismatch"). An agent's action made again under its
//! idempotency key is one such replay.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test action_replay_custody`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::code_run::actions::ActionDispatch;
use oneiron::test_doors::action_replay_custody::remember_twice;
use oneiron::{Error, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const UNHELD_PASSPHRASE: &str = "summer harbour pencil compass";

/// The replay cursor's refusal of a call that drifted from its row.
const REQUEST_MISMATCH: &str = "code-run replay request mismatch";

fn vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    Ok((directory, vault))
}

/// Checks that the action's second making answered from the row its first
/// making recorded: as the first answered, or, for a first making a gate
/// refused, with that refusal again. Never a drift from the row.
fn answered_from_row(answers: [oneiron::Result<ActionDispatch>; 2]) -> TestResult {
    let [first, second] = answers;
    let second = second.map_err(|error| format!("{error:?}"));
    if let Err(error) = &second {
        assert!(
            !error.contains(REQUEST_MISMATCH),
            "the action made again drifted from its own row: {error}"
        );
    }
    match first {
        Ok(first) => assert_eq!(
            second,
            Ok(first),
            "the action made again answers as its first making did"
        ),
        Err(refusal @ Error::Gate(_)) => assert_eq!(
            second,
            Err(format!("{refusal:?}")),
            "a first making the gate refused answers that refusal again"
        ),
        Err(other) => {
            return Err(format!("the action's first making did not run: {other:?}").into());
        }
    }
    Ok(())
}

#[test]
fn an_action_made_again_with_a_passphrase_custody_holds_answers_from_its_row() -> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret(
        "orchard passphrase",
        HELD_PASSPHRASE.as_bytes(),
        Vec::new(),
        1,
    )?;

    answered_from_row(remember_twice(&vault, HELD_PASSPHRASE, "held-passphrase")?)
}

/// Guard: the same action with a passphrase no custody record holds keeps
/// it as written in its row, and answers from that row on main and head.
#[test]
fn an_action_made_again_with_a_passphrase_no_custody_holds_answers_from_its_row() -> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret(
        "orchard passphrase",
        HELD_PASSPHRASE.as_bytes(),
        Vec::new(),
        1,
    )?;

    answered_from_row(remember_twice(
        &vault,
        UNHELD_PASSPHRASE,
        "unheld-passphrase",
    )?)
}
