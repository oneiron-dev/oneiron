//! FIX SIGNAL-NEW-KEY-MASKED-ANSWER: an ask's answer is stored through the
//! side-row wall, which gives a value base custody holds its record's
//! handle, a value no shape rule places too (a passphrase). The identical
//! answer given again under its own signal key replays by the keyed intent
//! (FIX 10066), but that intent names the key, so under a new key the
//! signal door compared the held answer with the raw one as written and
//! refused the identical answer as "ask already answered".
//!
//! The raw answer is now planned with the values the writer reads, as
//! `open_ask` plans its questions (FIX REPLAY-COMPARE-KNOWN-OTHER-CALLERS):
//! the identical answer under a new key is taken, and an answer holding a
//! passphrase another custody record holds reads as another handle and
//! still refuses.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! signal_ask_answer_known_value`.
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::attempt_queue::{ClaimAttempt, ClaimOutcome};
use oneiron::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::run_tree::{
    RunAskAnswerKind, RunAskQuestion, RunBranchSignal, RunSignalInput, RunSignalKind,
};
use oneiron::store::GateDecisionId;
use oneiron::{AttemptQueue, RunTreeAdapter, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const UNHELD_PASSPHRASE: &str = "summer harbour pencil compass";
/// A passphrase a second custody record holds.
const OTHER_HELD_PASSPHRASE: &str = "autumn meadow candle ribbon";
/// An answer holding the held passphrase and a word after it.
const HELD_PASSPHRASE_AND_WORD: &str = "winter orchard notebook lantern twice";

const RUN: &str = "known-answer-run";
const LEASE: &str = "known-answer-worker";
const ASK_HANDLE: &str = "archive-unlock";
const WHO: &str = "owner";
const ACTOR: &str = "person:owner";
const FIRST_KEY: &str = "answer-1";
const SECOND_KEY: &str = "answer-2";

/// A vault whose custody holds two passphrases, each in its own record.
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

/// Opens one ask on a leased branch, then answers it twice: `answers[0]`
/// under `keys[0]`, then `answers[1]` under `keys[1]`, and gives both
/// signal results.
fn answered_twice(
    vault: &Vault,
    answers: [&str; 2],
    keys: [&str; 2],
) -> TestResult<[oneiron::Result<RunBranchSignal>; 2]> {
    let [first, second] = answered_in_turn(
        vault,
        [(answers[0], keys[0]), (answers[1], keys[1])],
        |_| Ok(()),
    )?;
    Ok([first, second])
}

/// Opens one ask on a leased branch, then gives each answer under its key
/// in turn, running `after_first` once the first is given, and gives every
/// signal result.
fn answered_in_turn<const N: usize>(
    vault: &Vault,
    given: [(&str, &str); N],
    after_first: impl FnOnce(&Vault) -> TestResult,
) -> TestResult<[oneiron::Result<RunBranchSignal>; N]> {
    let outcome = DreamerRunnerStore::new(vault).enqueue(EnqueueDreamerAttempt {
        attempt_type: "known-answer-ask".to_owned(),
        input: rmpv::Value::Nil,
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some(RUN.to_owned()),
        now: 1,
    })?;
    let EnqueueDreamerAttemptOutcome::Enqueued(status) = outcome else {
        return Err("a fresh attempt is enqueued".into());
    };
    let ClaimOutcome::Claimed(claimed) = AttemptQueue::new(vault).claim(ClaimAttempt {
        lease_owner: LEASE.to_owned(),
        now: 2,
    })?
    else {
        return Err("the attempt is claimed".into());
    };
    assert_eq!(
        claimed.id, status.attempt.id,
        "the claim leases this branch"
    );
    let adapter = RunTreeAdapter::new(vault);
    adapter.open_ask(
        claimed.id,
        RUN,
        LEASE,
        claimed.attempt_count,
        ASK_HANDLE,
        vec![RunAskQuestion {
            who: WHO.to_owned(),
            prompt: "Which passphrase unlocks the archive?".to_owned(),
            options: Vec::new(),
            deadline: None,
        }],
    )?;
    let answer = |answer: &str, key: &str| {
        adapter.signal(RunSignalInput {
            branch: claimed.id,
            run_id: RUN.to_owned(),
            key: key.to_owned(),
            actor: ACTOR.to_owned(),
            kind: RunSignalKind::AskAnswer {
                handle: ASK_HANDLE.to_owned(),
                who: WHO.to_owned(),
                answer: answer.to_owned(),
                kind: RunAskAnswerKind::Word,
            },
        })
    };
    let mut after_first = Some(after_first);
    let mut results = Vec::with_capacity(N);
    for (text, key) in given {
        results.push(answer(text, key));
        if let Some(run) = after_first.take() {
            run(vault)?;
        }
    }
    results
        .try_into()
        .map_err(|_| "one result per answer given".into())
}

/// Checks that the answer given again under a new key is taken: its
/// receipt is the new key's.
fn answer_again_is_taken(signals: [oneiron::Result<RunBranchSignal>; 2]) -> TestResult {
    let [first, second] = signals;
    let first = first.map_err(|error| format!("the first answer was refused: {error:?}"))?;
    assert_eq!(first.key, FIRST_KEY, "the first receipt is its key's");
    let second = second
        .map_err(|error| format!("the identical answer under a new key was refused: {error:?}"))?;
    assert_eq!(
        second.key, SECOND_KEY,
        "the second receipt is the new key's"
    );
    assert_eq!(second.actor, ACTOR, "the second receipt names its actor");
    Ok(())
}

/// Red on main: the held answer reads as the passphrase's handle, the raw
/// one as written, and the identical answer under a new key refuses as
/// "ask already answered".
#[test]
fn an_answer_given_again_under_a_new_key_with_a_passphrase_custody_holds_is_taken() -> TestResult {
    let (_directory, vault) = vault()?;
    answer_again_is_taken(answered_twice(
        &vault,
        [HELD_PASSPHRASE, HELD_PASSPHRASE],
        [FIRST_KEY, SECOND_KEY],
    )?)
}

/// Guard: an answer with a passphrase no custody record holds is kept as
/// written, and the identical answer under a new key is taken on main and
/// head.
#[test]
fn an_answer_given_again_under_a_new_key_with_a_passphrase_no_custody_holds_is_taken() -> TestResult
{
    let (_directory, vault) = vault()?;
    answer_again_is_taken(answered_twice(
        &vault,
        [UNHELD_PASSPHRASE, UNHELD_PASSPHRASE],
        [FIRST_KEY, SECOND_KEY],
    )?)
}

/// Guard: the identical answer under its own key replays its receipt by
/// the keyed intent (FIX 10066), on main and head.
#[test]
fn an_answer_given_again_under_its_own_key_with_a_passphrase_custody_holds_replays_it() -> TestResult
{
    let (_directory, vault) = vault()?;
    let [first, second] = answered_twice(
        &vault,
        [HELD_PASSPHRASE, HELD_PASSPHRASE],
        [FIRST_KEY, FIRST_KEY],
    )?;
    let first = first.map_err(|error| format!("the first answer was refused: {error:?}"))?;
    let second = second.map_err(|error| format!("{error:?}"));
    assert_eq!(
        second,
        Ok(first),
        "the identical answer under its own key replays its receipt"
    );
    Ok(())
}

/// Guard: an answer holding a passphrase another custody record holds is
/// another answer: under a new key it refuses, on main and head, and the
/// first passphrase's handle never stands for it.
#[test]
fn an_answer_under_a_new_key_with_another_passphrase_custody_holds_refuses() -> TestResult {
    let (_directory, vault) = vault()?;
    let [first, second] = answered_twice(
        &vault,
        [HELD_PASSPHRASE, OTHER_HELD_PASSPHRASE],
        [FIRST_KEY, SECOND_KEY],
    )?;
    first.map_err(|error| format!("the first answer was refused: {error:?}"))?;
    match second {
        Err(oneiron::Error::InvalidConfig(reason)) if reason == "ask already answered" => Ok(()),
        other => Err(format!(
            "an answer with another held passphrase under a new key refuses, got {other:?}"
        )
        .into()),
    }
}

/// Guard: an answer holding a passphrase no custody record holds, given
/// after one holding a held passphrase, is another answer and refuses
/// under a new key, on main and head.
#[test]
fn an_answer_under_a_new_key_with_a_passphrase_no_custody_holds_after_a_held_one_refuses()
-> TestResult {
    let (_directory, vault) = vault()?;
    let [first, second] = answered_twice(
        &vault,
        [HELD_PASSPHRASE, UNHELD_PASSPHRASE],
        [FIRST_KEY, SECOND_KEY],
    )?;
    first.map_err(|error| format!("the first answer was refused: {error:?}"))?;
    match second {
        Err(oneiron::Error::InvalidConfig(reason)) if reason == "ask already answered" => Ok(()),
        other => Err(format!(
            "an answer with an unheld passphrase under a new key refuses, got {other:?}"
        )
        .into()),
    }
}

/// Turns the owner's secret scan off: the wall then stores a row as given.
fn scan_off(vault: &Vault) -> TestResult {
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.set_secret_scan_mode(&owner, SecretScanMode::Off, 3)?;
    Ok(())
}

/// Checks the receipts of an answer given, the same answer given again
/// under a new key, and that again under that key: the second carries the
/// held answer of the first, and the third replays the second.
fn answer_again_carries_the_held_answer(
    signals: [oneiron::Result<RunBranchSignal>; 3],
) -> TestResult {
    let [first, second, third] = signals;
    let first = first.map_err(|error| format!("the first answer was refused: {error:?}"))?;
    let second = second
        .map_err(|error| format!("the identical answer under a new key was refused: {error:?}"))?;
    assert_eq!(
        second.key, SECOND_KEY,
        "the second receipt is the new key's"
    );
    assert_eq!(
        second.kind, first.kind,
        "the new key's receipt carries the held answer"
    );
    let third = third.map_err(|error| format!("{error:?}"));
    assert_eq!(
        third,
        Ok(second),
        "the same answer again under the new key replays its receipt"
    );
    Ok(())
}

/// The answer is given with the scan on, so the wall holds the
/// passphrase's handle; the owner then turns the scan off, and the
/// identical answer comes under a new key. It meets the held answer, and
/// its receipt carries that held answer: the branch still holds one answer
/// for the ask and reads again. Red at b526283dab7 (blind review round 1 of
/// #9531): the receipt held the raw passphrase beside the held handle, and
/// the branch no longer read ("orphan Signal ask answer").
#[test]
fn an_answer_given_again_under_a_new_key_with_the_scan_off_carries_the_held_answer() -> TestResult {
    let (_directory, vault) = vault()?;
    answer_again_carries_the_held_answer(answered_in_turn(
        &vault,
        [
            (HELD_PASSPHRASE, FIRST_KEY),
            (HELD_PASSPHRASE, SECOND_KEY),
            (HELD_PASSPHRASE, SECOND_KEY),
        ],
        scan_off,
    )?)
}

/// The answer holds the held passphrase and a word after it; custody then
/// takes the whole answer as a value of its own. The identical answer under
/// a new key meets the held answer, the passphrase's handle and the word,
/// and its receipt carries that held answer, which the wall leaves as it
/// is. Red at b526283dab7 (blind review round 1 of #9531): the wall gave
/// the raw answer the longer value's handle, the receipt no longer matched
/// the held answer, and the save refused.
#[test]
fn an_answer_given_again_under_a_new_key_after_custody_took_it_whole_carries_the_held_answer()
-> TestResult {
    let (_directory, vault) = vault()?;
    answer_again_carries_the_held_answer(answered_in_turn(
        &vault,
        [
            (HELD_PASSPHRASE_AND_WORD, FIRST_KEY),
            (HELD_PASSPHRASE_AND_WORD, SECOND_KEY),
            (HELD_PASSPHRASE_AND_WORD, SECOND_KEY),
        ],
        |vault| {
            vault.register_test_secret(
                "whole answer",
                HELD_PASSPHRASE_AND_WORD.as_bytes(),
                Vec::new(),
                3,
            )?;
            Ok(())
        },
    )?)
}
