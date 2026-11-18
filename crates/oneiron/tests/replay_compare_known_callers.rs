//! FIX REPLAY-COMPARE-KNOWN-OTHER-CALLERS (follow-up of FIX
//! REPLAY-COMPARE-KNOWN-MATCHER, #8458): the side-row wall gives a value base
//! custody holds its record's handle in a row stored through the vault, a
//! value no shape rule places too (a passphrase). The same request made
//! again with that value meets its held row at each compare of a held row
//! with a raw offer, not only at the code-run replay cursor. Before, these
//! compares planned the offer with none of the values custody holds: the
//! identical ask opened again on its branch refused as "ask handle reused",
//! and the identical browser program filed again took a second id.
//!
//! Both sides are planned with those values, each read as its record's
//! handle, so a passphrase another record holds is another request: the ask
//! with it opened under the same handle still refuses, and the program with
//! it filed again takes its own id. A row that holds a passphrase as written,
//! admitted before custody held it, meets its call once custody does.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! replay_compare_known_callers`.
#![cfg(feature = "test-support")]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::attempt_queue::{ClaimAttempt, ClaimOutcome};
use oneiron::browser_library::{Filing, file_workflow};
use oneiron::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::run_tree::{RunAsk, RunAskQuestion};
use oneiron::store::GateDecisionId;
use oneiron::{AttemptQueue, EntityId, RunTreeAdapter, TimeRange, Vault, VaultConfig};
use oneiron_browser::{
    BatchStep, BrowserEngine, ExpectInput, ReplayGuest, WorkflowProgram, WorkflowProof,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const UNHELD_PASSPHRASE: &str = "summer harbour pencil compass";
/// A passphrase a second custody record holds.
const OTHER_HELD_PASSPHRASE: &str = "autumn meadow candle ribbon";
/// A passphrase custody takes only after a row holds it as written.
const LATER_PASSPHRASE: &str = "spring valley mirror basket";

const RUN: &str = "known-callers-run";
const LEASE: &str = "known-callers-worker";
const ASK_HANDLE: &str = "archive-unlock";
const SITE: &str = "example.com";

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

/// Opens the same ask, whose words hold `passphrase`, twice on one leased
/// branch, and gives both answers.
fn ask_opened_twice(vault: &Vault, passphrase: &str) -> TestResult<[oneiron::Result<RunAsk>; 2]> {
    ask_opened_with(vault, [passphrase, passphrase], |_| Ok(()))
}

/// Opens an ask under one handle twice on one leased branch, its words
/// holding `words[0]` and then, once `between` ran, `words[1]`, and gives
/// both answers.
fn ask_opened_with(
    vault: &Vault,
    words: [&str; 2],
    between: impl FnOnce(&Vault) -> TestResult,
) -> TestResult<[oneiron::Result<RunAsk>; 2]> {
    let outcome = DreamerRunnerStore::new(vault).enqueue(EnqueueDreamerAttempt {
        attempt_type: "known-callers-ask".to_owned(),
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
    let questions = |passphrase: &str| {
        vec![RunAskQuestion {
            who: "owner".to_owned(),
            prompt: format!("Unlock the archive with {passphrase}?"),
            options: vec![passphrase.to_owned(), "skip".to_owned()],
            deadline: None,
        }]
    };
    let adapter = RunTreeAdapter::new(vault);
    let open = |passphrase: &str| {
        adapter.open_ask(
            claimed.id,
            RUN,
            LEASE,
            claimed.attempt_count,
            ASK_HANDLE,
            questions(passphrase),
        )
    };
    let first = open(words[0]);
    between(vault)?;
    Ok([first, open(words[1])])
}

/// Checks that the ask opened again is the ask its branch holds.
fn reopened_ask_is_held_ask(answers: [oneiron::Result<RunAsk>; 2]) -> TestResult {
    let [first, second] = answers;
    let first = first.map_err(|error| format!("the ask did not open: {error:?}"))?;
    let second = second.map_err(|error| format!("{error:?}"));
    assert_eq!(
        second,
        Ok(first),
        "the identical ask opened again is the ask its branch holds"
    );
    Ok(())
}

#[test]
fn an_ask_opened_again_with_a_passphrase_custody_holds_is_its_held_ask() -> TestResult {
    let (_directory, vault) = vault()?;
    reopened_ask_is_held_ask(ask_opened_twice(&vault, HELD_PASSPHRASE)?)
}

/// Guard: an ask with a passphrase no custody record holds keeps it as
/// written, and the identical ask opened again meets it on main and head.
#[test]
fn an_ask_opened_again_with_a_passphrase_no_custody_holds_is_its_held_ask() -> TestResult {
    let (_directory, vault) = vault()?;
    reopened_ask_is_held_ask(ask_opened_twice(&vault, UNHELD_PASSPHRASE)?)
}

/// An ask whose words hold a passphrase another custody record holds is
/// another ask: opened under the handle the first one holds, it refuses,
/// as on main, and never answers with the ask that holds the first
/// passphrase's handle.
#[test]
fn an_ask_opened_again_with_another_passphrase_custody_holds_refuses() -> TestResult {
    let (_directory, vault) = vault()?;
    let [first, second] =
        ask_opened_with(&vault, [HELD_PASSPHRASE, OTHER_HELD_PASSPHRASE], |_| Ok(()))?;
    first.map_err(|error| format!("the ask did not open: {error:?}"))?;
    match second {
        Err(oneiron::Error::InvalidConfig(reason)) if reason == "ask handle reused" => Ok(()),
        other => Err(format!(
            "an ask with another held passphrase under the same handle refuses, got {other:?}"
        )
        .into()),
    }
}

/// Custody holds a value, `secret`, that spells part of the handle the wall
/// placed in the ask's words (`[secret sc12]`). The handle names its record
/// and holds no value, so the held row is never read inside it, and the
/// identical ask opened again is its held ask, as on main.
#[test]
fn an_ask_opened_again_while_custody_holds_a_word_of_its_handle_is_its_held_ask() -> TestResult {
    let (_directory, vault) = vault()?;
    vault.register_test_secret("handle word", b"secret", Vec::new(), 1)?;
    reopened_ask_is_held_ask(ask_opened_twice(&vault, HELD_PASSPHRASE)?)
}

/// With the owner's switch off the wall seeks no shape (FIX 8644), so an ask
/// whose words hold a key a shape rule reads keeps it as written. An ask with
/// another key of that shape, opened under the same handle, is another ask:
/// it refuses, as on main. The held row is read for the values custody holds
/// alone, never for a shape, so the two keys never read as one stand-in.
#[test]
fn an_ask_held_with_the_switch_off_opened_again_with_another_shaped_key_refuses() -> TestResult {
    let (_directory, vault) = vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.set_secret_scan_mode(&owner, SecretScanMode::Off, 1)?;
    let [first, second] = ask_opened_with(
        &vault,
        ["AKIA1234567890123456", "AKIA1234567890123457"],
        |_| Ok(()),
    )?;
    first.map_err(|error| format!("the ask did not open: {error:?}"))?;
    match second {
        Err(oneiron::Error::InvalidConfig(reason)) if reason == "ask handle reused" => Ok(()),
        other => Err(format!(
            "an ask with another key held as written under the same handle refuses, got {other:?}"
        )
        .into()),
    }
}

/// A row admitted while custody held one passphrase of its words and not the
/// other holds the first as its handle and the second as written. Once
/// custody holds the second too, the identical ask opened again meets that
/// row: both read with each value custody holds as its record's handle.
#[test]
fn an_ask_held_before_custody_took_one_of_its_passphrases_is_its_held_ask() -> TestResult {
    let (_directory, vault) = vault()?;
    let words = format!("{HELD_PASSPHRASE} and {LATER_PASSPHRASE}");
    reopened_ask_is_held_ask(ask_opened_with(
        &vault,
        [words.as_str(), words.as_str()],
        |vault| {
            vault.register_test_secret(
                "valley passphrase",
                LATER_PASSPHRASE.as_bytes(),
                Vec::new(),
                3,
            )?;
            Ok(())
        },
    )?)
}

fn program(passphrase: &str) -> WorkflowProgram {
    WorkflowProgram {
        subgoal: format!("unlock the expense archive with {passphrase}"),
        params: Vec::new(),
        secret_params: Vec::new(),
        steps: vec![BatchStep::Open {
            url: "https://example.com/expenses".to_owned(),
        }],
        postcondition: vec![ExpectInput {
            role: Some("heading".to_owned()),
            name: Some("Archive unlocked".to_owned()),
            ..Default::default()
        }],
    }
}

fn proof() -> WorkflowProof {
    WorkflowProof {
        args: BTreeMap::new(),
        replay_args: BTreeMap::new(),
        held_out: false,
        seed: None,
        solved_url: "https://example.com/expenses".to_owned(),
        solved_title: "Expenses".to_owned(),
        replay_receipts: Vec::new(),
        replay_decisions: Vec::new(),
        replay_url: "https://example.com/expenses".to_owned(),
        replay_guest: ReplayGuest {
            engine: BrowserEngine::Lightpanda,
            carried: Vec::new(),
            not_carried: Vec::new(),
        },
    }
}

/// Files the same program, whose subgoal holds `passphrase`, twice on one
/// site, and gives the id each filing took.
fn program_filed_twice(vault: &Vault, passphrase: &str) -> TestResult<[EntityId; 2]> {
    programs_filed(vault, [passphrase, passphrase])
}

/// Files a program on one site twice, its subgoal holding `passphrases[0]`
/// and then `passphrases[1]`, and gives the id each filing took.
fn programs_filed(vault: &Vault, passphrases: [&str; 2]) -> TestResult<[EntityId; 2]> {
    let by = EntityId::now();
    vault.put_entity(
        &by,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 10, end: 10 },
        10,
        b"human",
    )?;
    let proof = proof();
    let mut ids = [by; 2];
    for ((id, at), passphrase) in ids.iter_mut().zip([11, 12]).zip(passphrases) {
        let program = program(passphrase);
        let filing = file_workflow(
            vault, by, SITE, &program, &proof, at, None, None, None, None, None,
        )?;
        let Filing::Filed { id: filed, .. } = filing else {
            return Err(format!("the filing at {at} was refused: {filing:?}").into());
        };
        *id = filed;
    }
    Ok(ids)
}

#[test]
fn a_program_filed_again_with_a_passphrase_custody_holds_is_its_filed_program() -> TestResult {
    let (_directory, vault) = vault()?;
    let [first, second] = program_filed_twice(&vault, HELD_PASSPHRASE)?;
    assert_eq!(
        second, first,
        "the identical program filed again is the program its site holds"
    );
    Ok(())
}

/// Guard: a program with a passphrase no custody record holds keeps it as
/// written, and the identical program filed again meets it on main and head.
#[test]
fn a_program_filed_again_with_a_passphrase_no_custody_holds_is_its_filed_program() -> TestResult {
    let (_directory, vault) = vault()?;
    let [first, second] = program_filed_twice(&vault, UNHELD_PASSPHRASE)?;
    assert_eq!(
        second, first,
        "the identical program filed again is the program its site holds"
    );
    Ok(())
}

/// A program whose subgoal holds a passphrase another custody record holds
/// is another program: filed on the same site, it takes its own id, as on
/// main, and never the id of the program that holds the first passphrase's
/// handle.
#[test]
fn a_program_filed_with_another_passphrase_custody_holds_takes_its_own_id() -> TestResult {
    let (_directory, vault) = vault()?;
    let [first, second] = programs_filed(&vault, [HELD_PASSPHRASE, OTHER_HELD_PASSPHRASE])?;
    assert_ne!(
        second, first,
        "a program with another held passphrase is filed as its own program"
    );
    Ok(())
}
