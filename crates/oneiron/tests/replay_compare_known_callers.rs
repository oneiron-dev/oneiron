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
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::run_tree::{RunAsk, RunAskQuestion};
use oneiron::{AttemptQueue, EntityId, RunTreeAdapter, TimeRange, Vault, VaultConfig};
use oneiron_browser::{
    BatchStep, BrowserEngine, ExpectInput, ReplayGuest, WorkflowProgram, WorkflowProof,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const UNHELD_PASSPHRASE: &str = "summer harbour pencil compass";

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
    Ok((directory, vault))
}

/// Opens the same ask, whose words hold `passphrase`, twice on one leased
/// branch, and gives both answers.
fn ask_opened_twice(vault: &Vault, passphrase: &str) -> TestResult<[oneiron::Result<RunAsk>; 2]> {
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
    let questions = || {
        vec![RunAskQuestion {
            who: "owner".to_owned(),
            prompt: format!("Unlock the archive with {passphrase}?"),
            options: vec![passphrase.to_owned(), "skip".to_owned()],
            deadline: None,
        }]
    };
    let adapter = RunTreeAdapter::new(vault);
    let open = || {
        adapter.open_ask(
            claimed.id,
            RUN,
            LEASE,
            claimed.attempt_count,
            ASK_HANDLE,
            questions(),
        )
    };
    Ok([open(), open()])
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
    let by = EntityId::now();
    vault.put_entity(
        &by,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 10, end: 10 },
        10,
        b"human",
    )?;
    let program = program(passphrase);
    let proof = proof();
    let mut ids = [by; 2];
    for (id, at) in ids.iter_mut().zip([11, 12]) {
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
