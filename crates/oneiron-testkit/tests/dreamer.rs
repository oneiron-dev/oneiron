//! In-process Dreamer wake passes over a small seeded vault, every model
//! call answered by the scripted backend.
//!
//! The prompts' digests are unknown until a fleet run: each list below
//! starts empty, every call misses, and `ScriptedBackend::finish` fails the
//! test with the backend's miss report, which prints each prompt and its
//! digest. Script a step per reported call as `(digest, reply)`. A reply
//! that proposes no claim and no person is
//! `r#"{"candidates":[],"persons":[]}"#`.

use oneiron::WakePassStop;
use oneiron_testkit::dreamer::{
    DreamerPass, allow_scripted_extraction, attach_test_host, grant_dreamer_read,
    read_everything_scope,
};
use oneiron_testkit::{PromptDigest, ScriptedBackend, Step, TestVault, door};
use serde_json::json;

/// The turn wake's model calls, as `(prompt digest, reply)`: at least its
/// extraction over the seeded turn.
const TURN_WAKE_CALLS: &[(&str, &str)] = &[];

/// The Timer wake's model calls, as `(prompt digest, reply)`. A Timer wake
/// plans from the Dreamer's interest queue and may make none.
const TIMER_WAKE_CALLS: &[(&str, &str)] = &[];

/// The one owner turn the passes read.
const SAID: &str = "I moved to Lisbon last March, and my sister Ana lives two streets away.";

/// A vault holding one owner turn, prepared for a scripted pass.
fn seeded() -> TestVault {
    TestVault::seeded("dreamer-pass", |vault, clock| {
        let owner = door::owner(vault).map_err(|error| format!("the owner: {error}"))?;
        attach_test_host(vault).map_err(|error| format!("the test host: {error}"))?;
        allow_scripted_extraction(vault)
            .map_err(|error| format!("the scripted extraction: {error}"))?;
        let conversation = vault
            .new_entity_id()
            .map_err(|error| format!("a conversation id: {error}"))?
            .to_hex();
        door::invoke(
            &owner,
            "vault.witness",
            json!({
                "conversation_ref": conversation,
                "messages": [{
                    "author": "user",
                    "message_type": "dialogue",
                    "content": SAID,
                    "is_visible": true,
                    "order": 0,
                }],
                "occurred_at": clock.now(),
            }),
        )
        .map_err(|error| format!("vault.witness: {error}"))?;
        clock.advance(60);
        Ok(())
    })
    .expect("the Dreamer fixture seeds through public doors")
}

/// A scripted backend answering `calls`, one step each.
fn backend(calls: &[(&str, &str)]) -> ScriptedBackend {
    let steps = calls
        .iter()
        .enumerate()
        .map(|(index, (digest, reply))| {
            Step::text(
                format!("dreamer-call-{index}"),
                PromptDigest::from_hex(digest).expect("a 64-hex prompt digest"),
                *reply,
            )
        })
        .collect();
    ScriptedBackend::new(steps).expect("the script")
}

#[test]
fn a_turn_wake_reads_the_fresh_owner_turn_and_runs_to_an_empty_queue() {
    let test_vault = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    attach_test_host(&vault).expect("the test host attaches after the open");
    let backend = backend(TURN_WAKE_CALLS);

    let pass = DreamerPass::new(&backend)
        .with_run_id("turn-wake")
        .run_turn_wake(&vault, test_vault.clock());
    // An unscripted call fails here, first, with the prompt and its digest.
    let seen = backend.finish();
    let report = pass.unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(report.stop(), WakePassStop::QueueEmpty);
    assert!(report.tally.completed > 0, "{report:#?}");
    assert!(
        !seen.is_empty(),
        "the turn wake made no model call: {report:#?}"
    );
}

#[test]
fn a_timer_wake_over_one_witnessed_turn_runs_to_an_empty_queue() {
    let test_vault = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    attach_test_host(&vault).expect("the test host attaches after the open");
    // The shipped policy lets the Dreamer read ordinary turns; private and
    // relationship content needs the owner's Grant, minted here as a caller
    // with such content would.
    grant_dreamer_read(&vault, read_everything_scope())
        .expect("the owner grants the Dreamer its reads");
    let backend = backend(TIMER_WAKE_CALLS);

    let pass = DreamerPass::new(&backend)
        .with_run_id("timer-wake")
        .run_timer_wake(&vault, test_vault.clock());
    let seen = backend.finish();
    let report = pass.unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(report.stop(), WakePassStop::QueueEmpty);
    assert!(report.tally.completed > 0, "{report:#?}");
    println!("{} model call(s); queue after the pass:", seen.len());
    for row in &report.queue {
        println!("  {} {} {}", row.kind, row.attempt_id, row.state);
    }
}
