//! In-process Dreamer wake passes over a small seeded vault, every model
//! call answered by the scripted backend.
//!
//! Each table below lists one wake's model calls as `(prompt digest,
//! reply)`. A call no table answers fails the test in
//! `ScriptedBackend::finish` with the backend's miss report, which names the
//! prompt and its digest; `print_seen` puts every request on a `## SEEN`
//! line in full. A reply that proposes no claim and no person is
//! `r#"{"candidates":[],"persons":[]}"#`.

use oneiron::WakePassStop;
use oneiron_testkit::TestVault;
use oneiron_testkit::door;
use oneiron_testkit::dreamer::{
    DreamerPass, allow_scripted_extraction, attach_test_host, grant_dreamer_read, print_seen,
    read_everything_scope, scripted_backend,
};
use serde_json::json;

/// The turn wake's model calls: the reading of the turn's two name spans,
/// then the extraction over the turn, which proposes nothing.
const TURN_WAKE_CALLS: &[(&str, &str)] = &[
    (
        "68ab6de1d6a827b746eec1d062ce4cdc857fa3b6ae5270e169bbf23b1c4f8629",
        r#"{"readings":[{"span":1,"kind":"name","novel":true,"confidence":90,"entity":null},{"span":2,"kind":"name","novel":true,"confidence":90,"entity":null}]}"#,
    ),
    (
        "78d9143fe540c8d87f9f1c3807d66bd8622baf605aaa7e445e123a51655ea334",
        r#"{"candidates":[],"persons":[]}"#,
    ),
];

/// The Timer wake's model calls. A Timer wake plans from the Dreamer's
/// interest queue, and over one turn it makes none.
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

#[test]
fn a_turn_wake_reads_the_fresh_owner_turn_and_runs_to_an_empty_queue() {
    let test_vault = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    attach_test_host(&vault).expect("the test host attaches after the open");
    let backend = scripted_backend("turn-wake", TURN_WAKE_CALLS);

    let pass = DreamerPass::new(&backend)
        .with_run_id("turn-wake")
        .run_turn_wake(&vault, test_vault.clock());
    print_seen(&backend.seen());
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
    let backend = scripted_backend("timer-wake", TIMER_WAKE_CALLS);

    let pass = DreamerPass::new(&backend)
        .with_run_id("timer-wake")
        .run_timer_wake(&vault, test_vault.clock());
    print_seen(&backend.seen());
    let seen = backend.finish();
    let report = pass.unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(report.stop(), WakePassStop::QueueEmpty);
    assert!(report.tally.completed > 0, "{report:#?}");
    println!("{} model call(s); queue after the pass:", seen.len());
    for row in &report.queue {
        println!("  {} {} {}", row.kind, row.attempt_id, row.state);
    }
}
