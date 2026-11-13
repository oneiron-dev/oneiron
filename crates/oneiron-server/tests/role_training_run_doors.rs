//! The role-training run doors served over the real facade route
//! (ROLE-TRAINING-RUN, LEARN-TRAIN Q1 and Q3):
//! - the owner prepares a role run with no Train offer on a trainer connector
//!   the host names, and the split holds one training and one held-out row;
//! - `vault.coach.training_runs.get` answers outstanding on the owner's
//!   authorization, running once authorized, and outstanding on the host once
//!   the host holds a role run it has no trainer for;
//! - a read that waits returns at its bound with the run untouched, and a
//!   wait above the cap is refused;
//! - prepare takes the owner's own proof: an agent is refused and nothing
//!   is prepared, and a connector the host does not name is refused;
//! - an agent reads a run only with a Grant listing `get`, and never sees the
//!   held-out split.
//!
//! Reads JSON only (no engine type of the new verbs), so on a main without
//! the verbs every test fails on its first status assertion.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! role_training_run_doors`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;
#[path = "support/role_training_fixture.rs"]
mod role_training_fixture;

use axum::http::StatusCode;
use engine_stack::run_on_engine_stack;
use role_training_fixture::{CONNECTOR, Fixture, GET_VERB, PREPARE_VERB, seed_role_run};
use serde_json::{Value, json};

/// The owner prepares the seeded run; returns the answer.
async fn prepare_as_owner(fixture: &Fixture, draft: &Value) -> Value {
    let (status, answer) = fixture
        .as_owner(
            PREPARE_VERB,
            json!({"draft": draft, "connector": CONNECTOR}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "owner prepare: {answer}");
    answer
}

/// The owner reads `run`, waiting up to `wait_ms`.
async fn get_as_owner(fixture: &Fixture, run: &str, wait_ms: u64) -> Value {
    let (status, answer) = fixture
        .as_owner(GET_VERB, json!({"run": run, "wait_ms": wait_ms}))
        .await;
    assert_eq!(status, StatusCode::OK, "owner get: {answer}");
    answer
}

#[test]
fn owner_prepares_a_role_run_with_no_offer_and_reads_it_through_authorization_and_hold() {
    run_on_engine_stack("role-prepare-owner", || async {
        let fixture = Fixture::new().await;
        let seeded = seed_role_run(&fixture.vault);

        let prepared = prepare_as_owner(&fixture, &seeded.draft).await;
        assert_eq!(prepared["state"], "prepared", "{prepared}");
        assert_eq!(prepared["training_rows"], 1, "{prepared}");
        assert_eq!(prepared["held_out_rows"], 1, "{prepared}");
        assert_eq!(prepared["exact_hash_overlaps"], 0, "{prepared}");
        let run = prepared["run"].as_str().expect("run id").to_owned();
        let spec = prepared["spec"].as_str().expect("spec hex").to_owned();
        assert_eq!(spec.len(), 64, "{prepared}");
        assert!(
            prepared["training"]["bytes"].as_u64() > Some(0),
            "{prepared}"
        );
        assert_ne!(
            prepared["training"]["artifact"], prepared["held_out"]["artifact"],
            "{prepared}"
        );
        let stored = fixture
            .vault
            .training_runs()
            .expect("read the runs")
            .into_iter()
            .find(|stored| stored.id.to_hex() == run)
            .expect("the prepared run is stored");
        assert!(
            stored.plan.target.question().is_none(),
            "a role run, not a question head"
        );
        assert_eq!(
            stored.corpus.rows.len(),
            2,
            "both pairs split: {:?}",
            stored.corpus.rows
        );

        // Prepared: outstanding on the owner's authorization.
        let read = get_as_owner(&fixture, &run, 0).await;
        assert_eq!(read["state"], "prepared", "{read}");
        assert_eq!(
            read["progress"],
            json!({"status": "outstanding", "needs": "owner_authorization"}),
            "{read}"
        );
        assert_eq!(read["spec"], spec.as_str(), "{read}");
        assert!(read["hold"].is_null(), "{read}");
        assert_eq!(read["training"], prepared["training"], "{read}");

        // Authorized: running, queued for the host.
        let (status, handoff) = fixture.authorize(&run, &spec).await;
        assert_eq!(status, StatusCode::OK, "owner authorize: {handoff}");
        let read = get_as_owner(&fixture, &run, 0).await;
        assert_eq!(read["state"], "authorized", "{read}");
        assert_eq!(
            read["progress"],
            json!({"status": "running", "phase": "queued"}),
            "{read}"
        );

        // A bounded wait on a run nothing moves returns at its bound, and the
        // run stays as it was.
        let read = get_as_owner(&fixture, &run, 300).await;
        assert_eq!(read["state"], "authorized", "{read}");
        assert_eq!(
            read["progress"],
            json!({"status": "running", "phase": "queued"}),
            "{read}"
        );
        assert!(read["waited_ms"].as_u64() >= Some(300), "{read}");
        assert!(read["waited_ms"].as_u64() < Some(10_000), "{read}");

        // The host has no trainer for a role: its round holds the run, and the
        // read names the hold.
        fixture.coach_round().await;
        let read = get_as_owner(&fixture, &run, 0).await;
        assert_eq!(read["state"], "authorized", "{read}");
        assert_eq!(
            read["progress"],
            json!({"status": "outstanding", "needs": "host"}),
            "{read}"
        );
        assert_eq!(read["hold"]["code"], "training.no_connector", "{read}");

        // A wait above the cap is refused.
        let (status, body) = fixture
            .as_owner(GET_VERB, json!({"run": run, "wait_ms": 30_001}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // An unknown run reads as none.
        let (status, body) = fixture
            .as_owner(GET_VERB, json!({"run": oneiron::EntityId::now().to_hex()}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.is_null(), "{body}");
        fixture.finish().await;
    });
}

#[test]
fn prepare_takes_the_owners_own_proof() {
    run_on_engine_stack("role-prepare-agent", || async {
        let fixture = Fixture::new().await;
        let seeded = seed_role_run(&fixture.vault);
        let agent = fixture.pair_agent("role-prepare-agent", [0x52; 32]).await;

        let (status, body) = fixture
            .as_agent(
                &agent,
                PREPARE_VERB,
                json!({"draft": seeded.draft, "connector": CONNECTOR}),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "agent prepare: {body}");
        assert!(
            fixture
                .vault
                .training_runs()
                .expect("read the runs")
                .is_empty(),
            "a refused prepare stores no run"
        );

        // A connector this host does not name is refused for the owner too.
        let (status, body) = fixture
            .as_owner(
                PREPARE_VERB,
                json!({"draft": seeded.draft, "connector": "no-such-trainer"}),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unnamed connector: {body}");
        fixture.finish().await;
    });
}

#[test]
fn agent_reads_a_run_only_with_a_grant_listing_get() {
    run_on_engine_stack("role-get-agent", || async {
        let fixture = Fixture::new().await;
        let seeded = seed_role_run(&fixture.vault);
        let prepared = prepare_as_owner(&fixture, &seeded.draft).await;
        let run = prepared["run"].as_str().expect("run id").to_owned();
        let agent = fixture.pair_agent("role-get-agent", [0x53; 32]).await;

        let (status, body) = fixture
            .as_agent(&agent, GET_VERB, json!({"run": run}))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "no Grant: {body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|text| text.contains(GET_VERB)),
            "the refusal names the verb: {body}"
        );

        fixture
            .mint_grant(&agent.principal.to_hex(), &[GET_VERB])
            .await;
        let (status, read) = fixture
            .as_agent(&agent, GET_VERB, json!({"run": run}))
            .await;
        assert_eq!(status, StatusCode::OK, "granted agent: {read}");
        assert_eq!(
            read["progress"],
            json!({"status": "outstanding", "needs": "owner_authorization"}),
            "{read}"
        );
        assert_eq!(read["training"], prepared["training"], "{read}");
        assert!(
            read.get("held_out").is_none(),
            "the read never names the held-out split: {read}"
        );
        assert!(
            !read
                .to_string()
                .contains(prepared["held_out"]["artifact"].as_str().unwrap_or("-")),
            "the held-out artifact appears nowhere in the read: {read}"
        );
        fixture.finish().await;
    });
}
