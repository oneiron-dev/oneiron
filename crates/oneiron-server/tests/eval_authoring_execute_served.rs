//! `vault.evals.authoring.execute` served over the real facade route (FIX
//! EVAL-AUTHORING-EXECUTE-SERVER-CASE): the owner's call runs one Coach
//! eval-authoring pass on a fake model and answers `Ran` with an `Applied`
//! record while the Coach attempt completes and its lease and `coach.host`
//! budget line settle; an agent with no Grant is refused FORBIDDEN and queues
//! no Coach job; an answer holding no plan ends the record `NoPlan` and the
//! attempt still completes.
//!
//! Reads JSON only (no engine type of the new verb), so on a main without the
//! verb every test fails on its first status assertion.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! eval_authoring_execute_served`.
#![cfg(oneiron_test_support)]

#[path = "support/eval_authoring_fixture.rs"]
mod eval_authoring_fixture;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use axum::http::StatusCode;
use eval_authoring_fixture::{
    Fixture, VERB, answer_without_plan, assert_budget_settled, assert_no_eval_authoring_job_queued,
    echo_plan, run_on_engine_stack,
};
use oneiron::skill_optimize::eval_authoring_skill_id;
use serde_json::{Value, json};

/// The digest the fake received in the pass's user message.
fn digest_the_model_saw(fixture: &Fixture) -> String {
    let calls = fixture.model.seen();
    let content = calls.last().expect("the model was called").body["messages"]
        .as_array()
        .and_then(|messages| messages.last())
        .and_then(|message| message["content"].as_str())
        .expect("the inventory message")
        .to_owned();
    serde_json::from_str::<Value>(&content).expect("inventory JSON")["inventory_digest"]
        .as_str()
        .expect("inventory digest")
        .to_owned()
}

#[test]
fn owner_call_applies_the_pass_and_settles_the_attempt() {
    run_on_engine_stack("execute-owner-applied", || async {
        let fixture = Fixture::new(None, vec![], Some(echo_plan())).await;
        let (status, answer) = fixture.as_owner(VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner execute: {answer}");
        assert_eq!(answer["state"], "ran", "{answer}");
        let execution = &answer["execution"];
        assert_eq!(execution["outcome"], "applied", "{answer}");
        // The host-root credential acts as the vault's embedded owner.
        let owner = fixture
            .vault
            .ensure_embedded_owner_actor()
            .expect("embedded owner")
            .to_hex();
        assert_eq!(execution["caller"]["kind"], "owner", "{answer}");
        assert_eq!(execution["caller"]["person"], owner.as_str(), "{answer}");
        assert_eq!(
            execution["skill"]["skill"],
            eval_authoring_skill_id()
                .expect("eval-authoring skill id")
                .to_hex()
                .as_str(),
            "{answer}"
        );
        assert_eq!(execution["skill"]["revision"], "1", "{answer}");
        assert_eq!(
            execution["inventory_digest"],
            digest_the_model_saw(&fixture).as_str(),
            "{answer}"
        );
        assert!(execution["report"].is_object(), "{answer}");
        assert_eq!(execution["report"]["cases_recorded"], 0, "{answer}");
        assert!(!execution["requested_at"].is_null() && !execution["ended_at"].is_null());

        // The fake saw exactly the pass's one call.
        let calls = fixture.model.seen();
        assert_eq!(calls.len(), 1, "one model call");
        assert_eq!(fixture.eval_authoring_calls(), 1, "carrying the skill body");
        assert_eq!(calls[0].path, "/v1/chat/completions");

        // The attempt completed, the lease and the budget line settled.
        let attempt = execution["attempt"].as_str().expect("attempt id");
        let result = fixture.result_of(attempt).await;
        assert_eq!(result["state"], "Completed", "{result}");
        assert_eq!(result["terminal"], true, "{result}");
        assert!(result["last_error"].is_null(), "{result}");
        assert_eq!(
            result["execution"], *execution,
            "the result reads the kept record"
        );
        assert_budget_settled(&fixture.vault);
        fixture.finish().await;
    });
}

#[test]
fn agent_without_a_grant_is_refused_and_queues_nothing() {
    run_on_engine_stack("execute-agent-grant", || async {
        let fixture = Fixture::new(None, vec![], Some(echo_plan())).await;
        let agent = fixture
            .pair_agent("execute-no-grant-agent", [0x61; 32])
            .await;

        let (status, body) = fixture.as_agent(&agent, VERB, json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "no Grant: {body}");
        assert_eq!(body["error"]["code"], "FORBIDDEN", "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|text| text.contains(VERB)),
            "the refusal names the verb: {body}"
        );
        assert_eq!(fixture.model.seen().len(), 0, "no model call");
        assert_no_eval_authoring_job_queued(&fixture.vault);

        // Positive control: the same agent with a Grant listing the verb runs.
        let grant = fixture.mint_execute_grant(&agent.principal.to_hex()).await;
        let (status, answer) = fixture.as_agent(&agent, VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "granted agent: {answer}");
        assert_eq!(answer["state"], "ran", "{answer}");
        let caller = &answer["execution"]["caller"];
        assert_eq!(caller["kind"], "agent", "{answer}");
        assert_eq!(
            caller["agent"],
            agent.principal.to_hex().as_str(),
            "{answer}"
        );
        assert_eq!(caller["grant"], grant.as_str(), "{answer}");
        fixture.finish().await;
    });
}

#[test]
fn answer_without_a_plan_ends_the_record_no_plan_and_completes_the_attempt() {
    run_on_engine_stack("execute-no-plan", || async {
        let fixture = Fixture::new(None, vec![], Some(answer_without_plan())).await;
        let (status, answer) = fixture.as_owner(VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner execute: {answer}");
        assert_eq!(answer["state"], "ran", "{answer}");
        let execution = &answer["execution"];
        assert_eq!(execution["outcome"], "no_plan", "{answer}");
        assert!(execution["report"].is_null(), "{answer}");
        assert_eq!(execution["skill"]["revision"], "1", "{answer}");
        assert_eq!(
            execution["inventory_digest"],
            digest_the_model_saw(&fixture).as_str(),
            "{answer}"
        );
        assert_eq!(fixture.model.seen().len(), 1, "one model call");

        // NoPlan settles COMPLETED (finish returns Ok: eval_authoring.rs:157).
        let attempt = execution["attempt"].as_str().expect("attempt id");
        let result = fixture.result_of(attempt).await;
        assert_eq!(result["state"], "Completed", "{result}");
        assert_eq!(result["terminal"], true, "{result}");
        assert!(result["last_error"].is_null(), "{result}");
        assert_eq!(result["execution"], *execution, "{result}");
        assert_budget_settled(&fixture.vault);
        fixture.finish().await;
    });
}
