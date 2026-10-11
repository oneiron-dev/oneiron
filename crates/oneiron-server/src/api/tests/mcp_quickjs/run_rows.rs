//! The rows a code run serves itself (`self.memory.search`, `put_claim`,
//! `supersede_claim`, `put_edge`) meet the connector's door at each call, as
//! the rows its host serves do (ARCH-0028: narrowing per connector at call
//! time).

use super::*;

/// One run whose guest searches, then states a claim, catching each refusal.
fn search_then_claim(claim: oneiron::EntityId, subject: oneiron::EntityId) -> String {
    format!(
        "const seen = []; \
         try {{ await self.memory.search({{query: 'heron lantern'}}); seen.push('searched'); }} \
         catch (error) {{ seen.push('search refused'); }} \
         try {{ await self.memory.put_claim({{id: '{}', predicate: 'profile.favorite_drink', \
         subject: '{}', value: 'tea'}}); seen.push('claimed'); }} \
         catch (error) {{ seen.push('claim refused'); }} \
         finish(seen.join(', '));",
        claim.to_hex(),
        subject.to_hex()
    )
}

/// One `execute_code` call on `/mcp` under `credential`.
fn run_request(actor: oneiron::EntityId, credential: &str, run_ref: &str) -> Request<Body> {
    let args = mcp_merge_args(
        mcp_endpoint_envelope(actor, "write_memory"),
        json!({"run_ref": run_ref, "task": "search, then state a favorite drink"}),
    );
    mcp_endpoint_call_request("/mcp", credential, run_ref, "execute_code", args)
}

/// The outcome of the run's call to `effect`, from its step log.
fn row_outcome(body: &Value, effect: &str) -> Value {
    body["result"]["structuredContent"]["steps"]
        .as_array()
        .unwrap_or_else(|| panic!("step log: {body}"))
        .iter()
        .find(|step| step["effect"] == effect)
        .unwrap_or_else(|| panic!("no {effect} call: {body}"))["outcome"]
        .clone()
}

/// A run row the door refused, as the step log records it.
fn row_refusal(effect: &str, code: &str) -> Value {
    json!({"kind": "denied", "effect": effect, "outcome": code, "reason_codes": []})
}

/// Review repro (burn engine-prs-03): a connector bound only to `execute_code`
/// made its run `put_claim` and the claim committed, where `claim_upsert`
/// would have answered `mcp_verb_not_bound`; its run's search read the index
/// too. A run row now needs its own binding: refused, nothing stored. A
/// connector bound to the rows by name runs both.
#[tokio::test]
async fn quickjs_run_rows_need_the_connectors_binding() {
    let subject = seeded_test_entity_id(0x0024_65b1);
    let claim = seeded_test_entity_id(0x0024_65b2);
    let script = search_then_claim(claim, subject);
    let mode = code_mode_server(vec![script.clone(), script]);
    mode.vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"quickjs subject",
        )
        .unwrap();

    let bound = seeded_test_entity_id(0x0024_65b3);
    register_bound_verb_mcp_actor(&mode.server, "quickjs-rows-bound", bound, &["execute_code"])
        .await;
    let (_, body) = route_json(
        mode.server.clone(),
        run_request(bound, "quickjs-rows-bound", "quickjs-rows-bound"),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    for effect in ["self.memory.search", "self.memory.put_claim"] {
        assert_eq!(
            row_outcome(&body, effect),
            row_refusal(effect, "mcp_verb_not_bound"),
            "{body}"
        );
    }
    assert!(mode.vault.get_claim(&claim).unwrap().is_none(), "{body}");

    let named = seeded_test_entity_id(0x0024_65b4);
    register_bound_verb_mcp_actor(
        &mode.server,
        "quickjs-rows-named",
        named,
        &["execute_code", "search", "put_claim"],
    )
    .await;
    let (_, body) = route_json(
        mode.server.clone(),
        run_request(named, "quickjs-rows-named", "quickjs-rows-named"),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(
        row_outcome(&body, "self.memory.search")["kind"],
        "memory_search",
        "{body}"
    );
    assert!(mode.vault.get_claim(&claim).unwrap().is_some(), "{body}");
}

/// Review repro (burn engine-prs-03): a run admitted while its slip was live
/// kept searching after the owner revoked it. A run row now meets the
/// credential at each call: the run whose slip is revoked before its model
/// answers reads nothing. While the slip lives, the same search reads the
/// slip's own words on its read lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quickjs_a_revoked_slip_ends_its_runs_own_reads() {
    // An empty answer: the run's trailing speech meets the door too, and this
    // test reads the search's own refusal.
    let script = "try { await self.memory.search({query: 'heron lantern'}); } catch (error) {} \
        finish('');";
    let mode = code_mode_server(vec![script.to_owned(), script.to_owned()]);
    let actor = seeded_test_entity_id(0x0024_65b5);
    let credential = "quickjs-rows-revoked";
    register_mcp_actor(
        &mode.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    witness_through_tool_list(
        &mode.server,
        credential,
        actor,
        "The heron lantern hangs by the north gate.",
    )
    .await;

    let (_, body) = route_json(
        mode.server.clone(),
        run_request(actor, credential, "quickjs-rows-live"),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let searched = row_outcome(&body, "self.memory.search");
    assert_eq!(searched["kind"], "memory_search", "{body}");
    assert!(
        !searched["results"].as_array().unwrap().is_empty(),
        "the live slip's search reads its own words: {body}"
    );

    // Hold the model's answer until the run is admitted and its seat chosen,
    // then revoke the slip before the guest's search runs.
    let judged = mode.judge.calls.load(Ordering::SeqCst);
    let held = mode.backend.requests.lock().unwrap();
    let run = tokio::spawn(route_json(
        mode.server.clone(),
        run_request(actor, credential, "quickjs-rows-revoked"),
    ));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while mode.judge.calls.load(Ordering::SeqCst) == judged {
        assert!(
            std::time::Instant::now() < deadline,
            "the run never chose a seat"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(b"secret").unwrap();
    let revoked = mode
        .vault
        .revoke_held_capability_slips(&issuer, &actor.to_hex(), [0; 32])
        .unwrap();
    assert!(!revoked.is_empty(), "fixture check: the slip was live");
    drop(held);

    let (_, body) = run.await.unwrap();
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(
        row_outcome(&body, "self.memory.search"),
        row_refusal("self.memory.search", "mcp_auth_required"),
        "{body}"
    );
}
