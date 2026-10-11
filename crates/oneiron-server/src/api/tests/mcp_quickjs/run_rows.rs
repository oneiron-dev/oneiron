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

/// One field of a call outcome as the run's durable record keeps it.
fn recorded_field<'a>(outcome: &'a rmpv::Value, key: &str) -> Option<&'a str> {
    outcome
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))?
        .1
        .as_str()
}

/// Review repro (burn engine-prs-03): a run admitted while its slip was live
/// kept searching after the owner revoked it, and its results went back to
/// the revoked caller. A run row now meets the credential at each call, and
/// the run's results meet it once more before they leave: the step the slip
/// dies under reads nothing, and its caller gets the credential's refusal.
/// While the slip lives, the same search reads the slip's own words on its
/// read lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quickjs_a_revoked_slip_ends_its_runs_own_reads() {
    let search = "await self.memory.search({query: 'heron lantern'});";
    // Step 1 answers with nothing, so it speaks no trailing bubble: its
    // search is the one call of the step that meets the door.
    let scripts = vec![
        search.to_owned(),
        format!("try {{ {search} }} catch (error) {{}} finish('');"),
    ];
    let mode = code_mode_server(scripts);
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

    // Step 0 runs under the live slip, then yields at the soft step limit.
    let (_, body) = route_json(
        mode.server.clone(),
        run_request(actor, credential, credential),
    )
    .await;
    assert!(body.get("error").is_none(), "{body}");
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["result"]["status"], "yielded", "{body}");
    let searched = row_outcome(&body, "self.memory.search");
    assert_eq!(searched["kind"], "memory_search", "{body}");
    assert!(
        !searched["results"].as_array().unwrap().is_empty(),
        "the live slip's search reads its own words: {body}"
    );
    let run_id = oneiron::EntityId::from_hex(structured["run_id"].as_str().unwrap()).unwrap();

    // Re-enter the run, hold the model's answer for step 1 until the run
    // has asked for it, and revoke the slip before the guest's search runs.
    let held = mode.backend.scripts.lock().unwrap();
    let run = tokio::spawn(route_json(
        mode.server.clone(),
        run_request(actor, credential, credential),
    ));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while mode.backend.requests.lock().unwrap().len() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "the re-entered run never asked its model for step 1"
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
    assert_mcp_structured_error(&body, "mcp_auth_required");
    assert!(body.get("result").is_none(), "{body}");
    let record = mode
        .vault
        .get_code_run_replay_record(&run_id)
        .unwrap()
        .unwrap();
    assert_eq!(record.bridge_calls.len(), 2, "one search per step");
    let step_one = &record.bridge_calls[1];
    assert_eq!(step_one.effect.as_str(), "self.memory.search");
    assert_eq!(recorded_field(&step_one.outcome, "kind"), Some("denied"));
    assert_eq!(
        recorded_field(&step_one.outcome, "outcome"),
        Some("mcp_auth_required")
    );
}
