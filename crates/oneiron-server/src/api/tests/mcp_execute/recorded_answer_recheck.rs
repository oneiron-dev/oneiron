//! Recorded-answer rechecks for caller-source runs (FIX CODE-MODE-LENDING-W11).
//!
//! A caller-source run parks after a Bridge read through `vault.search`; the
//! SAME credential is then re-registered without that row; the resume holds
//! instead of releasing the recorded answer. The control keeps the binding
//! and gets the same answer back.

use super::*;

/// Witnesses a message for `vault.search` to find.
fn witness_searchable_turn(vault: &oneiron::Vault, actor: oneiron::EntityId, text: &str) {
    vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .witness(&oneiron::memory::WitnessTurn {
            conversation_ref: oneiron::EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            project: None,
            messages: vec![oneiron::memory::WitnessMessage {
                id: None,
                author: oneiron::memory::WitnessAuthor::User,
                message_type: "text".to_owned(),
                content: text.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 1_772_400_000,
            assertions: oneiron::memory::WitnessAssertions::default(),
        })
        .expect("the searchable turn");
}

/// Re-registers `label`'s SAME credential token under `verbs`, keeping actor and scope.
async fn rebind_credential(
    server: &Arc<SyncServer>,
    label: &str,
    actor: oneiron::EntityId,
    verbs: &[&'static str],
) {
    let token = mcp_registered_credential(server, label);
    let mut registry = server.mcp_registry.lock().await;
    assert!(registry.unregister(&token), "the credential was registered");
    registry
        .register(
            &token,
            crate::mcp::McpConnectorActorRecord::new(
                actor,
                oneiron::EdgeActorClass::Human,
                crate::mcp::McpConnectorScope::vault_wide(),
            )
            .with_bound_verbs(verbs.iter().copied()),
        )
        .expect("re-register the same credential with new bounds");
}

/// T1 is red without Part 1 item 3c: a resumed caller run whose row lost its
/// binding must hold instead of reading the answer or dispatching again.
#[tokio::test]
async fn a_resumed_caller_run_does_not_get_back_an_answer_its_row_no_longer_binds() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_7101);
    let turn = seeded_test_entity_id(0x0024_7102);
    let credential = "p5-search-recheck-credential";
    register_bound_verb_mcp_actor(
        &seatless.server,
        credential,
        actor,
        &["execute", "resume", "vault.search", "tasks.answer"],
    )
    .await;
    seed_turn(&seatless.vault, turn, actor);
    witness_searchable_turn(
        &seatless.vault,
        actor,
        "The heron lantern hangs by the north gate.",
    );
    let code = format!(
        r#"const found = await vault.search({{query: "heron lantern"}});
const results = found.results;
const r = await ask({{who: {{responder: {{human: {{actor_ref: "{actor}"}}}}}}, what: {{reference: {{turn: "{turn}"}}, revision: 1, options: {{}}, context_refs: []}}}});
const ans = await wait({{handle: r.handle, step_key: "p5-search-wait"}});
return {{found_ids: results.map(h => h.id), ans: ans}};"#,
        actor = actor.to_hex(),
        turn = turn.to_hex()
    );
    let run_ref = "p5-search-park";
    let parked = execute(&seatless.server, credential, "park", &code, Some(run_ref)).await;
    let waiting = structured(&parked);
    assert_eq!(waiting["status"], "paused", "{parked:?}");
    assert_eq!(waiting["run_ref"], run_ref, "{parked:?}");
    assert_eq!(waiting["waiting_on"]["kind"], "answer", "{parked:?}");
    assert!(
        !waiting["calls"].as_array().expect("calls").is_empty(),
        "{parked:?}"
    );
    let search_call = call_entry(&waiting["calls"], "self.memory.search");
    assert_eq!(search_call["outcome"], "read", "{parked:?}");
    call_entry(&waiting["calls"], "ask");
    let context = mcp_test_context(&seatless.server, credential, "ctx").await;
    let run_id = crate::mcp::mcp_code_run_id(run_ref, &context);
    let parked_record = seatless
        .vault
        .get_code_run_replay_record(&run_id)
        .unwrap()
        .expect("a record after park");
    let parked_len = parked_record.bridge_calls.len();
    assert_eq!(
        parked_record
            .bridge_calls
            .iter()
            .filter(|call| call.effect.as_str() == "self.memory.search")
            .count(),
        1,
        "one live search dispatch: {parked:?}"
    );

    // The SAME credential loses the producer row; entry and wait rows stay.
    rebind_credential(
        &seatless.server,
        credential,
        actor,
        &["execute", "resume", "tasks.answer"],
    )
    .await;
    let context_after = mcp_test_context(&seatless.server, credential, "ctx-after").await;
    let run_id_after = crate::mcp::mcp_code_run_id(run_ref, &context_after);
    assert_eq!(run_id_after, run_id, "same credential, same run");

    let answer = json!({"result_ref": actor.to_hex(), "option": null, "inform_for": null});
    let held = resume(
        &seatless.server,
        credential,
        "answer",
        run_ref,
        Some(answer),
    )
    .await;
    let refused = structured(&held);
    assert_eq!(refused["status"], "error", "{held:?}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("the bound door no longer releases the caller source reply"),
        "{held:?}"
    );
    assert!(refused["result"].is_null(), "{held:?}");
    let held_search = call_entry(&refused["calls"], "self.memory.search");
    assert_eq!(held_search["outcome"], "read", "{held:?}");
    let held_record = seatless
        .vault
        .get_code_run_replay_record(&run_id)
        .unwrap()
        .expect("the record stands");
    assert_eq!(
        held_record.bridge_calls.len(),
        parked_len,
        "the producer is not dispatched again"
    );
    assert_eq!(
        held_record
            .bridge_calls
            .iter()
            .filter(|call| call.effect.as_str() == "self.memory.search")
            .count(),
        1,
        "{held:?}"
    );
}

/// Proves the control: with the binding kept, the resumed run gets the same
/// answer back and the producer was dispatched once.
#[tokio::test]
async fn a_resumed_caller_run_gets_back_an_answer_its_row_still_binds() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_7111);
    let turn = seeded_test_entity_id(0x0024_7112);
    let credential = "p5-search-control-credential";
    register_bound_verb_mcp_actor(
        &seatless.server,
        credential,
        actor,
        &["execute", "resume", "vault.search", "tasks.answer"],
    )
    .await;
    seed_turn(&seatless.vault, turn, actor);
    witness_searchable_turn(
        &seatless.vault,
        actor,
        "The heron lantern hangs by the north gate.",
    );
    let code = format!(
        r#"const found = await vault.search({{query: "heron lantern"}});
const results = found.results;
const r = await ask({{who: {{responder: {{human: {{actor_ref: "{actor}"}}}}}}, what: {{reference: {{turn: "{turn}"}}, revision: 1, options: {{}}, context_refs: []}}}});
const ans = await wait({{handle: r.handle, step_key: "p5-control-wait"}});
return {{found_ids: results.map(h => h.id), ans: ans}};"#,
        actor = actor.to_hex(),
        turn = turn.to_hex()
    );
    let run_ref = "p5-control-park";
    let parked = execute(&seatless.server, credential, "park", &code, Some(run_ref)).await;
    let waiting = structured(&parked);
    assert_eq!(waiting["status"], "paused", "{parked:?}");
    assert_eq!(waiting["waiting_on"]["kind"], "answer", "{parked:?}");
    let search_call = call_entry(&waiting["calls"], "self.memory.search");
    assert_eq!(search_call["outcome"], "read", "{parked:?}");
    let context = mcp_test_context(&seatless.server, credential, "ctx").await;
    let run_id = crate::mcp::mcp_code_run_id(run_ref, &context);
    let parked_record = seatless
        .vault
        .get_code_run_replay_record(&run_id)
        .unwrap()
        .expect("a record after park");
    let search = parked_record
        .bridge_calls
        .iter()
        .find(|call| call.effect == oneiron::code_run::SelfEffect::MemorySearch)
        .expect("the parked search row");
    let results = oneiron_contracts::msgpack::Entries::of(&search.outcome)
        .unwrap()
        .require("results")
        .unwrap()
        .as_array()
        .expect("the recorded search hits");
    assert!(
        !results.is_empty(),
        "the search found the witnessed message"
    );
    let found_ids: Vec<_> = results
        .iter()
        .map(|hit| {
            let id = oneiron_contracts::msgpack::Entries::of(hit)
                .unwrap()
                .require("id")
                .unwrap();
            let rmpv::Value::Binary(bytes) = id else {
                panic!("a recorded hit has a binary entity ID");
            };
            oneiron::EntityId::from_bytes(bytes.as_slice().try_into().unwrap())
                .unwrap()
                .to_hex()
        })
        .collect();

    let answer = json!({"result_ref": actor.to_hex(), "option": null, "inform_for": null});
    let done = resume(
        &seatless.server,
        credential,
        "answer",
        run_ref,
        Some(answer),
    )
    .await;
    let completed = structured(&done);
    assert_eq!(completed["status"], "complete", "{done:?}");
    assert_eq!(completed["run_ref"], run_ref, "{done:?}");
    assert_eq!(
        completed["result"]["found_ids"],
        json!(found_ids),
        "the guest sees the same search hits in order: {done:?}"
    );
    assert!(!completed["result"]["ans"].is_null(), "{done:?}");
    assert_eq!(completed["tree_reads"], 0, "{done:?}");
    assert!(completed["console"].is_array(), "{done:?}");
    let replayed_search = call_entry(&completed["calls"], "self.memory.search");
    assert_eq!(replayed_search["outcome"], "read", "{done:?}");
    let done_record = seatless
        .vault
        .get_code_run_replay_record(&run_id)
        .unwrap()
        .expect("a record after resume");
    assert_eq!(
        done_record
            .bridge_calls
            .iter()
            .filter(|call| call.effect.as_str() == "self.memory.search")
            .count(),
        1,
        "the producer was dispatched once: {done:?}"
    );
}
