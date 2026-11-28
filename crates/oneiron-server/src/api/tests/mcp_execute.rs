//! The MCP `execute` and `resume` tools over caller-source runs (FIX EXECUTE-CALLER-CODE).
//!
//! Each test's comment names what it proves (cutover brief part 6): (a) both endpoints list
//! `execute` and `resume` beside their own tools on a ready host, including a seatless one,
//! and neither lists `execute_code` or `read_result`; (b) `execute`
//! mints a run ref, replays the stored result, and refuses a reused ref; (c) `resume`
//! continues a paused run, repeats a complete one, and refuses an unknown ref. The
//! verb-behavior tests (d)-(j) live in `verbs`.

use super::mcp_quickjs::{code_mode_server_with, factory};
use super::*;

mod recorded_answer_recheck;
mod verbs;

/// One server bound to the production caller-source provider: the verified component with
/// no generative seat, prompt package or model (FIX EXECUTE-CALLER-CODE).
struct Seatless {
    server: Arc<SyncServer>,
    vault: Arc<oneiron::Vault>,
    _dir: tempfile::TempDir,
}

fn seatless_server() -> Seatless {
    seatless_server_with_vault_config(oneiron::VaultConfig::device())
}

fn seatless_server_with_vault_config(config: oneiron::VaultConfig) -> Seatless {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), config).unwrap());
    crate::test_credentials::install_fixture_keystore(&vault, b"secret");
    let provider = crate::mcp::McpQuickJsProvider::for_caller_source(Arc::new(factory())).unwrap();
    let server = Arc::new(
        SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("secret".to_owned()),
                ..Default::default()
            },
        )
        .unwrap()
        .with_mcp_quickjs_provider(provider, crate::mcp::CodeRunLimits::default()),
    );
    Seatless {
        server,
        vault,
        _dir: dir,
    }
}

/// One `execute` call on `/mcp`: closed args, no envelope (FIX EXECUTE-CALLER-CODE).
async fn execute(
    server: &Arc<SyncServer>,
    credential: &str,
    id: &str,
    code: &str,
    run_ref: Option<&str>,
) -> Value {
    let mut args = json!({ "code": code });
    if let Some(run_ref) = run_ref {
        args["run_ref"] = json!(run_ref);
    }
    let (_, body) = route_json(
        server.clone(),
        mcp_endpoint_call_request("/mcp", credential, id, "execute", args),
    )
    .await;
    body
}

/// One `resume` call on `/mcp`.
async fn resume(
    server: &Arc<SyncServer>,
    credential: &str,
    id: &str,
    run_ref: &str,
    answer: Option<Value>,
) -> Value {
    let mut args = json!({ "run_ref": run_ref });
    if let Some(answer) = answer {
        args["answer"] = answer;
    }
    let (_, body) = route_json(
        server.clone(),
        mcp_endpoint_call_request("/mcp", credential, id, "resume", args),
    )
    .await;
    body
}

/// The new-shape payload of a call that reached its run: pre-gate failures stay JSON-RPC,
/// while everything past admission renders `status` here.
fn structured(body: &Value) -> &Value {
    assert!(
        body.get("error").is_none(),
        "the call reached its run: {body:?}"
    );
    &body["result"]["structuredContent"]
}

/// A minted run ref: `run:` and 16 lowercase hex chars.
fn assert_minted_run_ref(run_ref: &str) {
    assert!(
        run_ref.len() == 20
            && run_ref.starts_with("run:")
            && run_ref[4..]
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "a minted run_ref: {run_ref:?}"
    );
}

/// Seeds a PERSON the test's claims are about, readable by `actor`.
fn seed_subject(vault: &oneiron::Vault, subject: oneiron::EntityId, actor: oneiron::EntityId) {
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"execute subject",
        )
        .unwrap();
    put_actor_read_grant(vault, actor, None);
}

/// Gives `actor` an explicit `auto` actor ceiling, so its caller-code writes land instead
/// of proposing: approval determinism for tests that count on landed writes.
fn seed_auto_ceiling(
    vault: &oneiron::Vault,
    actor: oneiron::EntityId,
    manifest: oneiron::EntityId,
) {
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        vault,
        oneiron::write_envelope::WriteActor::new(owner, oneiron::edge::EdgeActorClass::Human),
        manifest,
        &json!({
            "schema_version": "1.2", "pack_id": "execute-auto-ceiling", "pack_version": "v1",
            "min_engine_version": "0.0.0",
            "defaults": { "criticality": "normal", "sensitivity": "normal" },
            "rules": [],
            "actor_ceilings": [
                { "actor_class": "human", "ceiling": "auto" },
                { "actor_class": "human", "actor_ref": actor.to_hex(), "ceiling": "auto" },
            ],
        }),
    )
    .unwrap();
}

/// How many CLAIM rows the vault holds.
fn claim_count(vault: &oneiron::Vault) -> usize {
    vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_CLAIM)
        .expect("list claims")
        .len()
}

/// The `calls` entry for `verb`, failing loudly when the run never called it.
fn call_entry<'a>(calls: &'a Value, verb: &str) -> &'a Value {
    calls
        .as_array()
        .expect("calls is an array")
        .iter()
        .find(|call| call["verb"] == verb)
        .unwrap_or_else(|| panic!("the run called {verb}: {calls:?}"))
}

/// Seeds a TURN an ask can reference, readable by `actor`.
fn seed_turn(vault: &oneiron::Vault, turn: oneiron::EntityId, actor: oneiron::EntityId) {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("question"),
        )]),
    )
    .expect("turn body");
    vault
        .put_entity(
            &turn,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 2, end: 2 },
            2,
            &body,
        )
        .expect("question turn");
    put_actor_read_grant(vault, actor, None);
}

/// The listing of a ready host on `path`: the two code tools beside the endpoint's own
/// tools (setup on `/mcp`, the generated verbs on tool-first, the action door on both), and
/// no retired tool.
fn assert_ready_listing(path: &str, listing: &Value) {
    let names = mcp_listed_tool_names(listing);
    for name in ["execute", "resume", "invoke_action"] {
        assert!(names.contains(&name), "{path} lists {name}: {names:?}");
    }
    assert_eq!(
        names.contains(&"setup_oneiron"),
        path == "/mcp",
        "{path}: {names:?}"
    );
    for retired in ["execute_code", "read_result"] {
        assert!(
            !names.contains(&retired),
            "{path} lists no {retired}: {names:?}"
        );
    }
}

/// Proves (a): on a ready host both endpoints list `execute` and `resume` beside their own
/// tools, and neither lists `execute_code` or `read_result`.
#[tokio::test]
async fn ready_host_lists_execute_and_resume_on_both_endpoints() {
    let mode = code_mode_server_with(Vec::new(), None);
    let actor = seeded_test_entity_id(0x0024_6601);
    let credential = "execute-listing-credential";
    register_mcp_actor(
        &mode.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
        let (_, listing) = route_json(
            mode.server.clone(),
            mcp_list_request(path, credential, "list"),
        )
        .await;
        assert_ready_listing(path, &listing);
    }
}

/// Proves (a): a host bound with caller-source readiness and no models lists both tools,
/// and runs caller code with no model seat.
#[tokio::test]
async fn seatless_host_lists_execute_and_resume_with_no_models() {
    let seatless = seatless_server();
    let host = seatless
        .server
        .code_execution_host()
        .expect("a host is bound");
    assert!(host.production_runtime_available());
    assert!(
        !host.task_runtime_available(),
        "caller-source readiness only: no task seat"
    );
    let actor = seeded_test_entity_id(0x0024_6602);
    let credential = "execute-seatless-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
        let (_, listing) = route_json(
            seatless.server.clone(),
            mcp_list_request(path, credential, "list"),
        )
        .await;
        assert_ready_listing(path, &listing);
    }
    // A trivial return completes (any model call is refused: the provider has no seat).
    let body = execute(&seatless.server, credential, "canary", "return 1;", None).await;
    let answered = structured(&body);
    assert_eq!(answered["status"], "complete", "{body:?}");
    assert_eq!(answered["result"], json!(1), "{body:?}");
}

/// Proves (b): `execute` with no run_ref mints one; the same run_ref and code replays the
/// stored result with no second write; other code under that run_ref answers RUN_REF_REUSED
/// and changes nothing.
#[tokio::test]
async fn execute_mints_run_ref_replays_same_code_and_refuses_reused_ref() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6611);
    let subject = seeded_test_entity_id(0x0024_6612);
    let credential = "execute-mint-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    seed_subject(&seatless.vault, subject, actor);
    seed_auto_ceiling(&seatless.vault, actor, seeded_test_entity_id(0x0024_6613));
    let code = format!(
        r#"return await vault.remember({{subject_ref: "{hex}", predicate: "test.execute_b", value: {{n: 1}}, confidence: 0.9, source: "observed"}});"#,
        hex = subject.to_hex()
    );
    let before = claim_count(&seatless.vault);
    let first = execute(&seatless.server, credential, "first", &code, None).await;
    let answered = structured(&first).clone();
    assert_eq!(answered["status"], "complete", "{first:?}");
    let run_ref = answered["run_ref"].as_str().expect("run_ref").to_owned();
    assert_minted_run_ref(&run_ref);
    assert_eq!(answered["tree_reads"], 0, "{first:?}");
    assert!(answered["console"].is_array(), "{first:?}");
    assert_eq!(
        claim_count(&seatless.vault),
        before + 1,
        "one write lands: {first:?}"
    );
    let text = first["result"]["content"].to_string();
    assert!(
        text.contains(&run_ref) && text.contains("result:"),
        "one header line, then the result: {text}"
    );

    let replayed = execute(
        &seatless.server,
        credential,
        "replay",
        &code,
        Some(&run_ref),
    )
    .await;
    let again = structured(&replayed);
    assert_eq!(again["status"], "complete", "{replayed:?}");
    assert_eq!(again["run_ref"], json!(run_ref), "{replayed:?}");
    assert_eq!(
        again["result"], answered["result"],
        "the replay returns the stored result: {replayed:?}"
    );
    assert_eq!(
        claim_count(&seatless.vault),
        before + 1,
        "no second write: {replayed:?}"
    );

    let other = execute(
        &seatless.server,
        credential,
        "reused",
        "return 2;",
        Some(&run_ref),
    )
    .await;
    let refused = structured(&other);
    assert_eq!(refused["status"], "error", "{other:?}");
    assert_eq!(refused["error"]["code"], "RUN_REF_REUSED", "{other:?}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("new run_ref"),
        "the hint names a new run_ref: {other:?}"
    );
    assert_eq!(refused["run_ref"], run_ref, "{other:?}");
    assert_eq!(
        claim_count(&seatless.vault),
        before + 1,
        "nothing changes: {other:?}"
    );
}

/// Proves (c): a run paused on an ask answers `paused` with `waiting_on`; `resume` with the
/// answer completes it in the execute shape.
#[tokio::test]
async fn resume_completes_a_run_paused_on_an_ask() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6621);
    let turn = seeded_test_entity_id(0x0024_6622);
    let credential = "execute-ask-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    seed_turn(&seatless.vault, turn, actor);
    // A bare ask mints its receipt; the wait on its handle parks the run (the TASK ask/wait
    // lane: a prompt-only ask has no human task target on the MCP host and fails closed).
    let code = format!(
        r#"const r = await ask({{who: {{responder: {{human: {{actor_ref: "{actor}"}}}}}}, what: {{reference: {{turn: "{turn}"}}, revision: 1, options: {{}}, context_refs: []}}}}); return await wait({{handle: r.handle, step_key: "c-wait"}});"#,
        actor = actor.to_hex(),
        turn = turn.to_hex()
    );
    let paused = execute(
        &seatless.server,
        credential,
        "park",
        &code,
        Some("c-ask-run"),
    )
    .await;
    let waiting = structured(&paused);
    assert_eq!(waiting["status"], "paused", "{paused:?}");
    assert_eq!(waiting["run_ref"], "c-ask-run", "{paused:?}");
    assert_eq!(waiting["waiting_on"]["kind"], "answer", "{paused:?}");
    assert!(
        !waiting["calls"].as_array().expect("calls").is_empty(),
        "{paused:?}"
    );
    call_entry(&waiting["calls"], "ask");

    let answer = json!({"result_ref": actor.to_hex(), "option": null, "inform_for": null});
    let done = resume(
        &seatless.server,
        credential,
        "answer",
        "c-ask-run",
        Some(answer),
    )
    .await;
    let completed = structured(&done);
    assert_eq!(completed["status"], "complete", "{done:?}");
    assert_eq!(completed["run_ref"], "c-ask-run", "{done:?}");
    assert!(!completed["result"].is_null(), "{done:?}");
    assert_eq!(completed["tree_reads"], 0, "{done:?}");
    assert!(completed["console"].is_array(), "{done:?}");
}

/// Proves (c): `resume` of a complete run returns its stored result.
#[tokio::test]
async fn resume_of_a_complete_run_returns_its_stored_result() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6631);
    let credential = "execute-repeat-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let first = execute(
        &seatless.server,
        credential,
        "run",
        r#"return {hello: "world"};"#,
        Some("c-complete-run"),
    )
    .await;
    let answered = structured(&first).clone();
    assert_eq!(answered["status"], "complete", "{first:?}");
    let again = resume(
        &seatless.server,
        credential,
        "retry",
        "c-complete-run",
        None,
    )
    .await;
    let repeated = structured(&again);
    assert_eq!(repeated["status"], "complete", "{again:?}");
    assert_eq!(repeated["run_ref"], "c-complete-run", "{again:?}");
    assert_eq!(
        repeated["result"], answered["result"],
        "the stored result comes back: {again:?}"
    );
}

/// Proves (c): `resume` of an unknown run_ref answers UNKNOWN_REF and creates no record.
#[tokio::test]
async fn resume_of_an_unknown_run_ref_answers_unknown_ref_and_writes_nothing() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6641);
    let credential = "execute-unknown-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let missing = resume(&seatless.server, credential, "missing", "no-such-run", None).await;
    let refused = structured(&missing);
    assert_eq!(refused["status"], "error", "{missing:?}");
    assert_eq!(refused["error"]["code"], "UNKNOWN_REF", "{missing:?}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no run under this run_ref"),
        "{missing:?}"
    );
    let context = mcp_test_context(&seatless.server, credential, "ctx").await;
    let run_id = crate::mcp::mcp_code_run_id("no-such-run", &context);
    assert!(
        seatless
            .vault
            .get_code_run_replay_record(&run_id)
            .unwrap()
            .is_none(),
        "nothing is written"
    );
}

/// Proves the plan's capped result remains readable in code by its own
/// credential, and the same run_ref resolves nothing for another credential.
#[tokio::test]
async fn caller_reads_past_the_result_cap_only_under_its_own_credential() {
    let seatless = seatless_server();
    let first = "execute-cap-credential";
    let second = "execute-cap-other";
    for (label, id) in [(first, 0x0024_66c1), (second, 0x0024_66c2)] {
        register_mcp_actor(
            &seatless.server,
            label,
            seeded_test_entity_id(id),
            oneiron::EdgeActorClass::Human,
        )
        .await;
    }
    let body = execute(
        &seatless.server,
        first,
        "large",
        "return 'a'.repeat(20000) + 'tail-cap-proof';",
        Some("cap-run"),
    )
    .await;
    let answer = structured(&body);
    assert_eq!(answer["status"], "complete", "{body:?}");
    assert_eq!(answer["result"].as_str().map(str::len), Some(20_000));
    assert!(
        body["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("vault.runs.read_result"))
    );
    let reference = body["result"]["_meta"]["result_ref"]
        .as_str()
        .expect("a clipped result has a stored reference");
    let input =
        json!({"run_ref": "cap-run", "result_ref": reference, "offset": 20_001, "limit": 20});
    let read = format!("return await vault.runs.read_result({input});");
    let own = execute(&seatless.server, first, "read-own", &read, None).await;
    assert!(
        structured(&own)["result"]
            .to_string()
            .contains("tail-cap-proof"),
        "{own:?}"
    );
    let other = execute(&seatless.server, second, "read-other", &read, None).await;
    assert_eq!(
        structured(&other)["result"]["denied"],
        "unknown_handle",
        "{other:?}"
    );
    assert!(!other.to_string().contains("tail-cap-proof"), "{other:?}");
}

/// Proves (Astra review of PR D at d8201ba7) that `vault.runs.read_result` from caller code
/// meets the credential's own allowlist as any other verb call from code does: a credential
/// bound to `execute` alone is refused `mcp_verb_not_bound` on its own run's capped result,
/// and the refusal names the verb; one bound to both reads the same kind of result.
#[tokio::test]
async fn result_read_outside_the_credential_allowlist_is_refused_naming_the_verb() {
    let seatless = seatless_server();
    let unbound = "execute-cap-execute-only";
    let bound = "execute-cap-reader-bound";
    for (credential, id, verbs) in [
        (unbound, 0x0024_66c3, &["execute"][..]),
        (
            bound,
            0x0024_66c4,
            &["execute", "vault.runs.read_result"][..],
        ),
    ] {
        register_bound_verb_mcp_actor(
            &seatless.server,
            credential,
            seeded_test_entity_id(id),
            verbs,
        )
        .await;
    }
    let mut reads = Vec::new();
    for credential in [unbound, bound] {
        let body = execute(
            &seatless.server,
            credential,
            "large",
            "return 'a'.repeat(20000) + 'tail-allowlist-proof';",
            Some("allowlist-cap-run"),
        )
        .await;
        assert_eq!(structured(&body)["status"], "complete", "{body:?}");
        let reference = body["result"]["_meta"]["result_ref"]
            .as_str()
            .expect("a clipped result has a stored reference");
        let input = json!({
            "run_ref": "allowlist-cap-run",
            "result_ref": reference,
            "offset": 20_001,
            "limit": 30,
        });
        let read = format!("return await vault.runs.read_result({input});");
        reads.push(execute(&seatless.server, credential, "read", &read, None).await);
    }
    let refused = structured(&reads[0]);
    assert_eq!(refused["status"], "error", "{:?}", reads[0]);
    assert_eq!(
        refused["error"]["code"], "mcp_verb_not_bound",
        "{:?}",
        reads[0]
    );
    assert_eq!(
        refused["error"]["verb"], "vault.runs.read_result",
        "the refusal names the verb: {:?}",
        reads[0]
    );
    let call = call_entry(&refused["calls"], "vault.runs.read_result");
    assert_eq!(call["outcome"], "refused", "{:?}", reads[0]);
    assert_eq!(call["code"], "mcp_verb_not_bound", "{:?}", reads[0]);
    assert!(
        !reads[0].to_string().contains("tail-allowlist-proof"),
        "{:?}",
        reads[0]
    );
    assert!(
        structured(&reads[1])["result"]
            .to_string()
            .contains("tail-allowlist-proof"),
        "{:?}",
        reads[1]
    );
}

/// Proves (P1-7): a source-only host starts no resident pump; agent attempts wait instead of
/// being claimed to fail on task config.
#[tokio::test]
async fn source_only_host_leaves_the_agent_pump_unstarted() {
    let seatless = seatless_server();
    let host = seatless
        .server
        .code_execution_host()
        .expect("a host is bound");
    assert!(
        !host.task_runtime_available(),
        "caller-source readiness only: no task seat"
    );
    assert!(
        seatless.server.spawn_resident_pump().is_none(),
        "no pump starts on a source-only host"
    );
}

/// Proves (P2-10): production boot with no `[models]` binds the verified component as a
/// caller-source host through `AiHost::attach`, listing both tools and running caller code.
#[tokio::test]
async fn attach_with_no_models_binds_caller_source_through_production_boot() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    crate::test_credentials::install_fixture_keystore(&vault, b"secret");
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        },
    )
    .unwrap();
    let (server, _host) = crate::ai_host::AiHost::attach(server, None).await;
    let server = Arc::new(server);
    let host = server
        .code_execution_host()
        .expect("production boot binds a host");
    assert!(host.production_runtime_available());
    assert!(
        !host.task_runtime_available(),
        "caller-source readiness only: no task seat"
    );
    let actor = seeded_test_entity_id(0x0024_66d1);
    let credential = "execute-attach-seatless";
    register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
        let (_, listing) =
            route_json(server.clone(), mcp_list_request(path, credential, "list")).await;
        assert_ready_listing(path, &listing);
    }
    let body = execute(&server, credential, "canary", "return 1;", None).await;
    let answered = structured(&body);
    assert_eq!(answered["status"], "complete", "{body:?}");
    assert_eq!(answered["result"], json!(1), "{body:?}");
}

/// Proves (P1-5): a run parked on an ask that settles by deadline answers
/// EXPIRED on a resume that carries an answer, instead of WRONG_INPUT; a
/// resume without an answer re-enters as today and completes on the delivered
/// deadline result.
#[tokio::test]
async fn resume_after_a_delivered_deadline_answers_expired_with_an_answer_and_reenters_without() {
    const NOW: u64 = 1_772_000_000;
    const UNTIL: u64 = NOW + 100;
    const PAST: u64 = NOW + 101;
    let clock = oneiron::store::ports::ManualClock::new(NOW);
    let mut config = oneiron::VaultConfig::device();
    config.store_clock = clock.bundle();
    let clocked = seatless_server_with_vault_config(config);
    let actor = seeded_test_entity_id(0x0024_6701);
    let turn = seeded_test_entity_id(0x0024_6702);
    let credential = "resume-deadline-credential";
    register_mcp_actor(
        &clocked.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    seed_turn(&clocked.vault, turn, actor);
    let code = format!(
        r#"const r = await ask({{who: {{responder: {{human: {{actor_ref: "{actor}"}}}}}}, what: {{reference: {{turn: "{turn}"}}, revision: 1, options: {{}}, context_refs: []}}, until: {until}}}); return await wait({{handle: r.handle, step_key: "deadline-wait"}});"#,
        actor = actor.to_hex(),
        turn = turn.to_hex(),
        until = UNTIL,
    );
    let paused = execute(
        &clocked.server,
        credential,
        "park",
        &code,
        Some("deadline-run"),
    )
    .await;
    let waiting = structured(&paused);
    assert_eq!(waiting["status"], "paused", "{paused:?}");
    // The parked wait's key and group, for the settlement trigger below.
    let context = mcp_test_context(&clocked.server, credential, "ctx").await;
    let run_id = crate::mcp::mcp_code_run_id("deadline-run", &context);
    let record = clocked
        .vault
        .get_code_run_replay_record(&run_id)
        .unwrap()
        .expect("a record");
    let (key, wait) = oneiron::engine_executor::code_run_parked_wait(&clocked.vault, &record)
        .unwrap()
        .expect("parked");
    let group = wait.wait_id;
    // Past the cutoff, a status wait settles the ask by deadline and delivers
    // to the still-parked run.
    clock.set(PAST);
    let settle_args = mcp_merge_args(
        mcp_endpoint_envelope(actor, "read_tasks"),
        json!({"arguments": {"spec": {"handle": {"group_ref": group.to_hex()}, "step_key": "settle-deadline"}}}),
    );
    let (_, settlement) = route_json(
        clocked.server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "settle",
            "wait",
            settle_args,
        ),
    )
    .await;
    let delivered = oneiron::code_run::WaitDeliveries::canonical(&clocked.vault)
        .delivery(&key)
        .unwrap();
    let delivered =
        delivered.unwrap_or_else(|| panic!("the deadline did not deliver: {settlement:?}"));
    let status: oneiron::task_verb::TaskAskStatus = serde_json::from_str(&delivered.reply).unwrap();
    assert!(matches!(
        status,
        oneiron::task_verb::TaskAskStatus::Settled(result)
            if result.settlement.reason == oneiron::task_verb::TaskAskSettlementReason::Deadline
    ));
    // With an answer: EXPIRED, not WRONG_INPUT; the run stays parked.
    let word = json!({"result_ref": actor.to_hex(), "option": null, "inform_for": null});
    let refused = resume(
        &clocked.server,
        credential,
        "answer-late",
        "deadline-run",
        Some(word),
    )
    .await;
    let expired = structured(&refused);
    assert_eq!(expired["status"], "error", "{refused:?}");
    assert_eq!(expired["error"]["code"], "EXPIRED", "{refused:?}");
    // Without an answer: re-enters as today and completes on the delivery.
    let done = resume(&clocked.server, credential, "reenter", "deadline-run", None).await;
    let completed = structured(&done);
    assert_eq!(completed["status"], "complete", "{done:?}");
    assert_eq!(completed["run_ref"], "deadline-run", "{done:?}");
}

/// Proves (P1-4 path): a refused answer names `tasks.answer` and leaves the
/// ask pending, so a good answer still completes the run. The refusal goes
/// through the answer verb's served rows; a release difference needs a
/// retained producer and is not asserted here.
#[tokio::test]
async fn a_refused_answer_names_the_answer_verb_and_keeps_the_ask() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6721);
    let turn = seeded_test_entity_id(0x0024_6722);
    let missing = seeded_test_entity_id(0x0024_6723);
    let credential = "resume-refusal-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    seed_turn(&seatless.vault, turn, actor);
    let code = format!(
        r#"const r = await ask({{who: {{responder: {{human: {{actor_ref: "{actor}"}}}}}}, what: {{reference: {{turn: "{turn}"}}, revision: 1, options: {{}}, context_refs: []}}}}); return await wait({{handle: r.handle, step_key: "refusal-wait"}});"#,
        actor = actor.to_hex(),
        turn = turn.to_hex(),
    );
    let paused = execute(
        &seatless.server,
        credential,
        "park",
        &code,
        Some("refusal-run"),
    )
    .await;
    assert_eq!(structured(&paused)["status"], "paused", "{paused:?}");
    // A result ref that names nothing the vault holds: the row refuses after
    // it lists the ask group.
    let bad = json!({"result_ref": missing.to_hex(), "option": null, "inform_for": null});
    let refused = resume(
        &seatless.server,
        credential,
        "bad-answer",
        "refusal-run",
        Some(bad),
    )
    .await;
    let errored = structured(&refused);
    assert_eq!(errored["status"], "error", "{refused:?}");
    assert_eq!(
        errored["error"]["verb"], "tasks.answer",
        "the refusal names the verb: {refused:?}"
    );
    // The ask is still pending: a good answer completes the run.
    let good = json!({"result_ref": actor.to_hex(), "option": null, "inform_for": null});
    let done = resume(
        &seatless.server,
        credential,
        "good-answer",
        "refusal-run",
        Some(good),
    )
    .await;
    let completed = structured(&done);
    assert_eq!(completed["status"], "complete", "{done:?}");
    assert_eq!(completed["run_ref"], "refusal-run", "{done:?}");
}

/// P1-2: a resumed TASK whose answer has program feedback keeps an
/// `InvocationRelease` whose value has no `steps` (and no `_returned_null` or
/// `structuredContent.program_steps`).
#[tokio::test]
async fn claimed_keep_has_no_steps_with_program_feedback() {
    use crate::api::mcp_gateway::{capturing_for_test, kept_for_test};

    // A real completed TASK: even without a checker the engine keeps
    // unavailable feedback, and the completed outcome re-reads it from storage.
    let mode = code_mode_server_with(vec!["finish('feedback canary');".to_owned()], None);
    let actor = seeded_test_entity_id(0x0024_6e01);
    let credential = "p1-2-claimed-credential";
    register_mcp_actor(
        &mode.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let started =
        execute_task_run_for_test(&mode.server, credential, "p1-2-task", "p1-2 task").await;
    assert!(
        started.get("error").is_none(),
        "the task run starts: {started:?}"
    );
    assert_eq!(
        started["result"]["structuredContent"]["resume"]["terminal"], true,
        "the task completes: {started:?}"
    );
    // Resume through the new shape, capturing the claimed keep.
    let ctx = mcp_test_context(&mode.server, credential, "p1-2-resume").await;
    let args = crate::mcp::McpResumeToolArgs {
        run_ref: "p1-2-task".to_owned(),
        answer: None,
    };
    let (resumed, judged) = capturing_for_test(crate::api::mcp_gateway::execute_mcp_resume(
        &mode.server,
        &ctx,
        &args,
    ))
    .await;
    let reply = resumed.expect("the resume renders");
    assert!(
        reply["structuredContent"].is_object(),
        "a tool result: {reply:?}"
    );
    assert!(
        reply["_meta"]["program_steps"]
            .as_array()
            .is_some_and(|steps| !steps.is_empty()),
        "the answer carries program feedback in _meta: {reply:?}"
    );
    assert!(
        reply["structuredContent"].get("program_steps").is_none(),
        "wire shape strips program_steps from structuredContent: {reply:?}"
    );
    let saved = serde_json::json!({ "result": reply.clone() });
    let kept = kept_for_test(oneiron::authority::PeerMachine::Unknown, &saved, judged)
        .expect("recorded equals reply, so kept returns Some");
    assert!(
        kept.value.pointer("/structuredContent/steps").is_none(),
        "kept value has no steps: {:?}",
        kept.value
    );
    assert!(
        kept.value
            .pointer("/structuredContent/_returned_null")
            .is_none(),
        "kept value has no _returned_null: {:?}",
        kept.value
    );
    assert!(
        kept.value
            .pointer("/structuredContent/program_steps")
            .is_none(),
        "kept value has no structuredContent.program_steps: {:?}",
        kept.value
    );
}

/// P1-8: a syntax error on line 2 of plain JavaScript answers line 2 (and a column).
#[tokio::test]
async fn syntax_error_names_line_2() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6e11);
    let credential = "p1-8-syntax-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let body = execute(
        &seatless.server,
        credential,
        "syntax",
        "const a = 1;\nconst b = ;\nreturn a;",
        Some("p1-8-syntax-run"),
    )
    .await;
    let answered = structured(&body);
    assert_eq!(answered["status"], "error", "{body:?}");
    assert_eq!(answered["error"]["code"], "SYNTAX", "{body:?}");
    assert_eq!(answered["error"]["line"], 2, "{body:?}");
    assert!(
        answered["error"]["column"].is_number(),
        "SYNTAX names its column: {body:?}"
    );
}

/// P1-8: a `throw` on line 3 of plain JavaScript answers line 3 (no column).
#[tokio::test]
async fn thrown_error_names_line_3() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6e12);
    let credential = "p1-8-thrown-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let body = execute(
        &seatless.server,
        credential,
        "thrown",
        "const a = 1;\nconst b = 2;\nthrow new Error('boom');",
        Some("p1-8-thrown-run"),
    )
    .await;
    let answered = structured(&body);
    assert_eq!(answered["status"], "error", "{body:?}");
    assert_eq!(answered["error"]["code"], "THROWN", "{body:?}");
    assert_eq!(answered["error"]["line"], 3, "{body:?}");
    assert!(
        answered["error"].get("column").is_none(),
        "THROWN names its line only: {body:?}"
    );
}

/// P1-9: caller code `tasks.create` that lands shows its `task_ref`.
#[tokio::test]
async fn landed_tasks_create_shows_its_task_ref() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6e21);
    let credential = "p1-9-tasks-create-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    seed_auto_ceiling(&seatless.vault, actor, seeded_test_entity_id(0x0024_6e22));
    let body = execute(
        &seatless.server,
        credential,
        "create",
        "return await tasks.create({spec: {goal: \"p1-9-task\"}, label: \"p1-9-task\"});",
        Some("p1-9-create-run"),
    )
    .await;
    let answered = structured(&body);
    assert_eq!(answered["status"], "complete", "{body:?}");
    let call = call_entry(&answered["calls"], "tasks.create");
    assert_eq!(call["outcome"], "landed", "{body:?}");
    let task_ref = answered["result"]["task_ref"]
        .as_str()
        .expect("the receipt names its task_ref");
    assert_eq!(call["ref"], task_ref, "{body:?}");
}

/// P1-10: a run logging past the cap ends its console with the cut line.
#[tokio::test]
async fn console_past_cap_ends_with_cut_line() {
    let seatless = seatless_server();
    let actor = seeded_test_entity_id(0x0024_6e31);
    let credential = "p1-10-console-credential";
    register_mcp_actor(
        &seatless.server,
        credential,
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let body = execute(
        &seatless.server,
        credential,
        "console",
        "for (let i = 0; i < 1000; i++) console.log(\"line \" + i + \" \" + \"x\".repeat(50)); return \"done\";",
        Some("p1-10-console-run"),
    )
    .await;
    let answered = structured(&body);
    assert_eq!(answered["status"], "complete", "{body:?}");
    let console = answered["console"].as_array().expect("console array");
    assert!(
        console.len() < 1000,
        "the console is cut: {}",
        console.len()
    );
    let omitted = 1_000 - (console.len() - 1);
    let marker = format!("console cut at 20,000 characters; {omitted} lines not shown");
    assert_eq!(
        console.last().and_then(Value::as_str),
        Some(marker.as_str())
    );
}
