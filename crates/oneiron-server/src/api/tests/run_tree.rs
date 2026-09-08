//! Run-tree attempt-queue reads, agent_id projection, intervene effects, unbounded-read rejection.

use super::*;

#[tokio::test]
async fn v1_core_run_tree_reads_attempt_queue_rows() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let root = enqueue_queue_attempt(server.vault.as_ref(), "api-worker", 10, "run-api");
    let _other = enqueue_queue_attempt(server.vault.as_ref(), "other-run", 20, "run-other");

    let (status, body) = core_json(
        server.clone(),
        "GET",
        "/v1/core/run-tree?run_id=run-api",
        "core:read",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["repairs"], json!([]));
    let roots = body["roots"].as_array().expect("run tree roots");
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0]["job_id"], Value::from(attempt_id_hex(root.id)));
    assert_eq!(roots[0]["run_id"], Value::from("run-api"));
    assert_eq!(roots[0]["parent_id"], Value::Null);
    assert_eq!(roots[0]["worker_kind"], Value::from("api-worker"));
    assert_eq!(roots[0]["status"], Value::from("queued"));
    assert_eq!(roots[0]["timestamps"]["created_at"], Value::from(10));
    assert_eq!(
        roots[0]["events"],
        json!([{
            "sequence": 0,
            "at": 10,
            "actor": "runtime",
            "kind": "created",
            "note": null,
        }])
    );
    assert_eq!(roots[0]["children"], json!([]));

    let (observe_status, observe_body) = core_json(
        server,
        "GET",
        "/v1/core/run-tree/observe?run_id=run-api",
        "core:read",
        None,
    )
    .await;
    assert_eq!(observe_status, StatusCode::OK);
    assert_eq!(observe_body, body);
}

#[tokio::test]
async fn v1_core_run_tree_includes_agent_id_for_dispatched_agents() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let plain = enqueue_queue_attempt(server.vault.as_ref(), "api-worker", 10, "run-agent-api");

    let def_id = oneiron::EntityId::now();
    let def = oneiron::agent_def::AgentDefinition::new(
        "oneiron.agent.api",
        "Run-tree API dispatch fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        oneiron::agent_def::AgentScope::All,
        oneiron::agent_def::AgentCeiling::Proposed,
        None,
        oneiron::ClaimApprovalStatus::Approved,
        oneiron::ClaimLifecycleStatus::Active,
        oneiron::ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("test"),
        )]),
        None,
        true,
        None,
    );
    server
        .vault
        .put_agent_definition(&def_id, &def, oneiron::TimeRange { start: 1, end: 1 }, 1)
        .expect("persist agent definition");

    let dispatcher = oneiron::agent_dispatch::AgentDispatcher::new(server.vault.as_ref());
    let oneiron::agent_dispatch::AgentDispatchOutcome::Dispatched(dispatched) = dispatcher
        .dispatch(oneiron::agent_dispatch::DispatchAgent {
            target: oneiron::agent_dispatch::AgentDispatchTarget::Custom(def_id),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-agent-api".to_owned()),
            now: 20,
        })
        .expect("dispatch agent")
    else {
        panic!("expected fresh dispatch");
    };

    let (status, body) = core_json(
        server,
        "GET",
        "/v1/core/run-tree?run_id=run-agent-api",
        "core:read",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let roots = body["roots"].as_array().expect("run tree roots");
    assert_eq!(roots.len(), 2);
    assert_eq!(roots[0]["job_id"], Value::from(attempt_id_hex(plain.id)));
    assert!(
        roots[0].get("agent_id").is_none(),
        "non-agent nodes must elide agent_id entirely"
    );
    assert_eq!(
        roots[1]["job_id"],
        Value::from(attempt_id_hex(dispatched.attempt.id))
    );
    assert_eq!(roots[1]["worker_kind"], Value::from("agent.dispatch"));
    assert_eq!(
        roots[1]["agent_id"],
        Value::from("oneiron.agent.api"),
        "agent.dispatch nodes must carry the dispatched agent's label"
    );
}

#[tokio::test]
async fn v1_core_run_tree_intervene_requires_write_and_returns_snapshot() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let root = enqueue_queue_attempt(server.vault.as_ref(), "api-worker", 10, "run-api");
    let request = json!({
        "job_id": attempt_id_hex(root.id),
        "kind": "pause",
        "note": "hold branch",
    });

    let (forbidden_status, forbidden_body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/run-tree/intervene",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(forbidden_status, StatusCode::FORBIDDEN);
    assert_error_envelope(&forbidden_body, "FORBIDDEN");

    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/run-tree/intervene",
        "core:write",
        Some(&request),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["job_id"], Value::from(attempt_id_hex(root.id)));
    assert_eq!(body["run_id"], Value::from("run-api"));
    assert_eq!(body["kind"], Value::from("pause"));
    assert_eq!(body["effect"], Value::from("paused"));
    let roots = body["tree"]["roots"].as_array().expect("snapshot roots");
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0]["job_id"], Value::from(attempt_id_hex(root.id)));
    assert_eq!(roots[0]["status"], Value::from("paused"));
    assert_eq!(roots[0]["events"].as_array().unwrap().len(), 2);
    assert_eq!(roots[0]["events"][0]["sequence"], Value::from(0));
    assert_eq!(roots[0]["events"][0]["kind"], Value::from("created"));
    assert_eq!(roots[0]["events"][1]["sequence"], Value::from(1));
    assert_eq!(roots[0]["events"][1]["kind"], Value::from("paused"));
    assert_eq!(roots[0]["events"][1]["actor"], Value::from("bearer"));
    assert_eq!(roots[0]["events"][1]["note"], Value::from("hold branch"));

    let repeated = json!({
        "job_id": attempt_id_hex(root.id),
        "kind": "pause",
    });
    let (repeat_status, repeat_body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/run-tree/intervene",
        "core:write",
        Some(&repeated),
    )
    .await;
    assert_eq!(repeat_status, StatusCode::OK);
    assert_eq!(repeat_body["effect"], Value::from("already_paused"));
    let repeat_roots = repeat_body["tree"]["roots"]
        .as_array()
        .expect("repeat snapshot roots");
    assert_eq!(repeat_roots[0]["events"].as_array().unwrap().len(), 2);

    let resume = json!({
        "job_id": attempt_id_hex(root.id),
        "kind": "resume",
    });
    let (resume_status, resume_body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/run-tree/intervene",
        "core:write",
        Some(&resume),
    )
    .await;
    assert_eq!(resume_status, StatusCode::OK);
    assert_eq!(resume_body["effect"], Value::from("resumed"));
    let resume_roots = resume_body["tree"]["roots"]
        .as_array()
        .expect("resume snapshot roots");
    assert_eq!(resume_roots[0]["status"], Value::from("queued"));
    assert_eq!(resume_roots[0]["events"].as_array().unwrap().len(), 3);
    assert_eq!(resume_roots[0]["events"][2]["kind"], Value::from("resumed"));

    let interrupt = json!({
        "job_id": attempt_id_hex(root.id),
        "kind": "interrupt",
        "note": "snapshot now",
    });
    let (interrupt_status, interrupt_body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/run-tree/intervene",
        "core:write",
        Some(&interrupt),
    )
    .await;
    assert_eq!(interrupt_status, StatusCode::OK);
    assert_eq!(interrupt_body["effect"], Value::from("interrupted"));
    let interrupt_roots = interrupt_body["tree"]["roots"]
        .as_array()
        .expect("interrupt snapshot roots");
    assert_eq!(interrupt_roots[0]["status"], Value::from("queued"));
    assert_eq!(interrupt_roots[0]["events"].as_array().unwrap().len(), 4);
    assert_eq!(
        interrupt_roots[0]["events"][3]["kind"],
        Value::from("interrupted")
    );
    assert_eq!(
        interrupt_roots[0]["events"][3]["note"],
        Value::from("snapshot now")
    );

    let cancel = json!({
        "job_id": attempt_id_hex(root.id),
        "kind": "cancel",
    });
    let (cancel_status, cancel_body) = core_json(
        server,
        "POST",
        "/v1/core/run-tree/intervene",
        "core:write",
        Some(&cancel),
    )
    .await;
    assert_eq!(cancel_status, StatusCode::OK);
    assert_eq!(cancel_body["effect"], Value::from("cancelled"));
    let cancel_roots = cancel_body["tree"]["roots"]
        .as_array()
        .expect("cancel snapshot roots");
    assert_eq!(cancel_roots[0]["status"], Value::from("cancelled"));
    assert_eq!(cancel_roots[0]["events"].as_array().unwrap().len(), 5);
    assert_eq!(
        cancel_roots[0]["events"][4]["kind"],
        Value::from("cancelled")
    );
}

#[tokio::test]
async fn v1_core_run_tree_rejects_unbounded_reads() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = core_json(server, "GET", "/v1/core/run-tree", "core:read", None).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["message"],
        Value::from("run_id is required; unfiltered run-tree reads are not supported")
    );
}
