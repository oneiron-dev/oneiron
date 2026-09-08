//! Shared MCP test harness: legacy adapter, tool-first endpoints, scoping, code-run fixtures.

use super::*;

pub(super) fn mcp_call_request(
    credential: &str,
    id: &str,
    name: &str,
    arguments: Value,
) -> McpLegacyCall {
    McpLegacyCall {
        credential: credential.to_owned(),
        id: id.to_owned(),
        name: name.to_owned(),
        arguments,
    }
}

/// Drives one retired adapter and returns the same `(status, JSON-RPC body)`
/// pair the wire used to return, so every row below keeps its exact assertions.
pub(super) async fn mcp_legacy_adapter_json(
    server: Arc<SyncServer>,
    call: McpLegacyCall,
) -> (StatusCode, Value) {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {credential}", credential = call.credential)
            .parse()
            .expect("bearer credential header"),
    );
    let id = Value::from(call.id.clone());
    let body = match mcp_legacy_adapter_result(&server, &headers, &call).await {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => crate::api::mcp_error_response(id, error),
    };
    (StatusCode::OK, body)
}

pub(super) async fn mcp_legacy_adapter_result(
    server: &Arc<SyncServer>,
    headers: &axum::http::HeaderMap,
    call: &McpLegacyCall,
) -> Result<Value, crate::api::McpGatewayError> {
    let actor = crate::api::resolve_mcp_gateway_actor(
        crate::mcp::McpSurfaceMode::Primary,
        &call.id,
        headers,
        server,
    )
    .await?;
    let tool = crate::mcp::McpToolName::from_name(&call.name)
        .unwrap_or_else(|| panic!("{} is not a retired plain-verb name", call.name));
    let args = crate::mcp::validate_mcp_tool_args(tool, call.arguments.clone())
        .map_err(crate::api::mcp_tool_validation_error)?;
    crate::api::ensure_mcp_actor_matches(&args, &actor)?;
    crate::api::execute_mcp_tool(server, args, &actor).await
}

pub(super) async fn register_mcp_actor(
    server: &Arc<SyncServer>,
    credential: &str,
    actor_ref: oneiron::EntityId,
    actor_class: oneiron::EdgeActorClass,
) {
    let actor_type = match actor_class {
        oneiron::EdgeActorClass::Human => oneiron::registry::ENTITY_TYPE_PERSON,
        oneiron::EdgeActorClass::Agent => oneiron::registry::ENTITY_TYPE_MACHINE,
        oneiron::EdgeActorClass::System => oneiron::registry::ENTITY_TYPE_MACHINE,
    };
    server
        .vault
        .put_entity(
            &actor_ref,
            actor_type,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"mcp actor",
        )
        .expect("seed mcp actor entity");
    server
        .mcp_registry
        .lock()
        .await
        .register(
            credential,
            crate::mcp::McpConnectorActorRecord::new(
                actor_ref,
                actor_class,
                crate::mcp::McpConnectorScope::vault_wide(),
            ),
        )
        .expect("register mcp actor");
}

pub(super) fn mcp_actor_json(actor_ref: oneiron::EntityId, actor_class: &str) -> Value {
    json!({
        "actor_ref": actor_ref.to_hex(),
        "actor_class": actor_class,
        "gate_actor_class": actor_class,
        "gate_actor_ref": actor_ref.to_hex(),
        "scope": {},
    })
}

pub(super) fn mcp_consent_json(purpose: &str, require_human_approval: bool) -> Value {
    json!({
        "policy_ref": "policy:foreign-mcp",
        "purpose": purpose,
        "approval_ref": "approval:one-1222",
        "consent_receipt_ref": "consent:one-1222",
        "require_human_approval": require_human_approval,
    })
}

pub(super) fn mcp_context_pack_json(result_id: oneiron::EntityId) -> Value {
    json!({
        "schema_version": "context_pack_ref.v1",
        "context_version": "v4",
        "pack_ref": "context-pack:one-1222",
        "retrieval_run_id": "retrieval:one-1222",
        "result_ids": [result_id.to_hex()],
        "budget_ref": "budget:standard",
    })
}

pub(super) fn mcp_propose_claim_args(
    actor_ref: oneiron::EntityId,
    subject_ref: oneiron::EntityId,
    idempotency_key: &str,
) -> Value {
    json!({
        "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": mcp_actor_json(actor_ref, "human"),
        "consent": mcp_consent_json("write_memory", false),
        "verb": "propose_claim",
        "idempotency_key": idempotency_key,
        "subject": { "entity": subject_ref.to_hex() },
        "predicate": "profile.mcp_gateway",
        "value": "MCP gateway write",
        "confidence": 0.8
    })
}

/// Issues one `oneiron.edit` call and returns the JSON-RPC `error` object,
/// failing loudly when the call unexpectedly succeeded.
pub(super) async fn mcp_edit_error(
    server: &Arc<SyncServer>,
    credential: &str,
    args: Value,
) -> Value {
    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(credential, "mcp-stale-edit", "oneiron.edit", args),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body.get("error")
        .cloned()
        .unwrap_or_else(|| panic!("the edit should have been refused: {body:#}"))
}

pub(super) const MCP_TOOL_FIRST_PATH: &str = "/mcp/tool-first";

pub(super) fn mcp_endpoint_request(path: &str, credential: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {credential}"))
        .body(Body::from(body.to_string()))
        .expect("mcp endpoint request")
}

/// The credential headers one registered connector presents.
///
/// Used where a test drives a gateway seam directly instead of through the
/// router, so the credential still resolves exactly the way the wire resolves
/// it — nothing here fabricates an actor.
pub(super) fn mcp_credential_headers(credential: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {credential}")
            .parse()
            .expect("bearer credential header"),
    );
    headers
}

pub(super) fn mcp_list_request(path: &str, credential: &str, id: &str) -> Request<Body> {
    mcp_endpoint_request(
        path,
        credential,
        json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list" }),
    )
}

pub(super) fn mcp_endpoint_call_request(
    path: &str,
    credential: &str,
    id: &str,
    name: &str,
    arguments: Value,
) -> Request<Body> {
    mcp_endpoint_request(
        path,
        credential,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        }),
    )
}

pub(super) fn mcp_listed_tool_names(body: &Value) -> Vec<&str> {
    body["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect()
}

pub(super) fn mcp_expected_generated_names() -> Vec<&'static str> {
    let mut expected = oneiron::board_verb::BOARD_VERBS
        .iter()
        .chain(oneiron::task_verb::TASKS_VERBS.iter())
        .copied()
        .collect::<Vec<_>>();
    expected.sort_unstable();
    expected
}

pub(super) fn mcp_endpoint_envelope(actor_ref: oneiron::EntityId, purpose: &str) -> Value {
    json!({
        "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": mcp_actor_json(actor_ref, "human"),
        "consent": mcp_consent_json(purpose, false),
    })
}

pub(super) fn mcp_merge_args(mut base: Value, extra: Value) -> Value {
    let Value::Object(extra) = extra else {
        panic!("mcp argument overlay must be an object");
    };
    let base_object = base
        .as_object_mut()
        .expect("mcp argument base is an object");
    for (key, value) in extra {
        base_object.insert(key, value);
    }
    base
}

pub(super) fn assert_mcp_result_metadata(meta: &Value) {
    assert_eq!(meta["ttlMs"], Value::from(0));
    assert_eq!(meta["cacheScope"], Value::from("private"));
    assert!(
        ["Complete", "More"].contains(&meta["end"].as_str().expect("end marker")),
        "the end marker is explicit: {meta:?}"
    );
    assert!(
        ["healthy", "degraded", "partial", "unavailable"]
            .contains(&meta["retrieval_health"].as_str().expect("retrieval health")),
        "retrieval health is a closed enum: {meta:?}"
    );
    assert!(meta.get("effective_scope").is_some(), "{meta:?}");
    assert!(meta["help"].is_array(), "{meta:?}");
    assert!(
        meta["request_id"].as_str().is_some_and(|id| !id.is_empty()),
        "{meta:?}"
    );
}

pub(super) fn assert_mcp_structured_error(body: &Value, error_code: &str) {
    let data = &body["error"]["data"];
    assert_eq!(data["error_code"], Value::from(error_code), "{body:?}");
    assert!(
        data["human_message"]
            .as_str()
            .is_some_and(|message| !message.trim().is_empty()),
        "{body:?}"
    );
    assert!(
        data["recovery_suggestions"]
            .as_array()
            .is_some_and(|suggestions| !suggestions.is_empty()),
        "{body:?}"
    );
    assert!(
        data["request_id"].as_str().is_some_and(|id| !id.is_empty()),
        "{body:?}"
    );
}

/// Registers a connector whose ceiling is NARROWED to one world and facet.
///
/// The class stays `human` because the seeded default manifest carries the
/// class-wide human ceiling; what varies here is the SCOPE, which is the axis
/// the byte-identity invariant is about.
pub(super) async fn register_scoped_mcp_actor(
    server: &Arc<SyncServer>,
    credential: &str,
    actor_ref: oneiron::EntityId,
    scope: crate::mcp::McpConnectorScope,
) {
    server
        .vault
        .put_entity(
            &actor_ref,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"scoped mcp actor",
        )
        .expect("seed scoped mcp actor entity");
    server
        .mcp_registry
        .lock()
        .await
        .register(
            credential,
            crate::mcp::McpConnectorActorRecord::new(
                actor_ref,
                oneiron::EdgeActorClass::Human,
                scope,
            ),
        )
        .expect("register scoped mcp actor");
}

/// A fixture backend that always answers with the same plain-JS step.
pub(super) struct McpFixtureCodeBackend;

impl oneiron::LlmBackend for McpFixtureCodeBackend {
    fn generate<'a>(
        &'a self,
        _request: oneiron::LlmRequest,
        _lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmGenerateFuture<'a> {
        Box::pin(async {
            Ok(oneiron::LlmResponse {
                message: oneiron::LlmMessage {
                    role: oneiron::LlmMessageRole::Assistant,
                    content: vec![oneiron::ContentPart::Text {
                        text: "const found = await self.memory.search(\"launch plan\");".to_owned(),
                    }],
                },
                usage: oneiron::LlmUsage::zero(),
                finish_reason: oneiron::FinishReason::Stop,
            })
        })
    }

    fn stream<'a>(
        &'a self,
        _request: oneiron::LlmRequest,
        _lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmStreamResult<'a> {
        unimplemented!("the executor fixture never streams")
    }
}

/// A fixture sandbox/REPL runtime.
///
/// It drives `self.*` through the host bridge, so reaching it proves the
/// gateway entered a RUNTIME and that runtime entered `HostSelfDispatcher`.
pub(super) struct McpFixtureCodeRuntime;

impl oneiron::engine_executor::JsCodeModeRuntime for McpFixtureCodeRuntime {
    fn run_step(
        &mut self,
        _step: oneiron::engine_executor::JsCodeModeStep<'_>,
        host: &mut dyn oneiron::engine_executor::JsCodeModeHost,
    ) -> oneiron::Result<oneiron::engine_executor::JsCodeModeStepOutcome> {
        host.dispatch_self(oneiron::code_run::SelfCall::MemorySearch(
            oneiron::code_run::SelfMemorySearchCall::new("launch plan", 3),
        ))?;
        host.dispatch_self(oneiron::code_run::SelfCall::OutboundFixture(
            oneiron::code_run::SelfFixtureEffectCall::new("notify the owner"),
        ))?;
        Ok(oneiron::engine_executor::JsCodeModeStepOutcome::pending(
            "parked on an outbound effect",
        ))
    }
}

pub(super) struct McpFixtureCodeProvider {
    backend: McpFixtureCodeBackend,
    lease: oneiron::BudgetLease,
}

/// How many times the bound fixture host was ENTERED for a run.
///
/// ONE-1704 B2 reads this to prove ZERO runs are created by a refused
/// `execute_code` call: the host is bound in this process, and the counter is
/// the run-creation witness rather than an absence someone has to infer.
pub(super) static MCP_FIXTURE_CODE_RUNS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) fn mcp_fixture_code_runs() -> usize {
    MCP_FIXTURE_CODE_RUNS.load(std::sync::atomic::Ordering::SeqCst)
}

impl crate::mcp::McpCodeModeProvider for McpFixtureCodeProvider {
    fn backend(&self) -> &dyn oneiron::LlmBackend {
        &self.backend
    }

    fn lease(&self) -> &oneiron::BudgetLease {
        &self.lease
    }

    fn runtime(&self) -> Box<dyn oneiron::engine_executor::JsCodeModeRuntime + Send> {
        Box::new(McpFixtureCodeRuntime)
    }

    fn executor_config(
        &self,
        run_id: oneiron::EntityId,
        task: &str,
    ) -> oneiron::engine_executor::EngineExecutorConfig {
        // The earliest point the injected host is entered for a run at all.
        MCP_FIXTURE_CODE_RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        oneiron::engine_executor::EngineExecutorConfig {
            run_id,
            task: task.to_owned(),
            // ONE-1929: the executor wire teaching comes from the DEPLOYED
            // prompt package, so every run input must carry its root.
            prompt_package_root: oneiron::prompt::workspace_prompt_package_root()
                .expect("workspace prompt package"),
            model: oneiron::ModelId::new("fixture/executor@v1").expect("fixture model id"),
            model_locality: oneiron::ModelLocality::OnDevice,
            global_tier: oneiron::ModelTierRef("fixture-tier".to_owned()),
            determinism: oneiron::code_run::CodeRunDeterminism::new(
                1_000,
                [7; oneiron::code_run::CODE_RUN_RNG_SEED_LEN],
            ),
            limits: oneiron::engine_executor::EngineExecutorLimits::default(),
        }
    }
}

/// Binds the process's fixture `execute_code` host exactly once.
pub(super) fn bind_mcp_test_code_host() {
    static BOUND: std::sync::Once = std::sync::Once::new();
    BOUND.call_once(|| {
        let provider = std::sync::Arc::new(McpFixtureCodeProvider {
            backend: McpFixtureCodeBackend,
            lease: oneiron::BudgetLease::for_test("mcp-execute-code-fixture"),
        });
        assert!(
            crate::mcp::bind_mcp_code_execution_host(std::sync::Arc::new(
                crate::mcp::McpEngineNativeCodeHost::new(provider),
            )),
            "the execute_code host binds once per process",
        );
    });
}

/// An envelope whose claimed actor scope MATCHES a narrowed registration.
pub(super) fn mcp_scoped_envelope(
    actor_ref: oneiron::EntityId,
    purpose: &str,
    scope: &crate::mcp::McpConnectorScope,
) -> Value {
    json!({
        "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": {
            "actor_ref": actor_ref.to_hex(),
            "actor_class": "human",
            "gate_actor_class": "human",
            "gate_actor_ref": actor_ref.to_hex(),
            "scope": {
                "world_ref": scope.world_ref.map(|id| id.to_hex()),
                "facet_ref": scope.facet_ref.map(|id| id.to_hex()),
            },
        },
        "consent": mcp_consent_json(purpose, false),
    })
}

/// Registers a connector NARROWED to an explicit bound-verb set.
pub(super) async fn register_bound_verb_mcp_actor(
    server: &Arc<SyncServer>,
    credential: &str,
    actor_ref: oneiron::EntityId,
    verbs: &[&'static str],
) {
    server
        .vault
        .put_entity(
            &actor_ref,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"bound-verb mcp actor",
        )
        .expect("seed bound-verb mcp actor entity");
    server
        .mcp_registry
        .lock()
        .await
        .register(
            credential,
            crate::mcp::McpConnectorActorRecord::new(
                actor_ref,
                oneiron::EdgeActorClass::Human,
                crate::mcp::McpConnectorScope::vault_wide(),
            )
            .with_bound_verbs(verbs.iter().copied()),
        )
        .expect("register bound-verb mcp actor");
}

/// Drives one call and returns the JSON-RPC refusal, failing loudly on success.
pub(super) async fn mcp_refusal(server: &Arc<SyncServer>, request: Request<Body>) -> Value {
    let (status, body) = route_json(server.clone(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("result").is_none(),
        "this call was supposed to be refused: {body:?}"
    );
    body
}

/// Every actor-derived refusal states the same four things AND the effective
/// scope it was refused under.
pub(super) fn assert_scoped_refusal(body: &Value, expected_scope: &Value, label: &str) {
    let data = &body["error"]["data"];
    assert!(
        data["error_code"]
            .as_str()
            .is_some_and(|code| !code.is_empty()),
        "{label}: {body:?}"
    );
    assert!(
        data["human_message"]
            .as_str()
            .is_some_and(|message| !message.trim().is_empty()),
        "{label}: {body:?}"
    );
    assert!(
        data["recovery_suggestions"]
            .as_array()
            .is_some_and(|suggestions| !suggestions.is_empty()),
        "{label}: {body:?}"
    );
    assert!(
        data["request_id"].as_str().is_some_and(|id| !id.is_empty()),
        "{label}: {body:?}"
    );
    assert_eq!(
        &data["effective_scope"], expected_scope,
        "{label}: an actor-derived refusal must state its effective scope: {body:?}"
    );
}

/// The verb names one setup result actually returned, in listing order.
pub(super) fn mcp_setup_verb_names(structured: &Value) -> Vec<String> {
    structured["verb_grammar"]["verbs"]
        .as_array()
        .expect("the setup result pages over the verb grammar")
        .iter()
        .map(|verb| verb["name"].as_str().expect("a verb name").to_owned())
        .collect()
}
