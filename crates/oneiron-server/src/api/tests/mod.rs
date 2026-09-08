use super::*;

mod depth_quality;
mod depth_spend;
mod memory_reason_repairs;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header::AUTHORIZATION, header::CONTENT_TYPE};
use oneiron::registry::ENTITY_TYPE_POLICY_MANIFEST;
use oneiron::retrieval_depth::{BackendSpend, RetrievalResult};
use serde_json::Map;
use serde_json::Value;
use tower::ServiceExt;

mod mcp_source_gate;

mod auth_idempotency;
mod billing_usage;
mod companion;
mod context_pack_disclosure;
mod context_pack_v4;
mod contract_snapshots;
mod core_memory_conversations;
mod mcp_paging_cursors;
mod mcp_results_carrier;
mod mcp_scoping;
mod mcp_tool_endpoints;
mod mcp_write_guards;
mod reactive;
mod retrieval_depth_quality;
mod retrieval_shaping;
mod run_tree;
mod support_contract;
mod support_mcp;
mod surface_events;
mod surface_routes;
mod vad_and_error_mapping;
use support_contract::*;
use support_mcp::*;

pub(super) const V1_CORE_OPENAPI_CONTRACT_SNAPSHOT: &str =
    include_str!("../../../tests/fixtures/v1_core_openapi_contract.snapshot.json");
pub(super) const V1_CORE_OPENAPI_CONTRACT_SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v1_core_openapi_contract.snapshot.json"
);
pub(super) const V1_CORE_SUCCESS_CONTRACT_SNAPSHOT: &str =
    include_str!("../../../tests/fixtures/v1_core_success_contract.snapshot.json");
pub(super) const V1_CORE_SUCCESS_CONTRACT_SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v1_core_success_contract.snapshot.json"
);
pub(super) const V1_CORE_ERROR_CONTRACT_SNAPSHOT: &str =
    include_str!("../../../tests/fixtures/v1_core_error_contract.snapshot.json");
pub(super) const V1_CORE_ERROR_CONTRACT_SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v1_core_error_contract.snapshot.json"
);
pub(super) const V1_CORE_OPENAPI_CONTRACT_OPERATIONS: &[(&str, &str)] = &[
    ("/v1/core/batch", "post"),
    ("/v1/core/query", "post"),
    ("/v1/core/context-pack", "post"),
    ("/v1/core/context-board", "post"),
    ("/v1/core/hydrate", "post"),
    ("/v1/core/batch/shortId/hydrate", "post"),
    ("/v1/core/run-tree", "get"),
    ("/v1/core/run-tree/observe", "get"),
    ("/v1/core/run-tree/intervene", "post"),
    ("/v1/core/conversations", "get"),
    ("/v1/core/conversations", "post"),
    ("/v1/core/conversations/{conversation_id}/turns", "get"),
    ("/v1/core/conversations/{conversation_id}/turns", "post"),
    ("/v1/core/turns/{turn_id}", "get"),
    ("/v1/core/turns/annotate", "get"),
    ("/v1/core/turns/annotate", "post"),
    ("/v1/core/outbound/capabilities", "get"),
    ("/v1/core/outbound/capabilities/{connector}", "get"),
    (
        "/v1/core/outbound/capabilities/{connector}/verbs/{verb}",
        "get",
    ),
    ("/v1/core/surface-events", "post"),
    ("/v1/core/surface-events/{correlation_id}", "get"),
];
pub(super) const V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES: &[&str] = &[
    "ApiError",
    "ApiErrorDetails",
    "ApiErrorEnvelope",
    "ErrorCode",
    "CoreBatchEntityInput",
    "CoreBatchEntityResult",
    "CoreBatchRequest",
    "CoreBatchResponse",
    "CoreContextEdge",
    "CoreContextEntity",
    "CoreContextPackItemAccounting",
    "ContextPackBudgetControls",
    "ContextPackDepthControls",
    "ContextPackPolicyControls",
    "ContextPackRetrievalBudgetControls",
    "ContextPackTimeControls",
    "ContextBoardCompanionControls",
    "ContextBoardMemoriesControls",
    "ContextBoardMemoriesSlotControls",
    "ContextBoardSessionControls",
    "CoreContextPackEvidence",
    "CoreContextPackRequest",
    "CoreContextPackResponse",
    "CoreContextPackScoreComponent",
    "CoreContextPackScoreEvidence",
    "CoreContextPackState",
    "CoreContextPackStateKind",
    "CoreContextPackStateReason",
    "CoreContextPackStats",
    "ContextBoardCompanionAssembly",
    "ContextBoardMemories",
    "ContextBoardMemoriesBudget",
    "ContextBoardMemoryRow",
    "ContextBoardMemorySlot",
    "ContextBoardMemorySource",
    "CoreDisclosureAssembly",
    "ContextBoardMemoriesCursor",
    "ContextBoardRequest",
    "ContextBoardResponse",
    "ContextBoardSession",
    "ContextBoardNotification",
    "ContextBoardUnprocessedItem",
    "ContextBoardBudget",
    "CoreInterlocutorControls",
    "CoreInterlocutorParty",
    "CoreInterlocutorStamp",
    "CoreCreateEntityRequest",
    "CoreCreateTurnRequest",
    "CoreEntityWriteResponse",
    "CoreBatchShortIdHydrateItem",
    "CoreBatchShortIdHydrateRequest",
    "CoreBatchShortIdHydrateResponse",
    "CoreShortIdHydrateOutcome",
    "CoreHydrateDeletionMetadata",
    "CoreHydrateDeletionReason",
    "CoreHydrateDeletionSource",
    "CoreHydrateRequest",
    "CoreHydrateResponse",
    "CoreHydrateStatus",
    "CoreListQuery",
    "CoreMemoryOperationKind",
    "CoreMemoryTimelineRecord",
    "CoreMemoryTimelineRecordState",
    "CoreMemoryTimelineResponse",
    "CoreMemoryVerbDeleteOutcome",
    "CoreMemoryVerbDeleteReason",
    "CoreMemoryVerbRequest",
    "CoreMemoryVerbResponse",
    "CoreQueryRequest",
    "SurfaceEventSubmitRequest",
    "SurfaceEventSourcePayload",
    "SurfaceSourceAppPayload",
    "SurfaceEventActionPayload",
    "SurfaceInteractionKindPayload",
    "SurfaceCounterpartyPayload",
    "SurfaceEventAckResponse",
    "SurfaceEventRejectionResponse",
    "SurfaceEventRejectionReasonPayload",
    "SurfaceEventStatusResponse",
    "SurfaceEventHandoffStatePayload",
    "CoreRunTreeEvent",
    "CoreRunTreeEventKind",
    "CoreRunTreeFailure",
    "CoreRunTreeInterventionEffect",
    "CoreRunTreeInterventionKind",
    "CoreRunTreeInterventionRequest",
    "CoreRunTreeInterventionResponse",
    "CoreRunTreeNode",
    "CoreRunTreeQuery",
    "CoreRunTreeRepair",
    "CoreRunTreeResponse",
    "CoreRunTreeStatus",
    "CoreRunTreeTimestamps",
    "CoreShortIdHydrateError",
    "CoreShortIdHydrateErrorKind",
    "CoreTextField",
    "CountMode",
    "ResponseMeta",
    "TurnVadAnnotateQuery",
    "TurnVadAnnotateRequest",
    "TurnVadAnnotateResponse",
    "TurnVadAnnotationSource",
    "VadPayload",
    "View",
];

pub(super) fn generated_spec() -> Value {
    openapi_document()
}

pub(super) fn assert_non_empty_string(value: &Value, context: &str) {
    assert!(
        value.as_str().is_some_and(|s| !s.trim().is_empty()),
        "{context} must be a non-empty string, got {value:?}"
    );
}

pub(super) fn test_server() -> (tempfile::TempDir, Arc<SyncServer>) {
    test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        ..Default::default()
    })
}

pub(super) fn test_server_with_config(
    config: SyncServerConfig,
) -> (tempfile::TempDir, Arc<SyncServer>) {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    assert_default_policy_manifest_fixture(vault.as_ref());
    let server = Arc::new(SyncServer::new(vault, config).expect("sync server"));
    (dir, server)
}

pub(super) fn run_artifact_git(repo_dir: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(repo_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("git test command starts");
    assert!(status.success(), "git test command failed: git {args:?}");
}

pub(super) fn create_artifact_repo(index: &[u8]) -> tempfile::TempDir {
    let repo_dir = tempfile::tempdir().expect("artifact repo dir");
    std::fs::write(repo_dir.path().join("index.html"), index).expect("write index");
    std::fs::write(
        repo_dir.path().join("app.js"),
        b"document.body.dataset.bundle = 'served';\n",
    )
    .expect("write app");
    run_artifact_git(repo_dir.path(), &["init"]);
    run_artifact_git(
        repo_dir.path(),
        &["config", "user.email", "oneiron@example.test"],
    );
    run_artifact_git(repo_dir.path(), &["config", "user.name", "Oneiron Test"]);
    run_artifact_git(repo_dir.path(), &["add", "."]);
    run_artifact_git(repo_dir.path(), &["commit", "-m", "initial"]);
    repo_dir
}

pub(super) fn commit_artifact_index(repo_dir: &std::path::Path, index: &[u8], message: &str) {
    std::fs::write(repo_dir.join("index.html"), index).expect("write index revision");
    run_artifact_git(repo_dir, &["add", "index.html"]);
    run_artifact_git(repo_dir, &["commit", "-m", message]);
}

pub(super) fn ingest_artifact_snapshot(
    server: &SyncServer,
    repo_dir: &std::path::Path,
    artifact: &str,
    learned_at: u64,
) -> oneiron::codebase::RepoIngestResult {
    let config = oneiron::codebase::RepoIngestConfig::new(repo_dir, ["index.html", "app.js"])
        .expect("repo ingest config");
    let result = server
        .vault
        .ingest_local_repo_at_commit(
            artifact,
            &config,
            "HEAD",
            oneiron::TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        )
        .expect("ingest artifact repo");
    let body = server
        .vault
        .get_code_artifact(&result.code_artifact_id)
        .expect("read CODE artifact")
        .expect("CODE artifact exists")
        .with_class(oneiron::code_artifact::CodeArtifactClass::Artifact);
    server
        .vault
        .put_code_artifact(
            &result.code_artifact_id,
            &body,
            oneiron::TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        )
        .expect("mark CODE artifact hostable");
    result
}

pub(super) async fn route_bytes(
    server: Arc<SyncServer>,
    request: Request<Body>,
) -> (StatusCode, HeaderMap, Bytes) {
    let response = api_routes(server)
        .oneshot(request)
        .await
        .expect("route response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    (status, headers, body)
}

pub(super) fn assert_default_policy_manifest_fixture(vault: &oneiron::Vault) {
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
            .expect("scan policy manifests")
            .len(),
        1
    );
}

pub(super) fn test_server_with_runtime_mode(
    mode: crate::runtime::RuntimeMode,
) -> (tempfile::TempDir, Arc<SyncServer>) {
    test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime: crate::runtime::RuntimeConfig::for_mode(mode),
        ..Default::default()
    })
}

pub(super) fn seeded_test_entity_id(counter: u128) -> oneiron::EntityId {
    let mut bytes = counter.to_be_bytes();
    bytes[0] = 0x7e;
    oneiron::EntityId::from_bytes(bytes).expect("seeded test id should be valid")
}

pub(super) fn synthetic_context_pack(result_count: usize) -> oneiron::ContextPack {
    oneiron::ContextPack {
        retrieval_quality: Default::default(),
        results: (0..result_count)
            .map(|index| {
                let id = seeded_test_entity_id(0x0012_6400 + index as u128);
                oneiron::ContextEntity {
                    id,
                    short_id: id.to_hex(),
                    content_hash: index as u8,
                    entity_type: ENTITY_TYPE_TURN,
                    score: 1.0,
                    fields: None,
                    edges: None,
                    vector: None,
                }
            })
            .collect(),
        neighbors: Vec::new(),
        stats: oneiron::PackStats {
            candidates_considered: result_count,
            signals_used: Vec::new(),
            query_time_us: 0,
            entities_hydrated: result_count,
            neighbors_hydrated: 0,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            tokens: oneiron::PackTokenStats::default(),
            items_truncated: oneiron::context_pack::PackItemAccounting::item_budget(),
            items_dropped: oneiron::context_pack::PackItemAccounting::token_budget(),
        },
        empty: None,
    }
}

pub(super) fn seed_active_claim(
    server: &SyncServer,
    id: oneiron::EntityId,
    subject: oneiron::EntityId,
    value: &str,
    learned_at: u64,
) {
    #[derive(serde::Serialize)]
    struct ClaimSeed<'a> {
        pred: &'a str,
        val: &'a str,
        conf: f32,
        #[serde(with = "serde_bytes")]
        subj: &'a [u8],
        appr: &'static str,
        life: &'static str,
    }

    let body = rmp_serde::to_vec_named(&ClaimSeed {
        pred: "profile.route_test",
        val: value,
        conf: 0.9,
        subj: subject.as_bytes(),
        appr: "auto",
        life: "active",
    })
    .expect("encode claim fixture");
    server
        .vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_CLAIM,
            oneiron::TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .expect("seed active claim");
}

pub(super) fn seed_companion_profile_access(
    server: &SyncServer,
    grant_id: oneiron::EntityId,
    principal_ref: oneiron::EntityId,
    person_ref: oneiron::EntityId,
    persona_ref: oneiron::EntityId,
) {
    let grant =
        oneiron::AccessGrant::companion_profile_read(principal_ref, person_ref, persona_ref, 10);
    server
        .vault
        .create_access_grant(&grant_id, &grant)
        .expect("seed companion profile grant");
}

pub(super) fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

/// Mints a v2 token against the `"secret"` these tests configure everywhere.
pub(super) fn test_bearer(claims: &str) -> String {
    format!(
        "Bearer {}",
        crate::auth::mint_core_token_v2("secret", claims)
    )
}

/// Owner-grade credential: the bare trust root over the standard header.
pub(super) fn owner_bearer() -> String {
    "Bearer secret".to_owned()
}

pub(super) fn core_request(
    method: &str,
    uri: &str,
    scope: &str,
    body: Option<&Value>,
) -> Request<Body> {
    core_request_with_authz(method, uri, test_bearer(&format!("scope={scope}")), body)
}

pub(super) fn core_request_with_principal_ref(
    method: &str,
    uri: &str,
    scope: &str,
    principal_ref: &str,
    body: Option<&Value>,
) -> Request<Body> {
    core_request_with_authz(
        method,
        uri,
        test_bearer(&format!("scope={scope};principal_ref={principal_ref}")),
        body,
    )
}

pub(super) fn core_request_with_authz(
    method: &str,
    uri: &str,
    authorization: String,
    body: Option<&Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, authorization);
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
        .expect("request")
}

pub(super) async fn route_json(
    server: Arc<SyncServer>,
    request: Request<Body>,
) -> (StatusCode, Value) {
    let response = api_routes(server)
        .oneshot(request)
        .await
        .expect("route response");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("JSON response body");
    let body: Value = serde_json::from_slice(&body).expect("JSON response");
    (status, body)
}

/// One call against a RETIRED plain-verb adapter.
///
/// ONE-1704 M1 took the seven `oneiron.*` names off the wire: neither
/// registered endpoint resolves them, which
/// `mcp_legacy_catalog_is_unknown_tool_on_both_endpoints` proves at the wire on
/// both routes. Their executor BODIES survive as private adapters over the same
/// gated vault API, and the rows below drive those adapters directly — the
/// gate, idempotency, and stale-target semantics they pin belong to the
/// adapter, not to a wire name.
pub(super) struct McpLegacyCall {
    credential: String,
    id: String,
    name: String,
    arguments: Value,
}

pub(super) fn error_envelope(body: &Value) -> &Value {
    body.get("error")
        .and_then(Value::as_object)
        .map(|_| &body["error"])
        .expect("typed error envelope")
}

pub(super) fn assert_error_envelope(body: &Value, code: &str) {
    let error = error_envelope(body);
    assert_eq!(error["code"], Value::from(code));
    assert!(
        error["requestId"]
            .as_str()
            .is_some_and(|request_id| !request_id.is_empty()),
        "enveloped errors must include a requestId: {body:?}"
    );
    assert!(
        body.get("code").is_none(),
        "v1 core errors must not serialize as a flat ApiError: {body:?}"
    );
}

pub(super) fn assert_json_snapshot(actual: Value, fixture: &str, path: &str, label: &str) {
    assert_json_snapshot_with_update(
        actual,
        fixture,
        path,
        label,
        std::env::var_os("ONEIRON_UPDATE_TEST_FIXTURES").is_some(),
    );
}

pub(super) fn assert_json_snapshot_with_update(
    mut actual: Value,
    fixture: &str,
    path: &str,
    label: &str,
    update_fixture: bool,
) {
    let mut expected: Value = serde_json::from_str(fixture).expect("snapshot fixture JSON");
    sort_json(&mut actual);
    let actual = serde_json::to_string_pretty(&actual).expect("serialize actual snapshot");
    if update_fixture {
        std::fs::write(path, format!("{actual}\n")).expect("write snapshot fixture");
        return;
    }
    let actual: Value = serde_json::from_str(&actual).expect("actual snapshot JSON");
    sort_json(&mut expected);
    if actual != expected {
        let actual = serde_json::to_string_pretty(&actual).expect("serialize actual snapshot");
        panic!("{label} snapshot drifted; update fixture with:\n{actual}");
    }
}

pub(super) fn sort_json(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                sort_json(item);
            }
        }
        Value::Object(object) => {
            let mut entries = std::mem::take(object).into_iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));

            for (key, mut value) in entries {
                sort_json(&mut value);
                object.insert(key, value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

pub(super) async fn core_json(
    server: Arc<SyncServer>,
    method: &str,
    uri: &str,
    scope: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    route_json(server, core_request(method, uri, scope, body)).await
}

/// Drives a `/v1/core` route with the owner-grade credential.
///
/// A `scope=…` bearer is a delegated instrument and is NOT owner-grade
/// (`CoreAuth::is_owner_grade`), so any assertion about owner-presence,
/// `owner_present: true`, or the absent-disclosure-block byte-identity
/// guarantee must travel on this helper rather than `core_json`.
pub(super) async fn owner_json(
    server: Arc<SyncServer>,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    route_json(
        server,
        core_request_with_authz(method, uri, owner_bearer(), body),
    )
    .await
}

pub(super) fn seed_turn(server: &SyncServer, text: &str) -> oneiron::EntityId {
    let turn = oneiron::EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({
        "txt": text,
        "spkr": "user",
        "at": 100_u64,
    }))
    .expect("encode turn body");
    server
        .vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("put turn");
    turn
}

pub(super) fn turn_annotation_request_body(turn: &oneiron::EntityId, annotated_at: u64) -> Value {
    json!({
        "turn_id": turn.to_hex(),
        "source": "model_inference",
        "vad": {
            "valence": 0.25,
            "arousal": 0.5,
            "dominance": 0.75,
        },
        "annotated_at": annotated_at,
    })
}

pub(super) async fn idempotent_core_annotate(
    server: Arc<SyncServer>,
    idempotency_key: &str,
    auth_header: (&str, &str),
    body: &Value,
) -> (StatusCode, Value) {
    route_json(
        server,
        Request::builder()
            .method("POST")
            .uri("/v1/core/turns/annotate")
            .header(auth_header.0, auth_header.1)
            .header("Idempotency-Key", idempotency_key)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await
}

pub(super) fn enqueue_queue_attempt(
    vault: &oneiron::Vault,
    kind: &str,
    now: u64,
    run_id: &str,
) -> oneiron::attempt_queue::AttemptRecord {
    match oneiron::AttemptQueue::new(vault)
        .enqueue(oneiron::attempt_queue::EnqueueAttempt {
            kind: kind.to_owned(),
            payload: Vec::new(),
            dedupe_key: None,
            run_id: Some(run_id.to_owned()),
            now,
        })
        .expect("enqueue attempt")
    {
        oneiron::attempt_queue::EnqueueOutcome::Enqueued(record)
        | oneiron::attempt_queue::EnqueueOutcome::Existing(record) => record,
        _ => panic!("unexpected enqueue outcome"),
    }
}

pub(super) fn attempt_id_hex(id: oneiron::AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) async fn top_up_route(
    server: Arc<SyncServer>,
    idempotency_key: &str,
    credit_units: f64,
) -> (StatusCode, Value) {
    route_json(
        server,
        json_request(
            "POST",
            "/v1/consumer/top-up",
            json!({
                "tenantId": "tenant-a",
                "idempotencyKey": idempotency_key,
                "creditUnits": credit_units,
            }),
        ),
    )
    .await
}

pub(super) async fn record_usage_event_route(
    server: Arc<SyncServer>,
    idempotency_key: &str,
    service_cost_usd: f64,
) -> (StatusCode, Value) {
    record_usage_event_for_vault_route(server, idempotency_key, "vault-a", service_cost_usd).await
}

pub(super) async fn record_usage_event_for_vault_route(
    server: Arc<SyncServer>,
    idempotency_key: &str,
    vault_id: &str,
    service_cost_usd: f64,
) -> (StatusCode, Value) {
    route_json(
        server,
        json_request(
            "POST",
            "/v1/usage/events",
            json!({
                "tenantId": "tenant-a",
                "vaultId": vault_id,
                "idempotencyKey": idempotency_key,
                "agentId": "agent-a",
                "model": "model-a",
                "service": "inference",
                "serviceCostUsd": service_cost_usd,
            }),
        ),
    )
    .await
}

/// Seeds one witnessed TURN + MESSAGE pair for the VAD annotation fixtures.
///
/// ONE-1686 closed the public raw MESSAGE put: a MESSAGE body is the gated
/// six-axis witness envelope now, and the engine's witness door is its only
/// writer. These fixtures therefore mint their rows through that door — the
/// same one production transcripts go through — under caller-pinned ids, so
/// what they annotate is a real transcript row rather than opaque bytes.
///
/// The door does NOT author the `ChildOf` message -> turn edge (it writes
/// `PartOf`/`BelongsTo`/`AuthoredBy`), and `require_message_in_turn` is what
/// reads `ChildOf`, so callers still add that edge themselves exactly as
/// before.
pub(super) fn witness_vad_message_fixture(
    server: &SyncServer,
    turn: &oneiron::EntityId,
    message: &oneiron::EntityId,
    content: &str,
    occurred_at: u64,
) {
    let actor = oneiron::EntityId::now();
    let conversation = oneiron::EntityId::now();
    let at = oneiron::TimeRange {
        start: occurred_at,
        end: occurred_at,
    };
    server
        .vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            at,
            occurred_at,
            b"vad fixture",
        )
        .expect("put fixture actor");
    server
        .vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .witness(&oneiron::WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![oneiron::WitnessMessage {
                id: Some(message.to_hex()),
                author: oneiron::WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at,
        })
        .expect("witness fixture turn");
}

pub(super) fn interlocutor_test_server() -> (tempfile::TempDir, Arc<SyncServer>) {
    test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    })
}

pub(super) fn seed_counterparty_contact(
    server: &SyncServer,
    contact_id: oneiron::EntityId,
    identity_ref: oneiron::EntityId,
    counterparty: &str,
) {
    let record = oneiron::counterparty_contact::CounterpartyContactRecord::user_introduction(
        identity_ref,
        counterparty,
        100,
    )
    .expect("contact record");
    server
        .vault
        .create_counterparty_contact(&contact_id, &record)
        .expect("create counterparty contact");
}

// ─── OF-365 disclosure clamp HTTP red-team suite (ONE-1517) ─────────────────

pub(super) fn seed_text_turn(server: &SyncServer, text: &str) -> oneiron::EntityId {
    let turn = oneiron::EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({
        "txt": text,
        "spkr": "user",
        "at": 100_u64,
    }))
    .expect("encode turn body");
    server
        .vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .text(&turn, &[("body", text)])
        .commit()
        .expect("seed text turn");
    turn
}

pub(super) fn seed_disclosure_scope(
    server: &SyncServer,
    contact_id: oneiron::EntityId,
    entities: Vec<oneiron::EntityId>,
) {
    let scope = oneiron::disclosure::DisclosureScope::task_scoped("party planning", entities, 100)
        .expect("disclosure scope");
    server
        .vault
        .set_counterparty_disclosure_scope(&contact_id, &scope)
        .expect("set disclosure scope");
}

// ─── Surface events (ONE-1259) ───────────────────────────────────────────────

/// Seeds an agent-bound, active email identity the surface-event routes can
/// address, and returns the address plus its agent ref.
pub(super) fn seed_surface_identity(server: &SyncServer, counter: u128, address: &str) -> String {
    let identity_ref = seeded_test_entity_id(counter);
    let agent_ref = seeded_test_entity_id(counter + 1);
    let mut identity = oneiron::channel_identity::ChannelIdentity::requested(
        "email",
        address,
        oneiron::channel_identity::SelfHeldShape::DedicatedAddress,
        oneiron::channel_identity::ChannelIdentityBinding::agent(agent_ref),
        1_782_357_000,
    );
    identity.state = oneiron::channel_identity::ChannelIdentityState::Active;
    identity.pending_fulfillment = None;
    server
        .vault
        .create_channel_identity(&identity_ref, &identity)
        .expect("seed channel identity");
    agent_ref.to_hex()
}

pub(super) fn surface_event_body(address: &str, correlation_id: &str) -> Value {
    json!({
        "event_id": correlation_id,
        "channel": "email",
        "receiving_address_or_handle": address,
        "counterparty": {
            "state": "unknown",
            "counterparty_key": "email:sender@example.com"
        },
        "received_at": 1_782_357_600_u64,
        "foreign_inbound": true
    })
}

// ─── ONE-1437 · reactive local-first read ────────────────────────────────────

/// A local query over one entity blob that also counts how many times it
/// actually touched the vault. The count is what lets a fixture assert
/// "exactly one re-query" instead of inferring it from the output value.
pub(super) struct ReactiveEntityProbe {
    id: oneiron::EntityId,
    dependencies: Vec<ReactiveDependency>,
    reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl ReactiveLocalQuery for ReactiveEntityProbe {
    type Output = Option<Vec<u8>>;

    fn dependencies(&self) -> &[ReactiveDependency] {
        &self.dependencies
    }

    fn read(&self, vault: &oneiron::Vault) -> oneiron::Result<Self::Output> {
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        vault.get(&self.id)
    }
}

pub(super) fn reactive_probe(
    id: oneiron::EntityId,
    dependencies: Vec<ReactiveDependency>,
) -> (ReactiveEntityProbe, Arc<std::sync::atomic::AtomicUsize>) {
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    (
        ReactiveEntityProbe {
            id,
            dependencies,
            reads: Arc::clone(&reads),
        },
        reads,
    )
}

pub(super) fn reactive_reads(counter: &Arc<std::sync::atomic::AtomicUsize>) -> usize {
    counter.load(std::sync::atomic::Ordering::Relaxed)
}

/// Seeds one turn body into the local vault at `learned_at`, which is also what
/// decides the window the engine mirror will place it in.
pub(super) fn seed_reactive_turn(vault: &oneiron::Vault, id: &oneiron::EntityId, learned_at: u64) {
    vault
        .put_entity(
            id,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            b"reactive local write",
        )
        .expect("seed reactive turn");
}

pub(super) fn reactive_window_frame(window_key: &str, sub_tag: u8) -> Vec<u8> {
    crate::protocol::encode_window_sync(window_key, sub_tag, b"payload")
        .into_result()
        .expect("window sync frame")
}

pub(super) fn reactive_window_update_frame(window_key: &str) -> Vec<u8> {
    reactive_window_frame(window_key, crate::protocol::window_sub_tags::UPDATE)
}

/// Every frame shape that reaches the broadcast channel yet must never re-run
/// an LMDB query: presence/ephemeral state, sync negotiation, lease traffic,
/// selector requests, malformed bytes, and tags this server does not know
/// (which is how a future app-tier RPC/SUB frame will arrive here).
pub(super) fn reactive_nonpersistent_frames(window_key: &str) -> Vec<Vec<u8>> {
    let mut root_version_vector = vec![crate::protocol::TAG_VERSION_VECTOR];
    root_version_vector.extend_from_slice(b"encoded-vv");

    vec![
        crate::protocol::encode_ephemeral(b"presence")
            .into_result()
            .expect("ephemeral frame"),
        root_version_vector,
        oneiron::sync::transport::encode_lease_request(7, &[3u8; 32], &[5u8; 64]),
        reactive_window_frame(window_key, crate::protocol::window_sub_tags::VV_REQUEST),
        reactive_window_frame(window_key, crate::protocol::window_sub_tags::VV_RESPONSE),
        reactive_window_frame(
            window_key,
            crate::protocol::window_sub_tags::SELECTOR_VV_REQUEST,
        ),
        Vec::new(),
        vec![30, 1, 2, 3],
    ]
}

// ── ONE-1936: MCP write-verb validity guard ──────────────────────────────

/// Seeds `subject`, an active claim, and its replacement, then supersedes —
/// leaving `old` as a stale target whose head is `new`.
pub(super) fn seed_superseded_claim_pair(
    server: &SyncServer,
    subject: oneiron::EntityId,
    old: oneiron::EntityId,
    new: oneiron::EntityId,
) {
    server
        .vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .expect("seed subject");
    seed_active_claim(server, old, subject, "before", 100);
    seed_active_claim(server, new, subject, "after", 200);
    server
        .vault
        .supersede_claim(&new, &old, 300)
        .expect("supersede claim");
}

/// Resolves a reported `successor_short_id` back through the SAME public
/// short-ref door a client would use. A ref that does not round-trip is not a
/// ref the caller can re-get with.
pub(super) fn resolve_short_ref(server: &SyncServer, short_ref: &str) -> oneiron::EntityId {
    let (short_id, content_hash) =
        crate::api::parse_short_ref(short_ref).expect("successor ref must be a public short ref");
    server
        .vault
        .hydrate_short_id(&short_id, content_hash)
        .expect("hydrate successor ref")
        .expect("successor ref must resolve")
        .id
}

// ═══════════════════════════════════════════════════════════════════════════
// ONE-1704 — two registered MCP endpoints over the wire
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// ONE-1704 M2 — the INJECTED execute_code host SEAM
//
// This crate ships no `JsCodeModeRuntime`, LLM backend, or budget lease, so the
// fixture below binds a PROVIDER into the shipped `McpEngineNativeCodeHost`
// adapter — the seam production would use.
//
// ONE-1704 B2: binding it here is a NEGATIVE control, not a positive one. With a
// host bound in this very process, a direct `execute_code` call is still refused
// at the wire with `execute_code_unavailable` and the counter below stays at
// zero, which is what proves the retirement is the registered surface's and not
// an accident of a missing provider.
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// ONE-1704 MATERIAL7 — fail-closed acceptance
// ═══════════════════════════════════════════════════════════════════════════

/// Seeds one CLAIM row whose own `world` key is `world`.
///
/// Only a CLAIM carries a world key, so this is the row shape the world ceiling
/// can actually answer for. `Auto`/`Active` is the surfaceable pair the engine's
/// own read admission requires.
pub(super) fn seed_world_claim(
    server: &Arc<SyncServer>,
    id: oneiron::EntityId,
    subject: oneiron::EntityId,
    world: oneiron::EntityId,
) {
    let mut body = oneiron::ClaimBody::new(
        "profile.mcp_gateway",
        oneiron::ClaimSubject::Entity(subject),
        rmpv::Value::from("world-scoped row"),
        0.8,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    );
    body.world = Some(world);
    server
        .vault
        .put_claim(
            &id,
            &body,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            101,
        )
        .expect("seed a world-scoped claim");
}

// ── ONE-207 · depth-dialed retrieval and the reasoning route ────────────

/// A host reasoning backend with scripted spend.
///
/// It proposes no follow-up queries, so the deep round loop ends after one
/// `decompose`; what the rows here are actually about is the ACCOUNTING —
/// `tokensUsed` must be the sum of what this stub reports, never the
/// `tokenBudget` the request carried.
pub(super) struct StubReasonBackend {
    answer: String,
    sources: Option<Vec<String>>,
    decompose_tokens: u64,
    rerank_tokens: u64,
    compose_tokens: u64,
    declined: bool,
}

impl StubReasonBackend {
    fn answering(answer: &str) -> Self {
        Self {
            answer: answer.to_owned(),
            sources: None,
            decompose_tokens: 3,
            rerank_tokens: 5,
            compose_tokens: 9,
            declined: false,
        }
    }
}

impl oneiron::retrieval_depth::DeepSearchBackend for StubReasonBackend {
    fn decompose(
        &self,
        _query: &str,
        _already_run: &[String],
        _max_queries: usize,
        _token_budget: Option<u64>,
        _lease: &oneiron::llm::BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>> {
        Ok(oneiron::retrieval_depth::BackendSpend {
            value: Vec::new(),
            tokens_used: self.decompose_tokens,
        })
    }

    fn rerank(
        &self,
        _query: &str,
        candidates: &[oneiron::rerank::RerankCandidate<'_>],
        _token_budget: Option<u64>,
        _lease: &oneiron::llm::BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        Ok(oneiron::retrieval_depth::BackendSpend {
            value: vec![0.0; candidates.len()],
            tokens_used: self.rerank_tokens,
        })
    }
}

impl MemoryReasonBackend for StubReasonBackend {
    fn compose(
        &self,
        request: &MemoryReasonComposeRequest<'_>,
        _lease: &oneiron::llm::BudgetLease,
    ) -> RetrievalResult<BackendSpend<MemoryReasonComposition>> {
        let source_short_ids = self.sources.clone().unwrap_or_else(|| {
            request
                .evidence
                .iter()
                .map(|row| row.short_id.clone())
                .collect()
        });
        Ok(oneiron::retrieval_depth::BackendSpend {
            value: MemoryReasonComposition {
                answer: self.answer.clone(),
                source_short_ids,
                confidence: 0.9,
                gaps: Vec::new(),
                declined: self.declined,
            },
            tokens_used: self.compose_tokens,
        })
    }
}

pub(super) fn memory_reason_server(
    backend: Option<Arc<dyn MemoryReasonBackend>>,
) -> (tempfile::TempDir, Arc<SyncServer>) {
    memory_reason_server_with_guard(
        backend,
        oneiron::llm::BudgetGuard::new(
            "one-207-server-tests",
            10_000,
            oneiron::llm::BudgetExhaustionPolicy::Suspend,
        ),
    )
}

pub(super) fn memory_reason_server_with_guard(
    backend: Option<Arc<dyn MemoryReasonBackend>>,
    guard: oneiron::llm::BudgetGuard,
) -> (tempfile::TempDir, Arc<SyncServer>) {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let turn = seeded_test_entity_id(0x0207_0001);
    let body = rmp_serde::to_vec_named(&json!({
        "txt": "the launch date moved to March",
        "spkr": "user",
        "at": 700_u64
    }))
    .expect("encode turn body");
    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 700,
                end: 700,
            },
            700,
            &body,
        )
        .text(&turn, &[("body", "the launch date moved to March")])
        .commit()
        .expect("seed reasoning evidence");

    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            allow_unauthenticated: true,
            ..Default::default()
        },
    )
    .expect("sync server");
    let server = match backend {
        Some(backend) => {
            server.with_deep_retrieval_host(Arc::new(DeepRetrievalHost::new(backend, guard)))
        }
        None => server,
    };
    (dir, Arc::new(server))
}

// Keep the frozen pre-extension fixtures intact. The in-memory expectation adds
// only these pinned fields; all existing fields, scores, and authority shapes
// are still compared against the original snapshots.
