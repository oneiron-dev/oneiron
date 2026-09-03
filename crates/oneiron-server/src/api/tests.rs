use super::*;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header::AUTHORIZATION, header::CONTENT_TYPE};
use oneiron::registry::ENTITY_TYPE_POLICY_MANIFEST;
use serde_json::Map;
use serde_json::Value;
use tower::ServiceExt;

const V1_CORE_OPENAPI_CONTRACT_SNAPSHOT: &str =
    include_str!("../../tests/fixtures/v1_core_openapi_contract.snapshot.json");
const V1_CORE_OPENAPI_CONTRACT_SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v1_core_openapi_contract.snapshot.json"
);
const V1_CORE_SUCCESS_CONTRACT_SNAPSHOT: &str =
    include_str!("../../tests/fixtures/v1_core_success_contract.snapshot.json");
const V1_CORE_SUCCESS_CONTRACT_SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v1_core_success_contract.snapshot.json"
);
const V1_CORE_ERROR_CONTRACT_SNAPSHOT: &str =
    include_str!("../../tests/fixtures/v1_core_error_contract.snapshot.json");
const V1_CORE_ERROR_CONTRACT_SNAPSHOT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v1_core_error_contract.snapshot.json"
);
const V1_CORE_OPENAPI_CONTRACT_OPERATIONS: &[(&str, &str)] = &[
    ("/v1/core/batch", "post"),
    ("/v1/core/query", "post"),
    ("/v1/core/context-pack", "post"),
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
const V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES: &[&str] = &[
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
    "EiriCompanionControls",
    "EiriMemoryBoardControls",
    "EiriMemoryBoardSlotControls",
    "EiriSessionRagControls",
    "CoreContextPackEvidence",
    "CoreContextPackRequest",
    "CoreContextPackResponse",
    "CoreContextPackScoreComponent",
    "CoreContextPackScoreEvidence",
    "CoreContextPackState",
    "CoreContextPackStateKind",
    "CoreContextPackStateReason",
    "CoreContextPackStats",
    "CoreEiriCompanionAssembly",
    "CoreEiriMemoryBoard",
    "CoreEiriMemoryBoardBudget",
    "CoreEiriMemoryBoardRow",
    "CoreEiriMemoryBoardSlot",
    "CoreEiriMemoryBoardSource",
    "CoreDisclosureAssembly",
    "CoreEiriSessionRagState",
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

#[test]
fn search_response_drops_stale_hydrated_hits() {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
    let scoped_read = vault
        .scoped_read(oneiron::claim::ScopedReadActorKey::new("test-reader").expect("actor key"));
    let stale_hit = oneiron::ScoredEntity {
        id: oneiron::EntityId::now(),
        score: 0.75,
    };

    for view in [View::Summary, View::Full] {
        let response = search_response(&scoped_read, vec![stale_hit], view, 10).unwrap();
        assert!(
            response.is_empty(),
            "{view:?} should skip missing search hits"
        );
    }
}

#[test]
fn search_response_rechecks_projected_claim_body() {
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

    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
    let claim_id = seeded_test_entity_id(0x0012_6901);
    let subject = seeded_test_entity_id(0x0012_6902);
    let body = rmp_serde::to_vec_named(&ClaimSeed {
        pred: "profile.projected",
        val: "hidden after update",
        conf: 0.9,
        subj: subject.as_bytes(),
        appr: "proposed",
        life: "active",
    })
    .expect("encode proposed claim");
    vault
        .put_entity(
            &claim_id,
            oneiron::registry::ENTITY_TYPE_CLAIM,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("seed proposed claim");

    let scoped_read = vault
        .scoped_read(oneiron::claim::ScopedReadActorKey::new("test-reader").expect("actor key"));
    let stale_hit = oneiron::ScoredEntity {
        id: claim_id,
        score: 0.75,
    };

    for view in [View::Summary, View::Full] {
        let response = search_response(&scoped_read, vec![stale_hit], view, 10).unwrap();
        assert!(
            response.is_empty(),
            "{view:?} should re-check the exact projected body through ScopedRead"
        );
    }
}

#[test]
fn search_queries_default_to_estimate_count_mode() {
    let text: TextSearchQuery = serde_json::from_value(serde_json::json!({
        "query": "hello"
    }))
    .unwrap();
    assert_eq!(text.limit, default_limit());
    assert_eq!(text.count_mode, CountMode::Estimate);

    let vector: VectorSearchQuery = serde_json::from_value(serde_json::json!({
        "query": "0.0,0.0"
    }))
    .unwrap();
    assert_eq!(vector.limit, default_limit());
    assert_eq!(vector.count_mode, CountMode::Estimate);
}

#[test]
fn search_meta_honors_none_without_counting() {
    assert_eq!(search_meta(CountMode::None, 25), ResponseMeta::none());
    assert_eq!(search_fetch_limit(CountMode::None, 25), 25);
}

#[test]
fn search_meta_reports_estimate_not_exact() {
    assert_eq!(
        search_meta(CountMode::Estimate, 7),
        ResponseMeta::estimate(7)
    );
    assert_eq!(search_fetch_limit(CountMode::Estimate, 7), 8);
    assert_eq!(CountMode::Exact.for_search_response(), CountMode::Estimate);
}

fn generated_spec() -> Value {
    openapi_document()
}

fn assert_non_empty_string(value: &Value, context: &str) {
    assert!(
        value.as_str().is_some_and(|s| !s.trim().is_empty()),
        "{context} must be a non-empty string, got {value:?}"
    );
}

fn test_server() -> (tempfile::TempDir, Arc<SyncServer>) {
    test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        ..Default::default()
    })
}

fn test_server_with_config(config: SyncServerConfig) -> (tempfile::TempDir, Arc<SyncServer>) {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    assert_default_policy_manifest_fixture(vault.as_ref());
    let server = Arc::new(SyncServer::new(vault, config).expect("sync server"));
    (dir, server)
}

fn run_artifact_git(repo_dir: &std::path::Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(repo_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("git test command starts");
    assert!(status.success(), "git test command failed: git {args:?}");
}

fn create_artifact_repo(index: &[u8]) -> tempfile::TempDir {
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

fn commit_artifact_index(repo_dir: &std::path::Path, index: &[u8], message: &str) {
    std::fs::write(repo_dir.join("index.html"), index).expect("write index revision");
    run_artifact_git(repo_dir, &["add", "index.html"]);
    run_artifact_git(repo_dir, &["commit", "-m", message]);
}

fn ingest_artifact_snapshot(
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

async fn route_bytes(
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

fn assert_default_policy_manifest_fixture(vault: &oneiron::Vault) {
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
            .expect("scan policy manifests")
            .len(),
        1
    );
}

#[tokio::test]
async fn companion_resume_hides_fresh_default_policy_manifest() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
            .expect("scan policy manifests")
            .len(),
        1
    );
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("sync server"),
    );

    let request = Request::builder()
        .method("POST")
        .uri("/api/companion/resume")
        .header(CONTENT_TYPE, "application/json")
        .header("x-oneiron-caller", "fresh-session")
        .body(Body::from("{}"))
        .expect("resume request");
    let (status, body) = route_json(server, request).await;

    assert_eq!(status, StatusCode::OK);
    // The engine-seeded POLICY MANIFEST stays hidden (it is the one
    // agent-invisible type). The seeded AGENT_DEF rows (six from ONE-1890,
    // plus ONE-1709's sys.team_lead — seven) are ordinary
    // agent-visible entities and DO appear — they are real dispatchable agents
    // a resuming companion must see — so `last_activity` carries their pinned
    // seed timestamp rather than staying null.
    let counts = body["session"]["counts"]
        .as_object()
        .expect("session counts");
    assert_eq!(
        counts.get(&ENTITY_TYPE_POLICY_MANIFEST.to_string()),
        None,
        "the engine-seeded policy manifest must stay out of resume counts"
    );
    assert_eq!(
        counts,
        &serde_json::Map::from_iter([(
            oneiron::registry::ENTITY_TYPE_AGENT_DEF.to_string(),
            Value::from(7),
        )]),
        "a fresh vault carries only the seven seeded agent definitions"
    );
    assert_eq!(body["session"]["last_activity"], Value::from(0));
}

fn test_server_with_runtime_mode(
    mode: crate::runtime::RuntimeMode,
) -> (tempfile::TempDir, Arc<SyncServer>) {
    test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime: crate::runtime::RuntimeConfig::for_mode(mode),
        ..Default::default()
    })
}

fn seeded_test_entity_id(counter: u128) -> oneiron::EntityId {
    let mut bytes = counter.to_be_bytes();
    bytes[0] = 0x7e;
    oneiron::EntityId::from_bytes(bytes).expect("seeded test id should be valid")
}

fn synthetic_context_pack(result_count: usize) -> oneiron::ContextPack {
    oneiron::ContextPack {
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

#[test]
fn context_pack_scoped_budget_preserves_default_response_split() {
    let (response, internal) = resolve_context_pack_retrieval_budgets(None, 5, 100, 7);
    let defaults =
        oneiron::ContextPackRetrievalBudget::from_limit(5, oneiron::TokenAllocation::default(), 7);

    assert_eq!(response, defaults);
    assert_eq!(internal.selected_edges, 7);
    assert_eq!(internal.claims, 100);
    assert_eq!(internal.turns, 100);
    assert_eq!(internal.summaries, 100);
    assert_eq!(internal.facets, 100);
    assert_eq!(internal.other, 100);
}

#[test]
fn context_pack_scoped_budget_preserves_explicit_zero_buckets() {
    let controls = ContextPackRetrievalBudgetControls {
        claims: Some(0),
        turns: Some(2),
        selected_edges: Some(3),
        ..Default::default()
    };

    let (response, internal) = resolve_context_pack_retrieval_budgets(Some(&controls), 10, 50, 9);

    assert_eq!(response.claims, 0);
    assert_eq!(internal.claims, 0);
    assert_eq!(response.turns, 2);
    assert_eq!(internal.turns, 50);
    assert_eq!(response.selected_edges, 3);
    assert_eq!(internal.selected_edges, 3);
}

#[test]
fn context_pack_response_limits_scrub_stats_after_scoped_truncation() {
    let mut pack = synthetic_context_pack(0);
    let claim_a = seeded_test_entity_id(0x0012_6501);
    let claim_b = seeded_test_entity_id(0x0012_6502);
    let turn = seeded_test_entity_id(0x0012_6503);
    let neighbor = seeded_test_entity_id(0x0012_6504);
    let entity = |id: oneiron::EntityId, entity_type: u8| oneiron::ContextEntity {
        id,
        short_id: id.to_hex(),
        content_hash: 0,
        entity_type,
        score: 1.0,
        fields: None,
        edges: None,
        vector: None,
    };
    pack.results = vec![
        entity(claim_a, oneiron::registry::ENTITY_TYPE_CLAIM),
        entity(claim_b, oneiron::registry::ENTITY_TYPE_CLAIM),
        entity(turn, ENTITY_TYPE_TURN),
    ];
    pack.neighbors = vec![
        entity(neighbor, oneiron::registry::ENTITY_TYPE_SUMMARY),
        entity(
            seeded_test_entity_id(0x0012_6505),
            oneiron::registry::ENTITY_TYPE_SUMMARY,
        ),
    ];
    pack.stats.candidates_considered = 99;
    pack.stats.entities_hydrated = 88;
    pack.stats.neighbors_hydrated = 77;

    apply_context_pack_response_limits(
        &mut pack,
        ContextPackResponseLimits {
            results: 10,
            neighbors: 1,
            retrieval: oneiron::ContextPackRetrievalBudget::new(1, 1, 0, 0, 0, 0),
        },
    );

    assert_eq!(
        pack.results
            .iter()
            .map(|entity| entity.id)
            .collect::<Vec<_>>(),
        vec![claim_a, turn]
    );
    assert_eq!(pack.neighbors.len(), 1);
    assert_eq!(pack.stats.candidates_considered, 2);
    assert_eq!(pack.stats.entities_hydrated, 2);
    assert_eq!(pack.stats.neighbors_hydrated, 1);
    assert!(pack.empty.is_none());
}

fn seed_active_claim(
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

fn seed_companion_profile_access(
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

#[tokio::test]
async fn health_runtime_summary_redacts_route_model_details_without_auth() {
    let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        crate::runtime::RuntimeRoleTargetOverride::target(
            RuntimeProviderKind::Local,
            "sensitive-orchestrator-model",
        ),
    ));
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        runtime,
        ..Default::default()
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("health response body");
    let body: Value = serde_json::from_slice(&body).expect("health JSON body");
    assert_eq!(body["runtime"]["mode"], Value::from("local_free"));
    assert_eq!(body["runtime"]["oneironSpendMetered"], Value::from(false));
    assert_eq!(body["runtime"]["state"], Value::from("available"));
    assert!(body["runtime"].get("routes").is_none());

    let runtime_json = body["runtime"].to_string();
    for redacted in [
        "sensitive-orchestrator-model",
        "orchestrator",
        "providerKind",
        "provenance",
    ] {
        assert!(
            !runtime_json.contains(redacted),
            "health runtime summary leaked {redacted}: {runtime_json}"
        );
    }
}

#[tokio::test]
async fn runtime_status_reflects_configured_runtime_mode() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime: crate::runtime::RuntimeConfig::for_mode(RuntimeMode::OneironCloud),
        ..Default::default()
    });

    let response = api_routes(server.clone())
        .oneshot(
            Request::builder()
                .uri("/api/core/discover")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("discover response body");
    let body: Value = serde_json::from_slice(&body).expect("discover JSON body");
    assert_eq!(body["runtime"]["mode"], Value::from("oneiron_cloud"));
    assert_eq!(body["runtime"]["oneironSpendMetered"], Value::from(true));
    assert!(
        body["runtime"]["routes"]
            .as_array()
            .expect("runtime routes array")
            .iter()
            .all(
                |route| route["providerKind"].as_str() == Some("oneiron_cloud")
                    && route["oneironSpendMetered"].as_bool() == Some(true)
            )
    );

    let health = api_routes(server)
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("health route response");
    assert_eq!(health.status(), StatusCode::OK);
    let body = to_bytes(health.into_body(), usize::MAX)
        .await
        .expect("health response body");
    let body: Value = serde_json::from_slice(&body).expect("health JSON body");
    assert_eq!(body["runtime"]["mode"], Value::from("oneiron_cloud"));
    assert_eq!(body["runtime"]["oneironSpendMetered"], Value::from(true));
    assert!(body["runtime"].get("routes").is_none());
}

#[tokio::test]
async fn discover_advertises_outbound_manifest_schema_on_demand() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let request = Request::builder()
        .uri("/api/core/discover")
        .header(AUTHORIZATION, owner_bearer())
        .body(Body::empty())
        .expect("discover request");
    let (status, body) = route_json(server, request).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body["feature_flags"]["capabilities"]
            .as_array()
            .expect("capabilities")
            .contains(&Value::from("core.outbound_capabilities"))
    );
    let outbound = &body["outbound_capabilities"];
    assert_eq!(
        outbound["manifest_version"],
        Value::from(oneiron::OUTBOUND_CAPABILITY_MANIFEST_VERSION)
    );
    assert_eq!(
        outbound["schema_on_demand"],
        Value::from("/v1/core/outbound/capabilities")
    );
    assert_eq!(
        outbound["field_contract"]
            .as_array()
            .expect("field contract")
            .len(),
        oneiron::OUTBOUND_VERB_FIELD_CONTRACT.len()
    );
    assert_eq!(
        outbound["unsupported_error_code"],
        Value::from("UNSUPPORTED_CAPABILITY")
    );
    assert_eq!(
        outbound["recovery_suggestions_field"],
        Value::from("recovery_suggestions")
    );
    assert!(
        outbound["connectors"]
            .as_array()
            .expect("connector summaries")
            .iter()
            .any(|connector| connector["connector"] == "slack"
                && connector["schema_on_demand"] == "/v1/core/outbound/capabilities/slack")
    );
}

#[tokio::test]
async fn core_outbound_capability_routes_expose_connector_and_verb_contracts() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server.clone(),
        core_request("GET", "/v1/core/outbound/capabilities", "core:read", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.as_array()
            .expect("manifest array")
            .iter()
            .any(|manifest| manifest["connector"] == "line")
    );

    let (status, manifest) = route_json(
        server.clone(),
        core_request(
            "GET",
            "/v1/core/outbound/capabilities/line",
            "core:read",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(manifest["connector"], Value::from("line"));
    assert_eq!(
        manifest["schema_on_demand"],
        Value::from("/v1/core/outbound/capabilities/line")
    );
    assert!(
        manifest["verbs"]
            .as_array()
            .expect("line verbs")
            .iter()
            .any(|verb| verb["kind"] == "narrowcast")
    );

    let (status, verb) = route_json(
        server,
        core_request(
            "GET",
            "/v1/core/outbound/capabilities/slack/verbs/react",
            "core:read",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verb["kind"], Value::from("react"));
    let fields = verb
        .as_object()
        .expect("verb object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(fields, oneiron::OUTBOUND_VERB_FIELD_CONTRACT);
}

#[tokio::test]
async fn unknown_outbound_connector_returns_typed_recovery_error() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server,
        core_request(
            "GET",
            "/v1/core/outbound/capabilities/not-a-connector",
            "core:read",
            None,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "UNSUPPORTED_CAPABILITY");
    let error = error_envelope(&body);
    assert_eq!(
        error["details"]["connector"],
        Value::from("not_a_connector")
    );
    assert_eq!(error["details"]["connectorKnown"], Value::from(false));
    assert!(
        error["details"].get("verb").is_none(),
        "connector-only discovery errors should not fabricate a verb"
    );
    assert!(
        error["details"]["supportedConnectors"]
            .as_array()
            .expect("supported connectors")
            .contains(&Value::from("slack"))
    );
}

#[tokio::test]
async fn unsupported_outbound_verb_returns_typed_recovery_error() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server,
        core_request(
            "GET",
            "/v1/core/outbound/capabilities/line/verbs/edit",
            "core:read",
            None,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "UNSUPPORTED_CAPABILITY");
    let error = error_envelope(&body);
    assert_eq!(error["details"]["connector"], Value::from("line"));
    assert_eq!(error["details"]["verb"], Value::from("edit"));
    assert_eq!(error["details"]["connectorKnown"], Value::from(true));
    assert!(
        error["details"]["supportedVerbs"]
            .as_array()
            .expect("supported verbs")
            .contains(&Value::from("send"))
    );
    assert!(
        error["details"]["recovery_suggestions"]
            .as_array()
            .expect("detail recovery suggestions")
            .iter()
            .any(|suggestion| suggestion
                .as_str()
                .is_some_and(|text| text.contains("/v1/core/outbound/capabilities/line")))
    );
    assert_eq!(
        error["suggestions"], error["details"]["recovery_suggestions"],
        "top-level suggestions should mirror typed recovery_suggestions"
    );
}

#[tokio::test]
async fn local_artifact_route_serves_pinned_pointer_and_hash_mounts() {
    let (_dir, server) = test_server();
    let repo = create_artifact_repo(b"<h1>v1</h1>\n");
    let first = ingest_artifact_snapshot(&server, repo.path(), "site", 10);
    server
        .vault
        .publish_artifact_pointer(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &first.snapshot.fork_hash,
        )
        .expect("publish first artifact pointer");

    let (status, headers, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/")
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<h1>v1</h1>\n");
    assert_eq!(
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some(ARTIFACT_POINTER_CACHE_CONTROL)
    );
    assert!(
        headers
            .get(CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("connect-src 'none'")),
        "artifact route must block vault API calls from served bundles"
    );
    assert_eq!(
        headers.get(ETAG).and_then(|value| value.to_str().ok()),
        Some(
            format!(
                "\"{}\"",
                oneiron::artifact_hex(blake3::hash(b"<h1>v1</h1>\n").as_bytes())
            )
            .as_str()
        )
    );
    let etag = headers.get(ETAG).cloned().expect("artifact ETag header");
    let (status, headers, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/")
            .header(IF_NONE_MATCH, etag)
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
    assert_eq!(
        headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some(ARTIFACT_POINTER_CACHE_CONTROL)
    );
    let (status, headers, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site?channel=published")
            .body(Body::empty())
            .expect("artifact redirect request"),
    )
    .await;
    assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
    assert!(body.is_empty());
    assert_eq!(
        headers.get(LOCATION).and_then(|value| value.to_str().ok()),
        Some("/a/site/?channel=published")
    );

    commit_artifact_index(repo.path(), b"<h1>v2</h1>\n", "second");
    let second = ingest_artifact_snapshot(&server, repo.path(), "site", 20);

    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/index.html")
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<h1>v1</h1>\n");

    let direct_fork_uri = format!(
        "/a/site/index.html?forkHash={}",
        oneiron::artifact_hex(&second.snapshot.fork_hash)
    );
    let (status, headers, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(direct_fork_uri)
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<h1>v2</h1>\n");
    assert_eq!(
        headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some(ARTIFACT_IMMUTABLE_CACHE_CONTROL)
    );

    server
        .vault
        .publish_artifact_pointer(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &second.snapshot.fork_hash,
        )
        .expect("repoint artifact pointer");
    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/")
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<h1>v2</h1>\n");

    server
        .vault
        .unpublish_artifact_pointer("site", oneiron::ArtifactPointerChannel::Published)
        .expect("unpublish artifact pointer");
    let (status, _, _) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/")
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let old_fork_uri = format!(
        "/a/site/index.html?forkHash={}",
        oneiron::artifact_hex(&first.snapshot.fork_hash)
    );
    let (status, _, body) = route_bytes(
        server,
        Request::builder()
            .uri(old_fork_uri)
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<h1>v1</h1>\n");
}

#[tokio::test]
async fn local_artifact_route_requires_api_auth_when_configured() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        allow_unauthenticated: false,
        ..Default::default()
    });
    let repo = create_artifact_repo(b"<h1>private</h1>\n");
    let snapshot = ingest_artifact_snapshot(&server, repo.path(), "site", 10);
    server
        .vault
        .publish_artifact_pointer(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &snapshot.snapshot.fork_hash,
        )
        .expect("publish artifact pointer");

    let (status, _, _) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/")
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, body) = route_bytes(
        server,
        Request::builder()
            .uri("/a/site/")
            .header(AUTHORIZATION, owner_bearer())
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<h1>private</h1>\n");
}

#[test]
fn artifact_content_type_maps_wasm() {
    assert_eq!(artifact_content_type("pkg/module.wasm"), "application/wasm");
}

#[tokio::test]
async fn local_artifact_route_serves_preview_pointer_and_rejects_ambiguous_selector() {
    let (_dir, server) = test_server();
    let repo = create_artifact_repo(b"<h1>preview</h1>\n");
    let ingest = ingest_artifact_snapshot(&server, repo.path(), "site", 10);
    server
        .vault
        .publish_artifact_pointer(
            "site",
            oneiron::ArtifactPointerChannel::Preview,
            &ingest.snapshot.fork_hash,
        )
        .expect("publish preview pointer");

    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/index.html?channel=preview")
            .body(Body::empty())
            .expect("preview request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<h1>preview</h1>\n");

    let ambiguous = format!(
        "/a/site/index.html?channel=preview&forkHash={}",
        oneiron::artifact_hex(&ingest.snapshot.fork_hash)
    );
    let (status, _, body) = route_bytes(
        server,
        Request::builder()
            .uri(ambiguous)
            .body(Body::empty())
            .expect("ambiguous request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: Value = serde_json::from_slice(&body).expect("error JSON");
    assert_error_envelope(&error, "BAD_REQUEST");
}

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

/// Mints a v2 token against the `"secret"` these tests configure everywhere.
fn test_bearer(claims: &str) -> String {
    format!(
        "Bearer {}",
        crate::auth::mint_core_token_v2("secret", claims)
    )
}

/// Owner-grade credential: the bare trust root over the standard header.
fn owner_bearer() -> String {
    "Bearer secret".to_owned()
}

fn core_request(method: &str, uri: &str, scope: &str, body: Option<&Value>) -> Request<Body> {
    core_request_with_authz(method, uri, test_bearer(&format!("scope={scope}")), body)
}

fn core_request_with_principal_ref(
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

fn core_request_with_authz(
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

async fn route_json(server: Arc<SyncServer>, request: Request<Body>) -> (StatusCode, Value) {
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
struct McpLegacyCall {
    credential: String,
    id: String,
    name: String,
    arguments: Value,
}

fn mcp_call_request(credential: &str, id: &str, name: &str, arguments: Value) -> McpLegacyCall {
    McpLegacyCall {
        credential: credential.to_owned(),
        id: id.to_owned(),
        name: name.to_owned(),
        arguments,
    }
}

/// Drives one retired adapter and returns the same `(status, JSON-RPC body)`
/// pair the wire used to return, so every row below keeps its exact assertions.
async fn mcp_legacy_adapter_json(
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

async fn mcp_legacy_adapter_result(
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

async fn register_mcp_actor(
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

fn mcp_actor_json(actor_ref: oneiron::EntityId, actor_class: &str) -> Value {
    json!({
        "actor_ref": actor_ref.to_hex(),
        "actor_class": actor_class,
        "gate_actor_class": actor_class,
        "gate_actor_ref": actor_ref.to_hex(),
        "scope": {},
    })
}

fn mcp_consent_json(purpose: &str, require_human_approval: bool) -> Value {
    json!({
        "policy_ref": "policy:foreign-mcp",
        "purpose": purpose,
        "approval_ref": "approval:one-1222",
        "consent_receipt_ref": "consent:one-1222",
        "require_human_approval": require_human_approval,
    })
}

fn mcp_context_pack_json(result_id: oneiron::EntityId) -> Value {
    json!({
        "schema_version": "context_pack_ref.v1",
        "context_version": "v4",
        "pack_ref": "context-pack:one-1222",
        "retrieval_run_id": "retrieval:one-1222",
        "result_ids": [result_id.to_hex()],
        "budget_ref": "budget:standard",
    })
}

fn mcp_propose_claim_args(
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

#[tokio::test]
async fn mcp_tools_call_read_uses_connector_actor_and_scoped_read() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1222_0001);
    let credential = "one-1222-read-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let entity_ref = seeded_test_entity_id(0x1222_0002);
    let body = rmp_serde::to_vec_named(&json!({
        "txt": "MCP read fixture",
    }))
    .expect("encode MCP read body");
    server
        .vault
        .put_entity(
            &entity_ref,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            101,
            &body,
        )
        .expect("seed MCP read entity");

    let (status, body) = mcp_legacy_adapter_json(
        server,
        mcp_call_request(
            credential,
            "mcp-read",
            "oneiron.read",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "consent": mcp_consent_json("read_memory", false),
                "target": { "entity_ref": entity_ref.to_hex() },
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "unexpected MCP error: {body:?}"
    );
    assert_eq!(
        body["result"]["structuredContent"]["found"],
        Value::Bool(true)
    );
    assert_eq!(
        body["result"]["structuredContent"]["item"]["id"],
        Value::from(entity_ref.to_hex())
    );
    assert_eq!(body["result"]["isError"], Value::Bool(false));
}

#[tokio::test]
async fn mcp_edit_propose_claim_persists_gate_decision_with_forced_stamp() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1222_0101);
    let credential = "one-1222-write-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let subject_ref = seeded_test_entity_id(0x1222_0102);
    server
        .vault
        .put_entity(
            &subject_ref,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange {
                start: 200,
                end: 200,
            },
            200,
            b"MCP subject",
        )
        .expect("seed MCP claim subject");

    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-write-allow",
            "oneiron.edit",
            mcp_propose_claim_args(actor_ref, subject_ref, "one-1222-propose-claim"),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "unexpected MCP error: {body:?}"
    );
    assert_eq!(
        body["result"]["structuredContent"]["verb"],
        Value::from("propose_claim")
    );
    assert_eq!(
        body["result"]["structuredContent"]["forced_source"],
        Value::from("tool_output")
    );
    assert_eq!(
        body["result"]["structuredContent"]["forced_approval"],
        Value::from("proposed")
    );
    let claim_id = oneiron::EntityId::from_hex(
        body["result"]["structuredContent"]["id"]
            .as_str()
            .expect("MCP proposed claim id"),
    )
    .expect("MCP proposed claim id parses");

    let stored = server
        .vault
        .get_claim(&claim_id)
        .expect("read stored MCP claim")
        .expect("MCP claim should be stored after an allow decision");
    assert_eq!(stored.source, Some(oneiron::ClaimSource::ToolOutput));
    assert_eq!(stored.approval, oneiron::ClaimApprovalStatus::Proposed);

    let decisions = server
        .vault
        .gate_decisions(10)
        .expect("gate decisions after MCP write");
    let decision = decisions
        .iter()
        .find(|decision| decision.claim_id == Some(*claim_id.as_bytes()))
        .expect("MCP write must persist a Gate decision");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.reason_codes, vec!["gate.allow"]);
    assert_eq!(decision.actor_class, "human");
    assert_eq!(
        decision.actor_ref.as_deref(),
        Some(actor_ref.to_hex().as_str())
    );
}

#[tokio::test]
async fn mcp_edit_idempotency_is_actor_scoped_and_replays_without_mutation() {
    let (_dir, server) = test_server();
    let actor_a = seeded_test_entity_id(0x1222_0601);
    let actor_b = seeded_test_entity_id(0x1222_0602);
    let credential_a = "one-1222-idem-a";
    let credential_b = "one-1222-idem-b";
    register_mcp_actor(
        &server,
        credential_a,
        actor_a,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    register_mcp_actor(
        &server,
        credential_b,
        actor_b,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let subject_ref = seeded_test_entity_id(0x1222_0603);
    server
        .vault
        .put_entity(
            &subject_ref,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange {
                start: 600,
                end: 600,
            },
            600,
            b"MCP idempotency subject",
        )
        .expect("seed MCP idempotency subject");

    let shared_key = "one-1222-shared-idempotency-key";
    let (status, first) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential_a,
            "mcp-write-idem-a-1",
            "oneiron.edit",
            mcp_propose_claim_args(actor_a, subject_ref, shared_key),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        first.get("error").is_none(),
        "unexpected MCP error: {first:?}"
    );
    let first_id = oneiron::EntityId::from_hex(
        first["result"]["structuredContent"]["id"]
            .as_str()
            .expect("first MCP id"),
    )
    .expect("first MCP id parses");

    let mut replay_args = mcp_propose_claim_args(actor_a, subject_ref, shared_key);
    replay_args["value"] = Value::from("changed replay payload");
    let (status, replay) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential_a,
            "mcp-write-idem-a-2",
            "oneiron.edit",
            replay_args,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        replay.get("error").is_none(),
        "unexpected MCP error: {replay:?}"
    );
    assert_eq!(
        replay["result"]["structuredContent"]["status"],
        Value::from("replayed")
    );
    assert_eq!(
        replay["result"]["structuredContent"]["id"],
        Value::from(first_id.to_hex())
    );

    let (status, second_actor) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential_b,
            "mcp-write-idem-b",
            "oneiron.edit",
            mcp_propose_claim_args(actor_b, subject_ref, shared_key),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        second_actor.get("error").is_none(),
        "unexpected MCP error: {second_actor:?}"
    );
    let second_actor_id = oneiron::EntityId::from_hex(
        second_actor["result"]["structuredContent"]["id"]
            .as_str()
            .expect("second actor MCP id"),
    )
    .expect("second actor MCP id parses");
    assert_ne!(
        first_id, second_actor_id,
        "same idempotency key must be scoped by the resolved actor"
    );

    let decisions = server
        .vault
        .gate_decisions(10)
        .expect("gate decisions after idempotency replay");
    assert_eq!(
        decisions.len(),
        2,
        "same-actor replay must not emit a second Gate decision"
    );
}

#[tokio::test]
async fn mcp_edit_rejects_source_approval_spoofing_without_partial_mutation() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1222_0201);
    let credential = "one-1222-denied-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let subject_ref = seeded_test_entity_id(0x1222_0202);
    server
        .vault
        .put_entity(
            &subject_ref,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange {
                start: 300,
                end: 300,
            },
            300,
            b"MCP denied subject",
        )
        .expect("seed MCP denied subject");

    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-write-denied",
            "oneiron.edit",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "consent": mcp_consent_json("write_memory", false),
                "verb": "propose_claim",
                "idempotency_key": "one-1222-spoof-source-approval",
                "subject": { "entity": subject_ref.to_hex() },
                "predicate": "profile.mcp_gateway",
                "value": "MCP gateway write",
                "confidence": 0.8,
                "source": "generated",
                "approval": "auto"
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], Value::from(-32602));
    assert_eq!(
        body["error"]["data"]["kind"],
        Value::from("tool_args_invalid")
    );

    let decisions = server
        .vault
        .gate_decisions(10)
        .expect("gate decisions after rejected MCP write");
    assert!(
        decisions.is_empty(),
        "schema-rejected MCP write must not emit a Gate decision"
    );
}

#[tokio::test]
async fn mcp_edit_rejects_legacy_entity_wrapper_without_partial_mutation() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1222_0401);
    let credential = "one-1222-non-claim-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let entity_ref = seeded_test_entity_id(0x1222_0402);
    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-write-non-claim",
            "oneiron.edit",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "consent": mcp_consent_json("write_memory", false),
                "verb": "propose_claim",
                "idempotency_key": "one-1222-legacy-entity-wrapper",
                "subject": { "entity": actor_ref.to_hex() },
                "predicate": "profile.mcp_gateway",
                "value": "MCP gateway write",
                "confidence": 0.8,
                "entity": {
                    "id": entity_ref.to_hex(),
                    "entity_type": ENTITY_TYPE_TURN,
                    "occurred_start": 400_u64,
                    "occurred_end": 400_u64,
                    "learned_at": 400_u64,
                    "body": { "txt": "non-claim MCP write should not persist" },
                    "text": [
                        {
                            "field": "body",
                            "value": "non-claim MCP write should not persist"
                        }
                    ]
                }
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], Value::from(-32602));
    assert_eq!(
        body["error"]["data"]["kind"],
        Value::from("tool_args_invalid")
    );
    assert!(
        !server
            .vault
            .entity_exists(&entity_ref)
            .expect("check non-claim entity"),
        "rejected non-claim MCP write must not persist the entity"
    );
    assert!(
        server
            .vault
            .gate_decisions(10)
            .expect("gate decisions")
            .is_empty(),
        "rejected non-claim MCP write must not emit a Gate decision"
    );
}

#[tokio::test]
async fn mcp_edit_supersede_claim_lands_deferred_proposal_without_closing_old_claim() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1222_0501);
    let credential = "one-1222-deferred-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let subject_ref = seeded_test_entity_id(0x1222_0502);
    let old_claim = seeded_test_entity_id(0x1222_0503);
    seed_active_claim(&server, old_claim, subject_ref, "before", 500);

    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-write-deferred",
            "oneiron.edit",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "consent": mcp_consent_json("write_memory", false),
                "verb": "supersede_claim",
                "idempotency_key": "one-1222-supersede-proposal",
                "old_claim_id": old_claim.to_hex(),
                "predicate": "profile.route_test",
                "value": "after",
                "confidence": 0.8,
                "reason": "user_correction"
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "unexpected MCP error: {body:?}"
    );
    assert_eq!(
        body["result"]["structuredContent"]["lifecycle"],
        Value::from("deferred_proposed")
    );
    let proposal_id = oneiron::EntityId::from_hex(
        body["result"]["structuredContent"]["proposal_id"]
            .as_str()
            .expect("MCP proposal id"),
    )
    .expect("MCP proposal id parses");

    let proposal = server
        .vault
        .get_claim(&proposal_id)
        .expect("read deferred proposal")
        .expect("deferred proposal should be stored");
    assert_eq!(proposal.source, Some(oneiron::ClaimSource::ToolOutput));
    assert_eq!(proposal.approval, oneiron::ClaimApprovalStatus::Proposed);

    let old_after = server
        .vault
        .get_claim(&old_claim)
        .expect("read old claim")
        .expect("old claim should still exist");
    assert_eq!(old_after.lifecycle, oneiron::ClaimLifecycleStatus::Active);
}

#[tokio::test]
async fn mcp_ask_returns_accepted_without_mutation() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1222_0301);
    let credential = "one-1222-ask-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let result_id = seeded_test_entity_id(0x1222_0302);

    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-ask",
            "oneiron.ask",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "context_pack": mcp_context_pack_json(result_id),
                "consent": mcp_consent_json("ask_memory", false),
                "query": "What does this context say?",
                "effort": "standard",
                "citation_mode": "claim_refs",
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "unexpected MCP error: {body:?}"
    );
    assert_eq!(
        body["result"]["structuredContent"]["status"],
        Value::from("accepted")
    );
    assert_eq!(
        body["result"]["structuredContent"]["tool"],
        Value::from("oneiron.ask")
    );
    assert!(
        server
            .vault
            .gate_decisions(10)
            .expect("gate decisions after ask")
            .is_empty(),
        "ask must not persist write Gate decisions"
    );
}

#[tokio::test]
async fn mcp_malformed_call_returns_stable_json_rpc_error() {
    let (_dir, server) = test_server();
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{"))
        .expect("malformed MCP request");

    let (status, body) = route_json(server, request).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["jsonrpc"], Value::from("2.0"));
    assert_eq!(body["id"], Value::Null);
    assert_eq!(body["error"]["code"], Value::from(-32700));
    assert_eq!(body["error"]["data"]["kind"], Value::from("parse_error"));
}

fn error_envelope(body: &Value) -> &Value {
    body.get("error")
        .and_then(Value::as_object)
        .map(|_| &body["error"])
        .expect("typed error envelope")
}

fn assert_error_envelope(body: &Value, code: &str) {
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

fn assert_json_snapshot(actual: Value, fixture: &str, path: &str, label: &str) {
    assert_json_snapshot_with_update(
        actual,
        fixture,
        path,
        label,
        std::env::var_os("ONEIRON_UPDATE_TEST_FIXTURES").is_some(),
    );
}

fn assert_json_snapshot_with_update(
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

#[test]
fn assert_json_snapshot_update_writes_fixture_without_comparing_stale_fixture() {
    let dir = tempfile::tempdir().expect("temp snapshot dir");
    let path = dir.path().join("snapshot.json");
    let path = path.to_str().expect("snapshot path should be UTF-8");

    assert_json_snapshot_with_update(
        json!({ "updated": true }),
        r#"{ "stale": true }"#,
        path,
        "fixture update",
        true,
    );

    let written = std::fs::read_to_string(path).expect("read updated fixture");
    let written: Value = serde_json::from_str(&written).expect("updated fixture JSON");
    assert_eq!(written, json!({ "updated": true }));
}

fn sort_json(value: &mut Value) {
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

#[test]
fn sort_json_orders_object_keys_recursively() {
    let mut value = json!({
        "z": {
            "nested_z": true,
            "nested_a": true
        },
        "a": [
            {
                "array_z": true,
                "array_a": true
            }
        ]
    });

    sort_json(&mut value);

    let serialized = serde_json::to_string(&value).expect("serialize sorted JSON");
    assert_eq!(
        serialized,
        r#"{"a":[{"array_a":true,"array_z":true}],"z":{"nested_a":true,"nested_z":true}}"#
    );
}

fn normalize_contract_body(body: &mut Value) {
    match body {
        Value::Array(items) => {
            for item in items {
                normalize_contract_body(item);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                match key.as_str() {
                    "deleted_at" => *value = Value::from("<deleted-at>"),
                    "query_time_us" => *value = Value::from("<duration-us>"),
                    "request_id" => *value = Value::from("<request-id>"),
                    "requestId" => *value = Value::from("<request-id>"),
                    "last_retrieval_run_id" => *value = Value::from("<retrieval-run-id>"),
                    "retrieval_run_id" => *value = Value::from("<retrieval-run-id>"),
                    _ => normalize_contract_body(value),
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn contract_exchange(
    name: &str,
    method: &str,
    path: &str,
    auth_scope: Option<&str>,
    request_body: Option<Value>,
    status: StatusCode,
    response_body: Value,
) -> Value {
    contract_exchange_with_auth(
        name,
        method,
        path,
        auth_scope.map_or_else(
            || json!({ "type": "none" }),
            |scope| json!({ "type": "bearer", "scope": scope }),
        ),
        request_body,
        status,
        response_body,
    )
}

/// Records one contract exchange under an explicitly described credential.
///
/// The `auth` descriptor is part of the contract, not decoration: a scoped
/// bearer and an owner-grade one produce genuinely different context-pack
/// bodies (the former is disclosure-clamped), so an exchange that documents
/// the wrong credential documents an unreachable response.
fn contract_exchange_with_auth(
    name: &str,
    method: &str,
    path: &str,
    auth: Value,
    request_body: Option<Value>,
    status: StatusCode,
    mut response_body: Value,
) -> Value {
    normalize_contract_body(&mut response_body);
    json!({
        "name": name,
        "request": {
            "method": method,
            "path": path,
            "auth": auth,
            "body": request_body.unwrap_or(Value::Null),
        },
        "response": {
            "status": status.as_u16(),
            "body": response_body,
        },
    })
}

fn openapi_operation_contract(operation: &Value) -> Value {
    let responses = operation["responses"]
        .as_object()
        .expect("responses object")
        .iter()
        .map(|(status, response)| {
            (
                status.clone(),
                json!({
                    "description": response["description"].clone(),
                    "schema": openapi_json_schema_ref(response),
                }),
            )
        })
        .collect::<Map<_, _>>();
    let parameters = operation["parameters"]
        .as_array()
        .map(|parameters| {
            parameters
                .iter()
                .map(|parameter| {
                    json!({
                        "name": parameter["name"].clone(),
                        "in": parameter["in"].clone(),
                        "required": parameter["required"].clone(),
                        "schema": openapi_schema_shape(&parameter["schema"]),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "operationId": operation["operationId"].clone(),
        "security": operation["security"].clone(),
        "parameters": parameters,
        "requestSchema": operation
            .get("requestBody")
            .map_or(Value::Null, openapi_json_schema_ref),
        "responses": responses,
    })
}

fn openapi_json_schema_ref(value: &Value) -> Value {
    value
        .pointer("/content/application~1json/schema")
        .map_or(Value::Null, openapi_schema_shape)
}

fn openapi_component_schema<'a>(spec: &'a Value, name: &str) -> &'a Value {
    spec.pointer(&format!("/components/schemas/{name}"))
        .unwrap_or_else(|| panic!("OpenAPI component schema {name} must exist"))
}

fn openapi_schema_contract(schema: &Value) -> Value {
    let mut contract = Map::new();
    for key in [
        "$ref",
        "type",
        "format",
        "enum",
        "const",
        "required",
        "default",
        "nullable",
        "additionalProperties",
        "discriminator",
    ] {
        if let Some(value) = schema.get(key) {
            contract.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        let mut property_contract = Map::new();
        for (name, property) in properties {
            property_contract.insert(name.clone(), openapi_schema_contract(property));
        }
        contract.insert("properties".to_owned(), Value::Object(property_contract));
    }
    if let Some(items) = schema.get("items") {
        contract.insert("items".to_owned(), openapi_schema_contract(items));
    }
    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(schemas) = schema.get(key).and_then(Value::as_array) {
            contract.insert(
                key.to_owned(),
                Value::Array(schemas.iter().map(openapi_schema_contract).collect()),
            );
        }
    }
    Value::Object(contract)
}

fn openapi_schema_shape(schema: &Value) -> Value {
    let mut shape = Map::new();
    for key in ["$ref", "type", "format", "enum", "required", "default"] {
        if let Some(value) = schema.get(key) {
            shape.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(items) = schema.get("items") {
        shape.insert("items".to_owned(), openapi_schema_shape(items));
    }
    if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
        shape.insert(
            "oneOf".to_owned(),
            Value::Array(one_of.iter().map(openapi_schema_shape).collect()),
        );
    }
    Value::Object(shape)
}

fn collect_schema_refs(value: &Value, refs: &mut BTreeSet<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_schema_refs(item, refs);
            }
        }
        Value::Object(object) => {
            if let Some(name) = object
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|reference| reference.strip_prefix("#/components/schemas/"))
            {
                refs.insert(name.to_owned());
            }
            for value in object.values() {
                collect_schema_refs(value, refs);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

async fn core_json(
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
async fn owner_json(
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

fn seed_turn(server: &SyncServer, text: &str) -> oneiron::EntityId {
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

fn turn_annotation_request_body(turn: &oneiron::EntityId, annotated_at: u64) -> Value {
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

async fn idempotent_core_annotate(
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

#[test]
fn v1_core_openapi_contract_snapshot_matches_fixture() {
    let spec = generated_spec();
    let mut paths = Map::new();
    for &(path, method) in V1_CORE_OPENAPI_CONTRACT_OPERATIONS {
        paths
            .entry(path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("path item object")
            .insert(
                method.to_owned(),
                openapi_operation_contract(&spec["paths"][path][method]),
            );
    }

    let mut schemas = Map::new();
    for name in V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES {
        schemas.insert(
            (*name).to_owned(),
            openapi_schema_contract(openapi_component_schema(&spec, name)),
        );
    }

    assert_json_snapshot(
        json!({
            "paths": paths,
            "components": {
                "schemas": schemas,
                "securitySchemes": spec["components"]["securitySchemes"].clone(),
            },
        }),
        V1_CORE_OPENAPI_CONTRACT_SNAPSHOT,
        V1_CORE_OPENAPI_CONTRACT_SNAPSHOT_PATH,
        "v1 core OpenAPI contract",
    );
}

#[test]
fn v1_core_openapi_contract_snapshots_referenced_schemas() {
    let spec = generated_spec();
    let mut references = BTreeSet::new();
    for &(path, method) in V1_CORE_OPENAPI_CONTRACT_OPERATIONS {
        collect_schema_refs(
            &openapi_operation_contract(&spec["paths"][path][method]),
            &mut references,
        );
    }
    for name in V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES {
        collect_schema_refs(
            &openapi_schema_contract(openapi_component_schema(&spec, name)),
            &mut references,
        );
    }

    let missing = references
        .into_iter()
        .filter(|name| !V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES.contains(&name.as_str()))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "OpenAPI contract references unsnapshotted schemas: {missing:?}"
    );
}

#[test]
fn v1_core_openapi_documents_invalid_state_envelopes() {
    let spec = generated_spec();
    let turn_create_post_responses =
        spec["paths"]["/v1/core/conversations/{conversation_id}/turns"]["post"]["responses"]
            .as_object()
            .expect("turn create POST responses object");
    assert!(
        turn_create_post_responses.contains_key("409"),
        "turn create POST must document INVALID_STATE conflict responses"
    );
    assert_eq!(
        turn_create_post_responses["409"]["content"]["application/json"]["schema"]["$ref"],
        Value::from("#/components/schemas/ApiErrorEnvelope"),
        "turn create 409 must use the ApiErrorEnvelope schema"
    );

    let turn_annotate_post_responses =
        spec["paths"]["/v1/core/turns/annotate"]["post"]["responses"]
            .as_object()
            .expect("turn annotate POST responses object");
    assert!(
        turn_annotate_post_responses.contains_key("409"),
        "turn annotate POST must document Gate INVALID_STATE conflict responses"
    );
    assert_eq!(
        turn_annotate_post_responses["409"]["content"]["application/json"]["schema"]["$ref"],
        Value::from("#/components/schemas/ApiErrorEnvelope"),
        "turn annotate 409 must use the ApiErrorEnvelope schema"
    );
}

#[test]
fn v1_core_openapi_contract_preserves_nested_error_schema_fidelity() {
    let spec = generated_spec();
    let envelope = openapi_schema_contract(openapi_component_schema(&spec, "ApiErrorEnvelope"));
    assert!(
        envelope
            .pointer("/properties/error/properties/code/enum")
            .and_then(Value::as_array)
            .is_some_and(|codes| codes.len() == ErrorCode::ALL.len()),
        "ApiErrorEnvelope.error.code must snapshot the full ErrorCode enum: {envelope}"
    );
    assert!(
        envelope
            .pointer("/properties/error/properties/details/oneOf")
            .and_then(Value::as_array)
            .is_some_and(|variants| variants.len() == ErrorCode::ALL.len()),
        "ApiErrorEnvelope.error.details must snapshot all ApiErrorDetails variants: {envelope}"
    );

    let api_error = openapi_schema_contract(openapi_component_schema(&spec, "ApiError"));
    assert!(
        api_error
            .pointer("/properties/code/enum")
            .and_then(Value::as_array)
            .is_some_and(|codes| codes.len() == ErrorCode::ALL.len()),
        "ApiError.code must snapshot the full ErrorCode enum: {api_error}"
    );
    assert!(
        api_error
            .pointer("/properties/details/oneOf")
            .and_then(Value::as_array)
            .is_some_and(|variants| variants.len() == ErrorCode::ALL.len()),
        "ApiError.details must snapshot all ApiErrorDetails variants: {api_error}"
    );

    let api_error_details =
        openapi_schema_contract(openapi_component_schema(&spec, "ApiErrorDetails"));
    assert!(
        api_error_details
            .pointer("/oneOf")
            .and_then(Value::as_array)
            .is_some_and(|variants| variants.len() == ErrorCode::ALL.len()),
        "ApiErrorDetails must snapshot all error detail variants: {api_error_details}"
    );

    let error_code = openapi_schema_contract(openapi_component_schema(&spec, "ErrorCode"));
    assert!(
        error_code
            .pointer("/enum")
            .and_then(Value::as_array)
            .is_some_and(|codes| codes.len() == ErrorCode::ALL.len()),
        "ErrorCode must snapshot the full enum catalog: {error_code}"
    );
}

#[tokio::test]
async fn v1_core_success_contract_snapshot_matches_fixture() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let batch_id = seeded_test_entity_id(0x1221_0001).to_hex();
    let conversation_id = seeded_test_entity_id(0x1221_0002).to_hex();
    let turn_id = seeded_test_entity_id(0x1221_0003).to_hex();
    let eiri_principal_ref = seeded_test_entity_id(0x1221_0004).to_hex();
    let eiri_person_ref = seeded_test_entity_id(0x1221_0005).to_hex();
    let eiri_persona_ref = seeded_test_entity_id(0x1221_0006).to_hex();
    let mut exchanges = Vec::new();

    let batch_request = json!({
        "entities": [{
            "id": batch_id,
            "entity_type": ENTITY_TYPE_TURN,
            "occurred_start": 1_782_357_600_u64,
            "occurred_end": 1_782_357_600_u64,
            "learned_at": 1_782_357_635_u64,
            "body": {
                "txt": "blue hallway contractneedle",
                "spkr": "user",
                "at": 1_782_357_600_u64
            },
            "text": [{ "field": "body", "value": "blue hallway contractneedle" }]
        }]
    });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/batch",
        "core:write",
        Some(&batch_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "core_batch",
        "POST",
        "/v1/core/batch",
        Some("core:write"),
        Some(batch_request),
        status,
        body,
    ));

    let query_request = json!({
        "query": "contractneedle",
        "limit": 3,
        "view": "full",
        "countMode": "estimate"
    });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/query",
        "core:read",
        Some(&query_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "core_query",
        "POST",
        "/v1/core/query",
        Some("core:read"),
        Some(query_request),
        status,
        body,
    ));

    let context_pack_request = json!({
        "query": "contractneedle",
        "limit": 3,
        "view": "full",
        "include_edges": false
    });
    // Owner-grade: this exchange documents the un-clamped context-pack shape,
    // so it must travel on the credential that reaches it. On a scoped bearer
    // the same request is disclosure-clamped and returns no results.
    let (status, context_pack_body) = owner_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        Some(&context_pack_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let context_entity = &context_pack_body["results"][0];
    let short_ref = format!(
        "{}:{}",
        context_entity["short_id"].as_str().expect("short id"),
        context_entity["content_hash"]
            .as_str()
            .expect("content hash")
    );
    exchanges.push(contract_exchange_with_auth(
        "core_context_pack",
        "POST",
        "/v1/core/context-pack",
        json!({ "type": "bearer", "grade": "owner" }),
        Some(context_pack_request),
        status,
        context_pack_body,
    ));

    let context_pack_v4_request = json!({
        "query": "contractneedle",
        "limit": 3,
        "view": "full",
        "include_edges": false,
        "context_version": "v4",
        "memory_board": {
            "slots": {
                "claims": 0,
                "turns": 1,
                "summaries": 0,
                "facets": 0,
                "companions": 0,
                "other": 0
            }
        },
        "session_rag": {},
        "companion": {
            "person_ref": eiri_person_ref,
            "persona_ref": eiri_persona_ref
        }
    });
    let (status, context_pack_v4_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &eiri_principal_ref,
            Some(&context_pack_v4_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(context_pack_v4_body["context_version"], Value::from("v4"));
    assert_eq!(
        context_pack_v4_body["memory_board"]["budget"]["turns"],
        Value::from(1)
    );
    assert_eq!(
        context_pack_v4_body["session_rag"]["query_count"],
        Value::from(1)
    );
    exchanges.push(contract_exchange_with_auth(
        "core_context_pack_v4",
        "POST",
        "/v1/core/context-pack",
        json!({ "type": "bearer", "scope": "core:read", "principal_ref": "bound" }),
        Some(context_pack_v4_request),
        status,
        context_pack_v4_body,
    ));

    let hydrate_request = json!({
        "ref": short_ref,
        "view": "full"
    });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/hydrate",
        "core:read",
        Some(&hydrate_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "core_hydrate",
        "POST",
        "/v1/core/hydrate",
        Some("core:read"),
        Some(hydrate_request),
        status,
        body,
    ));

    let conversation_request = json!({
        "id": conversation_id,
        "occurred_start": 1_782_357_700_u64,
        "occurred_end": 1_782_357_700_u64,
        "learned_at": 1_782_357_735_u64,
        "body": { "name": "Contract dream" },
        "text": [{ "field": "name", "value": "Contract dream" }]
    });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/conversations",
        "core:write",
        Some(&conversation_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "create_core_conversation",
        "POST",
        "/v1/core/conversations",
        Some("core:write"),
        Some(conversation_request),
        status,
        body,
    ));

    let conversations_path = "/v1/core/conversations?view=full&limit=5&countMode=exact";
    let (status, body) =
        core_json(server.clone(), "GET", conversations_path, "core:read", None).await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "list_core_conversations",
        "GET",
        conversations_path,
        Some("core:read"),
        None,
        status,
        body,
    ));

    let turn_request = json!({
        "id": turn_id,
        "occurred_start": 1_782_357_800_u64,
        "occurred_end": 1_782_357_800_u64,
        "learned_at": 1_782_357_835_u64,
        "body": {
            "txt": "turn contract envelope",
            "spkr": "assistant",
            "at": 1_782_357_800_u64
        },
        "text": [{ "field": "body", "value": "turn contract envelope" }]
    });
    let turns_path = format!("/v1/core/conversations/{conversation_id}/turns");
    let (status, body) = core_json(
        server.clone(),
        "POST",
        &turns_path,
        "core:write",
        Some(&turn_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "create_core_conversation_turn",
        "POST",
        &turns_path,
        Some("core:write"),
        Some(turn_request),
        status,
        body,
    ));

    let list_turns_path =
        format!("/v1/core/conversations/{conversation_id}/turns?view=full&limit=5");
    let (status, body) =
        core_json(server.clone(), "GET", &list_turns_path, "core:read", None).await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "list_core_conversation_turns",
        "GET",
        &list_turns_path,
        Some("core:read"),
        None,
        status,
        body,
    ));

    let get_turn_path = format!("/v1/core/turns/{turn_id}?view=full");
    let (status, body) = core_json(server.clone(), "GET", &get_turn_path, "core:read", None).await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "get_core_turn",
        "GET",
        &get_turn_path,
        Some("core:read"),
        None,
        status,
        body,
    ));

    let annotate_request = json!({
        "turn_id": turn_id,
        "source": "model_inference",
        "vad": {
            "valence": 0.25,
            "arousal": 0.5,
            "dominance": 0.75
        },
        "annotated_at": 1_782_357_900_u64
    });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/turns/annotate",
        "core:write",
        Some(&annotate_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "annotate_turn_vad",
        "POST",
        "/v1/core/turns/annotate",
        Some("core:write"),
        Some(annotate_request),
        status,
        body,
    ));

    let read_annotation_path = format!("/v1/core/turns/annotate?turn_id={turn_id}");
    let (status, body) = core_json(server, "GET", &read_annotation_path, "core:read", None).await;
    assert_eq!(status, StatusCode::OK);
    exchanges.push(contract_exchange(
        "read_turn_vad_annotation",
        "GET",
        &read_annotation_path,
        Some("core:read"),
        None,
        status,
        body,
    ));

    assert_json_snapshot(
        Value::Array(exchanges),
        V1_CORE_SUCCESS_CONTRACT_SNAPSHOT,
        V1_CORE_SUCCESS_CONTRACT_SNAPSHOT_PATH,
        "v1 core success contract",
    );
}

#[tokio::test]
async fn v1_core_error_contract_snapshot_matches_fixture() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let missing_id = seeded_test_entity_id(0x1221_00ff).to_hex();
    let deleted_id = seeded_test_entity_id(0x1221_dead);
    let deleted_body = rmp_serde::to_vec_named(&json!({
        "txt": "deleted contract turn",
        "spkr": "user",
        "at": 1_782_358_000_u64,
    }))
    .expect("encode deleted turn");
    server
        .vault
        .batch()
        .put(
            &deleted_id,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 1_782_358_000_u64,
                end: 1_782_358_000_u64,
            },
            1_782_358_000_u64,
            &deleted_body,
        )
        .text(&deleted_id, &[("body", "deleted contract turn")])
        .commit()
        .expect("seed deleted turn");
    let deleted_pack = server
        .vault
        .context_pack()
        .search_text("deleted contract turn", 1)
        .run()
        .expect("deleted context pack");
    let deleted_entity = deleted_pack
        .results
        .first()
        .expect("deleted entity has short ref");
    let deleted_ref = format!(
        "{}:{:02x}",
        deleted_entity.short_id, deleted_entity.content_hash
    );
    server
        .vault
        .delete_entity_with_reason(&deleted_id, oneiron::DeleteReason::UserDelete)
        .expect("delete seeded turn");

    let mut exchanges = Vec::new();

    let malformed_request = json!({ "ref": "bad-ref" });
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/hydrate",
        "core:read",
        Some(&malformed_request),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    exchanges.push(contract_exchange(
        "malformed_request",
        "POST",
        "/v1/core/hydrate",
        Some("core:read"),
        Some(malformed_request),
        status,
        body,
    ));

    let missing_auth_path = "/v1/core/turns/annotate?turn_id=not-an-entity";
    let (status, body) = route_json(
        server.clone(),
        Request::builder()
            .uri(missing_auth_path)
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_envelope(&body, "UNAUTHORIZED");
    exchanges.push(contract_exchange(
        "missing_auth",
        "GET",
        missing_auth_path,
        None,
        None,
        status,
        body,
    ));

    let wrong_scope_path = "/v1/core/turns/annotate?turn_id=not-an-entity";
    let (status, body) =
        core_json(server.clone(), "GET", wrong_scope_path, "core:write", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    exchanges.push(contract_exchange(
        "wrong_scope",
        "GET",
        wrong_scope_path,
        Some("core:write"),
        None,
        status,
        body,
    ));

    let not_found_path = format!("/v1/core/turns/{missing_id}");
    let (status, body) = core_json(server.clone(), "GET", &not_found_path, "core:read", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_error_envelope(&body, "NOT_FOUND");
    exchanges.push(contract_exchange(
        "not_found",
        "GET",
        &not_found_path,
        Some("core:read"),
        None,
        status,
        body,
    ));

    let deleted_request = json!({ "ref": deleted_ref });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/hydrate",
        "core:read",
        Some(&deleted_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], Value::from("deleted"));
    assert!(body.get("item").is_none());
    exchanges.push(contract_exchange(
        "deleted_entity",
        "POST",
        "/v1/core/hydrate",
        Some("core:read"),
        Some(deleted_request),
        status,
        body,
    ));

    assert_json_snapshot(
        Value::Array(exchanges),
        V1_CORE_ERROR_CONTRACT_SNAPSHOT,
        V1_CORE_ERROR_CONTRACT_SNAPSHOT_PATH,
        "v1 core error contract",
    );
}

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

fn enqueue_queue_attempt(
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

fn attempt_id_hex(id: oneiron::AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn top_up_route(
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

async fn record_usage_event_route(
    server: Arc<SyncServer>,
    idempotency_key: &str,
    service_cost_usd: f64,
) -> (StatusCode, Value) {
    record_usage_event_for_vault_route(server, idempotency_key, "vault-a", service_cost_usd).await
}

async fn record_usage_event_for_vault_route(
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

#[test]
fn generated_openapi_has_descriptions_examples_and_defaults() {
    let spec = generated_spec();

    assert!(
        spec["openapi"]
            .as_str()
            .is_some_and(|v| v.starts_with("3.1")),
        "OpenAPI version should start with 3.1: {:?}",
        spec["openapi"]
    );

    let paths = spec["paths"].as_object().expect("paths object");
    for path in [
        "/api/openapi.json",
        "/api/skills/oneiron.skills.md",
        "/api/core/discover",
        "/api/search/vector",
        "/api/search/text",
        "/api/entity/{id}",
        "/api/edges/{id}",
        "/v1/core/batch",
        "/v1/core/query",
        "/v1/core/context-pack",
        "/v1/core/hydrate",
        "/v1/core/conversations",
        "/v1/core/conversations/{conversation_id}/turns",
        "/v1/core/turns/{turn_id}",
        "/v1/core/turns/annotate",
        "/v1/core/outbound/capabilities",
        "/v1/core/outbound/capabilities/{connector}",
        "/v1/core/outbound/capabilities/{connector}/verbs/{verb}",
        "/v1/core/surface-events",
        "/v1/core/surface-events/{correlation_id}",
        "/v1/companion/access-grants",
        "/v1/companion/access-grants/{grant_id}/revoke",
        "/v1/companion/profiles/{persona_ref}",
        "/v1/companion/register/records",
        "/v1/companion/register/records/{record_id}",
        "/v1/companion/register/records/{record_id}/retire",
        "/v1/companion/register/records/{record_id}/end-relationship",
        "/api/lease/revoke",
        "/api/health",
        "/v1/consumer/usage",
        "/v1/consumer/usage/details",
        "/v1/consumer/top-up",
    ] {
        assert!(paths.contains_key(path), "missing path {path}");
    }
    assert!(
        !paths.contains_key("/api/context-pack"),
        "legacy context-pack path must be gone"
    );

    let vector_success = &spec["paths"]["/api/search/vector"]["get"]["responses"]["200"]["content"]
        ["application/json"];
    assert!(
        vector_success.get("example").is_some() || vector_success.get("examples").is_some(),
        "vector search 200 response must include an example: {vector_success:?}"
    );
    let vector_example = &vector_success["example"];
    assert!(
        vector_example["items"].is_array(),
        "vector search example must show paginated items: {vector_example:?}"
    );
    assert_eq!(
        vector_example["meta"]["countMode"],
        Value::from("estimate"),
        "vector search example must show estimate count metadata"
    );

    let discover_success = &spec["paths"]["/api/core/discover"]["get"]["responses"]["200"]["content"]
        ["application/json"];
    assert!(
        discover_success.get("example").is_some() || discover_success.get("examples").is_some(),
        "discover 200 response must include an example: {discover_success:?}"
    );

    let skills_pack_success = &spec["paths"]["/api/skills/oneiron.skills.md"]["get"]["responses"]["200"]
        ["content"][skills_pack_artifact::MEDIA_TYPE];
    assert!(
        skills_pack_success.get("example").is_some()
            || skills_pack_success.get("examples").is_some(),
        "skills pack 200 response must include a markdown example: {skills_pack_success:?}"
    );
    let skills_pack_unauthorized = &spec["paths"]["/api/skills/oneiron.skills.md"]["get"]["responses"]
        ["401"]["content"]["application/json"]["example"];
    assert_eq!(
        skills_pack_unauthorized,
        &serde_json::to_value(ApiError::unauthorized()).expect("serialize ApiError"),
        "skills pack 401 response example must match ApiError::unauthorized()"
    );

    assert!(
        spec["paths"]["/api/core/discover"]["get"]["responses"]
            .as_object()
            .is_some_and(|responses| responses.contains_key("401")),
        "discover must document its 401 ApiError response"
    );
    assert_eq!(
        discover_success["example"]["skill_pack"]["endpoint"],
        Value::from("/api/skills/oneiron.skills.md"),
        "discover example must advertise the committed skill pack endpoint"
    );
    let turn_annotate_post_responses =
        spec["paths"]["/v1/core/turns/annotate"]["post"]["responses"]
            .as_object()
            .expect("turn annotate POST responses object");
    assert!(
        turn_annotate_post_responses.contains_key("409"),
        "turn annotate POST must document Gate INVALID_STATE conflict responses"
    );
    assert_eq!(
        turn_annotate_post_responses["409"]["content"]["application/json"]["schema"]["$ref"],
        Value::from("#/components/schemas/ApiErrorEnvelope"),
        "turn annotate 409 must use the ApiErrorEnvelope schema"
    );
    assert_eq!(
        spec["components"]["schemas"]["DiscoverResponse"]["properties"]["skill_pack"]["$ref"],
        Value::from("#/components/schemas/SkillPackDiscovery"),
        "DiscoverResponse must reference the skill-pack discovery schema"
    );

    assert!(
        spec["components"]["securitySchemes"]
            .get("OneironSecret")
            .is_none(),
        "the removed custom-header scheme must not be documented"
    );
    assert_eq!(
        spec["components"]["securitySchemes"]["CoreBearer"]["scheme"],
        Value::from("bearer"),
        "protected operations must document bearer auth"
    );
    assert!(
        !serde_json::to_string(&spec)
            .expect("serialize spec")
            .contains("x-oneiron-secret"),
        "no description, example, or scheme in the spec may still name the removed header"
    );
    for (path, method) in [
        ("/api/openapi.json", "get"),
        ("/api/skills/oneiron.skills.md", "get"),
        ("/api/core/discover", "get"),
        ("/api/search/vector", "get"),
        ("/api/search/text", "get"),
        ("/api/entity/{id}", "get"),
        ("/api/edges/{id}", "get"),
        ("/api/lease/revoke", "post"),
        ("/v1/consumer/usage", "get"),
        ("/v1/consumer/usage/details", "get"),
        ("/v1/consumer/top-up", "post"),
        ("/v1/core/batch", "post"),
        ("/v1/core/query", "post"),
        ("/v1/core/context-pack", "post"),
        ("/v1/core/hydrate", "post"),
        ("/v1/core/batch/shortId/hydrate", "post"),
        ("/v1/core/run-tree", "get"),
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
        ("/v1/companion/access-grants", "post"),
        ("/v1/companion/access-grants/{grant_id}/revoke", "post"),
        ("/v1/companion/profiles/{persona_ref}", "get"),
        ("/v1/companion/register/records", "post"),
        ("/v1/companion/register/records/{record_id}", "get"),
        ("/v1/companion/register/records/{record_id}", "post"),
        ("/v1/companion/register/records/{record_id}/retire", "post"),
        (
            "/v1/companion/register/records/{record_id}/end-relationship",
            "post",
        ),
    ] {
        assert_eq!(
            spec["paths"][path][method]["security"],
            json!([{ "CoreBearer": [] }]),
            "{method} {path} must require bearer auth as the single scheme"
        );
    }

    assert!(
        spec["components"]["schemas"].get("ApiError").is_some(),
        "structured ApiError schema must be reusable from components"
    );
    assert!(
        spec["components"]["schemas"]
            .get("ApiErrorEnvelope")
            .is_some(),
        "v1 core ApiErrorEnvelope schema must be reusable from components"
    );
    assert!(
        spec["components"]["schemas"].get("ErrorCode").is_some(),
        "ErrorCode schema must be reusable from components"
    );
    assert!(
        spec["components"]["schemas"]["View"].get("enum").is_some(),
        "View schema must document allowed projection values"
    );

    let entity_octets = &spec["paths"]["/api/entity/{id}"]["get"]["responses"]["200"]["content"]["application/octet-stream"];
    assert_eq!(
        entity_octets["example"],
        Value::from("raw entity bytes"),
        "entity octet-stream example must not be a JSON byte array"
    );
    assert_eq!(
        entity_octets["schema"],
        json!({ "type": "string", "format": "binary" }),
        "entity octet-stream schema must model raw binary"
    );

    let entity_json = &spec["paths"]["/api/entity/{id}"]["get"]["responses"]["200"]["content"]["application/json"];
    assert_eq!(
        entity_json["schema"]["type"],
        Value::from("object"),
        "entity projection response must document a JSON object schema"
    );
    assert!(
        entity_json["examples"]["summary"].is_object(),
        "entity JSON projection response must include a summary example: {entity_json:?}"
    );
    assert!(
        entity_json["examples"]["full"].is_object(),
        "entity JSON projection response must include a full example: {entity_json:?}"
    );

    assert_non_empty_string(
        &spec["components"]["schemas"]["SearchResult"]["properties"]["score"]["description"],
        "SearchResult.score.description",
    );

    let lease_client_description = spec["components"]["schemas"]["LeaseRevokeRequest"]
            ["properties"]["client_id"]["description"]
            .as_str()
            .expect("LeaseRevokeRequest.client_id description");
    assert!(
        lease_client_description
            .to_ascii_lowercase()
            .contains("revoke"),
        "lease revoke client_id description should mention revoke: {lease_client_description}"
    );

    assert_eq!(
        spec["components"]["schemas"]["VectorSearchQuery"]["properties"]["limit"]["default"],
        Value::from(default_limit())
    );

    for schema_name in [
        "HealthResponse",
        "DiscoverResponse",
        "SkillPackDiscovery",
        "BoundContext",
        "DiscoveredEntity",
        "FeatureFlags",
        "RateLimitStatus",
        "RuntimeHealthStatus",
        "RuntimeStatus",
        "RuntimeRoute",
        "RuntimeRouteProvenance",
        "VectorSearchQuery",
        "SearchResult",
        "TextSearchQuery",
        "EdgeResult",
        "CoreBatchRequest",
        "CoreBatchEntityInput",
        "CoreBatchEntityResult",
        "CoreBatchResponse",
        "CoreTextField",
        "CoreQueryRequest",
        "CoreBatchShortIdHydrateItem",
        "CoreBatchShortIdHydrateRequest",
        "CoreBatchShortIdHydrateResponse",
        "CoreHydrateDeletionMetadata",
        "CoreHydrateRequest",
        "CoreHydrateResponse",
        "CoreShortIdHydrateError",
        "ContextPackDepthControls",
        "ContextPackPolicyControls",
        "ContextPackTimeControls",
        "ContextPackRetrievalBudgetControls",
        "ContextPackBudgetControls",
        "CoreContextPackRequest",
        "CoreContextPackResponse",
        "CoreContextEntity",
        "CoreContextEdge",
        "CoreContextPackStats",
        "CoreContextPackItemAccounting",
        "CoreContextPackState",
        "CoreContextPackScoreComponent",
        "CoreContextPackScoreEvidence",
        "CoreContextPackEvidence",
        "CoreEiriCompanionAssembly",
        "CoreEiriMemoryBoard",
        "CoreEiriMemoryBoardBudget",
        "CoreDisclosureAssembly",
        "CoreEiriMemoryBoardRow",
        "CoreEiriSessionRagState",
        "CoreInterlocutorControls",
        "CoreInterlocutorParty",
        "CoreInterlocutorStamp",
        "CoreListQuery",
        "CoreCreateEntityRequest",
        "CoreCreateTurnRequest",
        "CoreEntityWriteResponse",
        "VadPayload",
        "TurnVadAnnotateRequest",
        "TurnVadAnnotateQuery",
        "TurnVadAnnotateResponse",
        "CompanionAccessGrantScopePayload",
        "CompanionAccessGrantResponse",
        "CompanionCreateAccessGrantRequest",
        "CompanionRevokeAccessGrantRequest",
        "CompanionProfileAccess",
        "CompanionProfileConfidencePayload",
        "CompanionProfileDriftAnchor",
        "CompanionProfileNextAction",
        "CompanionProfilePayload",
        "CompanionProfileRefreshRequest",
        "CompanionProfileResponse",
        "CompanionProfileStaleReasonPayload",
        "CompanionRegisterScopePayload",
        "CompanionRegisterRelationshipRefPayload",
        "CompanionRegisterSubjectPayload",
        "CompanionRegisterProvenancePayload",
        "CompanionRegisterRecordPayload",
        "CompanionRegisterCreateRecordRequest",
        "CompanionRegisterUpdateRecordRequest",
        "CompanionRegisterRetireRecordRequest",
        "CompanionEndRelationshipRequest",
        "CompanionGoodbyeArtifactHookPayload",
        "CompanionEndRelationshipResponse",
        "CompanionRegisterRecordResponse",
        "LeaseRevokeRequest",
        "LeaseRevokeResponse",
        "ConsumerAllowanceState",
        "ConsumerAllowanceWarning",
        "ConsumerTopUp",
        "ConsumerTopUpRequest",
        "ConsumerTopUpState",
        "ConsumerUsageDetails",
        "ConsumerUsageState",
    ] {
        let properties = spec["components"]["schemas"][schema_name]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{schema_name} properties object"));
        assert!(
            properties.values().any(|property| property
                .get("description")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty())),
            "{schema_name} must have at least one described property"
        );
        for (field_name, property) in properties {
            assert_non_empty_string(
                &property["description"],
                &format!("{schema_name}.{field_name}.description"),
            );
        }
    }
}

#[tokio::test]
async fn openapi_route_serves_json_document() {
    let (_dir, server) = test_server();
    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .uri("/api/openapi.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("OpenAPI response body");
    let body: Value = serde_json::from_slice(&body).expect("OpenAPI JSON body");
    assert!(
        body["openapi"]
            .as_str()
            .is_some_and(|v| v.starts_with("3.1")),
        "served OpenAPI version should start with 3.1: {:?}",
        body["openapi"]
    );
}

#[tokio::test]
async fn openapi_route_uses_api_auth() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = Arc::new(SyncServer::new(vault, SyncServerConfig::default()).unwrap());
    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .uri("/api/openapi.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("ApiError response body");
    let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
    assert_eq!(body["code"], Value::from("UNAUTHORIZED"));
}

#[tokio::test]
async fn v1_core_route_missing_auth_returns_typed_error_envelope() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server,
        Request::builder()
            .uri("/v1/core/turns/annotate?turn_id=not-an-entity")
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_envelope(&body, "UNAUTHORIZED");
    assert_eq!(error_envelope(&body)["details"]["code"], "UNAUTHORIZED");
}

/// The revocation registry has teeth on the wire, not just in the auth unit
/// tests: a revoked bearer gets the same uniform 401 as any other refusal,
/// while a sibling minted from identical claims keeps working.
#[tokio::test]
async fn v1_core_route_rejects_a_revoked_bearer_and_admits_its_sibling() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (revoked, revoked_jti) =
        crate::auth::mint_identified_core_token_v2("secret", "scope=core:read");
    let (sibling, _) = crate::auth::mint_identified_core_token_v2("secret", "scope=core:read");
    let uri = "/v1/core/turns/annotate?turn_id=not-an-entity";

    // Both authenticate before the revocation act (the 400 is the handler
    // rejecting the deliberately malformed turn id — auth already passed).
    for token in [&revoked, &sibling] {
        let (status, _) = route_json(
            server.clone(),
            core_request_with_authz("GET", uri, format!("Bearer {token}"), None),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "token must authenticate");
    }

    crate::auth::revoke_token_jti(server.vault(), &revoked_jti).expect("revoke");

    let (status, body) = route_json(
        server.clone(),
        core_request_with_authz("GET", uri, format!("Bearer {revoked}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_envelope(&body, "UNAUTHORIZED");

    let (status, _) = route_json(
        server,
        core_request_with_authz("GET", uri, format!("Bearer {sibling}"), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "revoking one token must not revoke its sibling"
    );
}

/// The owner-grade surfaces consult the registry too: revocation binds to the
/// token's identity, not to which plane it is presented on.
#[tokio::test]
async fn legacy_api_route_rejects_a_revoked_owner_grade_bearer() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (token, jti) = crate::auth::mint_identified_core_token_v2("secret", "");
    let uri = "/api/core/discover";

    let (status, _) = route_json(
        server.clone(),
        core_request_with_authz("GET", uri, format!("Bearer {token}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "an identified owner token is live");

    crate::auth::revoke_token_jti(server.vault(), &jti).expect("revoke");

    let (status, _) = route_json(
        server,
        core_request_with_authz("GET", uri, format!("Bearer {token}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The owner-grade boundary itself, not revocation: a perfectly live scoped
/// bearer — authentic MAC, unrevoked jti, a scope the route would honor on
/// `/v1` — is still refused on the legacy `/api/*` plane, which reads the
/// whole vault under one actor ref. The same credential works on its own
/// `/v1` route in the same test, so the 401 pins the plane boundary and not
/// a broken token.
#[tokio::test]
async fn legacy_api_route_rejects_a_live_scoped_bearer_that_works_on_v1() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (scoped, jti) = crate::auth::mint_identified_core_token_v2("secret", "scope=core:read");
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {scoped}").parse().expect("bearer header"),
    );
    let auth = CoreAuth::from_headers(&headers, &server.config, server.vault().as_ref())
        .expect("scoped bearer authenticates");
    assert!(
        !auth.is_owner_grade(),
        "the fixture must be a scoped, non-owner-grade credential"
    );
    assert!(
        !crate::auth::is_revoked_or_unreadable(&jti, server.vault().as_ref()),
        "the fixture must be live: this test is about the plane, not revocation"
    );

    // Same credential, same server: accepted on its scoped /v1 route.
    let (status, _) = route_json(
        server.clone(),
        core_request_with_authz(
            "GET",
            "/v1/core/outbound/capabilities",
            format!("Bearer {scoped}"),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a scoped bearer is a /v1-plane instrument and must work there"
    );

    // Refused on every legacy `/api/*` route, read and mutating alike.
    for (method, uri, body) in [
        ("GET", "/api/core/discover", None),
        ("GET", "/api/openapi.json", None),
        ("GET", "/api/skills/oneiron.skills.md", None),
        ("GET", "/api/search/text?query=anything", None),
        (
            "POST",
            "/api/lease/revoke",
            Some(json!({ "client_id": "0000000000000042" })),
        ),
    ] {
        let (status, _) = route_json(
            server.clone(),
            core_request_with_authz(method, uri, format!("Bearer {scoped}"), body.as_ref()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "legacy {method} {uri} must refuse a scoped bearer"
        );
    }
}

#[tokio::test]
async fn v1_core_idempotency_preflight_uses_typed_error_envelope() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server,
        Request::builder()
            .method("POST")
            .uri("/v1/core/turns/annotate")
            .header("Idempotency-Key", "idem-1")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "turn_id": "not-an-entity",
                    "source": "model_inference",
                    "vad": {
                        "valence": 0.0,
                        "arousal": 0.0,
                        "dominance": 0.0,
                    },
                    "annotated_at": 1_u64,
                })
                .to_string(),
            ))
            .expect("request"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_envelope(&body, "UNAUTHORIZED");
}

#[tokio::test]
async fn v1_core_route_rejects_valid_bearer_without_required_scope() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server,
        Request::builder()
            .uri("/v1/core/turns/annotate?turn_id=not-an-entity")
            .header(AUTHORIZATION, test_bearer("scope=core:write"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("core:read")
    );
}

#[tokio::test]
async fn v1_core_route_wraps_handler_errors_after_bearer_auth() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, body) = route_json(
        server,
        Request::builder()
            .uri("/v1/core/turns/annotate?turn_id=not-an-entity")
            .header(AUTHORIZATION, test_bearer("scope=core:read"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("turn_id")
    );
}

#[tokio::test]
async fn v1_companion_profile_access_grants_allow_deny_and_revoke() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let grant_id = seeded_test_entity_id(0x1265_0001).to_hex();
    let principal_ref = seeded_test_entity_id(0x1265_0002).to_hex();
    let person_ref = seeded_test_entity_id(0x1265_0003).to_hex();
    let persona_ref = seeded_test_entity_id(0x1265_0004).to_hex();
    let other_person_ref = seeded_test_entity_id(0x1265_0005).to_hex();
    let other_principal_ref = seeded_test_entity_id(0x1265_0006).to_hex();
    let cross_principal_grant_id = seeded_test_entity_id(0x1265_0007).to_hex();

    let profile_path_with_override = format!(
        "/v1/companion/profiles/{persona_ref}?principal_ref={principal_ref}&person_ref={person_ref}"
    );
    let (status, body) = route_json(
        server.clone(),
        core_request("GET", &profile_path_with_override, "core:read", None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("core:auth")
    );

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &profile_path_with_override,
            "companion:profile:read",
            &other_principal_ref,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("core:auth")
    );

    let profile_path = format!("/v1/companion/profiles/{persona_ref}?person_ref={person_ref}");
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &profile_path,
            "companion:profile:read",
            &principal_ref,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("companion_profile.read")
    );

    let create_request = json!({
        "id": grant_id,
        "principal_ref": principal_ref,
        "scope": {
            "kind": "companion_profile",
            "person_ref": person_ref,
            "persona_ref": persona_ref,
        },
        "created_at": 10_u64,
    });
    let cross_principal_create_request = json!({
        "id": cross_principal_grant_id,
        "principal_ref": principal_ref,
        "scope": {
            "kind": "companion_profile",
            "person_ref": person_ref,
            "persona_ref": persona_ref,
        },
        "created_at": 10_u64,
    });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/companion/access-grants",
            "companion:access-grant:write",
            &other_principal_ref,
            Some(&cross_principal_create_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("core:auth")
    );
    assert!(
        server
            .vault
            .get_access_grant(
                &oneiron::EntityId::from_hex(&cross_principal_grant_id)
                    .expect("cross-principal grant id")
            )
            .expect("read cross-principal grant")
            .is_none(),
        "cross-principal create must not write an AccessGrant"
    );

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/companion/access-grants",
            "companion:access-grant:write",
            &principal_ref,
            Some(&create_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], Value::from(grant_id.clone()));
    assert_eq!(body["status"], Value::from("active"));
    assert_eq!(body["capability"], Value::from("companion_profile.read"));

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &profile_path,
            "companion:profile:read",
            &principal_ref,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["access"]["grant_id"], Value::from(grant_id.clone()));
    assert_eq!(body["persona_ref"], Value::from(persona_ref.clone()));

    let wrong_scope_path =
        format!("/v1/companion/profiles/{persona_ref}?person_ref={other_person_ref}");
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &wrong_scope_path,
            "companion:profile:read",
            &principal_ref,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");

    let revoke_path = format!("/v1/companion/access-grants/{grant_id}/revoke");
    let revoke_request = json!({ "revoked_at": 20_u64 });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &revoke_path,
            "companion:access-grant:write",
            &other_principal_ref,
            Some(&revoke_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("core:auth")
    );
    assert_eq!(
        server
            .vault
            .get_access_grant(&oneiron::EntityId::from_hex(&grant_id).expect("test grant id"))
            .expect("read grant")
            .expect("grant exists")
            .status,
        oneiron::access_grant::AccessGrantStatus::Active,
        "cross-principal revoke must not mutate the grant"
    );

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &revoke_path,
            "companion:access-grant:write",
            &principal_ref,
            Some(&revoke_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], Value::from("revoked"));
    assert_eq!(body["revoked_at"], Value::from(20_u64));

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/companion/access-grants",
            "companion:access-grant:write",
            &principal_ref,
            Some(&create_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_envelope(&body, "INVALID_STATE");
    assert_eq!(
        error_envelope(&body)["details"]["state"],
        Value::from("access_grant_exists")
    );
    assert_eq!(
        server
            .vault
            .get_access_grant(&oneiron::EntityId::from_hex(&grant_id).expect("test grant id"))
            .expect("read grant")
            .expect("grant exists")
            .status,
        oneiron::access_grant::AccessGrantStatus::Revoked
    );

    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &profile_path,
            "companion:profile:read",
            &principal_ref,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
}

#[tokio::test]
async fn v1_companion_profile_read_returns_persisted_tiers_snapshot() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let grant_id = seeded_test_entity_id(0x1218_0001);
    let principal_ref = seeded_test_entity_id(0x1218_0002);
    let person_ref = seeded_test_entity_id(0x1218_0003);
    let persona_ref = seeded_test_entity_id(0x1218_0004);
    let source_a = seeded_test_entity_id(0x1218_0005);
    let source_b = seeded_test_entity_id(0x1218_0006);
    seed_companion_profile_access(&server, grant_id, principal_ref, person_ref, persona_ref);

    let profile = oneiron::PsychProfile::new(
        persona_ref,
        "compact tier",
        "retrieval text tier",
        "Narrative profile tier.",
        vec![source_b, source_a],
        oneiron::psych_profile::PsychProfileConfidence::new(0.8, 0.7, 0.6).expect("confidence"),
    )
    .expect("profile");
    server
        .vault
        .put_psych_profile(&persona_ref, &profile)
        .expect("put psych profile");

    let path = format!(
        "/v1/companion/profiles/{}?person_ref={}&sourceRevisionIds={},{}",
        persona_ref.to_hex(),
        person_ref.to_hex(),
        source_b.to_hex(),
        source_a.to_hex()
    );
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "GET",
            &path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "persona_ref": persona_ref.to_hex(),
            "person_ref": person_ref.to_hex(),
            "access": {
                "grant_id": grant_id.to_hex(),
                "principal_ref": principal_ref.to_hex(),
                "scope": {
                    "kind": "companion_profile",
                    "person_ref": person_ref.to_hex(),
                    "persona_ref": persona_ref.to_hex(),
                },
            },
            "state": "fresh",
            "profile": {
                "subject_ref": persona_ref.to_hex(),
                "compact": "compact tier",
                "text": "retrieval text tier",
                "narrative": "Narrative profile tier.",
                "sourceRevisionIds": [source_a.to_hex(), source_b.to_hex()],
                "confidence": {
                    "compact": 0.8,
                    "text": 0.7,
                    "narrative": 0.6,
                },
                "status": "fresh",
            },
            "stale_reason": null,
            "next_action": null,
            "drift_anchors": [
                {
                    "state": "keep",
                    "sourceRevisionRef": source_a.to_hex(),
                },
                {
                    "state": "keep",
                    "sourceRevisionRef": source_b.to_hex(),
                },
            ],
        })
    );
}

#[tokio::test]
async fn v1_companion_profile_read_returns_missing_and_stale_next_actions() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal_ref = seeded_test_entity_id(0x1218_0101);
    let person_ref = seeded_test_entity_id(0x1218_0102);
    let missing_persona_ref = seeded_test_entity_id(0x1218_0103);
    let stale_persona_ref = seeded_test_entity_id(0x1218_0104);
    let source_a = seeded_test_entity_id(0x1218_0105);
    let source_b = seeded_test_entity_id(0x1218_0106);
    let existing_persona_ref = seeded_test_entity_id(0x1218_0109);
    seed_companion_profile_access(
        &server,
        seeded_test_entity_id(0x1218_0107),
        principal_ref,
        person_ref,
        missing_persona_ref,
    );
    seed_companion_profile_access(
        &server,
        seeded_test_entity_id(0x1218_0108),
        principal_ref,
        person_ref,
        stale_persona_ref,
    );
    seed_companion_profile_access(
        &server,
        seeded_test_entity_id(0x1218_010A),
        principal_ref,
        person_ref,
        existing_persona_ref,
    );
    server
        .vault
        .put_entity(
            &existing_persona_ref,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"persona entity without psych profile",
        )
        .expect("seed existing persona entity");
    let stale_profile = oneiron::PsychProfile::new(
        stale_persona_ref,
        "stale compact",
        "stale text",
        "Stale narrative.",
        vec![source_a],
        oneiron::psych_profile::PsychProfileConfidence::new(0.5, 0.5, 0.5).expect("confidence"),
    )
    .expect("profile")
    .marked_stale();
    server
        .vault
        .put_psych_profile(&stale_persona_ref, &stale_profile)
        .expect("put stale profile");

    let missing_path = format!(
        "/v1/companion/profiles/{}?person_ref={}",
        missing_persona_ref.to_hex(),
        person_ref.to_hex()
    );
    let (missing_status, missing_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &missing_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(missing_status, StatusCode::OK);
    assert_eq!(missing_body["state"], Value::from("missing"));
    assert!(missing_body["profile"].is_null());
    assert_eq!(missing_body["next_action"]["kind"], Value::from("refresh"));
    assert_eq!(
        missing_body["next_action"]["reason"],
        Value::from("missing")
    );

    let existing_path = format!(
        "/v1/companion/profiles/{}?person_ref={}",
        existing_persona_ref.to_hex(),
        person_ref.to_hex()
    );
    let (existing_status, existing_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &existing_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(existing_status, StatusCode::OK);
    assert_eq!(existing_body["state"], Value::from("missing"));
    assert!(existing_body["profile"].is_null());
    assert_eq!(
        existing_body["next_action"]["reason"],
        Value::from("missing")
    );

    let stale_path = format!(
        "/v1/companion/profiles/{}?person_ref={}&sourceRevisionIds={}",
        stale_persona_ref.to_hex(),
        person_ref.to_hex(),
        source_b.to_hex()
    );
    let (stale_status, stale_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &stale_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(stale_status, StatusCode::OK);
    assert_eq!(stale_body["state"], Value::from("stale"));
    assert_eq!(
        stale_body["stale_reason"],
        json!({
            "kind": "marked_stale",
            "expectedSourceRevisionIds": null,
            "actualSourceRevisionIds": null,
        })
    );
    assert_eq!(
        stale_body["next_action"]["sourceRevisionIds"],
        json!([source_b.to_hex()])
    );
    assert_eq!(
        stale_body["drift_anchors"],
        json!([
            {
                "state": "revert",
                "sourceRevisionRef": source_a.to_hex(),
            },
            {
                "state": "tune",
                "sourceRevisionRef": source_b.to_hex(),
            },
        ])
    );

    let stale_fallback_path = format!(
        "/v1/companion/profiles/{}?person_ref={}",
        stale_persona_ref.to_hex(),
        person_ref.to_hex()
    );
    let (fallback_status, fallback_body) = route_json(
        server,
        core_request_with_principal_ref(
            "GET",
            &stale_fallback_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(fallback_status, StatusCode::OK);
    assert_eq!(fallback_body["state"], Value::from("stale"));
    assert_eq!(
        fallback_body["next_action"]["sourceRevisionIds"],
        json!([source_a.to_hex()])
    );
    assert_eq!(
        fallback_body["drift_anchors"],
        json!([
            {
                "state": "keep",
                "sourceRevisionRef": source_a.to_hex(),
            },
        ])
    );
    assert_eq!(
        fallback_body["next_action"]["drift_anchors"],
        fallback_body["drift_anchors"]
    );
}

#[tokio::test]
async fn v1_companion_profile_refresh_preserves_sources_and_drift_anchors() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let grant_id = seeded_test_entity_id(0x1218_0201);
    let principal_ref = seeded_test_entity_id(0x1218_0202);
    let person_ref = seeded_test_entity_id(0x1218_0203);
    let persona_ref = seeded_test_entity_id(0x1218_0204);
    let keep_source = seeded_test_entity_id(0x1218_0205);
    let revert_source = seeded_test_entity_id(0x1218_0206);
    let tune_source = seeded_test_entity_id(0x1218_0207);
    seed_companion_profile_access(&server, grant_id, principal_ref, person_ref, persona_ref);
    let profile = oneiron::PsychProfile::new(
        persona_ref,
        "refresh compact",
        "refresh text",
        "Refresh narrative.",
        vec![revert_source, keep_source],
        oneiron::psych_profile::PsychProfileConfidence::new(0.9, 0.8, 0.7).expect("confidence"),
    )
    .expect("profile");
    let stored_source_revision_ids = profile.source_revision_ids.clone();
    server
        .vault
        .put_psych_profile(&persona_ref, &profile)
        .expect("put profile");

    let refresh_path = format!(
        "/v1/companion/profiles/{}?person_ref={}",
        persona_ref.to_hex(),
        person_ref.to_hex()
    );
    let refresh_request = json!({
        "sourceRevisionIds": [
            keep_source.to_hex(),
            tune_source.to_hex(),
            tune_source.to_hex(),
        ],
    });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&refresh_request),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], Value::from("stale"));
    assert_eq!(
        body["profile"]["sourceRevisionIds"],
        json!([keep_source.to_hex(), revert_source.to_hex()])
    );
    assert_eq!(
        body["stale_reason"],
        json!({
            "kind": "source_revision_mismatch",
            "expectedSourceRevisionIds": [keep_source.to_hex(), tune_source.to_hex()],
            "actualSourceRevisionIds": [keep_source.to_hex(), revert_source.to_hex()],
        })
    );
    assert_eq!(
        body["drift_anchors"],
        json!([
            {
                "state": "keep",
                "sourceRevisionRef": keep_source.to_hex(),
            },
            {
                "state": "revert",
                "sourceRevisionRef": revert_source.to_hex(),
            },
            {
                "state": "tune",
                "sourceRevisionRef": tune_source.to_hex(),
            },
        ])
    );
    assert_eq!(body["next_action"]["drift_anchors"], body["drift_anchors"]);
    assert_eq!(
        server
            .vault
            .get_psych_profile(&persona_ref)
            .expect("read profile")
            .expect("profile persists")
            .source_revision_ids,
        stored_source_revision_ids
    );

    let refresh_query_path = format!(
        "/v1/companion/profiles/{}?person_ref={}&sourceRevisionIds={},{}",
        persona_ref.to_hex(),
        person_ref.to_hex(),
        keep_source.to_hex(),
        tune_source.to_hex()
    );
    let (query_status, query_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_query_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&json!({})),
        ),
    )
    .await;
    assert_eq!(query_status, StatusCode::OK);
    assert_eq!(
        query_body["stale_reason"],
        json!({
            "kind": "source_revision_mismatch",
            "expectedSourceRevisionIds": [keep_source.to_hex(), tune_source.to_hex()],
            "actualSourceRevisionIds": [keep_source.to_hex(), revert_source.to_hex()],
        })
    );

    let (bodyless_query_status, bodyless_query_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_query_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(bodyless_query_status, StatusCode::OK);
    assert_eq!(
        bodyless_query_body["stale_reason"],
        json!({
            "kind": "source_revision_mismatch",
            "expectedSourceRevisionIds": [keep_source.to_hex(), tune_source.to_hex()],
            "actualSourceRevisionIds": [keep_source.to_hex(), revert_source.to_hex()],
        })
    );

    let malformed_request = Request::builder()
        .method("POST")
        .uri(&refresh_query_path)
        .header(
            AUTHORIZATION,
            test_bearer(&format!(
                "scope=companion:profile:read;principal_ref={}",
                principal_ref.to_hex()
            )),
        )
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{"))
        .expect("request");
    let (malformed_status, malformed_body) = route_json(server.clone(), malformed_request).await;
    assert_eq!(malformed_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&malformed_body, "BAD_REQUEST");

    let reordered_request = json!({
        "sourceRevisionIds": [tune_source.to_hex(), keep_source.to_hex()],
    });
    let (reordered_status, reordered_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_query_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&reordered_request),
        ),
    )
    .await;
    assert_eq!(reordered_status, StatusCode::OK);
    assert_eq!(reordered_body["state"], Value::from("stale"));
    assert_eq!(
        reordered_body["stale_reason"],
        json!({
            "kind": "source_revision_mismatch",
            "expectedSourceRevisionIds": [keep_source.to_hex(), tune_source.to_hex()],
            "actualSourceRevisionIds": [keep_source.to_hex(), revert_source.to_hex()],
        })
    );

    let conflict_request = json!({
        "sourceRevisionIds": [keep_source.to_hex()],
    });
    let (conflict_status, conflict_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_query_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&conflict_request),
        ),
    )
    .await;
    assert_eq!(conflict_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&conflict_body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&conflict_body)["details"]["field"],
        Value::from("sourceRevisionIds")
    );

    let refresh_empty_query_path = format!(
        "/v1/companion/profiles/{}?person_ref={}&sourceRevisionIds=",
        persona_ref.to_hex(),
        person_ref.to_hex()
    );
    let (empty_query_status, empty_query_body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            &refresh_empty_query_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&json!({})),
        ),
    )
    .await;
    assert_eq!(empty_query_status, StatusCode::OK);
    assert_eq!(empty_query_body["state"], Value::from("fresh"));
    assert!(empty_query_body["next_action"].is_null());

    let (empty_status, empty_body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            &refresh_path,
            "companion:profile:read",
            &principal_ref.to_hex(),
            Some(&json!({ "sourceRevisionIds": [] })),
        ),
    )
    .await;
    assert_eq!(empty_status, StatusCode::OK);
    assert_eq!(empty_body["state"], Value::from("fresh"));
    assert!(empty_body["next_action"].is_null());
}

#[tokio::test]
async fn v1_companion_access_grant_create_replays_idempotency_key() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal_ref = seeded_test_entity_id(0x1265_0101).to_hex();
    let person_ref = seeded_test_entity_id(0x1265_0102).to_hex();
    let persona_ref = seeded_test_entity_id(0x1265_0103).to_hex();
    let create_request = json!({
        "principal_ref": principal_ref,
        "scope": {
            "kind": "companion_profile",
            "person_ref": person_ref,
            "persona_ref": persona_ref,
        },
        "created_at": 30_u64,
    });

    let make_request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/companion/access-grants")
            .header(AUTHORIZATION, test_bearer("scope=core:auth"))
            .header("Idempotency-Key", "companion-create-replay")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(create_request.to_string()))
            .expect("request")
    };
    let (first_status, first_body) = route_json(server.clone(), make_request()).await;
    let (replay_status, replay_body) = route_json(server.clone(), make_request()).await;

    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(replay_status, StatusCode::OK);
    assert_eq!(replay_body, first_body);

    let grant_id = oneiron::EntityId::from_hex(first_body["id"].as_str().expect("grant id"))
        .expect("grant id parses");
    assert_eq!(
        server
            .vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_ACCESS_GRANT)
            .expect("list access grants"),
        vec![grant_id]
    );
    assert_eq!(
        server
            .vault
            .companion_profile_access_grant(
                &oneiron::EntityId::from_hex(&principal_ref).expect("principal id"),
                &oneiron::EntityId::from_hex(&person_ref).expect("person id"),
                &oneiron::EntityId::from_hex(&persona_ref).expect("persona id"),
            )
            .expect("grant lookup"),
        Some(grant_id)
    );
}

#[tokio::test]
#[expect(clippy::too_many_lines)]
async fn v1_companion_register_api_create_update_read_and_retire_typed_envelopes() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let neutral_id = seeded_test_entity_id(0x1219_0001).to_hex();
    let personal_id = seeded_test_entity_id(0x1219_0002).to_hex();
    let shared_id = seeded_test_entity_id(0x1219_0003).to_hex();
    let actor_ref = seeded_test_entity_id(0x1219_0004).to_hex();
    let persona_ref = seeded_test_entity_id(0x1219_0005).to_hex();
    let person_ref = seeded_test_entity_id(0x1219_0006).to_hex();
    let source_ref = seeded_test_entity_id(0x1219_0007).to_hex();
    let target_ref = seeded_test_entity_id(0x1219_0008).to_hex();

    let provenance = json!({
        "actor_ref": actor_ref,
        "actor_class": 1,
        "source": "user_stated",
        "approval": "approved",
        "value": { "source": "settings" }
    });
    let neutral_record = json!({
        "kind": "persona",
        "scope": { "kind": "neutral" },
        "subject": { "kind": "persona", "persona_ref": persona_ref },
        "value": { "style": "neutral @Oneiron" },
        "provenance": provenance.clone(),
        "export": "portable"
    });
    let personal_record = json!({
        "kind": "persona",
        "scope": { "kind": "personal", "person_ref": person_ref },
        "subject": { "kind": "persona", "persona_ref": persona_ref },
        "value": { "note": "private per-person companion note" },
        "provenance": provenance.clone(),
        "export": "local_only"
    });
    let shared_record = json!({
        "kind": "relationship",
        "scope": { "kind": "shared_vault", "vault_id": 7_u64 },
        "subject": {
            "kind": "relationship",
            "relationship_ref": {
                "source_ref": source_ref,
                "target_ref": target_ref
            }
        },
        "value": { "note": "shared-vault boundary note" },
        "provenance": provenance.clone(),
        "export": "shared_vault"
    });

    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "core:write",
            Some(&json!({
                "id": seeded_test_entity_id(0x1219_0010).to_hex(),
                "record": neutral_record.clone()
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("companion:register:write")
    );

    for (id, record, learned_at) in [
        (&neutral_id, neutral_record.clone(), 30_u64),
        (&personal_id, personal_record.clone(), 31_u64),
        (&shared_id, shared_record.clone(), 32_u64),
    ] {
        let request = json!({ "id": id, "learned_at": learned_at, "record": record });
        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                "/v1/companion/register/records",
                "companion:register:write",
                Some(&request),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], Value::from(id.clone()));
        assert_eq!(body["record"]["lifecycle"], Value::from("active"));
    }

    let mut shared_scope_portable_export = shared_record.clone();
    shared_scope_portable_export["export"] = Value::from("portable");
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": seeded_test_entity_id(0x1219_0009).to_hex(),
                "record": shared_scope_portable_export
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("record.export")
    );

    let mut neutral_scope_shared_export = neutral_record.clone();
    neutral_scope_shared_export["export"] = Value::from("shared_vault");
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": seeded_test_entity_id(0x1219_000A).to_hex(),
                "record": neutral_scope_shared_export
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("record.export")
    );

    let mut retired_create_record = personal_record.clone();
    retired_create_record["lifecycle"] = Value::from("retracted");
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": seeded_test_entity_id(0x1219_000C).to_hex(),
                "record": retired_create_record
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("record.lifecycle")
    );

    let read_path = format!("/v1/companion/register/records/{personal_id}");
    let (status, body) = route_json(
        server.clone(),
        core_request("GET", &read_path, "core:read", None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&body)["details"]["requiredScope"],
        Value::from("companion:register:read")
    );

    let (status, body) = route_json(
        server.clone(),
        core_request("GET", &read_path, "companion:register:read", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["record"]["value"]["note"],
        Value::from("private per-person companion note")
    );

    let mut scalar_update_record = body["record"].clone();
    scalar_update_record["value"] = Value::from("scalar private per-person note");
    scalar_update_record["provenance"]["value"] = Value::from(true);
    let scalar_update_request = json!({ "learned_at": 32_u64, "record": scalar_update_record });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &read_path,
            "companion:register:write",
            Some(&scalar_update_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["record"]["value"],
        Value::from("scalar private per-person note")
    );
    assert_eq!(body["record"]["provenance"]["value"], Value::from(true));

    let scalar_roundtrip_request =
        json!({ "learned_at": 33_u64, "record": body["record"].clone() });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &read_path,
            "companion:register:write",
            Some(&scalar_roundtrip_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["record"]["value"],
        Value::from("scalar private per-person note")
    );

    let updated_record = json!({
        "kind": "persona",
        "scope": { "kind": "personal", "person_ref": person_ref },
        "subject": { "kind": "persona", "persona_ref": persona_ref },
        "value": { "note": "updated private per-person companion note" },
        "provenance": body["record"]["provenance"].clone(),
        "export": "local_only"
    });
    let update_request = json!({ "learned_at": 34_u64, "record": updated_record });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &read_path,
            "companion:register:write",
            Some(&update_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["record"]["value"]["note"],
        Value::from("updated private per-person companion note")
    );

    let mut retire_via_update_record = updated_record.clone();
    retire_via_update_record["lifecycle"] = Value::from("retracted");
    let retire_via_update = json!({
        "learned_at": 35_u64,
        "record": retire_via_update_record
    });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &read_path,
            "companion:register:write",
            Some(&retire_via_update),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("record.lifecycle")
    );

    let retire_path = format!("/v1/companion/register/records/{personal_id}/retire");
    let retire_request = json!({ "retired_at": 36_u64 });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &retire_path,
            "companion:register:write",
            Some(&retire_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["lifecycle"], Value::from("retracted"));

    let reactivate_request = json!({
        "learned_at": 37_u64,
        "record": {
            "kind": "persona",
            "scope": { "kind": "personal", "person_ref": person_ref },
            "subject": { "kind": "persona", "persona_ref": persona_ref },
            "value": { "note": "reactivated private note" },
            "provenance": body["record"]["provenance"].clone(),
            "export": "local_only"
        }
    });
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &read_path,
            "companion:register:write",
            Some(&reactivate_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");

    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": seeded_test_entity_id(0x1219_0009).to_hex(),
                "record": neutral_record
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_envelope(&body, "INVALID_STATE");
    assert_eq!(
        error_envelope(&body)["details"]["state"],
        Value::from("companion_record_exists")
    );

    let ending_id = seeded_test_entity_id(0x1219_0011).to_hex();
    let ending_private_note = "route-private-relationship-note-one1488";
    let ending_record = json!({
        "kind": "relationship",
        "scope": { "kind": "personal", "person_ref": person_ref },
        "subject": {
            "kind": "relationship",
            "relationship_ref": {
                "source_ref": person_ref,
                "target_ref": persona_ref
            }
        },
        "value": { "note": ending_private_note },
        "provenance": provenance.clone(),
        "export": "local_only"
    });
    let (status, _body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": ending_id,
                "learned_at": 38_u64,
                "record": ending_record.clone()
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let general_id = seeded_test_entity_id(0x1219_0013);
    server
        .vault
        .batch()
        .put(
            &general_id,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 38, end: 38 },
            38,
            b"route-general-vault-data",
        )
        .commit()
        .expect("seed general vault data");

    let end_path = format!("/v1/companion/register/records/{ending_id}/end-relationship");
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &end_path,
            "companion:register:write",
            Some(&json!({
                "ended_at": 39_u64,
                "ended_badly": false,
                "run_id": "route-goodbye-one1488"
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["lifecycle"], Value::from("retracted"));
    assert_eq!(
        body["record"]["value"]["kind"],
        Value::from("relationship_ended")
    );
    assert_eq!(
        body["record"]["value"]["private_memory"],
        Value::from("removed")
    );
    assert!(
        !body["record"]["value"]
            .to_string()
            .contains(ending_private_note),
        "ended relationship response must not retain private memory"
    );
    assert_eq!(
        server
            .vault
            .get(&general_id)
            .expect("read general data")
            .as_deref(),
        Some(b"route-general-vault-data".as_slice())
    );
    assert_eq!(body["goodbye_artifact"]["status"], Value::from("enqueued"));
    assert_eq!(
        body["goodbye_artifact"]["task"],
        Value::from("goodbye_artifact")
    );
    assert_eq!(
        body["goodbye_artifact"]["run_id"],
        Value::from("route-goodbye-one1488")
    );
    assert_eq!(
        body["goodbye_artifact"]["job_id"]
            .as_str()
            .expect("attempt id")
            .len(),
        32
    );
    let claimed = oneiron::companion::CompanionQueue::new(server.vault.as_ref())
        .claim(oneiron::companion::ClaimCompanionTask {
            lease_owner: "route-goodbye-worker".to_owned(),
            now: 40,
        })
        .expect("claim goodbye artifact task");
    let oneiron::companion::ClaimCompanionTaskOutcome::Claimed(claimed) = claimed else {
        panic!("amicable route ending must enqueue a claimable goodbye task");
    };
    assert_eq!(
        claimed.task.kind,
        oneiron::CompanionTaskKind::GoodbyeArtifact
    );
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &end_path,
            "companion:register:write",
            Some(&json!({
                "ended_at": 41_u64,
                "run_id": "route-goodbye-retry-one1488"
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["goodbye_artifact"]["status"],
        Value::from("already_ended")
    );
    assert!(body["goodbye_artifact"]["job_id"].is_null());
    assert!(
        !body["record"]["value"]
            .to_string()
            .contains(ending_private_note),
        "idempotent route ending must keep private memory scrubbed"
    );

    let bad_end_id = seeded_test_entity_id(0x1219_0012).to_hex();
    let mut bad_end_record = ending_record;
    bad_end_record["subject"]["relationship_ref"]["source_ref"] = Value::from(source_ref);
    bad_end_record["subject"]["relationship_ref"]["target_ref"] = Value::from(target_ref);
    bad_end_record["value"] = json!({ "note": "route-bad-end-private-note-one1488" });
    let (status, _body) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/register/records",
            "companion:register:write",
            Some(&json!({
                "id": bad_end_id,
                "learned_at": 41_u64,
                "record": bad_end_record
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bad_end_path = format!("/v1/companion/register/records/{bad_end_id}/end-relationship");
    let (status, body) = route_json(
        server.clone(),
        core_request(
            "POST",
            &bad_end_path,
            "companion:register:write",
            Some(&json!({
                "ended_at": 42_u64,
                "ended_badly": true,
                "run_id": "route-bad-end-one1488"
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["goodbye_artifact"]["status"],
        Value::from("skipped_bad_end")
    );
    assert!(body["goodbye_artifact"]["job_id"].is_null());
    assert_eq!(
        oneiron::companion::CompanionQueue::new(server.vault.as_ref())
            .claim(oneiron::companion::ClaimCompanionTask {
                lease_owner: "route-goodbye-worker".to_owned(),
                now: 43,
            })
            .expect("bad end should not enqueue another task"),
        oneiron::companion::ClaimCompanionTaskOutcome::Empty
    );

    assert!(
        server
            .vault
            .get_companion_record(
                &oneiron::EntityId::from_hex(&shared_id).expect("shared record id")
            )
            .expect("read shared record")
            .is_some()
    );
}

#[tokio::test]
async fn v1_core_idempotency_read_only_token_cannot_replay_cached_write_success() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let turn = seed_turn(&server, "cached write success");
    let body = turn_annotation_request_body(&turn, 300);

    let (write_status, write_body) = idempotent_core_annotate(
        server.clone(),
        "scoped-write-success",
        (
            AUTHORIZATION.as_str(),
            test_bearer("scope=core:write").as_str(),
        ),
        &body,
    )
    .await;
    assert_eq!(write_status, StatusCode::OK);
    assert_eq!(write_body["turn_id"], Value::from(turn.to_hex()));

    let (read_status, read_body) = idempotent_core_annotate(
        server,
        "scoped-write-success",
        (
            AUTHORIZATION.as_str(),
            test_bearer("scope=core:read").as_str(),
        ),
        &body,
    )
    .await;
    assert_eq!(read_status, StatusCode::FORBIDDEN);
    assert_error_envelope(&read_body, "FORBIDDEN");
    assert_eq!(
        error_envelope(&read_body)["details"]["requiredScope"],
        Value::from("core:write")
    );
}

#[tokio::test]
async fn v1_core_idempotency_write_token_retry_is_not_poisoned_by_read_only_403() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let turn = seed_turn(&server, "read-only poison");
    let body = turn_annotation_request_body(&turn, 301);

    let (read_status, read_body) = idempotent_core_annotate(
        server.clone(),
        "scoped-read-poison",
        (
            AUTHORIZATION.as_str(),
            test_bearer("scope=core:read").as_str(),
        ),
        &body,
    )
    .await;
    assert_eq!(read_status, StatusCode::FORBIDDEN);
    assert_error_envelope(&read_body, "FORBIDDEN");

    let (write_status, write_body) = idempotent_core_annotate(
        server.clone(),
        "scoped-read-poison",
        (
            AUTHORIZATION.as_str(),
            test_bearer("scope=core:write").as_str(),
        ),
        &body,
    )
    .await;
    assert_eq!(write_status, StatusCode::OK);
    assert_eq!(write_body["turn_id"], Value::from(turn.to_hex()));
    assert!(
        server
            .vault
            .get_turn_vad_annotation(&turn)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn v1_core_idempotency_legacy_shared_secret_still_replays_and_conflicts() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let turn = seed_turn(&server, "legacy idempotency");
    let body = turn_annotation_request_body(&turn, 302);

    let (first_status, first_body) = idempotent_core_annotate(
        server.clone(),
        "legacy-core-idem",
        (AUTHORIZATION.as_str(), owner_bearer().as_str()),
        &body,
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);

    let (replay_status, replay_body) = idempotent_core_annotate(
        server.clone(),
        "legacy-core-idem",
        (AUTHORIZATION.as_str(), owner_bearer().as_str()),
        &body,
    )
    .await;
    assert_eq!(replay_status, StatusCode::OK);
    assert_eq!(replay_body, first_body);

    let changed_body = turn_annotation_request_body(&turn, 303);
    let (conflict_status, conflict_body) = idempotent_core_annotate(
        server,
        "legacy-core-idem",
        (AUTHORIZATION.as_str(), owner_bearer().as_str()),
        &changed_body,
    )
    .await;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_error_envelope(&conflict_body, "IDEMPOTENCY_REPLAY_CONFLICT");
}

#[tokio::test]
async fn v1_core_batch_query_context_pack_and_hydrate_routes_are_live() {
    let (_dir, server) = test_server();

    let (batch_status, batch_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/batch",
            json!({
                "entities": [{
                    "entity_type": ENTITY_TYPE_TURN,
                    "learned_at": 500_u64,
                    "occurred_start": 500_u64,
                    "occurred_end": 500_u64,
                    "body": {
                        "txt": "blue hallway contextneedle",
                        "spkr": "user",
                        "at": 500_u64
                    }
                }]
            }),
        ),
    )
    .await;
    assert_eq!(batch_status, StatusCode::OK);
    let id = batch_body["entities"][0]["id"]
        .as_str()
        .expect("written id")
        .to_owned();
    assert_eq!(batch_body["count"], Value::from(1));

    let (query_status, query_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/query",
            json!({
                "query": "contextneedle",
                "limit": 5,
                "view": "full"
            }),
        ),
    )
    .await;
    assert_eq!(query_status, StatusCode::OK);
    assert_eq!(query_body["items"][0]["id"], Value::from(id.clone()));
    assert_eq!(
        query_body["items"][0]["txt"],
        Value::from("blue hallway contextneedle")
    );
    assert_eq!(query_body["meta"]["countMode"], Value::from("estimate"));

    let (pack_status, pack_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "contextneedle",
                "limit": 5,
                "view": "full"
            }),
        ),
    )
    .await;
    assert_eq!(pack_status, StatusCode::OK);
    assert_eq!(pack_body["results"][0]["id"], Value::from(id.clone()));
    assert_eq!(
        pack_body["results"][0]["fields"]["txt"],
        Value::from("blue hallway contextneedle")
    );
    assert_eq!(
        pack_body["stats"]["signals_used"],
        Value::Array(vec![Value::from("text")])
    );
    let short_id = pack_body["results"][0]["short_id"]
        .as_str()
        .expect("short id");
    let content_hash = pack_body["results"][0]["content_hash"]
        .as_str()
        .expect("content hash");
    let short_ref = format!("{short_id}:{content_hash}");

    let (hydrate_status, hydrate_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/hydrate",
            json!({
                "ref": short_ref,
                "view": "full"
            }),
        ),
    )
    .await;
    assert_eq!(hydrate_status, StatusCode::OK);
    assert_eq!(hydrate_body["status"], Value::from("live"));
    assert_eq!(hydrate_body["id"], Value::from(id.clone()));
    assert_eq!(
        hydrate_body["item"]["txt"],
        Value::from("blue hallway contextneedle")
    );
}

#[tokio::test]
async fn v1_core_memory_timeline_scrubs_filtered_supersession_links() {
    let (_dir, server) = test_server();
    let subject = seeded_test_entity_id(0x1261_0100);
    let old = seeded_test_entity_id(0x1261_0101);
    let new = seeded_test_entity_id(0x1261_0102);
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
    seed_active_claim(&server, old, subject, "osaka", 100);
    seed_active_claim(&server, new, subject, "tokyo", 200);
    server
        .vault
        .supersede_claim(&new, &old, 777)
        .expect("supersede claim");

    let path = format!("/v1/core/memory/{}/timeline?view=full", new.to_hex());
    let (status, body) = route_json(
        server,
        Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("timeline request"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body:#}");
    assert_eq!(body["anchor_id"], Value::from(new.to_hex()));
    let records = body["records"].as_array().expect("timeline records");
    assert_eq!(records.len(), 1, "{body:#}");
    assert_eq!(records[0]["id"], Value::from(new.to_hex()));
    assert_eq!(records[0]["state"], Value::from("live"));
    assert_eq!(records[0]["supersedes"], Value::Array(vec![]));
}

#[tokio::test]
async fn v1_core_memory_verbs_resolve_aliases_to_typed_operations() {
    let (_dir, server) = test_server();
    let remembered = seeded_test_entity_id(0x1261_0200);
    let remember_request = json!({
        "entity": {
            "id": remembered.to_hex(),
            "entity_type": ENTITY_TYPE_TURN,
            "learned_at": 300_u64,
            "occurred_start": 300_u64,
            "occurred_end": 300_u64,
            "body": {
                "txt": "memory verb remembered turn",
                "spkr": "user",
                "at": 300_u64
            },
            "text": [{ "field": "body", "value": "memory verb remembered turn" }]
        }
    });
    let (remember_status, remember_body) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/memory/verbs/remember", remember_request),
    )
    .await;
    assert_eq!(remember_status, StatusCode::OK, "{remember_body:#}");
    assert_eq!(remember_body["verb"], Value::from("remember"));
    assert_eq!(remember_body["operation"], Value::from("put_entity"));
    assert_eq!(
        remember_body["entity"]["id"],
        Value::from(remembered.to_hex())
    );

    let subject = seeded_test_entity_id(0x1261_0201);
    let old = seeded_test_entity_id(0x1261_0202);
    let new = seeded_test_entity_id(0x1261_0203);
    let retractable = seeded_test_entity_id(0x1261_0204);
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
    seed_active_claim(&server, old, subject, "before", 310);
    seed_active_claim(&server, new, subject, "after", 320);
    seed_active_claim(&server, retractable, subject, "withdraw", 330);

    let (replace_status, replace_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/replace",
            json!({
                "new_id": new.to_hex(),
                "old_id": old.to_hex(),
                "at": 900_u64
            }),
        ),
    )
    .await;
    assert_eq!(replace_status, StatusCode::OK, "{replace_body:#}");
    assert_eq!(replace_body["verb"], Value::from("supersede"));
    assert_eq!(replace_body["operation"], Value::from("supersede_claim"));
    assert_eq!(replace_body["new_id"], Value::from(new.to_hex()));
    assert_eq!(replace_body["old_id"], Value::from(old.to_hex()));

    let (withdraw_status, withdraw_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/withdraw",
            json!({
                "id": retractable.to_hex(),
                "at": 901_u64
            }),
        ),
    )
    .await;
    assert_eq!(withdraw_status, StatusCode::OK, "{withdraw_body:#}");
    assert_eq!(withdraw_body["verb"], Value::from("retract"));
    assert_eq!(withdraw_body["operation"], Value::from("retract_claim"));
    assert_eq!(withdraw_body["id"], Value::from(retractable.to_hex()));

    let (soft_gdpr_status, soft_gdpr_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/delete",
            json!({
                "id": remembered.to_hex(),
                "reason": "gdpr_delete"
            }),
        ),
    )
    .await;
    assert_eq!(soft_gdpr_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&soft_gdpr_body, "BAD_REQUEST");

    let (soft_hard_status, soft_hard_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/delete",
            json!({
                "id": remembered.to_hex(),
                "reason": "user_hard_delete"
            }),
        ),
    )
    .await;
    assert_eq!(soft_hard_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&soft_hard_body, "BAD_REQUEST");

    let (delete_at_status, delete_at_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/delete",
            json!({
                "id": remembered.to_hex(),
                "at": 902_u64
            }),
        ),
    )
    .await;
    assert_eq!(delete_at_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&delete_at_body, "BAD_REQUEST");

    let (hard_user_status, hard_user_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/hard_delete",
            json!({
                "id": remembered.to_hex(),
                "reason": "user_delete"
            }),
        ),
    )
    .await;
    assert_eq!(hard_user_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&hard_user_body, "BAD_REQUEST");

    let (forget_status, forget_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/memory/verbs/forget",
            json!({ "id": remembered.to_hex() }),
        ),
    )
    .await;
    assert_eq!(forget_status, StatusCode::OK, "{forget_body:#}");
    assert_eq!(forget_body["verb"], Value::from("delete"));
    assert_eq!(forget_body["operation"], Value::from("delete_entity"));
    assert_eq!(forget_body["delete"]["existed"], Value::from(true));
    assert_eq!(forget_body["delete"]["reason"], Value::from("user_delete"));
    assert_eq!(forget_body["delete"]["hard"], Value::from(false));
    assert!(forget_body.get("at").is_none());

    let deleted_path = format!("/v1/core/memory/{}/timeline", remembered.to_hex());
    let (timeline_status, timeline_body) = route_json(
        server,
        Request::builder()
            .uri(deleted_path)
            .body(Body::empty())
            .expect("deleted timeline request"),
    )
    .await;
    assert_eq!(timeline_status, StatusCode::OK, "{timeline_body:#}");
    let records = timeline_body["records"].as_array().expect("records");
    assert_eq!(records.len(), 1, "{timeline_body:#}");
    assert_eq!(records[0]["id"], Value::from(remembered.to_hex()));
    assert_eq!(records[0]["state"], Value::from("deleted"));
    assert_eq!(records[0]["deletion"]["reason"], Value::from("user_delete"));
    assert!(records[0].get("item").is_none());
}

#[tokio::test]
async fn v1_core_hydrate_distinguishes_malformed_not_found_and_deleted() {
    let (_dir, server) = test_server();
    let entity_id = oneiron::EntityId::now();
    let body = json!({
        "txt": "hydrate deleted needle",
        "spkr": "user",
        "at": 600_u64
    });
    server
        .vault
        .batch()
        .put(
            &entity_id,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 600,
                end: 600,
            },
            600,
            &rmp_serde::to_vec_named(&body).expect("encode body"),
        )
        .text(&entity_id, &[("body", "hydrate deleted needle")])
        .commit()
        .expect("seed turn");

    let pack = server
        .vault
        .context_pack()
        .search_text("hydrate deleted needle", 1)
        .run()
        .expect("context pack");
    let entity = pack.results.first().expect("hydrated result");
    let short_ref = format!("{}:{:02x}", entity.short_id, entity.content_hash);

    let (malformed_status, malformed_body) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/hydrate", json!({ "ref": "bad-ref" })),
    )
    .await;
    assert_eq!(malformed_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&malformed_body, "BAD_REQUEST");

    let (not_found_status, not_found_body) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/hydrate", json!({ "ref": "tn999:aa" })),
    )
    .await;
    assert_eq!(not_found_status, StatusCode::NOT_FOUND);
    assert_error_envelope(&not_found_body, "NOT_FOUND");

    let empty_id = oneiron::EntityId::now();
    server
        .vault
        .batch()
        .put(
            &empty_id,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 601,
                end: 601,
            },
            601,
            b"",
        )
        .text(&empty_id, &[("body", "empty live body needle")])
        .commit()
        .expect("seed empty live turn");
    let empty_pack = server
        .vault
        .context_pack()
        .search_text("empty live body needle", 1)
        .run()
        .expect("empty context pack");
    let empty_entity = empty_pack.results.first().expect("empty live result");
    let empty_short_ref = format!(
        "{}:{:02x}",
        empty_entity.short_id, empty_entity.content_hash
    );
    let (empty_status, empty_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/hydrate",
            json!({ "ref": empty_short_ref }),
        ),
    )
    .await;
    assert_eq!(empty_status, StatusCode::OK, "{empty_body:#}");
    assert_eq!(empty_body["status"], Value::from("live"));
    assert_eq!(empty_body["id"], Value::from(empty_id.to_hex()));
    assert_eq!(empty_body["item"]["bodyBytes"], Value::Array(Vec::new()));

    server
        .vault
        .delete_entity_with_reason(&entity_id, oneiron::DeleteReason::UserDelete)
        .expect("soft delete turn");

    let (deleted_status, deleted_body) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/hydrate", json!({ "ref": short_ref })),
    )
    .await;
    assert_eq!(deleted_status, StatusCode::OK);
    assert_eq!(deleted_body["status"], Value::from("deleted"));
    assert_eq!(deleted_body["id"], Value::from(entity_id.to_hex()));
    assert!(
        matches!(
            deleted_body["deletion"]["source"].as_str(),
            Some("pending_tombstone" | "tombstone")
        ),
        "{deleted_body:#}"
    );
    assert_eq!(
        deleted_body["deletion"]["reason"],
        Value::from("user_delete")
    );
    assert_eq!(deleted_body["deletion"]["hard"], Value::from(false));
    assert!(
        deleted_body["deletion"]["deleted_at"].as_u64().is_some(),
        "{deleted_body:#}"
    );
    assert!(
        deleted_body["deletion"]["request_id"].as_str().is_some(),
        "{deleted_body:#}"
    );
    assert!(deleted_body.get("item").is_none());

    let too_many_refs = vec![empty_short_ref.clone(); CORE_MAX_BATCH_ENTITIES + 1];
    let (too_many_status, too_many_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/batch/shortId/hydrate",
            json!({ "refs": too_many_refs }),
        ),
    )
    .await;
    assert_eq!(too_many_status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&too_many_body, "BAD_REQUEST");

    let (batch_status, batch_body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/core/batch/shortId/hydrate",
            json!({
                "refs": [
                    empty_short_ref,
                    short_ref,
                    "bad-ref",
                    "tn999:aa"
                ]
            }),
        ),
    )
    .await;
    assert_eq!(batch_status, StatusCode::OK, "{batch_body:#}");
    let results = batch_body["results"].as_array().expect("batch results");
    assert_eq!(results.len(), 4);
    assert_eq!(results[0]["outcome"], Value::from("live"));
    assert_eq!(results[0]["result"]["status"], Value::from("live"));
    assert_eq!(results[0]["result"]["id"], Value::from(empty_id.to_hex()));
    assert_eq!(results[1]["outcome"], Value::from("deleted"));
    assert_eq!(results[1]["result"]["status"], Value::from("deleted"));
    assert_eq!(
        results[1]["result"]["deletion"]["reason"],
        Value::from("user_delete")
    );
    assert_eq!(results[2]["outcome"], Value::from("malformed_short_id"));
    assert_eq!(
        results[2]["error"]["kind"],
        Value::from("malformed_short_id")
    );
    assert_eq!(results[3]["outcome"], Value::from("not_found"));
    assert_eq!(results[3]["error"]["kind"], Value::from("not_found"));
}

#[tokio::test]
async fn v1_core_conversation_routes_create_list_and_read_turns() {
    let (_dir, server) = test_server();

    let (conversation_status, conversation_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({
                "learned_at": 700_u64,
                "occurred_start": 700_u64,
                "occurred_end": 700_u64,
                "body": { "name": "Dream session" }
            }),
        ),
    )
    .await;
    assert_eq!(conversation_status, StatusCode::OK);
    let conversation_id = conversation_body["id"]
        .as_str()
        .expect("conversation id")
        .to_owned();

    let (conversations_status, conversations_body) = route_json(
        server.clone(),
        Request::builder()
            .uri("/v1/core/conversations?view=full")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(conversations_status, StatusCode::OK);
    assert_eq!(
        conversations_body["items"][0]["id"],
        Value::from(conversation_id.clone())
    );
    assert_eq!(
        conversations_body["items"][0]["name"],
        Value::from("Dream session")
    );

    let (turn_status, turn_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/conversations/{conversation_id}/turns"),
            json!({
                "learned_at": 701_u64,
                "occurred_start": 701_u64,
                "occurred_end": 701_u64,
                "body": {
                    "txt": "conversation turn needle",
                    "spkr": "assistant",
                    "at": 701_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(turn_status, StatusCode::OK);
    let turn_id = turn_body["id"].as_str().expect("turn id").to_owned();
    assert_eq!(
        turn_body["item"]["txt"],
        Value::from("conversation turn needle")
    );

    let (turns_status, turns_body) = route_json(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/v1/core/conversations/{conversation_id}/turns?view=full"
            ))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(turns_status, StatusCode::OK);
    assert_eq!(turns_body["items"][0]["id"], Value::from(turn_id.clone()));
    assert_eq!(
        turns_body["items"][0]["txt"],
        Value::from("conversation turn needle")
    );

    let (read_status, read_body) = route_json(
        server,
        Request::builder()
            .uri(format!("/v1/core/turns/{turn_id}?view=full"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(read_status, StatusCode::OK);
    assert_eq!(read_body["txt"], Value::from("conversation turn needle"));
}

#[tokio::test]
async fn v1_core_conversation_turns_honor_after_and_filter_deleted_shells() {
    let (_dir, server) = test_server();

    let (conversation_status, conversation_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({
                "learned_at": 800_u64,
                "body": { "name": "Cursor session" }
            }),
        ),
    )
    .await;
    assert_eq!(conversation_status, StatusCode::OK);
    let conversation_id = conversation_body["id"]
        .as_str()
        .expect("conversation id")
        .to_owned();

    let mut turn_ids = Vec::new();
    for index in 0..3_u64 {
        let (turn_status, turn_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                &format!("/v1/core/conversations/{conversation_id}/turns"),
                json!({
                    "learned_at": 801_u64 + index,
                    "occurred_start": 801_u64 + index,
                    "occurred_end": 801_u64 + index,
                    "body": {
                        "txt": format!("cursor turn {index}"),
                        "spkr": "assistant",
                        "at": 801_u64 + index
                    }
                }),
            ),
        )
        .await;
        assert_eq!(turn_status, StatusCode::OK);
        turn_ids.push(turn_body["id"].as_str().expect("turn id").to_owned());
    }

    let (first_page_status, first_page) = route_json(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none"
            ))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(first_page_status, StatusCode::OK);
    let first_id = first_page["items"][0]["id"]
        .as_str()
        .expect("first page id")
        .to_owned();
    assert_eq!(first_page["nextCursor"], Value::from(first_id.clone()));

    let (second_page_status, second_page) = route_json(
            server.clone(),
            Request::builder()
                .uri(format!(
                    "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none&after={first_id}"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(second_page_status, StatusCode::OK);
    assert_ne!(second_page["items"][0]["id"], Value::from(first_id.clone()));

    let deleted_id = oneiron::EntityId::from_hex(&turn_ids[1]).expect("turn id parses");
    server
        .vault
        .delete_entity_with_reason(&deleted_id, oneiron::DeleteReason::UserDelete)
        .expect("soft delete turn");

    let (deleted_gap_status, deleted_gap_page) = route_json(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none"
            ))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(deleted_gap_status, StatusCode::OK);
    let deleted_gap_first = deleted_gap_page["items"][0]["id"]
        .as_str()
        .expect("deleted gap first id")
        .to_owned();
    assert_ne!(deleted_gap_first, turn_ids[1]);
    assert_eq!(
        deleted_gap_page["nextCursor"],
        Value::from(deleted_gap_first.clone())
    );

    let (after_deleted_gap_status, after_deleted_gap_page) = route_json(
            server.clone(),
            Request::builder()
                .uri(format!(
                    "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none&after={deleted_gap_first}"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(after_deleted_gap_status, StatusCode::OK);
    let after_deleted_gap_id = after_deleted_gap_page["items"][0]["id"]
        .as_str()
        .expect("after deleted gap id");
    assert_ne!(after_deleted_gap_id, deleted_gap_first);
    assert_ne!(after_deleted_gap_id, turn_ids[1]);

    let (filtered_status, filtered_body) = route_json(
        server,
        Request::builder()
            .uri(format!(
                "/v1/core/conversations/{conversation_id}/turns?view=full&countMode=exact"
            ))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(filtered_status, StatusCode::OK);
    let listed_ids: Vec<&str> = filtered_body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("item id"))
        .collect();
    assert_eq!(listed_ids.len(), 2);
    assert!(!listed_ids.contains(&turn_ids[1].as_str()));
    assert_eq!(filtered_body["meta"]["total"], Value::from(2));
}

#[tokio::test]
async fn v1_core_turn_create_maps_childof_constraints_to_invalid_state() {
    let (_dir, server) = test_server();

    let create_conversation = |name: &str| {
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({
                "body": { "name": name }
            }),
        )
    };
    let (first_status, first_body) = route_json(server.clone(), create_conversation("first")).await;
    assert_eq!(first_status, StatusCode::OK);
    let first_conversation = first_body["id"].as_str().expect("first id").to_owned();
    let (second_status, second_body) =
        route_json(server.clone(), create_conversation("second")).await;
    assert_eq!(second_status, StatusCode::OK);
    let second_conversation = second_body["id"].as_str().expect("second id").to_owned();

    let turn_id = oneiron::EntityId::now().to_hex();
    let turn_body = json!({
        "id": turn_id,
        "body": {
            "txt": "cardinality turn",
            "spkr": "assistant",
            "at": 900_u64
        }
    });
    let (first_turn_status, _) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/conversations/{first_conversation}/turns"),
            turn_body.clone(),
        ),
    )
    .await;
    assert_eq!(first_turn_status, StatusCode::OK);

    let (conflict_status, conflict_body) = route_json(
        server,
        json_request(
            "POST",
            &format!("/v1/core/conversations/{second_conversation}/turns"),
            turn_body,
        ),
    )
    .await;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_error_envelope(&conflict_body, "INVALID_STATE");
}

#[tokio::test]
async fn platform_announcement_turn_never_projects_as_eiri_voice() {
    let (_dir, server) = test_server();
    let (conversation_status, conversation_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({ "body": { "name": "Announcement stream" } }),
        ),
    )
    .await;
    assert_eq!(conversation_status, StatusCode::OK);
    let conversation_id = conversation_body["id"].as_str().expect("conversation id");
    let turn_id = seeded_test_entity_id(0x1479_0001).to_hex();

    let (turn_status, turn_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/conversations/{conversation_id}/turns"),
            json!({
                "id": turn_id,
                "learned_at": 1_782_400_001_u64,
                "occurred_start": 1_782_400_001_u64,
                "occurred_end": 1_782_400_001_u64,
                "body": {
                    "message_type": PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE,
                    "txt": "Maintenance begins at 22:00 UTC.",
                    "spkr": "Eiri",
                    "speaker": "Eiri",
                    "voice": "eiri",
                    "attribution": "Eiri",
                    "render_voice": "eiri",
                    "at": 1_782_400_001_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(turn_status, StatusCode::OK, "{turn_body:#}");
    let item = &turn_body["item"];
    assert_eq!(
        item["message_type"],
        Value::from(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE)
    );
    assert_eq!(item["spkr"], Value::from(PLATFORM_ANNOUNCEMENT_VOICE));
    assert_eq!(item["speaker"], Value::from(PLATFORM_ANNOUNCEMENT_VOICE));
    assert_eq!(item["voice"], Value::from(PLATFORM_ANNOUNCEMENT_VOICE));
    assert_eq!(
        item["attribution"],
        Value::from(PLATFORM_ANNOUNCEMENT_VOICE)
    );
    assert_eq!(
        item["render_voice"],
        Value::from(PLATFORM_ANNOUNCEMENT_VOICE)
    );
    assert_eq!(item["platform_voice"], Value::from(true));
    assert_eq!(item["is_eiri"], Value::from(false));

    let (read_status, read_body) = route_json(
        server,
        Request::builder()
            .uri(format!("/v1/core/turns/{turn_id}?view=standard"))
            .body(Body::empty())
            .expect("read request"),
    )
    .await;
    assert_eq!(read_status, StatusCode::OK, "{read_body:#}");
    assert_eq!(
        read_body["message_type"],
        Value::from(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE)
    );
    assert_eq!(read_body["voice"], Value::from(PLATFORM_ANNOUNCEMENT_VOICE));
    assert_ne!(read_body["voice"], Value::from("eiri"));
}

#[tokio::test]
async fn platform_announcement_correction_and_retraction_update_delivered_turn() {
    let (_dir, server) = test_server();
    let (conversation_status, conversation_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({ "body": { "name": "Ops notices" } }),
        ),
    )
    .await;
    assert_eq!(conversation_status, StatusCode::OK);
    let conversation_id = conversation_body["id"].as_str().expect("conversation id");
    let turn_id = seeded_test_entity_id(0x1479_0002).to_hex();
    let turns_path = format!("/v1/core/conversations/{conversation_id}/turns");

    let (create_status, create_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &turns_path,
            json!({
                "id": turn_id,
                "learned_at": 1_782_400_010_u64,
                "occurred_start": 1_782_400_010_u64,
                "occurred_end": 1_782_400_010_u64,
                "body": {
                    "message_type": PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE,
                    "txt": "Storage maintenance starts at 20:00 UTC.",
                    "announcement_status": "active",
                    "at": 1_782_400_010_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(create_status, StatusCode::OK, "{create_body:#}");

    let (correct_status, correct_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &turns_path,
            json!({
                "id": turn_id,
                "learned_at": 1_782_400_020_u64,
                "occurred_start": 1_782_400_010_u64,
                "occurred_end": 1_782_400_020_u64,
                "body": {
                    "message_type": PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE,
                    "txt": "Storage maintenance starts at 21:00 UTC.",
                    "announcement_status": "corrected",
                    "at": 1_782_400_020_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(correct_status, StatusCode::OK, "{correct_body:#}");
    assert_eq!(
        correct_body["item"]["announcement_status"],
        Value::from(ANNOUNCEMENT_STATUS_CORRECTED)
    );
    assert_eq!(correct_body["item"]["corrected"], Value::from(true));

    let (retract_status, retract_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &turns_path,
            json!({
                "id": turn_id,
                "learned_at": 1_782_400_030_u64,
                "occurred_start": 1_782_400_010_u64,
                "occurred_end": 1_782_400_030_u64,
                "body": {
                    "message_type": PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE,
                    "txt": "Storage maintenance announcement retracted.",
                    "retracted": true,
                    "at": 1_782_400_030_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(retract_status, StatusCode::OK, "{retract_body:#}");
    assert_eq!(
        retract_body["item"]["announcement_status"],
        Value::from(ANNOUNCEMENT_STATUS_RETRACTED)
    );
    assert_eq!(retract_body["item"]["retracted"], Value::from(true));

    let (read_status, read_body) = route_json(
        server,
        Request::builder()
            .uri(format!("/v1/core/turns/{turn_id}?view=full"))
            .body(Body::empty())
            .expect("read request"),
    )
    .await;
    assert_eq!(read_status, StatusCode::OK, "{read_body:#}");
    assert_eq!(
        read_body["txt"],
        Value::from("Storage maintenance announcement retracted.")
    );
    assert_eq!(
        read_body["announcement_status"],
        Value::from(ANNOUNCEMENT_STATUS_RETRACTED)
    );
    assert_eq!(read_body["voice"], Value::from(PLATFORM_ANNOUNCEMENT_VOICE));
}

#[tokio::test]
async fn localized_platform_announcement_exposes_original_text_toggle() {
    let (_dir, server) = test_server();
    let (conversation_status, conversation_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({ "body": { "name": "Localized notices" } }),
        ),
    )
    .await;
    assert_eq!(conversation_status, StatusCode::OK);
    let conversation_id = conversation_body["id"].as_str().expect("conversation id");
    let turn_id = seeded_test_entity_id(0x1479_0003).to_hex();

    let (turn_status, turn_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            &format!("/v1/core/conversations/{conversation_id}/turns"),
            json!({
                "id": turn_id,
                "learned_at": 1_782_400_040_u64,
                "occurred_start": 1_782_400_040_u64,
                "occurred_end": 1_782_400_040_u64,
                "body": {
                    "messageType": PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE,
                    "txt": "メンテナンスは22:00 UTCに開始します。",
                    "locale": "ja-JP",
                    "originalText": "Maintenance begins at 22:00 UTC.",
                    "showOriginal": false,
                    "at": 1_782_400_040_u64
                }
            }),
        ),
    )
    .await;
    assert_eq!(turn_status, StatusCode::OK, "{turn_body:#}");
    assert_eq!(turn_body["item"]["localized"], Value::from(true));
    assert_eq!(turn_body["item"]["locale"], Value::from("ja-JP"));
    assert_eq!(
        turn_body["item"]["original_txt"],
        Value::from("Maintenance begins at 22:00 UTC.")
    );
    assert_eq!(turn_body["item"]["show_original"], Value::from(false));

    let (read_status, read_body) = route_json(
        server,
        Request::builder()
            .uri(format!("/v1/core/turns/{turn_id}?view=standard"))
            .body(Body::empty())
            .expect("read request"),
    )
    .await;
    assert_eq!(read_status, StatusCode::OK, "{read_body:#}");
    assert_eq!(
        read_body["message_type"],
        Value::from(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE)
    );
    assert_eq!(read_body["show_original"], Value::from(false));
}

#[tokio::test]
async fn usage_event_uses_runtime_mode_for_byo_no_debit_boundary() {
    let runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);
    let config = SyncServerConfig {
        allow_unauthenticated: true,
        runtime,
        ..Default::default()
    };
    let (_dir, server) = test_server_with_config(config);
    let payload = json!({
        "tenantId": "tenant-a",
        "vaultId": "vault-a",
        "idempotencyKey": "byo-boundary",
        "source": "oneiron_cloud",
        "eventType": "inference",
        "model": "external-model",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": {
            "inputTokenUsdPerMillion": 2.0,
            "outputTokenUsdPerMillion": 4.0,
            "cacheReadTokenUsdPerMillion": 0.0,
            "cacheWriteTokenUsdPerMillion": 0.0
        }
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
    assert_eq!(body["source"], Value::from("byo"));
    assert_eq!(body["debit"], Value::Null);
    assert_eq!(body["recorded"], Value::from(false));
}

#[tokio::test]
async fn usage_event_on_default_runtime_resolves_local_no_debit() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        ..Default::default()
    });
    let payload = json!({
        "tenantId": "tenant-a",
        "vaultId": "vault-a",
        "idempotencyKey": "legacy-usage-default-runtime",
        "source": "local",
        "eventType": "inference",
        "model": "local-orchestrator-default",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": {
            "inputTokenUsdPerMillion": 2.0,
            "outputTokenUsdPerMillion": 4.0,
            "cacheReadTokenUsdPerMillion": 0.0,
            "cacheWriteTokenUsdPerMillion": 0.0
        }
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
    assert_eq!(body["source"], Value::from("local"));
    assert_eq!(body["recorded"], Value::from(false));
    assert!(body["debit"].is_null());
}

#[tokio::test]
async fn usage_event_rejects_mixed_runtime_without_model_discriminator() {
    let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        crate::runtime::RuntimeRoleTargetOverride {
            mode: Some(RuntimeMode::OneironCloud),
            provider_kind: None,
            model: Some("hosted-orchestrator".to_owned()),
        },
    ));
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime,
        ..Default::default()
    });
    let payload = json!({
        "tenantId": "tenant-a",
        "vaultId": "vault-a",
        "idempotencyKey": "ambiguous-mixed-route",
        "source": "oneiron_cloud",
        "eventType": "inference",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": {
            "inputTokenUsdPerMillion": 2.0,
            "outputTokenUsdPerMillion": 4.0,
            "cacheReadTokenUsdPerMillion": 0.0,
            "cacheWriteTokenUsdPerMillion": 0.0
        }
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
    assert_eq!(body["code"], Value::from("BAD_REQUEST"));
    assert_eq!(body["details"]["field"], Value::from("model"));
}

#[tokio::test]
async fn usage_event_uses_unanimous_hosted_routes_without_model_discriminator() {
    let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    for role in RuntimeRole::ALL {
        runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
            role,
            crate::runtime::RuntimeRoleTargetOverride {
                mode: Some(RuntimeMode::OneironCloud),
                provider_kind: None,
                model: Some(format!("hosted-{role}")),
            },
        ));
    }
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime,
        ..Default::default()
    });
    let payload = json!({
        "tenantId": "tenant-a",
        "vaultId": "vault-a",
        "idempotencyKey": "unmodeled-hosted-routes",
        "source": "local",
        "eventType": "inference",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": {
            "inputTokenUsdPerMillion": 2.0,
            "outputTokenUsdPerMillion": 4.0,
            "cacheReadTokenUsdPerMillion": 0.0,
            "cacheWriteTokenUsdPerMillion": 0.0
        }
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
    assert_eq!(body["source"], Value::from("oneiron_cloud"));
    assert_eq!(body["recorded"], Value::from(true));
    assert!(body["debit"].is_object());
}

#[tokio::test]
async fn usage_event_accepts_all_unmetered_runtime_mix_without_model_discriminator() {
    let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        crate::runtime::RuntimeRoleTargetOverride::mode(RuntimeMode::ByoCloudKey),
    ));
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime,
        ..Default::default()
    });
    let payload = json!({
        "tenantId": "tenant-a",
        "vaultId": "vault-a",
        "idempotencyKey": "unmodeled-unmetered-routes",
        "source": "oneiron_cloud",
        "eventType": "inference",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": {
            "inputTokenUsdPerMillion": 2.0,
            "outputTokenUsdPerMillion": 4.0,
            "cacheReadTokenUsdPerMillion": 0.0,
            "cacheWriteTokenUsdPerMillion": 0.0
        }
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
    assert_eq!(body["recorded"], Value::from(false));
    assert_eq!(body["debit"], Value::Null);
}

#[tokio::test]
async fn usage_event_uses_matching_hosted_route_for_debit_boundary() {
    let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        crate::runtime::RuntimeRoleTargetOverride {
            mode: Some(RuntimeMode::OneironCloud),
            provider_kind: None,
            model: Some("hosted-orchestrator".to_owned()),
        },
    ));
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime,
        ..Default::default()
    });
    let payload = json!({
        "tenantId": "tenant-a",
        "vaultId": "vault-a",
        "idempotencyKey": "hosted-route-boundary",
        "source": "local",
        "eventType": "inference",
        "model": "hosted-orchestrator",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": {
            "inputTokenUsdPerMillion": 2.0,
            "outputTokenUsdPerMillion": 4.0,
            "cacheReadTokenUsdPerMillion": 0.0,
            "cacheWriteTokenUsdPerMillion": 0.0
        }
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
    assert_eq!(body["source"], Value::from("oneiron_cloud"));
    assert_eq!(body["recorded"], Value::from(true));
    assert!(body["debit"].is_object());
}

#[tokio::test]
async fn usage_event_uses_matching_local_route_for_no_debit_boundary() {
    let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
    runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
        RuntimeRole::Subagent,
        crate::runtime::RuntimeRoleTargetOverride {
            mode: Some(RuntimeMode::LocalFree),
            provider_kind: None,
            model: Some("local-subagent".to_owned()),
        },
    ));
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime,
        ..Default::default()
    });
    let payload = json!({
        "tenantId": "tenant-a",
        "vaultId": "vault-a",
        "idempotencyKey": "local-route-boundary",
        "source": "oneiron_cloud",
        "eventType": "inference",
        "model": "local-subagent",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": {
            "inputTokenUsdPerMillion": 2.0,
            "outputTokenUsdPerMillion": 4.0,
            "cacheReadTokenUsdPerMillion": 0.0,
            "cacheWriteTokenUsdPerMillion": 0.0
        }
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
    assert_eq!(body["source"], Value::from("local"));
    assert_eq!(body["recorded"], Value::from(false));
    assert_eq!(body["debit"], Value::Null);
}

#[tokio::test]
async fn usage_event_rejects_unavailable_model_route_match_before_debiting() {
    let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
    runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        crate::runtime::RuntimeRoleTargetOverride::target(
            RuntimeProviderKind::Local,
            "unavailable-hosted-model",
        ),
    ));
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime,
        ..Default::default()
    });
    let payload = json!({
        "tenantId": "tenant-a",
        "vaultId": "vault-a",
        "idempotencyKey": "unavailable-model-route",
        "source": "oneiron_cloud",
        "eventType": "inference",
        "model": "unavailable-hosted-model",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": {
            "inputTokenUsdPerMillion": 2.0,
            "outputTokenUsdPerMillion": 4.0,
            "cacheReadTokenUsdPerMillion": 0.0,
            "cacheWriteTokenUsdPerMillion": 0.0
        }
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
    assert_eq!(body["code"], Value::from("BAD_REQUEST"));
    assert_eq!(body["details"]["field"], Value::from("model"));
}

#[tokio::test]
async fn usage_event_rejects_unmodeled_unavailable_routes_before_debiting() {
    let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
    runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        crate::runtime::RuntimeRoleTargetOverride::target(
            RuntimeProviderKind::Local,
            "unavailable-hosted-model",
        ),
    ));
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime,
        ..Default::default()
    });
    let payload = json!({
        "tenantId": "tenant-a",
        "vaultId": "vault-a",
        "idempotencyKey": "unmodeled-unavailable-route",
        "source": "oneiron_cloud",
        "eventType": "inference",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": {
            "inputTokenUsdPerMillion": 2.0,
            "outputTokenUsdPerMillion": 4.0,
            "cacheReadTokenUsdPerMillion": 0.0,
            "cacheWriteTokenUsdPerMillion": 0.0
        }
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
    assert_eq!(body["code"], Value::from("BAD_REQUEST"));
    assert_eq!(body["details"]["field"], Value::from("model"));
}

#[tokio::test]
async fn usage_event_accepts_duplicate_unmetered_model_matches() {
    let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
    runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_byo_key_env(
        Some("PATH".to_owned()),
    ));
    for (role, mode) in [
        (RuntimeRole::Orchestrator, RuntimeMode::LocalFree),
        (RuntimeRole::Subagent, RuntimeMode::ByoCloudKey),
    ] {
        runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
            role,
            crate::runtime::RuntimeRoleTargetOverride {
                mode: Some(mode),
                provider_kind: None,
                model: Some("shared-unmetered-model".to_owned()),
            },
        ));
    }
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime,
        ..Default::default()
    });
    let payload = json!({
        "tenantId": "tenant-a",
        "vaultId": "vault-a",
        "idempotencyKey": "duplicate-unmetered-model",
        "source": "oneiron_cloud",
        "eventType": "inference",
        "model": "shared-unmetered-model",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": {
            "inputTokenUsdPerMillion": 2.0,
            "outputTokenUsdPerMillion": 4.0,
            "cacheReadTokenUsdPerMillion": 0.0,
            "cacheWriteTokenUsdPerMillion": 0.0
        }
    });

    let response = api_routes(server)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
    assert_eq!(body["recorded"], Value::from(false));
    assert_eq!(body["debit"], Value::Null);
}

#[tokio::test]
async fn consumer_top_up_route_is_idempotent() {
    let (_dir, server) = test_server_with_runtime_mode(RuntimeMode::OneironCloud);

    let (first_status, first) = top_up_route(server.clone(), "top-up-idem", 10.0).await;
    let (second_status, second) = top_up_route(server.clone(), "top-up-idem", 10.0).await;
    let (usage_status, usage) = route_json(
        server,
        Request::builder()
            .uri("/v1/consumer/usage?tenantId=tenant-a")
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(usage_status, StatusCode::OK);
    assert_eq!(first["recorded"], Value::from(true));
    assert_eq!(first["replayed"], Value::from(false));
    assert_eq!(second["recorded"], Value::from(false));
    assert_eq!(second["replayed"], Value::from(true));
    assert_eq!(first["topUp"], second["topUp"]);
    assert_eq!(
        usage["allowance"]["allowanceCreditUnits"],
        Value::from(10.0)
    );
    assert_eq!(
        usage["allowance"]["remainingCreditUnits"],
        Value::from(10.0)
    );
}

#[tokio::test]
async fn consumer_top_up_route_with_http_idempotency_header_reaches_ledger_replay() {
    let (_dir, server) = test_server_with_runtime_mode(RuntimeMode::OneironCloud);
    let top_up = json!({
        "tenantId": "tenant-a",
        "idempotencyKey": "top-up-http-idem",
        "creditUnits": 10.0,
    });
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/consumer/top-up")
            .header(CONTENT_TYPE, "application/json")
            .header(
                crate::idempotency::IDEMPOTENCY_KEY_HEADER,
                "http-top-up-key",
            )
            .body(Body::from(top_up.to_string()))
            .expect("request")
    };

    let (first_status, first) = route_json(server.clone(), request()).await;
    let (second_status, second) = route_json(server, request()).await;

    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(first["recorded"], Value::from(true));
    assert_eq!(first["replayed"], Value::from(false));
    assert_eq!(second["recorded"], Value::from(false));
    assert_eq!(second["replayed"], Value::from(true));
    assert_eq!(first["topUp"], second["topUp"]);
}

#[tokio::test]
async fn consumer_top_up_route_maps_malformed_json_to_api_error() {
    let (_dir, server) = test_server_with_runtime_mode(RuntimeMode::OneironCloud);

    let (status, body) = route_json(
        server,
        Request::builder()
            .method("POST")
            .uri("/v1/consumer/top-up")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{"))
            .expect("request"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], Value::from("BAD_REQUEST"));
    assert_eq!(body["details"]["code"], Value::from("BAD_REQUEST"));
    assert_eq!(body["message"], Value::from("invalid JSON request body"));
}

#[tokio::test]
async fn consumer_top_up_route_rejects_idempotency_conflicts() {
    let (_dir, server) = test_server_with_runtime_mode(RuntimeMode::OneironCloud);

    let (first_status, first) = top_up_route(server.clone(), "top-up-conflict", 10.0).await;
    let (conflict_status, conflict) = top_up_route(server.clone(), "top-up-conflict", 11.0).await;
    let (usage_status, usage) = route_json(
        server,
        Request::builder()
            .uri("/v1/consumer/usage?tenantId=tenant-a")
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(first["recorded"], Value::from(true));
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_eq!(conflict["code"], Value::from("IDEMPOTENCY_REPLAY_CONFLICT"));
    assert_eq!(
        conflict["details"]["idempotencyKey"],
        Value::from("top-up-conflict")
    );
    assert_eq!(
        conflict["suggestions"],
        json!(["Reuse the original top-up request body or send a new JSON idempotencyKey."])
    );
    assert_eq!(usage_status, StatusCode::OK);
    assert_eq!(
        usage["allowance"]["allowanceCreditUnits"],
        Value::from(10.0)
    );
}

#[tokio::test]
async fn consumer_top_up_route_rejects_normalized_zero_credit_units() {
    let (_dir, server) = test_server_with_runtime_mode(RuntimeMode::OneironCloud);

    let (tiny_status, tiny) = top_up_route(server.clone(), "tiny-top-up", 0.0000000000001).await;
    let (retry_status, retry) = top_up_route(server, "tiny-top-up", 1.0).await;

    assert_eq!(tiny_status, StatusCode::BAD_REQUEST);
    assert_eq!(tiny["code"], Value::from("BAD_REQUEST"));
    assert_eq!(tiny["details"]["field"], Value::from("creditUnits"));
    assert_eq!(retry_status, StatusCode::OK);
    assert_eq!(retry["recorded"], Value::from(true));
    assert_eq!(retry["topUp"]["creditUnits"], Value::from(1.0));
}

#[tokio::test]
async fn consumer_top_up_route_rejects_non_finite_allowance_balance() {
    let (_dir, server) = test_server_with_runtime_mode(RuntimeMode::OneironCloud);

    let (first_status, first) = top_up_route(server.clone(), "large-top-up-1", 1.0e296).await;
    let (overflow_status, overflow) = top_up_route(server.clone(), "large-top-up-2", 1.0e296).await;
    let (usage_status, usage) = route_json(
        server,
        Request::builder()
            .uri("/v1/consumer/usage?tenantId=tenant-a")
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(first["recorded"], Value::from(true));
    assert_eq!(overflow_status, StatusCode::BAD_REQUEST);
    assert_eq!(overflow["code"], Value::from("BAD_REQUEST"));
    assert_eq!(overflow["details"]["field"], Value::from("creditUnits"));
    assert_eq!(usage_status, StatusCode::OK);
    assert!(
        usage["allowance"]["allowanceCreditUnits"]
            .as_f64()
            .is_some_and(f64::is_finite),
        "allowance should remain finite after rejected top-up: {usage:?}"
    );
}

#[tokio::test]
async fn consumer_usage_route_returns_usage_allowance_and_warning_state() {
    let (_dir, server) = test_server_with_runtime_mode(RuntimeMode::OneironCloud);
    let (top_up_status, _) = top_up_route(server.clone(), "summary-top-up", 10.0).await;
    let (record_status, _) = record_usage_event_route(server.clone(), "summary-usage", 0.08).await;
    let (usage_status, usage) = route_json(
        server,
        Request::builder()
            .uri("/v1/consumer/usage?tenantId=tenant-a")
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(top_up_status, StatusCode::OK);
    assert_eq!(record_status, StatusCode::OK);
    assert_eq!(usage_status, StatusCode::OK);
    assert_eq!(usage["tenantId"], Value::from("tenant-a"));
    assert_eq!(usage["mode"], Value::from("oneiron_cloud"));
    assert_eq!(usage["counters"]["eventCount"], Value::from(1_u64));
    assert_eq!(
        usage["allowance"]["allowanceCreditUnits"],
        Value::from(10.0)
    );
    assert_eq!(usage["allowance"]["usedCreditUnits"], Value::from(8.0));
    assert_eq!(usage["allowance"]["remainingCreditUnits"], Value::from(2.0));
    assert_eq!(
        usage["allowance"]["warning"]["level"],
        Value::from("notice")
    );
    assert_eq!(usage["allowance"]["warning"]["usedRatio"], Value::from(0.8));
    assert_eq!(
        usage["allowance"]["warning"]["triggered"],
        Value::from(true)
    );
}

#[tokio::test]
async fn consumer_vault_scoped_usage_uses_tenant_allowance_burn_down() {
    let (_dir, server) = test_server_with_runtime_mode(RuntimeMode::OneironCloud);
    let (top_up_status, _) = top_up_route(server.clone(), "vault-scope-top-up", 10.0).await;
    let (vault_a_status, _) =
        record_usage_event_for_vault_route(server.clone(), "vault-a-usage", "vault-a", 0.08).await;
    let (vault_b_status, _) =
        record_usage_event_for_vault_route(server.clone(), "vault-b-usage", "vault-b", 0.015).await;
    let (usage_status, usage) = route_json(
        server.clone(),
        Request::builder()
            .uri("/v1/consumer/usage?tenantId=tenant-a&vaultId=vault-a")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    let (details_status, details) = route_json(
        server,
        Request::builder()
            .uri("/v1/consumer/usage/details?tenantId=tenant-a&vaultId=vault-a")
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(top_up_status, StatusCode::OK);
    assert_eq!(vault_a_status, StatusCode::OK);
    assert_eq!(vault_b_status, StatusCode::OK);
    assert_eq!(usage_status, StatusCode::OK);
    assert_eq!(details_status, StatusCode::OK);
    assert_eq!(usage["vaultId"], Value::from("vault-a"));
    assert_eq!(usage["counters"]["creditUnits"], Value::from(8.0));
    assert_eq!(usage["allowance"]["usedCreditUnits"], Value::from(9.5));
    assert_eq!(usage["allowance"]["remainingCreditUnits"], Value::from(0.5));
    assert_eq!(
        usage["allowance"]["warning"]["level"],
        Value::from("critical")
    );
    assert_eq!(
        usage["allowance"]["warning"]["usedRatio"],
        Value::from(0.95)
    );
    assert_eq!(
        details["usage"]["counters"]["creditUnits"],
        Value::from(8.0)
    );
    assert_eq!(
        details["usage"]["allowance"]["usedCreditUnits"],
        Value::from(9.5)
    );
    assert_eq!(
        details["usage"]["allowance"]["warning"]["level"],
        Value::from("critical")
    );
    assert_eq!(
        details["agents"]["agent-a"]["eventCount"],
        Value::from(1_u64)
    );
}

#[tokio::test]
async fn consumer_usage_details_route_returns_breakdowns() {
    let (_dir, server) = test_server_with_runtime_mode(RuntimeMode::OneironCloud);
    let (top_up_status, _) = top_up_route(server.clone(), "details-top-up", 100.0).await;
    let (record_status, _) = record_usage_event_route(server.clone(), "details-usage", 0.05).await;
    let (details_status, details) = route_json(
        server,
        Request::builder()
            .uri("/v1/consumer/usage/details?tenantId=tenant-a&vaultId=vault-a")
            .body(Body::empty())
            .expect("request"),
    )
    .await;

    assert_eq!(top_up_status, StatusCode::OK);
    assert_eq!(record_status, StatusCode::OK);
    assert_eq!(details_status, StatusCode::OK);
    assert_eq!(details["usage"]["vaultId"], Value::from("vault-a"));
    assert_eq!(
        details["usage"]["counters"]["creditUnits"],
        Value::from(5.0)
    );
    assert_eq!(
        details["agents"]["agent-a"]["eventCount"],
        Value::from(1_u64)
    );
    assert_eq!(
        details["models"]["model-a"]["creditUnits"],
        Value::from(5.0)
    );
    assert_eq!(
        details["services"]["inference"]["costUsd"],
        Value::from(0.05)
    );
}

#[tokio::test]
async fn consumer_usage_route_reports_allowance_warning_thresholds() {
    for (used_credit_units, expected_level, expected_triggered, expected_threshold) in [
        (7.0, "none", false, 0.8),
        (8.0, "notice", true, 0.8),
        (9.5, "critical", true, 0.95),
        (10.0, "exhausted", true, 1.0),
    ] {
        let (_dir, server) = test_server_with_runtime_mode(RuntimeMode::OneironCloud);
        let (top_up_status, _) = top_up_route(server.clone(), "threshold-top-up", 10.0).await;
        let (record_status, _) = record_usage_event_route(
            server.clone(),
            "threshold-usage",
            used_credit_units * crate::usage::CREDIT_UNIT_USD,
        )
        .await;
        let (usage_status, usage) = route_json(
            server,
            Request::builder()
                .uri("/v1/consumer/usage?tenantId=tenant-a")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(top_up_status, StatusCode::OK);
        assert_eq!(record_status, StatusCode::OK);
        assert_eq!(usage_status, StatusCode::OK);
        assert_eq!(
            usage["allowance"]["warning"]["level"],
            Value::from(expected_level),
            "used credit units: {used_credit_units}"
        );
        assert_eq!(
            usage["allowance"]["warning"]["triggered"],
            Value::from(expected_triggered),
            "used credit units: {used_credit_units}"
        );
        assert_eq!(
            usage["allowance"]["warning"]["thresholdRatio"],
            Value::from(expected_threshold),
            "used credit units: {used_credit_units}"
        );
    }
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
fn witness_vad_message_fixture(
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

#[tokio::test]
async fn turn_vad_annotate_route_persists_and_reads_annotations() {
    let (_dir, server) = test_server();
    let turn = oneiron::EntityId::now();
    let message = oneiron::EntityId::now();
    witness_vad_message_fixture(&server, &turn, &message, "message affect", 101);
    server
        .vault
        .put_edge(&message, oneiron::EdgeKind::ChildOf, &turn, 1.0)
        .expect("link message to turn");

    let response = api_routes(server.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/core/turns/annotate")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "turn_id": turn.to_hex(),
                        "source": "model_inference",
                        "vad": {
                            "valence": 0.25,
                            "arousal": 0.5,
                            "dominance": 0.75,
                        },
                        "annotated_at": 200_u64,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("turn annotate response body");
    let body: Value = serde_json::from_slice(&body).expect("annotation JSON body");
    assert_eq!(body["turn_id"], Value::from(turn.to_hex()));
    assert_eq!(body["message_id"], Value::Null);
    assert_eq!(body["source"], Value::from("model_inference"));
    assert_eq!(
        server
            .vault
            .get_turn_vad_annotation(&turn)
            .unwrap()
            .unwrap()
            .source,
        oneiron::VadAnnotationSource::ModelInference
    );

    let response = api_routes(server.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v1/core/turns/annotate?turn_id={}", turn.to_hex()))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("turn annotation read response body");
    let body: Value = serde_json::from_slice(&body).expect("annotation JSON body");
    assert_eq!(body["source"], Value::from("model_inference"));

    let response = api_routes(server.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/core/turns/annotate")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "turn_id": turn.to_hex(),
                        "message_id": message.to_hex(),
                        "source": "user_self_report",
                        "vad": {
                            "valence": -0.25,
                            "arousal": 0.25,
                            "dominance": 0.5,
                        },
                        "annotated_at": 201_u64,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("message annotate response body");
    let body: Value = serde_json::from_slice(&body).expect("annotation JSON body");
    assert_eq!(body["message_id"], Value::from(message.to_hex()));
    assert_eq!(body["source"], Value::from("user_self_report"));
    assert_eq!(
        server
            .vault
            .get_message_vad_annotation(&message)
            .unwrap()
            .unwrap()
            .source,
        oneiron::VadAnnotationSource::UserSelfReport
    );

    let response = api_routes(server.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/core/turns/annotate?turn_id={}&message_id={}",
                    turn.to_hex(),
                    message.to_hex()
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("message annotation read response body");
    let body: Value = serde_json::from_slice(&body).expect("annotation JSON body");
    assert_eq!(body["turn_id"], Value::from(turn.to_hex()));
    assert_eq!(body["message_id"], Value::from(message.to_hex()));
    assert_eq!(body["source"], Value::from("user_self_report"));
    assert_eq!(body["vad"]["valence"], Value::from(-0.25));
    assert_eq!(body["vad"]["arousal"], Value::from(0.25));
    assert_eq!(body["vad"]["dominance"], Value::from(0.5));
    assert_eq!(body["annotated_at"], Value::from(201_u64));
}

#[tokio::test]
async fn turn_vad_annotate_route_rejects_message_outside_supplied_turn() {
    let (_dir, server) = test_server();
    let requested_turn = oneiron::EntityId::now();
    let actual_turn = oneiron::EntityId::now();
    let message = oneiron::EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({"txt": "affect"})).expect("encode body");

    server
        .vault
        .put_entity(
            &requested_turn,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("put requested turn");
    // The message and the turn it really belongs to are witnessed together
    // (ONE-1686: the witness door is the only MESSAGE writer); the REQUESTED
    // turn above stays a bare TURN row, because the point of this fixture is
    // that the message was never in it.
    witness_vad_message_fixture(&server, &actual_turn, &message, "affect", 102);
    server
        .vault
        .put_edge(&message, oneiron::EdgeKind::ChildOf, &actual_turn, 1.0)
        .expect("link message to different turn");

    let response = api_routes(server.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/core/turns/annotate")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "turn_id": requested_turn.to_hex(),
                        "message_id": message.to_hex(),
                        "source": "model_inference",
                        "vad": {
                            "valence": 0.1,
                            "arousal": 0.2,
                            "dominance": 0.3,
                        },
                        "annotated_at": 250_u64,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("mismatch response body");
    let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("message_id")
    );
    assert_eq!(
        server.vault.get_message_vad_annotation(&message).unwrap(),
        None
    );

    let seeded = oneiron::VadAnnotation::new(
        oneiron::Vad {
            valence: 0.1,
            arousal: 0.2,
            dominance: 0.3,
        },
        oneiron::VadAnnotationSource::ModelInference,
        251,
    )
    .expect("annotation");
    server
        .vault
        .annotate_message_vad(&message, seeded)
        .expect("seed message annotation");

    let response = api_routes(server.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/core/turns/annotate?turn_id={}&message_id={}",
                    requested_turn.to_hex(),
                    message.to_hex()
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("mismatch read response body");
    let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("message_id")
    );
}

#[tokio::test]
async fn turn_vad_annotate_route_rejects_invalid_vad() {
    let (_dir, server) = test_server();
    let turn = oneiron::EntityId::now();
    let turn_body = rmp_serde::to_vec_named(&json!({
        "txt": "invalid turn affect",
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
            &turn_body,
        )
        .expect("put turn");

    let response = api_routes(server.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/core/turns/annotate")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "turn_id": turn.to_hex(),
                        "source": "user_self_report",
                        "vad": {
                            "valence": 0.0,
                            "arousal": -0.1,
                            "dominance": 0.5,
                        },
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("invalid VAD response body");
    let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("vad")
    );
    assert_eq!(server.vault.get_turn_vad_annotation(&turn).unwrap(), None);
}

#[test]
fn vad_annotation_core_error_maps_gate_rejection_to_invalid_state() {
    let error = vad_annotation_core_error(oneiron::Error::GateWriteRejected {
        outcome: "pending",
        reason_codes: vec!["gate.pending.source_trust"],
    });

    assert_eq!(error.status(), StatusCode::CONFLICT);
    assert_eq!(error.code(), ErrorCode::InvalidState);
    assert_eq!(
        error.details(),
        &ApiErrorDetails::InvalidState {
            state: Some("gate_write_rejected:pending:gate.pending.source_trust".to_owned()),
        }
    );
    assert!(
        error.message().contains("gate.pending.source_trust"),
        "message should expose the stable Gate reason code"
    );
}

#[test]
fn core_engine_error_maps_invalid_counterparty_contact_body_to_bad_request() {
    let error = core_engine_error(
        "core context-pack failed",
        oneiron::Error::InvalidCounterpartyContactBody("body failed validation"),
    );

    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert!(
        error
            .message()
            .contains("invalid counterparty contact body"),
        "message should expose the counterparty validation failure"
    );
}

#[test]
fn core_engine_error_maps_temporal_parse_errors_to_bad_request() {
    let error = core_engine_error(
        "core query failed",
        oneiron::Error::InvalidTemporalExpression(
            oneiron::temporal::TemporalExpressionParseError::Unsupported {
                expression: "last friday".to_owned(),
            },
        ),
    );

    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert!(
        error.message().contains("unsupported temporal expression"),
        "message should expose the temporal parse failure"
    );
}

#[test]
fn core_engine_error_maps_hosted_media_known_match_to_invalid_state() {
    let error = core_engine_error(
        "core ingest failed",
        oneiron::Error::HostedMediaHashMatchKnownMatch {
            provider: "unit-provider".into(),
            reference: "case-123".into(),
            path: "assets/known.bin".into(),
            content_hash: Box::new([0xAB; 32]),
        },
    );

    assert_eq!(error.status(), StatusCode::CONFLICT);
    assert_eq!(error.code(), ErrorCode::InvalidState);
    assert_eq!(
        error.details(),
        &ApiErrorDetails::InvalidState {
            state: Some("hosted_media_hash_match_known_match".to_owned()),
        }
    );
    assert!(error.message().contains("unit-provider"));
    assert!(error.message().contains("case-123"));
    assert!(error.message().contains("assets/known.bin"));
}

#[test]
fn core_engine_error_maps_invalid_skill_body_to_bad_request() {
    let error = core_engine_error(
        "core batch commit failed",
        oneiron::Error::InvalidSkillBody("provenance must be a non-empty MessagePack map"),
    );

    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert!(
        error.message().contains("invalid SKILL body"),
        "message should expose the SKILL validation failure"
    );
    assert!(
        error
            .message()
            .contains("provenance must be a non-empty MessagePack map"),
        "message should expose the specific SKILL validation detail"
    );
}

#[test]
fn core_engine_error_maps_agent_dispatch_failures_to_bad_request() {
    let id = oneiron::EntityId::from_bytes([0x71; 16]).expect("non-reserved fixture id");
    for error in [
        oneiron::Error::AgentNotDispatchable("agent definition not found"),
        oneiron::Error::InvalidAgentDispatchInput("input must decode as an agent dispatch map"),
        oneiron::Error::AgentDefinitionNotFound { id },
        oneiron::Error::AgentDefinitionDisabled { id },
    ] {
        let detail = error.to_string();
        let mapped = core_engine_error("core dispatch failed", error);

        assert_eq!(
            mapped.status(),
            StatusCode::BAD_REQUEST,
            "{detail}: dispatch validation/precondition failures are client-correctable"
        );
        assert_eq!(mapped.code(), ErrorCode::BadRequest, "{detail}");
        assert!(
            mapped.message().contains(&detail),
            "message should expose the dispatch failure detail: {detail}"
        );
    }
}

#[test]
fn core_engine_error_maps_invalid_task_body_to_bad_request() {
    let error = core_engine_error(
        "core batch commit failed",
        oneiron::Error::InvalidTaskBody("missing task role"),
    );

    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert!(
        error.message().contains("invalid TASK body"),
        "message should expose the TASK validation failure"
    );
    assert!(
        error.message().contains("missing task role"),
        "message should expose the specific TASK validation detail"
    );
}

#[tokio::test]
async fn context_pack_route_returns_pack_evidence_and_records_telemetry() {
    let (_dir, server) = test_server();
    let (batch_status, batch_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/batch",
            json!({
                "entities": [{
                    "entity_type": ENTITY_TYPE_TURN,
                    "learned_at": 500_u64,
                    "occurred_start": 500_u64,
                    "occurred_end": 500_u64,
                    "body": {
                        "txt": "public context pack evidence needle",
                        "spkr": "user",
                        "at": 500_u64
                    },
                    "text": [{ "field": "body", "value": "public context pack evidence needle" }]
                }]
            }),
        ),
    )
    .await;
    assert_eq!(batch_status, StatusCode::OK);
    let id = batch_body["entities"][0]["id"]
        .as_str()
        .expect("written id")
        .to_owned();

    let (status, body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "evidence needle",
                "limit": 5,
                "depth": { "edge_hop": 1, "max_neighbors": 5 },
                "policy": {
                    "hydrate": true,
                    "include_edges": true,
                    "view": "full",
                    "boost_confidence": true
                },
                "time": { "occurred_start": 500_u64, "occurred_end": 500_u64 },
                "budget": {
                    "max_item_tokens": 64,
                    "retrieval": {
                        "claims": 0,
                        "turns": 1,
                        "summaries": 0,
                        "facets": 0,
                        "other": 0,
                        "selected_edges": 5
                    }
                }
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["results"][0]["id"], Value::from(id.clone()));
    assert_eq!(body["state"]["kind"], Value::from("ok"));
    assert_eq!(body["evidence"]["telemetry_persisted"], Value::from(true));
    assert_eq!(
        body["evidence"]["result_ids"],
        Value::Array(vec![Value::from(id.clone())])
    );
    assert_eq!(body["evidence"]["scores"][0]["result_id"], Value::from(id));
    assert_eq!(
        body["evidence"]["scores"][0]["access_factor"],
        Value::from(1.0),
        "HTTP score evidence must expose the applied neutral factor"
    );
    assert_eq!(
        body["evidence"]["scores"][0]["components"][0]["signal"],
        Value::from("text")
    );

    let runs = server.vault.retrieval_runs(1).expect("retrieval runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].run_id.to_hex(),
        body["evidence"]["retrieval_run_id"]
    );
    assert_eq!(runs[0].action, oneiron::store::RetrievalAction::ContextPack);
}

fn interlocutor_test_server() -> (tempfile::TempDir, Arc<SyncServer>) {
    test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    })
}

fn seed_counterparty_contact(
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

#[tokio::test]
async fn core_context_pack_owner_present_true_on_scoped_bearer_is_forbidden() {
    let (_dir, server) = interlocutor_test_server();
    let principal_ref = seeded_test_entity_id(0x1516_0001).to_hex();
    let request = json!({
        "query": "hallway",
        "interlocutors": { "owner_present": true }
    });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        body["error"]["details"]["requiredScope"],
        Value::from("interlocutors.owner_present")
    );
    assert!(
        body.get("results").is_none(),
        "nothing is assembled on the forbidden path"
    );
}

#[tokio::test]
async fn core_context_pack_owner_session_without_block_carries_no_interlocutors_field() {
    let (_dir, server) = interlocutor_test_server();
    seed_turn(&server, "owner alone regression needle");
    let request = json!({ "query": "regression needle", "limit": 3 });
    let (status, body) = owner_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("interlocutors").is_none(),
        "owner-grade auth with no block must stay byte-identical: {body:?}"
    );

    // The same request on a scope-narrowed token is NOT the owner-grade path:
    // a delegated credential resolves an interlocutor set and gets echoed
    // stamps even though it carries no principal_ref.
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("interlocutors").is_some(),
        "a scope-narrowed token is not owner-grade: {body:?}"
    );
}

#[tokio::test]
async fn core_context_pack_echoes_stamps_for_supplied_block_on_owner_session() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1516_0011);
    let contact_id = seeded_test_entity_id(0x1516_0012);
    seed_counterparty_contact(&server, contact_id, identity_ref, "kenji@example.com");

    let request = json!({
        "query": "hallway",
        "interlocutors": {
            "third_parties": [
                { "contact_ref": contact_id.to_hex() },
                {
                    "channel_identity_ref": identity_ref.to_hex(),
                    "counterparty": "stranger@example.com"
                },
                { "label": "unknown speaker 2", "claimed_owner": true }
            ]
        }
    });
    let (status, body) = owner_json(server, "POST", "/v1/core/context-pack", Some(&request)).await;
    assert_eq!(status, StatusCode::OK);
    let stamps = body["interlocutors"].as_array().expect("stamps echoed");
    assert_eq!(stamps.len(), 4);
    assert_eq!(stamps[0]["speaker"], Value::from("owner"));
    assert_eq!(stamps[0]["class"], Value::from("owner"));
    assert_eq!(stamps[0]["claims_not_instructions"], Value::from(false));
    assert_eq!(stamps[1]["speaker"], Value::from(contact_id.to_hex()));
    assert_eq!(stamps[1]["class"], Value::from("known_contact"));
    assert_eq!(stamps[1]["claims_not_instructions"], Value::from(true));
    assert_eq!(stamps[2]["speaker"], Value::from("stranger@example.com"));
    assert_eq!(stamps[2]["class"], Value::from("unknown"));
    assert_eq!(stamps[3]["speaker"], Value::from("unknown speaker 2"));
    assert_eq!(stamps[3]["class"], Value::from("unknown"));
    assert_eq!(stamps[3]["claims_not_instructions"], Value::from(true));
}

#[tokio::test]
async fn core_context_pack_owner_present_false_narrows_owner_session() {
    let (_dir, server) = interlocutor_test_server();
    let request = json!({
        "query": "hallway",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "label": "guest", "claimed_owner": true }]
        }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let stamps = body["interlocutors"].as_array().expect("stamps echoed");
    assert_eq!(stamps.len(), 1, "narrowing removes the owner entry");
    assert_eq!(stamps[0]["speaker"], Value::from("guest"));
    assert_eq!(stamps[0]["class"], Value::from("unknown"));
    assert_eq!(stamps[0]["claims_not_instructions"], Value::from(true));
}

#[tokio::test]
async fn core_context_pack_scoped_bearer_gets_implicit_interlocutor_echo() {
    let (_dir, server) = interlocutor_test_server();

    // Companion-style principal with no contact row -> one Unknown stamp
    // labeled with the principal hex.
    let unknown_principal = seeded_test_entity_id(0x1516_0021).to_hex();
    let request = json!({ "query": "hallway" });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &unknown_principal,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let stamps = body["interlocutors"].as_array().expect("implicit echo");
    assert_eq!(stamps.len(), 1);
    assert_eq!(stamps[0]["speaker"], Value::from(unknown_principal.clone()));
    assert_eq!(stamps[0]["class"], Value::from("unknown"));
    assert_eq!(stamps[0]["claims_not_instructions"], Value::from(true));

    // A principal whose entity id IS a contact row -> KnownContact stamp.
    let identity_ref = seeded_test_entity_id(0x1516_0022);
    let contact_principal = seeded_test_entity_id(0x1516_0023);
    seed_counterparty_contact(
        &server,
        contact_principal,
        identity_ref,
        "kenji@example.com",
    );
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &contact_principal.to_hex(),
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let stamps = body["interlocutors"].as_array().expect("implicit echo");
    assert_eq!(stamps.len(), 1);
    assert_eq!(
        stamps[0]["speaker"],
        Value::from(contact_principal.to_hex())
    );
    assert_eq!(stamps[0]["class"], Value::from("known_contact"));
    assert_eq!(stamps[0]["claims_not_instructions"], Value::from(true));
}

#[tokio::test]
async fn core_context_pack_scoped_bearer_merges_principal_with_supplied_block() {
    // N14 (shape level, RATIFY-20260710 R8 merge-always): a scoped token
    // naming a wider-scoped contact gets BOTH operands into the resolved
    // set — the supplied block can never displace the principal party.
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1516_0031);
    let wider_contact = seeded_test_entity_id(0x1516_0032);
    seed_counterparty_contact(&server, wider_contact, identity_ref, "wider@example.com");
    let principal_ref = seeded_test_entity_id(0x1516_0033).to_hex();

    let request = json!({
        "query": "hallway",
        "interlocutors": {
            "third_parties": [{ "contact_ref": wider_contact.to_hex() }]
        }
    });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let stamps = body["interlocutors"].as_array().expect("merged echo");
    assert_eq!(
        stamps.len(),
        2,
        "both the supplied contact and the implicit principal party resolve"
    );
    assert_eq!(stamps[0]["speaker"], Value::from(wider_contact.to_hex()));
    assert_eq!(stamps[0]["class"], Value::from("known_contact"));
    assert_eq!(stamps[1]["speaker"], Value::from(principal_ref));
    assert_eq!(stamps[1]["class"], Value::from("unknown"));
    assert!(
        stamps.iter().all(|stamp| stamp["class"] != "owner"),
        "no owner entry on a scoped token"
    );
}

#[tokio::test]
async fn core_context_pack_rejects_malformed_interlocutor_parties() {
    let (_dir, server) = interlocutor_test_server();
    let contact_hex = seeded_test_entity_id(0x1516_0041).to_hex();

    let cases = [
        (
            json!({ "contact_ref": contact_hex, "label": "guest" }),
            "interlocutors.third_parties[0]",
        ),
        (json!({}), "interlocutors.third_parties[0]"),
        (
            json!({ "contact_ref": "not-hex" }),
            "interlocutors.third_parties[0].contact_ref",
        ),
        (
            json!({ "channel_identity_ref": contact_hex }),
            "interlocutors.third_parties[0]",
        ),
        (
            json!({ "channel_identity_ref": contact_hex, "counterparty": "  " }),
            "interlocutors.third_parties[0].counterparty",
        ),
        (
            json!({ "channel_identity_ref": contact_hex, "counterparty": " kenji@example.com " }),
            "interlocutors.third_parties[0].counterparty",
        ),
        (
            json!({ "channel_identity_ref": contact_hex, "counterparty": "k".repeat(513) }),
            "interlocutors.third_parties[0].counterparty",
        ),
        (
            json!({ "label": "   " }),
            "interlocutors.third_parties[0].label",
        ),
        (
            json!({ "label": "l".repeat(513) }),
            "interlocutors.third_parties[0].label",
        ),
        (
            json!({ "contact_ref": contact_hex, "claimed_owner": true }),
            "interlocutors.third_parties[0].claimed_owner",
        ),
    ];
    for (party, expected_field) in cases {
        let request = json!({
            "query": "hallway",
            "interlocutors": { "third_parties": [party.clone()] }
        });
        let (status, body) = core_json(
            server.clone(),
            "POST",
            "/v1/core/context-pack",
            "core:read",
            Some(&request),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "party {party:?}");
        assert_error_envelope(&body, "BAD_REQUEST");
        assert_eq!(
            body["error"]["details"]["field"],
            Value::from(expected_field),
            "party {party:?}"
        );
    }
}

// ─── OF-365 disclosure clamp HTTP red-team suite (ONE-1517) ─────────────────

fn seed_text_turn(server: &SyncServer, text: &str) -> oneiron::EntityId {
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

fn seed_disclosure_scope(
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

#[tokio::test]
async fn core_context_pack_owner_absent_happy_path_clamps_to_scope() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1517_0001);
    let contact_principal = seeded_test_entity_id(0x1517_0002);
    seed_counterparty_contact(
        &server,
        contact_principal,
        identity_ref,
        "kenji@example.com",
    );
    let party = seed_text_turn(&server, "hanami party planning needle17");
    let diary = seed_text_turn(&server, "private diary entry needle17");
    seed_disclosure_scope(&server, contact_principal, vec![party]);

    // Scoped bearer whose principal IS the contact row; no block (N13 shape
    // with a real scope). AbsenceClamp admits only the allowlisted party.
    let request = json!({ "query": "needle17", "limit": 10 });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &contact_principal.to_hex(),
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["disclosure"]["mode"], Value::from("absence_clamp"));
    assert!(
        body["disclosure"]["notice"].is_null(),
        "notice is Some iff supervised"
    );
    assert!(
        body["disclosure"]["clamped_out"].as_u64().unwrap_or(0) > 0,
        "candidate sweep counted removals: {body:?}"
    );
    let result_ids: Vec<&str> = body["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|entity| entity["id"].as_str())
        .collect();
    assert!(result_ids.contains(&party.to_hex().as_str()));
    assert!(
        !result_ids.contains(&diary.to_hex().as_str()),
        "out-of-scope Tier-B memory absent from the assembled context"
    );
    let neighbors = body["neighbors"].as_array().expect("neighbors");
    assert!(neighbors.is_empty());
    let stamps = body["disclosure"]["interlocutors"]
        .as_array()
        .expect("stamps");
    assert_eq!(stamps.len(), 1);
    assert_eq!(stamps[0]["class"], Value::from("known_contact"));
}

#[tokio::test]
async fn core_context_pack_supervised_path_carries_notice_and_tier_b() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1517_0011);
    let contact_id = seeded_test_entity_id(0x1517_0012);
    seed_counterparty_contact(&server, contact_id, identity_ref, "kenji@example.com");
    let diary = seed_text_turn(&server, "tier b memory needle18");

    let request = json!({
        "query": "needle18",
        "interlocutors": {
            "owner_present": true,
            "third_parties": [{ "contact_ref": contact_id.to_hex() }]
        }
    });
    // Supervised mode requires an owner-grade credential: `owner_present:
    // true` is a 403 on any narrowed token.
    let (status, body) = owner_json(server, "POST", "/v1/core/context-pack", Some(&request)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["disclosure"]["mode"], Value::from("supervised"));
    let notice = body["disclosure"]["notice"].as_str().expect("notice");
    assert!(
        notice.starts_with(
            "Others present: kenji@example.com (known_contact, first contact: user_introduction)"
        ),
        "pinned template: {notice}"
    );
    assert!(notice.ends_with(
        "Don't volunteer personal or sensitive information; if asked about private matters, \
         defer to the owner."
    ));
    let diary_id = diary.to_hex();
    let found = body["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|entity| entity["id"].as_str())
        .any(|id| id == diary_id);
    assert!(found, "supervised mode keeps Tier B present");
}

#[tokio::test]
async fn core_context_pack_n4_spoofed_owner_claim_stays_absence_clamped() {
    let (_dir, server) = interlocutor_test_server();
    let diary = seed_text_turn(&server, "tier b memory needle19");

    // Owner-grade auth narrows itself away; the only party is a spoofed
    // "it's me" claim. The claim is a label, never authority (I3/I4).
    let request = json!({
        "query": "needle19",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "label": "it's me", "claimed_owner": true }]
        }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["disclosure"]["mode"], Value::from("absence_clamp"));
    let stamps = body["disclosure"]["interlocutors"]
        .as_array()
        .expect("stamps");
    assert_eq!(stamps.len(), 1);
    assert_eq!(stamps[0]["speaker"], Value::from("it's me"));
    assert_eq!(stamps[0]["class"], Value::from("unknown"));
    assert!(
        body["results"].as_array().expect("results").is_empty(),
        "unknown party gets the deny-all scope: {diary:?} must not surface"
    );
}

#[tokio::test]
async fn core_context_pack_n5_voice_session_seam_cannot_widen() {
    // The ILD-3 roster seam is accepted but inert: a voice_session_ref with
    // no session owner resolves to no roster entries and stays AbsenceClamp.
    // The enrolled-print corroboration case (owner_print_matched) lands with
    // ONE-1518 and can never mint an Owner entry by construction.
    let (_dir, server) = interlocutor_test_server();
    seed_text_turn(&server, "tier b memory needle20");

    let request = json!({
        "query": "needle20",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "label": "speaker 1", "claimed_owner": false }],
            "voice_session_ref": "call-123"
        }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["disclosure"]["mode"], Value::from("absence_clamp"));
    assert!(body["results"].as_array().expect("results").is_empty());
}

#[tokio::test]
async fn core_context_pack_n9_scope_smuggling_members_are_ignored() {
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1517_0021);
    let contact_id = seeded_test_entity_id(0x1517_0022);
    seed_counterparty_contact(&server, contact_id, identity_ref, "kenji@example.com");
    let party = seed_text_turn(&server, "party event needle21");
    let diary = seed_text_turn(&server, "private diary needle21");
    seed_disclosure_scope(&server, contact_id, vec![party]);

    let clean = json!({
        "query": "needle21",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "contact_ref": contact_id.to_hex() }]
        }
    });
    // No request field can name scope entities; smuggled members fall to
    // serde's ignored-unknown-fields floor and change nothing.
    let smuggled = json!({
        "query": "needle21",
        "interlocutors": {
            "owner_present": false,
            "third_parties": [{ "contact_ref": contact_id.to_hex() }],
            "scope": { "entities": [diary.to_hex()] },
            "entities": [diary.to_hex()]
        }
    });
    let (clean_status, clean_body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&clean),
    )
    .await;
    let (smuggled_status, smuggled_body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&smuggled),
    )
    .await;
    assert_eq!(clean_status, StatusCode::OK);
    assert_eq!(smuggled_status, StatusCode::OK);
    let scrub = |mut body: Value| {
        // Retrieval run ids and query timings differ per request; everything
        // else must match.
        body["evidence"]["retrieval_run_id"] = Value::Null;
        body["stats"]["query_time_us"] = Value::Null;
        body
    };
    assert_eq!(
        scrub(clean_body),
        scrub(smuggled_body),
        "smuggled scope members must not change the assembly"
    );
}

#[tokio::test]
async fn core_context_pack_n13_scoped_token_defaults_to_absence_clamp() {
    let (_dir, server) = interlocutor_test_server();
    let diary = seed_text_turn(&server, "tier b memory needle22");
    let principal_ref = seeded_test_entity_id(0x1517_0031).to_hex();

    let request = json!({ "query": "needle22", "limit": 10 });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["disclosure"]["mode"],
        Value::from("absence_clamp"),
        "principal_ref tokens with no block assemble under AbsenceClamp"
    );
    let result_ids: Vec<&str> = body["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|entity| entity["id"].as_str())
        .collect();
    assert!(
        !result_ids.contains(&diary.to_hex().as_str()),
        "N1-style assertion: Tier-B memory absent for an unknown principal"
    );
    assert!(result_ids.is_empty());
}

#[tokio::test]
async fn core_context_pack_n14_wider_scoped_contact_cannot_widen_scoped_token() {
    // CONTENT-level N14 (RATIFY-20260710 R8): a bearer scoped to X naming a
    // wider-scoped contact Y resolves {X ∩ Y} — no Tier-B data readable via
    // the wider-scoped contact.
    let (_dir, server) = interlocutor_test_server();
    let identity_ref = seeded_test_entity_id(0x1517_0041);
    let wider_contact = seeded_test_entity_id(0x1517_0042);
    seed_counterparty_contact(&server, wider_contact, identity_ref, "wider@example.com");
    let party = seed_text_turn(&server, "party event needle23");
    seed_disclosure_scope(&server, wider_contact, vec![party]);
    // Principal X has no contact row: it contributes the deny-all scope.
    let principal_ref = seeded_test_entity_id(0x1517_0043).to_hex();

    let request = json!({
        "query": "needle23",
        "interlocutors": {
            "third_parties": [{ "contact_ref": wider_contact.to_hex() }]
        }
    });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["disclosure"]["mode"], Value::from("absence_clamp"));
    let stamps = body["disclosure"]["interlocutors"]
        .as_array()
        .expect("stamps");
    assert_eq!(stamps.len(), 2, "both operands enter the resolved set");
    assert!(
        body["results"].as_array().expect("results").is_empty(),
        "deny-all ∩ wider scope = nothing readable: {body:?}"
    );
}

#[tokio::test]
async fn core_context_pack_owner_auth_without_block_carries_no_disclosure_field() {
    let (_dir, server) = interlocutor_test_server();
    seed_text_turn(&server, "owner alone regression needle24");
    let request = json!({ "query": "needle24", "limit": 3 });
    let (status, body) = owner_json(server, "POST", "/v1/core/context-pack", Some(&request)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("disclosure").is_none(),
        "owner-grade auth with no block stays byte-identical: {body:?}"
    );
    assert!(
        !body["results"].as_array().expect("results").is_empty(),
        "owner-alone behavior unchanged"
    );
}

/// P1 regression (`l1-r2-verdicts`): a v2 token narrowed by SCOPE ALONE — no
/// `principal_ref` — is a delegated read-only credential, not the owner.
///
/// The old `is_owner_session` predicate read only `principal_ref.is_none()`,
/// so this token classified as owner-present: `resolve_core_interlocutor_set`
/// returned `None` and NO absence clamp applied, handing a delegated bearer
/// the owner's full Tier-B vault. Both halves of the fix are pinned here: the
/// clamp now applies, and `owner_present: true` is refused.
#[tokio::test]
async fn core_context_pack_scope_only_token_is_clamped_and_cannot_assert_owner_present() {
    let (_dir, server) = interlocutor_test_server();
    let diary = seed_text_turn(&server, "tier b memory needle25");
    let request = json!({ "query": "needle25", "limit": 10 });

    // The owner-grade credential still reads its own vault, unclamped.
    let (status, owner_body) = owner_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(owner_body.get("disclosure").is_none());
    let diary_id = diary.to_hex();
    assert!(
        owner_body["results"]
            .as_array()
            .expect("results")
            .iter()
            .filter_map(|entity| entity["id"].as_str())
            .any(|id| id == diary_id),
        "owner-grade verdict unchanged: {owner_body:?}"
    );

    // The same request on `scope=core:read` with NO principal_ref takes the
    // absence clamp. No party is identified, so the deny-all scope applies.
    let (status, body) = core_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["disclosure"]["mode"],
        Value::from("absence_clamp"),
        "an unbound scoped token must receive the clamp: {body:?}"
    );
    assert!(
        body["results"].as_array().expect("results").is_empty(),
        "Tier-B memory must not reach a delegated read-only token: {body:?}"
    );

    // ...and it cannot buy the supervised path back by asserting presence.
    let asserted = json!({
        "query": "needle25",
        "limit": 10,
        "interlocutors": { "owner_present": true }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&asserted),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&body, "FORBIDDEN");
    assert_eq!(
        body["error"]["details"]["requiredScope"],
        Value::from("interlocutors.owner_present")
    );
}

#[tokio::test]
async fn core_context_pack_caps_the_third_parties_block() {
    let (_dir, server) = interlocutor_test_server();

    let party = |index: usize| json!({ "label": format!("guest {index}") });
    let at_cap: Vec<Value> = (0..MAX_INTERLOCUTOR_THIRD_PARTIES).map(party).collect();
    let over_cap: Vec<Value> = (0..=MAX_INTERLOCUTOR_THIRD_PARTIES).map(party).collect();

    let request = json!({
        "query": "hallway",
        "interlocutors": { "third_parties": at_cap }
    });
    let (status, body) = owner_json(
        server.clone(),
        "POST",
        "/v1/core/context-pack",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "at-cap block accepted: {body:?}");
    assert_eq!(
        body["interlocutors"].as_array().map(Vec::len),
        Some(MAX_INTERLOCUTOR_THIRD_PARTIES + 1),
        "owner stamp plus every supplied party"
    );

    let request = json!({
        "query": "hallway",
        "interlocutors": { "third_parties": over_cap }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        body["error"]["details"]["field"],
        Value::from("interlocutors.third_parties")
    );
}

#[tokio::test]
async fn core_context_pack_dangling_contact_ref_fails_loudly() {
    let (_dir, server) = interlocutor_test_server();
    let request = json!({
        "query": "hallway",
        "interlocutors": {
            "third_parties": [
                { "contact_ref": seeded_test_entity_id(0x1516_0051).to_hex() }
            ]
        }
    });
    let (status, body) = core_json(
        server,
        "POST",
        "/v1/core/context-pack",
        "core:read",
        Some(&request),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_error_envelope(&body, "NOT_FOUND");
}

#[tokio::test]
async fn context_pack_v4_memory_board_enforces_slots_and_carries_session_rag() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal_id = seeded_test_entity_id(0x1741_0001);
    let principal_ref = principal_id.to_hex();
    let turn_a = seeded_test_entity_id(0x0012_6301);
    let turn_b = seeded_test_entity_id(0x0012_6302);
    let summary = seeded_test_entity_id(0x0012_6303);
    let body_a = rmp_serde::to_vec_named(&json!({
        "txt": "eiri v4 needle alpha",
        "spkr": "user",
        "at": 700_u64
    }))
    .expect("encode turn body");
    let body_b = rmp_serde::to_vec_named(&json!({
        "txt": "eiri v4 needle beta",
        "spkr": "assistant",
        "at": 701_u64
    }))
    .expect("encode turn body");
    let summary_body = rmp_serde::to_vec_named(&json!({
        "txt": "eiri v4 needle summary"
    }))
    .expect("encode summary body");

    server
        .vault
        .batch()
        .put(
            &turn_a,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 700,
                end: 700,
            },
            700,
            &body_a,
        )
        .text(&turn_a, &[("body", "eiri v4 needle alpha")])
        .put(
            &turn_b,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 701,
                end: 701,
            },
            701,
            &body_b,
        )
        .text(&turn_b, &[("body", "eiri v4 needle beta")])
        .put(
            &summary,
            oneiron::registry::ENTITY_TYPE_SUMMARY,
            oneiron::TimeRange {
                start: 702,
                end: 702,
            },
            702,
            &summary_body,
        )
        .text(&summary, &[("body", "eiri v4 needle summary")])
        .commit()
        .expect("seed context v4 rows");
    // Principal-scoped v1 context packs assemble under AbsenceClamp, so the
    // ported caller is a known contact whose disclosure scope contains the
    // rows exercised by this memory-board contract.
    seed_counterparty_contact(
        &server,
        principal_id,
        seeded_test_entity_id(0x1741_0005),
        "eiri-session-api@example.com",
    );
    seed_disclosure_scope(&server, principal_id, vec![turn_a, turn_b, summary]);

    let persona_ref = seeded_test_entity_id(0x1324_0001).to_hex();
    let request = json!({
        "query": "eiri v4 needle",
        "limit": 10,
        "context_version": "v4",
        "memory_board": {
            "slots": {
                "claims": 0,
                "turns": 1,
                "summaries": 1,
                "facets": 0,
                "companions": 0,
                "other": 0
            }
        },
        "session_rag": { "session_id": principal_ref.clone() },
        "companion": { "persona_ref": persona_ref.clone() }
    });

    let eiri_request = || {
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        )
    };

    let (status, first_body) = route_json(server.clone(), eiri_request()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first_body["context_version"], Value::from("v4"));
    assert_eq!(first_body["memory_board"]["version"], Value::from("v4"));
    assert_eq!(
        first_body["memory_board"]["budget"]["turns"],
        Value::from(1)
    );
    assert_eq!(
        first_body["memory_board"]["budget"]["summaries"],
        Value::from(1)
    );
    let rows = first_body["memory_board"]["rows"]
        .as_array()
        .expect("memory board rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["row_index"], Value::from(0));
    assert_eq!(rows[0]["slot"], Value::from("turns"));
    assert_eq!(rows[1]["row_index"], Value::from(1));
    assert_eq!(rows[1]["slot"], Value::from("summaries"));
    assert_eq!(
        first_body["memory_board"]["companion"]["caller"],
        Value::from(principal_ref.clone())
    );
    assert_eq!(
        first_body["memory_board"]["companion"]["persona_ref"],
        Value::from(persona_ref)
    );
    assert_eq!(
        first_body["memory_board"]["companion"]["scope"],
        Value::from("neutral")
    );
    assert_eq!(
        first_body["memory_board"]["companion"]["scope_source"],
        Value::from("neutral_default")
    );
    assert_eq!(
        first_body["memory_board"]["companion"]["expression"],
        Value::from("professional")
    );
    assert_eq!(
        first_body["session_rag"]["session_id"],
        Value::from(principal_ref.clone())
    );
    assert_eq!(first_body["session_rag"]["revision"], Value::from(1));
    assert_eq!(first_body["session_rag"]["query_count"], Value::from(1));
    assert!(
        first_body["session_rag"]["last_retrieval_run_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    assert_eq!(
        first_body["session_rag"]["last_result_ids"]
            .as_array()
            .map(Vec::len),
        first_body["results"].as_array().map(Vec::len)
    );

    let (status, second_body) = route_json(server.clone(), eiri_request()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second_body["session_rag"]["revision"], Value::from(2));
    assert_eq!(second_body["session_rag"]["query_count"], Value::from(2));

    let resume_request = Request::builder()
        .method("POST")
        .uri("/api/companion/resume")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, owner_bearer())
        .header("x-oneiron-caller", principal_ref.as_str())
        .body(Body::from("{}"))
        .expect("resume request");
    let (status, resume_body) = route_json(server, resume_request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        resume_body["session"]["rag_state"]["session_id"],
        Value::from(principal_ref)
    );
    assert_eq!(
        resume_body["session"]["rag_state"]["query_count"],
        Value::from(2)
    );
}

#[tokio::test]
async fn context_pack_v4_asset_text_consumer_hydrates_asset_text_by_ref() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let asset_text = seeded_test_entity_id(0x1482_0001);
    // ONE-1517: principal_ref tokens assemble under AbsenceClamp, so the
    // consumer principal is a known contact whose disclosure scope
    // allowlists the ASSET_TEXT entity — the intended scoped-read shape.
    let principal_contact = seeded_test_entity_id(0x1482_0002);
    let principal_ref = principal_contact.to_hex();
    seed_counterparty_contact(
        &server,
        principal_contact,
        seeded_test_entity_id(0x1482_0003),
        "asset-consumer@example.com",
    );
    let needle = "one1482 text-only asset transcript";
    let body = rmp_serde::to_vec_named(&json!({
        "txt": needle,
        "source_asset_ref": "asset-source-one1482"
    }))
    .expect("encode ASSET_TEXT body");
    server
        .vault
        .batch()
        .put(
            &asset_text,
            oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
            oneiron::TimeRange {
                start: 1482,
                end: 1482,
            },
            1482,
            &body,
        )
        .text(&asset_text, &[("body", needle)])
        .commit()
        .expect("seed ASSET_TEXT");
    seed_disclosure_scope(&server, principal_contact, vec![asset_text]);

    let request = json!({
        "query": needle,
        "limit": 3,
        "view": "full",
        "context_version": "v4",
        "memory_board": {
            "slots": {
                "claims": 0,
                "turns": 0,
                "summaries": 0,
                "facets": 0,
                "companions": 0,
                "other": 1
            }
        }
    });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let row = &body["memory_board"]["rows"][0];
    assert_eq!(
        row["entity_type"],
        Value::from(oneiron::registry::ENTITY_TYPE_ASSET_TEXT)
    );
    let asset_ref = row["asset_ref"]
        .as_str()
        .expect("ASSET_TEXT row exposes a core hydrate ref");

    let hydrate_request = json!({
        "ref": asset_ref,
        "view": "full"
    });
    let (status, hydrated) = core_json(
        server,
        "POST",
        "/v1/core/hydrate",
        "core:read",
        Some(&hydrate_request),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hydrated["status"], Value::from("live"));
    assert_eq!(
        hydrated["entity_type"],
        Value::from(oneiron::registry::ENTITY_TYPE_ASSET_TEXT)
    );
    assert_eq!(hydrated["item"]["txt"], Value::from(needle));
}

#[tokio::test]
async fn context_pack_v4_companion_resolves_warm_personal_relationship_without_private_note() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let private_note = "private warm companion note one1266";
    let person_ref = seeded_test_entity_id(0x1266_0001);
    let persona_ref = seeded_test_entity_id(0x1266_0002);
    let companion_id = seeded_test_entity_id(0x1266_0003);
    let turn_id = seeded_test_entity_id(0x1266_0004);
    let actor_ref = seeded_test_entity_id(0x1266_0005);
    let principal_ref = seeded_test_entity_id(0x1266_0006);
    let grant_id = seeded_test_entity_id(0x1266_0007);

    let record = oneiron::CompanionRecord::relationship(
        oneiron::CompanionScope::personal(person_ref),
        person_ref,
        persona_ref,
        oneiron::companion_value_from_json(&json!({ "note": private_note }))
            .expect("companion value"),
        oneiron::CompanionProvenance::new(
            actor_ref,
            oneiron::EdgeActorClass::Agent,
            oneiron::ClaimSource::UserStated,
            oneiron::ClaimApprovalStatus::Approved,
            oneiron::companion_value_from_json(&json!({ "source": "test" }))
                .expect("provenance value"),
        ),
        oneiron::CompanionExportClassification::LocalOnly,
    );
    server
        .vault
        .create_companion_record(&companion_id, &record, 10)
        .expect("create companion record");
    let turn_body = json!({ "txt": "warm companion route needle" });
    let turn_data = rmp_serde::to_vec_named(&turn_body).expect("encode turn body");
    server
        .vault
        .batch()
        .put(
            &turn_id,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 11, end: 11 },
            11,
            &turn_data,
        )
        .text(&turn_id, &[("body", "warm companion route needle")])
        .commit()
        .expect("seed turn");

    let core_request_body = json!({
        "query": "warm companion route needle",
        "context_version": "v4",
        "memory_board": { "slots": { "turns": 1, "companions": 0, "other": 0 } },
        "companion": {
            "person_ref": person_ref.to_hex(),
            "persona_ref": persona_ref.to_hex(),
            "expression": "warm"
        }
    });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref.to_hex(),
            Some(&core_request_body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let companion = &body["memory_board"]["companion"];
    assert_eq!(companion["scope"], Value::from("neutral"));
    assert_eq!(companion["scope_source"], Value::from("neutral_default"));
    assert_eq!(companion["expression"], Value::from("warm"));
    assert!(
        !serde_json::to_string(&body)
            .expect("response serializes")
            .contains(private_note),
        "unauthorized core context-pack must not leak companion relationship metadata"
    );

    let grant =
        oneiron::AccessGrant::companion_profile_read(principal_ref, person_ref, persona_ref, 12);
    server
        .vault
        .create_access_grant(&grant_id, &grant)
        .expect("create profile grant");
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref.to_hex(),
            Some(&core_request_body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let companion = &body["memory_board"]["companion"];
    assert_eq!(companion["scope"], Value::from("personal"));
    assert_eq!(
        companion["scope_source"],
        Value::from("relationship_record")
    );
    assert_eq!(companion["expression"], Value::from("warm"));
    assert_eq!(companion["person_ref"], Value::from(person_ref.to_hex()));
    assert_eq!(companion["persona_ref"], Value::from(persona_ref.to_hex()));
    assert!(
        !serde_json::to_string(&body)
            .expect("response serializes")
            .contains(private_note),
        "authorized core context-pack must not leak private register notes"
    );

    let invalid_request = json!({
        "query": "warm companion route needle",
        "context_version": "v4",
        "companion": {
            "person_ref": person_ref.to_hex(),
            "persona_ref": persona_ref.to_hex(),
            "expression": "future_closed"
        }
    });
    let (status, body) = route_json(
        server.clone(),
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref.to_hex(),
            Some(&invalid_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("companion.expression")
    );
    assert!(
        !serde_json::to_string(&body)
            .expect("response serializes")
            .contains(private_note),
        "invalid companion request must not leak private register notes"
    );

    let opaque_request = json!({
        "query": "warm companion route needle",
        "context_version": "v4",
        "companion": {
            "person_ref": "opaque-person-ref",
            "persona_ref": "persona-route-test",
            "expression": "warm"
        }
    });
    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref.to_hex(),
            Some(&opaque_request),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let companion = &body["memory_board"]["companion"];
    assert_eq!(companion["scope"], Value::from("neutral"));
    assert_eq!(companion["scope_source"], Value::from("neutral_default"));
    assert_eq!(companion["expression"], Value::from("warm"));
    assert_eq!(companion["person_ref"], Value::from("opaque-person-ref"));
    assert_eq!(companion["persona_ref"], Value::from("persona-route-test"));
    assert!(
        !serde_json::to_string(&body)
            .expect("response serializes")
            .contains(private_note),
        "opaque companion refs must not leak private register notes"
    );
}

#[test]
fn eiri_memory_board_default_other_budget_matches_retrieval_budget() {
    let limit = 24;
    let selected_edges = 8;
    let retrieval_defaults = oneiron::ContextPackRetrievalBudget::from_limit(
        limit,
        oneiron::TokenAllocation::default(),
        selected_edges,
    );

    let defaults = eiri_memory_board_budget(None, limit, selected_edges);
    assert_eq!(defaults.companions, 0);
    assert_eq!(defaults.other, retrieval_defaults.other);
    assert_eq!(
        defaults.companions + defaults.other,
        retrieval_defaults.other
    );

    let split = eiri_memory_board_budget(
        Some(&EiriMemoryBoardControls {
            enabled: None,
            slots: Some(EiriMemoryBoardSlotControls {
                companions: Some(2),
                ..Default::default()
            }),
        }),
        limit,
        selected_edges,
    );
    assert_eq!(split.companions, 2);
    assert_eq!(split.other, retrieval_defaults.other.saturating_sub(2));
}

#[test]
fn eiri_session_rag_store_evicts_oldest_entries_at_capacity() {
    let mut store = EiriSessionRagStore::default();
    for index in 0..=EIRI_SESSION_RAG_STATE_MAX_ENTRIES {
        let key = format!("vault:{index}");
        let session_id = format!("session-{index}");
        store.current(key, &session_id);
    }

    assert_eq!(store.entries.len(), EIRI_SESSION_RAG_STATE_MAX_ENTRIES);
    assert!(!store.entries.contains_key("vault:0"));
    assert!(
        store
            .entries
            .contains_key(&format!("vault:{EIRI_SESSION_RAG_STATE_MAX_ENTRIES}"))
    );
}

#[test]
fn eiri_session_rag_store_caps_persisted_result_ids() {
    let mut store = EiriSessionRagStore::default();
    let pack = synthetic_context_pack(EIRI_SESSION_RAG_LAST_RESULT_IDS_MAX + 5);
    let evidence = CoreContextPackEvidence {
        telemetry_persisted: false,
        retrieval_run_id: Some("test-run".to_owned()),
        result_ids: Vec::new(),
        scores: Vec::new(),
    };

    let state = store.advance(
        "vault:caller".to_owned(),
        "vault:caller:session".to_owned(),
        "session",
        &pack,
        &evidence,
    );

    assert_eq!(
        state.last_result_ids.len(),
        EIRI_SESSION_RAG_LAST_RESULT_IDS_MAX
    );
    assert_eq!(state.last_result_ids[0], pack.results[0].id.to_hex());
    assert_eq!(
        state.last_result_ids[EIRI_SESSION_RAG_LAST_RESULT_IDS_MAX - 1],
        pack.results[EIRI_SESSION_RAG_LAST_RESULT_IDS_MAX - 1]
            .id
            .to_hex()
    );
}

#[tokio::test]
async fn context_pack_v4_rejects_oversized_session_id() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let principal_ref = seeded_test_entity_id(0x1741_0002).to_hex();
    let request = json!({
        "query": "eiri v4 needle",
        "context_version": "v4",
        "session_rag": {
            "session_id": "x".repeat(EIRI_SESSION_RAG_SESSION_ID_MAX_BYTES + 1)
        }
    });

    let (status, body) = route_json(
        server,
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            &principal_ref,
            Some(&request),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("session_rag.session_id")
    );
}

#[tokio::test]
async fn context_pack_v4_rejects_shared_principal_session_scope() {
    let (_dir, server) = test_server();
    let request = json!({
        "query": "eiri v4 needle",
        "context_version": "v4",
        "session_rag": { "session_id": "explicit-session" }
    });

    let (status, body) = route_json(
        server,
        json_request("POST", "/v1/core/context-pack", request),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("session_rag.session_id")
    );
}

#[tokio::test]
async fn context_pack_v4_session_state_is_partitioned_by_caller() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let caller_a = seeded_test_entity_id(0x1741_0003).to_hex();
    let caller_b = seeded_test_entity_id(0x1741_0004).to_hex();
    let request = json!({
        "query": "eiri v4 partition needle",
        "context_version": "v4",
        "session_rag": { "session_id": "shared-session-name" }
    });

    let eiri_request = |caller: &str| {
        core_request_with_principal_ref(
            "POST",
            "/v1/core/context-pack",
            "core:read",
            caller,
            Some(&request),
        )
    };

    let (status, caller_a_first) = route_json(server.clone(), eiri_request(&caller_a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        caller_a_first["memory_board"]["companion"]["caller"],
        Value::from("shared-session-name")
    );
    assert_eq!(
        caller_a_first["session_rag"]["session_id"],
        Value::from("shared-session-name")
    );
    assert_eq!(caller_a_first["session_rag"]["query_count"], Value::from(1));

    let (status, caller_a_second) = route_json(server.clone(), eiri_request(&caller_a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        caller_a_second["session_rag"]["query_count"],
        Value::from(2)
    );

    let (status, caller_b_first) = route_json(server.clone(), eiri_request(&caller_b)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(caller_b_first["session_rag"]["query_count"], Value::from(1));

    let resume_request = |caller: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/companion/resume")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, owner_bearer())
            .header("x-oneiron-caller", caller)
            .body(Body::from("{}"))
            .expect("resume request")
    };

    let (status, caller_a_resume) = route_json(server.clone(), resume_request(&caller_a)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        caller_a_resume["session"]["rag_state"]["session_id"],
        Value::from("shared-session-name")
    );
    assert_eq!(
        caller_a_resume["session"]["rag_state"]["query_count"],
        Value::from(2)
    );

    let (status, caller_b_resume) = route_json(server, resume_request(&caller_b)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        caller_b_resume["session"]["rag_state"]["session_id"],
        Value::from("shared-session-name")
    );
    assert_eq!(
        caller_b_resume["session"]["rag_state"]["query_count"],
        Value::from(1)
    );
}

#[tokio::test]
async fn context_pack_route_projects_json_response_controls() {
    let (_dir, server) = test_server();
    let long_text = format!("projection budget needle {}", "x".repeat(800));
    let (batch_status, batch_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/batch",
            json!({
                "entities": [{
                    "entity_type": ENTITY_TYPE_TURN,
                    "learned_at": 510_u64,
                    "occurred_start": 510_u64,
                    "occurred_end": 510_u64,
                    "body": {
                        "txt": long_text,
                        "spkr": "user",
                        "at": 510_u64,
                        "sess": "session-alpha",
                        "debug": "private"
                    },
                    "text": [{ "field": "body", "value": "projection budget needle" }]
                }]
            }),
        ),
    )
    .await;
    assert_eq!(batch_status, StatusCode::OK);
    let id = batch_body["entities"][0]["id"]
        .as_str()
        .expect("written id")
        .to_owned();

    let (summary_status, summary_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "summary" }
            }),
        ),
    )
    .await;
    assert_eq!(summary_status, StatusCode::OK);
    assert_eq!(summary_body["results"][0]["id"], Value::from(id.clone()));
    let fields = summary_body["results"][0]["fields"]
        .as_object()
        .expect("projected fields");
    assert!(fields.contains_key("txt"));
    assert!(!fields.contains_key("spkr"));
    assert!(!fields.contains_key("at"));
    assert!(!fields.contains_key("sess"));
    assert!(!fields.contains_key("debug"));

    let (budget_status, budget_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "full" },
                "budget": { "max_item_tokens": 48 }
            }),
        ),
    )
    .await;
    assert_eq!(budget_status, StatusCode::OK);
    assert_eq!(budget_body["results"][0]["id"], Value::from(id.clone()));
    let truncated = budget_body["results"][0]["fields"]["txt"]
        .as_str()
        .expect("truncated text field");
    assert!(truncated.contains("truncated"));
    assert_eq!(
        budget_body["stats"]["items_truncated"]["count"],
        Value::from(1)
    );
    assert_eq!(
        budget_body["evidence"]["result_ids"],
        Value::Array(vec![Value::from(id.clone())])
    );

    let (token_budget_status, token_budget_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "full" },
                "budget": { "tokenBudget": 16 }
            }),
        ),
    )
    .await;
    assert_eq!(token_budget_status, StatusCode::OK);
    assert_eq!(token_budget_body["results"], Value::Array(Vec::new()));
    assert_eq!(token_budget_body["neighbors"], Value::Array(Vec::new()));
    assert_eq!(
        token_budget_body["stats"]["items_dropped"]["count"],
        Value::from(1)
    );
    assert_eq!(
        token_budget_body["stats"]["items_dropped"]["reason"],
        Value::from("token_budget")
    );
    assert_eq!(
        token_budget_body["state"]["reason"],
        Value::from("filter_matched_none")
    );
    assert!(
        token_budget_body["state"]["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("budget.token_budget"))
    );
    assert_eq!(
        token_budget_body["evidence"]["result_ids"],
        Value::Array(Vec::new())
    );
    assert_eq!(
        token_budget_body["evidence"]["scores"],
        Value::Array(Vec::new())
    );

    let (dropped_status, dropped_body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "full" },
                "budget": { "max_item_tokens": 1 }
            }),
        ),
    )
    .await;
    assert_eq!(dropped_status, StatusCode::OK);
    assert_eq!(dropped_body["results"], Value::Array(Vec::new()));
    assert_eq!(dropped_body["neighbors"], Value::Array(Vec::new()));
    assert_eq!(dropped_body["state"]["kind"], Value::from("missing_data"));
    assert_eq!(
        dropped_body["state"]["reason"],
        Value::from("filter_matched_none")
    );
    assert!(
        dropped_body["state"]["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("budget.max_item_tokens"))
    );
    assert_eq!(
        dropped_body["empty"]["reason"],
        Value::from("filter_matched_none")
    );
    assert_eq!(
        dropped_body["stats"]["items_dropped"]["count"],
        Value::from(1)
    );
    assert_eq!(
        dropped_body["evidence"]["result_ids"],
        Value::Array(Vec::new())
    );
    assert_eq!(dropped_body["evidence"]["scores"], Value::Array(Vec::new()));

    let runs = server.vault.retrieval_runs(1).expect("retrieval runs");
    assert_eq!(runs.len(), 1);
    assert!(runs[0].result_ids.is_empty());
    assert!(runs[0].score_breakdown.is_empty());
    assert_eq!(runs[0].empty_reason.as_deref(), Some("ItemBudget"));
}

#[test]
fn context_pack_evidence_omits_run_id_without_finalized_telemetry() {
    let (_dir, server) = test_server();
    let evidence = core_context_pack_evidence(&server.vault, Some(oneiron::RetrievalRunId::now()))
        .expect("context-pack evidence");

    assert!(!evidence.telemetry_persisted);
    assert_eq!(evidence.retrieval_run_id, None);
    assert!(evidence.result_ids.is_empty());
    assert!(evidence.scores.is_empty());
}

#[test]
fn non_empty_query_trims_and_filters_blank_values() {
    assert_eq!(non_empty_query(None), None);
    assert_eq!(non_empty_query(Some("")), None);
    assert_eq!(non_empty_query(Some("   \n\t  ")), None);
    assert_eq!(
        non_empty_query(Some("  recent decisions  ")),
        Some("recent decisions")
    );
}

#[tokio::test]
async fn context_pack_route_rejects_malformed_controls() {
    let (_dir, server) = test_server();
    let (status, body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "recent decisions",
                "depth": { "edge_hop": oneiron::context_pack::MAX_EDGE_HOP + 1 }
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("depth.edge_hop")
    );
    assert!(
        error_envelope(&body)["message"]
            .as_str()
            .is_some_and(|message| message.contains("edge_hop")),
        "control error should name the malformed field: {body:?}"
    );

    let (status, body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "recent decisions",
                "edge_hop": oneiron::context_pack::MAX_EDGE_HOP + 1
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("edge_hop")
    );

    let (status, body) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "recent decisions",
                "max_neighbors": oneiron::context_pack::MAX_CONTEXT_NEIGHBORS + 1
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("max_neighbors")
    );

    let (status, body) = route_json(
        server,
        json_request(
            "POST",
            "/v1/core/context-pack",
            json!({
                "query": "recent decisions",
                "time": {
                    "since": 300_u64,
                    "learned_start": 100_u64,
                    "learned_end": 200_u64
                }
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&body, "BAD_REQUEST");
    assert_eq!(
        error_envelope(&body)["details"]["field"],
        Value::from("time.since")
    );
    assert!(
        error_envelope(&body)["message"]
            .as_str()
            .is_some_and(|message| message.contains("learned_end")),
        "control error should name the contradictory learned bound: {body:?}"
    );
}

#[tokio::test]
async fn text_search_response_shape_still_deserializes() {
    let (_dir, server) = test_server();

    let response = search_text(
        HeaderMap::new(),
        State(server),
        Ok(Query(TextSearchQuery {
            query: "shape guard".to_owned(),
            limit: 1,
            view: Some(View::Summary),
            count_mode: CountMode::Estimate,
        })),
    )
    .await
    .expect("text search response");

    let body = serde_json::to_vec(&response.0).expect("serialize response");
    let parsed: Value = serde_json::from_slice(&body).expect("deserialize response");
    assert_eq!(parsed["items"], Value::Array(Vec::new()));
    assert_eq!(parsed["meta"]["countMode"], Value::from("estimate"));
}

// ─── Surface events (ONE-1259) ───────────────────────────────────────────────

/// Seeds an agent-bound, active email identity the surface-event routes can
/// address, and returns the address plus its agent ref.
fn seed_surface_identity(server: &SyncServer, counter: u128, address: &str) -> String {
    let identity_ref = seeded_test_entity_id(counter);
    let agent_ref = seeded_test_entity_id(counter + 1);
    let mut identity = oneiron::channel_identity::ChannelIdentity::requested(
        "email",
        address,
        oneiron::channel_identity::ChannelIdentityShape::DedicatedAddress,
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

fn surface_event_body(address: &str, correlation_id: &str) -> Value {
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

#[tokio::test]
async fn v1_core_surface_event_submit_acks_with_202_and_is_queryable() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let address = "surface-ack@example.com";
    seed_surface_identity(&server, 0x1259_0001, address);
    let body = surface_event_body(address, "provider-ack-1");

    let (status, ack) = core_json(
        server.clone(),
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&body),
    )
    .await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(ack["correlation_id"], Value::from("provider-ack-1"));
    assert_eq!(ack["state"], Value::from("queued"));
    assert_eq!(ack["replayed"], Value::from(false));
    let attempt_ref = ack["attempt_ref"].as_str().expect("attempt ref").to_owned();
    assert_eq!(attempt_ref.len(), 32);
    assert!(
        attempt_ref
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "attempt ref must be lowercase hex: {attempt_ref}"
    );
    let status_path = ack["status_path"].as_str().expect("status path").to_owned();
    assert_eq!(status_path, "/v1/core/surface-events/provider-ack-1");

    // The advertised status path is queryable immediately.
    let (status, snapshot) =
        core_json(server.clone(), "GET", &status_path, "core:read", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(snapshot["correlation_id"], Value::from("provider-ack-1"));
    assert_eq!(snapshot["attempt_ref"], Value::from(attempt_ref.as_str()));
    assert_eq!(snapshot["state"], Value::from("queued"));
    assert_eq!(snapshot["attempt_count"], Value::from(0));
    // Nullable-required, mirroring the engine envelope: a client never has to
    // tell "no error" apart from "field absent from this build".
    assert_eq!(
        snapshot.get("last_error"),
        Some(&Value::Null),
        "last_error is present and null while the row has no error"
    );
    assert!(snapshot["created_at"].as_u64().is_some());
}

#[tokio::test]
async fn v1_core_surface_event_replay_returns_the_original_attempt() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let address = "surface-replay@example.com";
    seed_surface_identity(&server, 0x1259_0010, address);
    let body = surface_event_body(address, "provider-replay-1");

    let (first_status, first) = core_json(
        server.clone(),
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&body),
    )
    .await;
    assert_eq!(first_status, StatusCode::ACCEPTED);
    assert_eq!(first["replayed"], Value::from(false));

    // A resubmission under the same correlation id is admitted (202), not
    // conflicted, and resolves to the same durable attempt.
    let (second_status, second) = core_json(
        server.clone(),
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&body),
    )
    .await;
    assert_eq!(second_status, StatusCode::ACCEPTED);
    assert_eq!(second["replayed"], Value::from(true));
    assert_eq!(second["attempt_ref"], first["attempt_ref"]);
    assert_eq!(second["accepted_at"], first["accepted_at"]);

    // The ack and the status snapshot describe one attempt, so the admission
    // timestamp reads the same on both endpoints. (The engine test carries the
    // clock-separated proof; there is no clock seam at this layer to inject.)
    let (status_code, snapshot) = core_json(
        server,
        "GET",
        "/v1/core/surface-events/provider-replay-1",
        "core:read",
        None,
    )
    .await;
    assert_eq!(status_code, StatusCode::OK);
    assert_eq!(snapshot["created_at"], first["accepted_at"]);
}

#[tokio::test]
async fn v1_core_surface_event_admits_interactions_and_long_correlation_ids() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let address = "surface-interaction@example.com";
    seed_surface_identity(&server, 0x1259_0020, address);

    let long_correlation_id = format!("provider-{}", "y".repeat(200));
    let mut body = surface_event_body(address, &long_correlation_id);
    body["source"] = json!({ "app": "telegram", "user_ref": "telegram:user:77" });
    body["action"] =
        json!({ "kind": "interaction", "interaction": "reaction", "target_ref": "msg-1" });
    body["correlation_id"] = Value::from(long_correlation_id.as_str());

    let (status, ack) = core_json(
        server.clone(),
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&body),
    )
    .await;

    // The public correlation id survives verbatim even though the queue's run
    // id folds to a digest.
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(
        ack["correlation_id"],
        Value::from(long_correlation_id.as_str())
    );

    let (status, snapshot) = core_json(
        server.clone(),
        "GET",
        ack["status_path"].as_str().expect("status path"),
        "core:read",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(snapshot["attempt_ref"], ack["attempt_ref"]);
    assert_eq!(snapshot["state"], Value::from("queued"));
}

#[tokio::test]
async fn v1_core_surface_event_rejects_unroutable_identity_without_queueing() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    seed_surface_identity(&server, 0x1259_0030, "surface-known@example.com");
    let body = surface_event_body("surface-unknown@example.com", "provider-reject-1");

    let (status, receipt) = core_json(
        server.clone(),
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&body),
    )
    .await;

    // The body is the pinned route receipt, not an error envelope carrying a
    // stringified reason: an adapter has to tell a wrong address from an
    // unbound identity from one that stopped accepting inbound, and act
    // differently on each.
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        receipt["rejection_reason"],
        Value::from("unknown_receiving_identity")
    );
    assert_eq!(receipt["outcome"], Value::from("rejected"));
    assert_eq!(
        receipt["receipt_kind"],
        Value::from("inbound_surface_event_route")
    );
    assert_eq!(receipt["schema_version"], Value::from(2));
    assert_eq!(receipt["event_id"], Value::from("provider-reject-1"));
    assert_eq!(receipt["channel"], Value::from("email"));
    assert_eq!(
        receipt["receiving_address_or_handle"],
        Value::from("surface-unknown@example.com")
    );
    assert_eq!(
        receipt["counterparty"],
        json!({ "state": "unknown", "counterparty_key": "email:sender@example.com" })
    );
    assert_eq!(receipt["foreign_inbound"], Value::from(true));
    assert_eq!(receipt["claims_not_instructions"], Value::from(true));
    assert_eq!(receipt["identity_retiring"], Value::from(false));
    // An address that resolves to nothing stamps neither identity nor agent,
    // and no error envelope is wrapped around any of it.
    assert!(receipt.get("receiving_identity_ref").is_none());
    assert!(receipt.get("agent_ref").is_none());
    assert!(receipt.get("error").is_none(), "{receipt:?}");
    assert!(receipt.get("surface_event").is_none(), "{receipt:?}");

    // Nothing was queued, so the correlation id has no status resource.
    let (status, error) = core_json(
        server.clone(),
        "GET",
        "/v1/core/surface-events/provider-reject-1",
        "core:read",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_error_envelope(&error, "NOT_FOUND");
}

#[tokio::test]
async fn v1_core_surface_event_rejection_receipt_names_which_identity_failed() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    // A resolved but vault-bound identity. Routing knows exactly which record
    // refused and why, and the receipt carries both — the previous flattened
    // envelope collapsed this onto the same body as an unknown address.
    let identity_ref = seeded_test_entity_id(0x1259_0080);
    let address = "surface-vault-bound@example.com";
    let mut identity = oneiron::channel_identity::ChannelIdentity::requested(
        "email",
        address,
        oneiron::channel_identity::ChannelIdentityShape::DedicatedAddress,
        oneiron::channel_identity::ChannelIdentityBinding::vault(7),
        1_782_357_000,
    );
    identity.state = oneiron::channel_identity::ChannelIdentityState::Active;
    identity.pending_fulfillment = None;
    server
        .vault
        .create_channel_identity(&identity_ref, &identity)
        .expect("seed vault-bound identity");

    let (status, receipt) = core_json(
        server.clone(),
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&surface_event_body(address, "provider-reject-2")),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        receipt["rejection_reason"],
        Value::from("non_agent_bound_identity")
    );
    assert_eq!(
        receipt["receiving_identity_ref"],
        Value::from(identity_ref.to_hex())
    );
    assert!(
        receipt.get("agent_ref").is_none(),
        "a vault-bound identity stamps no agent: {receipt:?}"
    );
}

/// The schema publishes the closed engine set, spelling for spelling. The
/// wire-payload enum exists only to give utoipa something to reference, so a
/// rename on either side has to fail here rather than ship a schema naming
/// values the engine never emits — the erasure to a bare `string` is exactly
/// what left adapters reading the four spellings out of prose.
#[test]
fn v1_core_surface_event_rejection_reason_schema_is_the_closed_engine_set() {
    use super::surface_events::SurfaceEventRejectionReasonPayload;

    let engine = [
        oneiron::InboundSurfaceRejectionReason::UnknownReceivingIdentity,
        oneiron::InboundSurfaceRejectionReason::NonAgentBoundIdentity,
        oneiron::InboundSurfaceRejectionReason::InactiveReceivingIdentity,
        oneiron::InboundSurfaceRejectionReason::TombstonedReceivingIdentity,
    ];

    let spec = generated_spec();
    let declared = openapi_component_schema(&spec, "SurfaceEventRejectionReasonPayload")["enum"]
        .as_array()
        .expect("rejection reason is a closed enum schema")
        .clone();
    assert_eq!(
        declared,
        engine
            .iter()
            .map(|reason| Value::from(reason.as_str()))
            .collect::<Vec<_>>()
    );

    // And each mirrored variant serializes to the engine's stable string.
    for reason in engine {
        assert_eq!(
            serde_json::to_value(SurfaceEventRejectionReasonPayload::from(reason))
                .expect("serialize rejection reason"),
            Value::from(reason.as_str())
        );
    }
}

#[tokio::test]
async fn v1_core_surface_event_unknown_correlation_id_is_typed_not_found() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });

    let (status, error) = core_json(
        server,
        "GET",
        "/v1/core/surface-events/never-admitted",
        "core:read",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_error_envelope(&error, "NOT_FOUND");
}

#[tokio::test]
async fn v1_core_surface_event_routes_enforce_core_scopes() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let address = "surface-scope@example.com";
    seed_surface_identity(&server, 0x1259_0040, address);
    let body = surface_event_body(address, "provider-scope-1");

    // Write route rejects a read-only token.
    let (status, error) = core_json(
        server.clone(),
        "POST",
        "/v1/core/surface-events",
        "core:read",
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&error, "FORBIDDEN");

    // Read route rejects a write-only token.
    let (status, error) = core_json(
        server.clone(),
        "GET",
        "/v1/core/surface-events/provider-scope-1",
        "core:write",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_envelope(&error, "FORBIDDEN");

    // Missing credentials are unauthorized on both.
    let (status, error) = route_json(
        server.clone(),
        json_request("POST", "/v1/core/surface-events", body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_envelope(&error, "UNAUTHORIZED");

    // The happy path still works with the right scope.
    let (status, _) = core_json(
        server,
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn v1_core_surface_event_submit_honors_the_idempotency_middleware() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let address = "surface-idem@example.com";
    seed_surface_identity(&server, 0x1259_0050, address);
    let body = surface_event_body(address, "provider-idem-1");

    let submit = |idempotency_key: &str, body: Value| {
        let server = server.clone();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/core/surface-events")
            .header(AUTHORIZATION, test_bearer("scope=core:write"))
            .header("Idempotency-Key", idempotency_key)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        route_json(server, request)
    };

    // An Idempotency-Key equal to the correlation id replays through the
    // middleware.
    let (first_status, first) = submit("provider-idem-1", body.clone()).await;
    assert_eq!(first_status, StatusCode::ACCEPTED);
    assert_eq!(first["replayed"], Value::from(false));

    let (replay_status, replay) = submit("provider-idem-1", body.clone()).await;
    assert_eq!(replay_status, StatusCode::ACCEPTED);
    assert_eq!(replay, first, "middleware replays the cached ack verbatim");

    // Reusing the key with a different body is the middleware's conflict.
    let mut other = body;
    other["event_id"] = Value::from("provider-idem-other");
    let (conflict_status, conflict) = submit("provider-idem-1", other).await;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_error_envelope(&conflict, "IDEMPOTENCY_REPLAY_CONFLICT");
}

/// A 422 route rejection is a verdict about identity state, and identity state
/// moves: an address still provisioning at first submission goes Active
/// minutes later. The adapter's retry under its original key is exactly the
/// one that should now be admitted, so the middleware must not have frozen the
/// rejection for the whole 24h TTL.
#[tokio::test]
async fn v1_core_surface_event_rejection_is_not_cached_under_the_idempotency_key() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let identity_ref = seeded_test_entity_id(0x1259_0090);
    let agent_ref = seeded_test_entity_id(0x1259_0091);
    let address = "surface-provisioning@example.com";
    server
        .vault
        .create_channel_identity(
            &identity_ref,
            &oneiron::channel_identity::ChannelIdentity::requested(
                "email",
                address,
                oneiron::channel_identity::ChannelIdentityShape::DedicatedAddress,
                oneiron::channel_identity::ChannelIdentityBinding::agent(agent_ref),
                1_782_357_000,
            ),
        )
        .expect("seed requested identity");

    let body = surface_event_body(address, "provider-idem-retry-1");
    let submit = || {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/core/surface-events")
            .header(AUTHORIZATION, test_bearer("scope=core:write"))
            .header("Idempotency-Key", "provider-idem-retry-1")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        route_json(server.clone(), request)
    };

    // The identity has not been fulfilled yet, so routing refuses to queue.
    let (rejected_status, receipt) = submit().await;
    assert_eq!(rejected_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        receipt["rejection_reason"],
        Value::from("inactive_receiving_identity")
    );

    // Provisioning completes.
    server
        .vault
        .transition_channel_identity(
            &identity_ref,
            oneiron::channel_identity::ChannelIdentityState::PendingFulfillment,
            Some(oneiron::channel_identity::ChannelIdentityFulfillment::Api),
            1_782_357_100,
            None,
        )
        .expect("pend fulfillment");
    server
        .vault
        .transition_channel_identity(
            &identity_ref,
            oneiron::channel_identity::ChannelIdentityState::Active,
            None,
            1_782_357_200,
            None,
        )
        .expect("activate identity");

    // Same key, same body: admitted for real, not replayed as the stale 422.
    let (accepted_status, ack) = submit().await;
    assert_eq!(accepted_status, StatusCode::ACCEPTED);
    assert_eq!(ack["replayed"], Value::from(false));
    assert_eq!(ack["state"], Value::from("queued"));
}

#[tokio::test]
async fn v1_core_surface_event_durability_does_not_depend_on_the_middleware() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let address = "surface-durable@example.com";
    seed_surface_identity(&server, 0x1259_0060, address);
    let body = surface_event_body(address, "provider-durable-1");

    // First submission carries an Idempotency-Key; the second carries none at
    // all. Durable once-per-correlation still holds, so the middleware's TTL is
    // never the thing keeping the handoff unique.
    let (_, first) = route_json(
        server.clone(),
        Request::builder()
            .method("POST")
            .uri("/v1/core/surface-events")
            .header(AUTHORIZATION, test_bearer("scope=core:write"))
            .header("Idempotency-Key", "unrelated-http-key")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await;
    assert_eq!(first["replayed"], Value::from(false));

    let (status, second) = core_json(
        server,
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(second["replayed"], Value::from(true));
    assert_eq!(second["attempt_ref"], first["attempt_ref"]);
}

#[tokio::test]
async fn v1_core_surface_event_malformed_submissions_are_typed_bad_requests() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let address = "surface-malformed@example.com";
    seed_surface_identity(&server, 0x1259_0070, address);

    // Unknown source app: the enum is closed, so this never reaches the engine.
    let mut unknown_app = surface_event_body(address, "provider-malformed-1");
    unknown_app["source"] = json!({ "app": "carrier_pigeon", "user_ref": "pigeon:1" });
    let (status, error) = core_json(
        server.clone(),
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&unknown_app),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&error, "BAD_REQUEST");

    // Unknown interaction kind is likewise closed.
    let mut unknown_interaction = surface_event_body(address, "provider-malformed-2");
    unknown_interaction["action"] = json!({ "kind": "interaction", "interaction": "shrug" });
    let (status, error) = core_json(
        server.clone(),
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&unknown_interaction),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&error, "BAD_REQUEST");

    // A blank correlation id fails engine validation rather than queueing.
    let mut blank_correlation = surface_event_body(address, "provider-malformed-3");
    blank_correlation["correlation_id"] = Value::from("   ");
    let (status, error) = core_json(
        server,
        "POST",
        "/v1/core/surface-events",
        "core:write",
        Some(&blank_correlation),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_envelope(&error, "BAD_REQUEST");
}

// ─── ONE-1437 · reactive local-first read ────────────────────────────────────

/// A local query over one entity blob that also counts how many times it
/// actually touched the vault. The count is what lets a fixture assert
/// "exactly one re-query" instead of inferring it from the output value.
struct ReactiveEntityProbe {
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

fn reactive_probe(
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

fn reactive_reads(counter: &Arc<std::sync::atomic::AtomicUsize>) -> usize {
    counter.load(std::sync::atomic::Ordering::Relaxed)
}

/// Seeds one turn body into the local vault at `learned_at`, which is also what
/// decides the window the engine mirror will place it in.
fn seed_reactive_turn(vault: &oneiron::Vault, id: &oneiron::EntityId, learned_at: u64) {
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

fn reactive_window_frame(window_key: &str, sub_tag: u8) -> Vec<u8> {
    crate::protocol::encode_window_sync(window_key, sub_tag, b"payload")
        .into_result()
        .expect("window sync frame")
}

fn reactive_window_update_frame(window_key: &str) -> Vec<u8> {
    reactive_window_frame(window_key, crate::protocol::window_sub_tags::UPDATE)
}

/// Every frame shape that reaches the broadcast channel yet must never re-run
/// an LMDB query: presence/ephemeral state, sync negotiation, lease traffic,
/// selector requests, malformed bytes, and tags this server does not know
/// (which is how a future app-tier RPC/SUB frame will arrive here).
fn reactive_nonpersistent_frames(window_key: &str) -> Vec<Vec<u8>> {
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

/// The initial path is synchronous end to end: this fixture runs with no Tokio
/// runtime at all, so an async constructor or a server round trip could not
/// even compile-and-run here, let alone a `Loading` state.
#[test]
fn local_reactive_read_is_synchronous() {
    let (_dir, server) = test_server();
    let id = seeded_test_entity_id(0x1437_0001);
    seed_reactive_turn(server.vault(), &id, 1_770_000_000);

    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::AnyPersistent]);
    let read = open_local_reactive_read(&server, probe).expect("open reactive read");

    assert_eq!(reactive_reads(&reads), 1, "open reads exactly once");
    assert!(
        read.snapshot().is_some(),
        "a cached read must be serveable immediately, with no socket and no network"
    );
    assert_eq!(read.revision(), 0);
}

/// A closed notice channel is terminal but harmless: the last snapshot stays
/// readable, which is what "keeps working offline" means for this contract.
#[tokio::test]
async fn local_reactive_read_keeps_snapshot_when_channel_closes() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let id = seeded_test_entity_id(0x1437_0002);
    seed_reactive_turn(&vault, &id, 1_770_000_000);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::AnyPersistent]);
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).expect("open");
    drop(tx);

    let err = read
        .refresh_on_change()
        .await
        .expect_err("a closed channel ends the wait");
    assert!(matches!(err, ReactiveReadError::ChannelClosed));
    assert!(
        read.snapshot().is_some(),
        "the retained snapshot survives channel closure"
    );
    assert_eq!(reactive_reads(&reads), 1, "closure triggers no re-query");
    assert_eq!(read.revision(), 0);
}

/// A matching persistent notice re-runs the query exactly once and bumps the
/// revision — once for a window update, once for a root update.
#[tokio::test]
async fn local_reactive_read_refreshes_on_matching_sync() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);

    let window_id = seeded_test_entity_id(0x1437_0003);
    let (window_probe, window_reads) = reactive_probe(
        window_id,
        vec![ReactiveDependency::Window(window_key.as_str().to_owned())],
    );
    let root_id = seeded_test_entity_id(0x1437_0004);
    let (root_probe, root_reads) = reactive_probe(root_id, vec![ReactiveDependency::Root]);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let mut window_read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, window_probe).unwrap();
    let mut root_read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, root_probe).unwrap();
    assert!(window_read.snapshot().is_none());
    assert!(root_read.snapshot().is_none());

    seed_reactive_turn(&vault, &window_id, learned_at);
    seed_reactive_turn(&vault, &root_id, learned_at);
    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame(window_key.as_str()))
        .expect("broadcast window update");
    crate::broadcast::broadcast(&tx, 0, crate::protocol::encode_root_update(b"root-delta"))
        .expect("broadcast root update");

    assert!(
        window_read
            .refresh_on_change()
            .await
            .expect("window update refreshes")
            .is_some()
    );
    assert_eq!(window_read.revision(), 1);
    assert_eq!(reactive_reads(&window_reads), 2);

    assert!(
        root_read
            .refresh_on_change()
            .await
            .expect("root update refreshes")
            .is_some()
    );
    assert_eq!(root_read.revision(), 1);
    assert_eq!(reactive_reads(&root_reads), 2);
}

/// Non-persistent frames are checked against the widest dependency set there
/// is, so what rejects them is the frame class itself and not a narrow
/// dependency that happened to miss.
#[tokio::test]
async fn local_reactive_read_ignores_nonpersistent_frames() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let id = seeded_test_entity_id(0x1437_0005);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(32);
    let (probe, reads) = reactive_probe(id, vec![ReactiveDependency::AnyPersistent]);
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();

    for frame in reactive_nonpersistent_frames(window_key.as_str()) {
        crate::broadcast::broadcast(&tx, 0, frame).expect("broadcast non-persistent frame");
    }
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read.refresh_on_change()
        )
        .await
        .is_err(),
        "ephemeral, VV, lease, selector, malformed, and unknown frames must not wake a local read"
    );
    assert_eq!(
        reactive_reads(&reads),
        1,
        "no re-query on negotiation noise"
    );
    assert_eq!(read.revision(), 0);

    seed_reactive_turn(&vault, &id, learned_at);
    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame(window_key.as_str()))
        .expect("broadcast window update");
    assert!(
        read.refresh_on_change()
            .await
            .expect("a persistent frame still wakes the same read")
            .is_some()
    );
    assert_eq!(read.revision(), 1);
    assert_eq!(reactive_reads(&reads), 2);
}

#[tokio::test]
async fn local_reactive_read_ignores_unrelated_window() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let other_window = "2026-03";
    assert_ne!(window_key.as_str(), other_window);
    let id = seeded_test_entity_id(0x1437_0006);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let (probe, reads) = reactive_probe(
        id,
        vec![ReactiveDependency::Window(window_key.as_str().to_owned())],
    );
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();

    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame(other_window))
        .expect("broadcast unrelated window update");
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            read.refresh_on_change()
        )
        .await
        .is_err(),
        "an update to a window this query does not read must not re-run it"
    );
    assert_eq!(reactive_reads(&reads), 1);

    seed_reactive_turn(&vault, &id, learned_at);
    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame(window_key.as_str()))
        .expect("broadcast matching window update");
    assert!(read.refresh_on_change().await.expect("refresh").is_some());
    assert_eq!(read.revision(), 1);
    assert_eq!(reactive_reads(&reads), 2);
}

/// Dropped notices degrade to extra work, never to stale data: the only frames
/// on this channel name a window the query does not read, so the refresh can
/// only be explained by the lag escalation itself.
#[tokio::test]
async fn local_reactive_read_recovers_from_lag() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let id = seeded_test_entity_id(0x1437_0007);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(2);
    let (probe, reads) = reactive_probe(
        id,
        vec![ReactiveDependency::Window(window_key.as_str().to_owned())],
    );
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();
    assert!(read.snapshot().is_none());

    seed_reactive_turn(&vault, &id, learned_at);
    for _ in 0..5 {
        crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame("2026-03"))
            .expect("overflow the receiver");
    }

    assert!(
        read.refresh_on_change()
            .await
            .expect("lag escalates to a coarse re-read")
            .is_some(),
        "a lagged receiver must produce a current snapshot, not a placeholder"
    );
    assert_eq!(read.revision(), 1);
    assert_eq!(reactive_reads(&reads), 2);
}

/// Local/bridge frames (`conn_id = 0`) and frames from the consumer's own
/// connection both reach the reactive subscriber — a writer's own device still
/// has to refresh its LMDB-derived view — while `BroadcastSubscriber` keeps
/// suppressing its own echo for WebSocket forwarding on the same channel.
#[tokio::test]
async fn local_reactive_read_observes_bridge_and_own_connection_origins() {
    let dir = tempfile::tempdir().expect("temp vault dir");
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let id = seeded_test_entity_id(0x1437_0008);
    seed_reactive_turn(&vault, &id, learned_at);

    let (tx, _rx) = tokio::sync::broadcast::channel::<crate::server::BroadcastPayload>(8);
    let (probe, reads) = reactive_probe(
        id,
        vec![ReactiveDependency::Window(window_key.as_str().to_owned())],
    );
    let mut read = ReactiveLocalRead::open(Arc::clone(&vault), &tx, probe).unwrap();
    let mut websocket_subscriber = crate::broadcast::BroadcastSubscriber::new(7, &tx);

    crate::broadcast::broadcast(&tx, 0, reactive_window_update_frame(window_key.as_str()))
        .expect("bridge-origin frame");
    read.refresh_on_change().await.expect("bridge origin wakes");
    assert_eq!(read.revision(), 1);

    crate::broadcast::broadcast(&tx, 7, reactive_window_update_frame(window_key.as_str()))
        .expect("own-connection frame");
    read.refresh_on_change()
        .await
        .expect("own-connection origin wakes");
    assert_eq!(read.revision(), 2);
    assert_eq!(reactive_reads(&reads), 3);

    // The WebSocket path is untouched: connection 7 sees the bridge frame and
    // skips its own echo, so it receives exactly one of the two.
    assert!(
        websocket_subscriber
            .recv()
            .await
            .expect("subscriber alive")
            .is_some()
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            websocket_subscriber.recv()
        )
        .await
        .is_err(),
        "echo suppression for WebSocket forwarding must be unchanged"
    );
}

/// Production wiring, end to end: a real LMDB write, mirrored into the window
/// by the engine's own LMDB→CRDT path, reaches a reactive read through
/// Observer A and the server's broadcast producer. No encoded frame is injected
/// anywhere in this fixture.
#[tokio::test]
async fn local_vault_write_reaches_reactive_read_through_engine_observer() {
    let (_dir, server) = test_server();
    let learned_at = 1_770_000_000;
    let window_key = oneiron::sync::WindowKey::from_timestamp(learned_at);
    let doc = server
        .get_or_create_window(&window_key)
        .await
        .expect("open window");

    let id = seeded_test_entity_id(0x1437_0009);
    let (probe, reads) = reactive_probe(
        id,
        vec![ReactiveDependency::Window(window_key.as_str().to_owned())],
    );
    let mut read = open_local_reactive_read(&server, probe).expect("open reactive read");
    assert!(read.snapshot().is_none());

    seed_reactive_turn(server.vault(), &id, learned_at);
    assert_eq!(
        oneiron::sync::window::reverse_rematerialize(server.vault(), &doc, &window_key)
            .expect("mirror local write into the window"),
        1
    );

    let refreshed =
        tokio::time::timeout(std::time::Duration::from_secs(5), read.refresh_on_change())
            .await
            .expect("observer notice reaches the reactive read")
            .expect("refresh succeeds")
            .is_some();
    assert!(refreshed, "the reactive read serves the newly written body");
    assert_eq!(read.revision(), 1);
    assert_eq!(reactive_reads(&reads), 2);
}

// ── ONE-1936: MCP write-verb validity guard ──────────────────────────────

/// Seeds `subject`, an active claim, and its replacement, then supersedes —
/// leaving `old` as a stale target whose head is `new`.
fn seed_superseded_claim_pair(
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
fn resolve_short_ref(server: &SyncServer, short_ref: &str) -> oneiron::EntityId {
    let (short_id, content_hash) =
        crate::api::parse_short_ref(short_ref).expect("successor ref must be a public short ref");
    server
        .vault
        .hydrate_short_id(&short_id, content_hash)
        .expect("hydrate successor ref")
        .expect("successor ref must resolve")
        .id
}

/// Issues one `oneiron.edit` call and returns the JSON-RPC `error` object,
/// failing loudly when the call unexpectedly succeeded.
async fn mcp_edit_error(server: &Arc<SyncServer>, credential: &str, args: Value) -> Value {
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

#[tokio::test]
async fn mcp_stale_edit_rejected_before_proposal() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1936_0101);
    let credential = "one-1936-stale-edit-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let subject = seeded_test_entity_id(0x1936_0102);
    let old = seeded_test_entity_id(0x1936_0103);
    let new = seeded_test_entity_id(0x1936_0104);
    seed_superseded_claim_pair(&server, subject, old, new);
    // The seeding supersession itself emits gate decisions; the guard's
    // evidence is that NOTHING is added on top of this baseline.
    let baseline_decisions = server
        .vault
        .gate_decisions(100)
        .expect("baseline gate decisions")
        .len();

    let supersede_args = |dry_run: bool| {
        json!({
            "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": mcp_actor_json(actor_ref, "human"),
            "consent": mcp_consent_json("write_memory", false),
            "verb": "supersede_claim",
            "idempotency_key": "one-1936-stale-supersede",
            "dry_run": dry_run,
            "old_claim_id": old.to_hex(),
            "predicate": "profile.route_test",
            "value": "later",
            "confidence": 0.8,
            "reason": "user_correction"
        })
    };

    // supersede_claim: typed kind + the successor as DATA, not prose.
    let error = mcp_edit_error(&server, credential, supersede_args(false)).await;
    assert_eq!(error["code"], Value::from(-32020), "{error:#}");
    assert_eq!(
        error["data"]["kind"],
        Value::from("write_verb_target_stale")
    );
    let head_ref = error["data"]["successor_short_id"]
        .as_str()
        .expect("successor travels as typed data, not prose")
        .to_owned();
    assert_eq!(
        resolve_short_ref(&server, &head_ref),
        new,
        "the reported ref must resolve to the current head"
    );
    assert_ne!(head_ref, new.to_hex(), "never a hex fallback");

    // Dry run reports the SAME condition — it never green-lights an edit the
    // real call will refuse.
    let dry_error = mcp_edit_error(&server, credential, supersede_args(true)).await;
    assert_eq!(
        dry_error["data"]["kind"],
        Value::from("write_verb_target_stale")
    );
    assert_eq!(
        dry_error["data"]["successor_short_id"],
        Value::from(head_ref.clone())
    );
    assert_eq!(
        server
            .vault
            .gate_decisions(100)
            .expect("gate decisions")
            .len(),
        baseline_decisions,
        "a dry run must report without writing"
    );

    // retract_claim maps its target from `claim_id`, and refuses the same way.
    let error = mcp_edit_error(
        &server,
        credential,
        json!({
            "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": mcp_actor_json(actor_ref, "human"),
            "consent": mcp_consent_json("write_memory", false),
            "verb": "retract_claim",
            "idempotency_key": "one-1936-stale-retract",
            "claim_id": old.to_hex(),
            "reason": "user_retraction"
        }),
    )
    .await;
    assert_eq!(
        error["data"]["kind"],
        Value::from("write_verb_target_stale")
    );
    assert_eq!(error["data"]["successor_short_id"], Value::from(head_ref));

    // Nothing committed: no proposal Claim, so no Gate decision, and the
    // targets are exactly as the refusal found them.
    assert_eq!(
        server
            .vault
            .gate_decisions(100)
            .expect("gate decisions")
            .len(),
        baseline_decisions,
        "a stale-target edit must not emit a Gate decision"
    );
    assert_eq!(
        server
            .vault
            .get_claim(&old)
            .expect("read old")
            .expect("old claim")
            .lifecycle,
        oneiron::ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        server
            .vault
            .get_claim(&new)
            .expect("read new")
            .expect("new claim")
            .lifecycle,
        oneiron::ClaimLifecycleStatus::Active,
        "the verb must never be applied to the successor"
    );

    // …and no idempotency row committed either: re-issuing the SAME
    // idempotency key against the live head proposes fresh rather than
    // replaying a phantom.
    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-stale-edit-retry",
            "oneiron.edit",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "consent": mcp_consent_json("write_memory", false),
                "verb": "supersede_claim",
                "idempotency_key": "one-1936-stale-supersede",
                "old_claim_id": new.to_hex(),
                "predicate": "profile.route_test",
                "value": "later",
                "confidence": 0.8,
                "reason": "user_correction"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"]["structuredContent"]["status"],
        Value::from("proposed"),
        "a refused edit must leave no idempotency row behind: {body:#}"
    );
}

#[tokio::test]
async fn mcp_stale_attest_returns_current_provenance_head() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1936_0201);
    let credential = "one-1936-stale-attest-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let source = seeded_test_entity_id(0x1936_0202);
    let target = seeded_test_entity_id(0x1936_0203);
    for id in [source, target] {
        server
            .vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"attest fixture",
            )
            .expect("seed entity");
    }
    server
        .vault
        .put_edge(&source, oneiron::EdgeKind::Mentions, &target, 0.5)
        .expect("seed semantic edge");

    let subject = oneiron::provenance::EdgeRef::new(source, oneiron::EdgeKind::Mentions, target);
    let prior = seeded_test_entity_id(0x1936_0204);
    let winner = seeded_test_entity_id(0x1936_0205);
    server
        .vault
        .put_edge_provenance(
            &prior,
            &subject,
            &oneiron::provenance::EdgeProvenanceClaimBody::new(
                actor_ref,
                0.5,
                oneiron::provenance::SupersessionStatus::Proposed,
            ),
            oneiron::EdgeActorClass::Human,
            100,
        )
        .expect("seed prior attestation");
    server
        .vault
        .supersede_edge_provenance(
            &prior,
            &winner,
            &subject,
            &oneiron::provenance::EdgeProvenanceClaimBody::new(
                actor_ref,
                0.9,
                oneiron::provenance::SupersessionStatus::Confirmed,
            ),
            oneiron::EdgeActorClass::Human,
            200,
        )
        .expect("supersede the prior attestation");

    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-stale-attest",
            "oneiron.edit",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "consent": mcp_consent_json("write_memory", false),
                "verb": "attest_edge_provenance",
                "idempotency_key": "one-1936-stale-attest",
                "subject": {
                    "edge": {
                        "source": source.to_hex(),
                        "kind": oneiron::EdgeKind::Mentions as u8,
                        "target": target.to_hex()
                    }
                },
                "old_claim_id": prior.to_hex(),
                "confidence": 0.8
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["error"]["data"]["kind"],
        Value::from("write_verb_target_stale"),
        "{body:#}"
    );
    // The head comes from the D14 COHORT winner, not from an invented
    // provenance Supersedes edge.
    let head_ref = body["error"]["data"]["successor_short_id"]
        .as_str()
        .expect("successor travels as typed data");
    assert_eq!(resolve_short_ref(&server, head_ref), winner);
}

#[tokio::test]
async fn mcp_first_attestation_without_a_prior_has_no_lifecycle_target() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1936_0301);
    let credential = "one-1936-first-attest-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let target = seeded_test_entity_id(0x1936_0302);
    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-first-attest",
            "oneiron.edit",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "consent": mcp_consent_json("write_memory", false),
                "verb": "attest_edge_provenance",
                "idempotency_key": "one-1936-first-attest",
                "subject": {
                    "edge": {
                        "source": actor_ref.to_hex(),
                        "kind": oneiron::EdgeKind::Mentions as u8,
                        "target": target.to_hex()
                    }
                },
                "confidence": 0.8
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.get("error").is_none(), "{body:#}");
    assert_eq!(
        body["result"]["structuredContent"]["status"],
        Value::from("proposed")
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// ONE-1704 — two registered MCP endpoints over the wire
// ═══════════════════════════════════════════════════════════════════════════

const MCP_TOOL_FIRST_PATH: &str = "/mcp/tool-first";

fn mcp_endpoint_request(path: &str, credential: &str, body: Value) -> Request<Body> {
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
fn mcp_credential_headers(credential: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {credential}")
            .parse()
            .expect("bearer credential header"),
    );
    headers
}

fn mcp_list_request(path: &str, credential: &str, id: &str) -> Request<Body> {
    mcp_endpoint_request(
        path,
        credential,
        json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list" }),
    )
}

fn mcp_endpoint_call_request(
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

fn mcp_listed_tool_names(body: &Value) -> Vec<&str> {
    body["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect()
}

fn mcp_expected_generated_names() -> Vec<&'static str> {
    let mut expected = oneiron::board_verb::BOARD_VERBS
        .iter()
        .chain(oneiron::task_verb::TASKS_VERBS.iter())
        .copied()
        .collect::<Vec<_>>();
    expected.sort_unstable();
    expected
}

fn mcp_endpoint_envelope(actor_ref: oneiron::EntityId, purpose: &str) -> Value {
    json!({
        "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": mcp_actor_json(actor_ref, "human"),
        "consent": mcp_consent_json(purpose, false),
    })
}

fn mcp_merge_args(mut base: Value, extra: Value) -> Value {
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

fn assert_mcp_result_metadata(meta: &Value) {
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

fn assert_mcp_structured_error(body: &Value, error_code: &str) {
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

#[tokio::test]
async fn mcp_endpoints_register_distinct_tool_listings() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0001);
    let credential = "one-1704-listing-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (status, primary) = route_json(
        server.clone(),
        mcp_list_request("/mcp", credential, "primary-list"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(primary["result"]["surfaceMode"], Value::from("primary"));
    // ONE-1704 B1: the primary catalog is the one tool this release ships.
    assert_eq!(mcp_listed_tool_names(&primary), vec!["setup_oneiron"]);
    assert!(
        !serde_json::to_string(&primary["result"])
            .expect("listing serializes")
            .contains("execute_code"),
        "a retired tool must not appear in the listing bytes: {primary:?}"
    );
    assert!(
        primary["result"].get("actor").is_none(),
        "a listing must not echo the caller: {primary:?}"
    );

    let (status, tool_first) = route_json(
        server,
        mcp_list_request(MCP_TOOL_FIRST_PATH, credential, "tool-first-list"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        tool_first["result"]["surfaceMode"],
        Value::from("tool_first")
    );
    assert_eq!(
        mcp_listed_tool_names(&tool_first),
        mcp_expected_generated_names(),
        "the tool-first listing is generated from the exported verb rows"
    );
    for name in mcp_listed_tool_names(&tool_first) {
        assert!(!name.starts_with("oneiron."), "{name} must not be listed");
    }
}

/// Registers a connector whose ceiling is NARROWED to one world and facet.
///
/// The class stays `human` because the seeded default manifest carries the
/// class-wide human ceiling; what varies here is the SCOPE, which is the axis
/// the byte-identity invariant is about.
async fn register_scoped_mcp_actor(
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

#[tokio::test]
async fn mcp_tools_list_bytes_are_identical_across_credentials_and_scopes() {
    let (_dir, server) = test_server();
    let wide_actor = seeded_test_entity_id(0x1704_0011);
    let scoped_actor = seeded_test_entity_id(0x1704_0012);
    register_mcp_actor(
        &server,
        "one-1704-wide-credential",
        wide_actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    register_scoped_mcp_actor(
        &server,
        "one-1704-scoped-credential",
        scoped_actor,
        crate::mcp::McpConnectorScope::scoped(
            Some(seeded_test_entity_id(0x1704_0013)),
            Some(seeded_test_entity_id(0x1704_0014)),
        ),
    )
    .await;

    for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
        let (_, wide) = route_json(
            server.clone(),
            mcp_list_request(path, "one-1704-wide-credential", "same-id"),
        )
        .await;
        let (_, scoped) = route_json(
            server.clone(),
            mcp_list_request(path, "one-1704-scoped-credential", "same-id"),
        )
        .await;
        assert_eq!(
            serde_json::to_string(&wide["result"]).expect("result serializes"),
            serde_json::to_string(&scoped["result"]).expect("result serializes"),
            "{path} listing must be byte-identical for every credential",
        );
    }
}

#[tokio::test]
async fn mcp_cross_endpoint_tool_calls_are_unknown_tool() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0021);
    let credential = "one-1704-cross-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (status, body) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "cross-1",
            "board.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "arguments": { "key": "TASKS" } }),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_mcp_structured_error(&body, "unknown_tool");
    assert!(
        body["error"]["data"]["effective_scope"].is_object(),
        "an actor-derived refusal states its scope: {body:?}"
    );

    let (_, body) = route_json(
        server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "cross-2",
            "setup_oneiron",
            mcp_endpoint_envelope(actor_ref, "read_board"),
        ),
    )
    .await;
    assert_mcp_structured_error(&body, "unknown_tool");
}

#[tokio::test]
async fn mcp_setup_returns_keyframe_grammar_instructions_and_no_carrier() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0031);
    let credential = "one-1704-setup-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (status, body) = route_json(
        server,
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "setup-1",
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "board_budget_tok": 800, "cache": { "ttl_ms": 900_000 } }),
            ),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "unexpected MCP error: {body:?}"
    );
    let result = &body["result"];
    let structured = &result["structuredContent"];
    assert_eq!(structured["tool"], Value::from("setup_oneiron"));
    assert!(
        structured["board"]["keyframe"]
            .as_str()
            .is_some_and(|text| text.contains("surface=\"board\"")),
        "{structured:?}"
    );
    assert_eq!(
        structured["board"]["render"]["budget_tok"],
        Value::from(800)
    );
    assert!(
        structured["board"]["render"]["floor_exceeds_cap"].is_boolean(),
        "render metadata passes through losslessly: {structured:?}"
    );
    assert_eq!(
        structured["verb_grammar"]["verbs"].as_array().map(Vec::len),
        Some(mcp_expected_generated_names().len()),
    );
    assert!(
        structured["instructions"]
            .as_str()
            .is_some_and(|text| !text.trim().is_empty()),
        "{structured:?}"
    );
    assert_mcp_result_metadata(&structured["meta"]);
    // A foreign TTL never widens ours, and setup never pairs its fresh
    // keyframe with an older carrier.
    assert_eq!(structured["meta"]["ttlMs"], Value::from(0));
    assert!(result.get("carrier").is_none(), "{result:?}");
}

/// ONE-1704 B2: a direct `execute_code` call is refused with ONE stable typed
/// code on BOTH routes, under full and narrowed credentials, BEFORE any run
/// exists — and it stays refused even with a host bound, because the retirement
/// is at the wire and not merely a missing provider.
#[tokio::test]
async fn mcp_direct_execute_code_is_typed_unavailable_before_any_run() {
    bind_mcp_test_code_host();
    let (_dir, server) = test_server();
    let wide_actor = seeded_test_entity_id(0x1704_0041);
    let wide = "one-1704-code-credential";
    register_mcp_actor(&server, wide, wide_actor, oneiron::EdgeActorClass::Human).await;

    let narrow_actor = seeded_test_entity_id(0x1704_0042);
    let narrow_scope =
        crate::mcp::McpConnectorScope::scoped(Some(seeded_test_entity_id(0x1704_0043)), None);
    let narrow = "one-1704-code-narrow-credential";
    register_scoped_mcp_actor(&server, narrow, narrow_actor, narrow_scope.clone()).await;

    let entered_before = mcp_fixture_code_runs();
    let code_args = json!({
        "run_ref": "one-1704-run",
        "page": { "limit": 4 },
        "task": "search memory for the launch plan, then park an outbound effect",
    });

    for (label, credential, envelope) in [
        (
            "vault-wide",
            wide,
            mcp_endpoint_envelope(wide_actor, "run_code"),
        ),
        (
            "narrowed",
            narrow,
            mcp_scoped_envelope(narrow_actor, "run_code", &narrow_scope),
        ),
    ] {
        for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
            let body = mcp_refusal(
                &server,
                mcp_endpoint_call_request(
                    path,
                    credential,
                    &format!("code-{label}"),
                    "execute_code",
                    mcp_merge_args(envelope.clone(), code_args.clone()),
                ),
            )
            .await;
            assert_mcp_structured_error(&body, "execute_code_unavailable");
            assert_eq!(
                body["error"]["data"]["field"],
                Value::from("name"),
                "{label} on {path}: {body:?}"
            );
            // Nothing a run would have published reaches the wire: no run
            // handle, no resume block, no terminal claim, no durable wait.
            let serialized = serde_json::to_string(&body).expect("refusal serializes");
            for forbidden in ["\"resume\"", "\"run_id\"", "\"terminal\"", "\"wait_id\""] {
                assert!(
                    !serialized.contains(forbidden),
                    "{label} on {path}: a refusal must publish no {forbidden}: {body:?}"
                );
            }
            assert!(body.get("result").is_none(), "{label} on {path}: {body:?}");
        }
    }

    assert_eq!(
        mcp_fixture_code_runs(),
        entered_before,
        "zero runs were created: the bound host was never entered",
    );

    // The tool is not listed on either endpoint either.
    for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
        let (_, listing) =
            route_json(server.clone(), mcp_list_request(path, wide, "code-list")).await;
        assert!(
            !mcp_listed_tool_names(&listing).contains(&"execute_code"),
            "{path} must not list a tool this release cannot run: {listing:?}"
        );
    }
}

/// ONE-1704 B3: narrowed admission is fail-closed on the world and facet axes
/// INDEPENDENTLY, for `execute_code` and for `tasks.create` alike, and a
/// vault-wide credential is untouched.
#[tokio::test]
async fn mcp_narrowed_admission_refuses_unscoped_execution_on_each_axis() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00d1);
    let world_only =
        crate::mcp::McpConnectorScope::scoped(Some(seeded_test_entity_id(0x1704_00d2)), None);
    let facet_only =
        crate::mcp::McpConnectorScope::scoped(None, Some(seeded_test_entity_id(0x1704_00d3)));
    let vault_wide = crate::mcp::McpConnectorScope::vault_wide();
    register_scoped_mcp_actor(
        &server,
        "one-1704-world-only",
        actor_ref,
        world_only.clone(),
    )
    .await;
    register_scoped_mcp_actor(
        &server,
        "one-1704-facet-only",
        actor_ref,
        facet_only.clone(),
    )
    .await;
    register_mcp_actor(
        &server,
        "one-1704-axis-wide",
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let create =
        |credential: &'static str, id: &'static str, scope: &crate::mcp::McpConnectorScope| {
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                id,
                "tasks.create",
                mcp_merge_args(
                    mcp_scoped_envelope(actor_ref, "write_tasks", scope),
                    json!({ "arguments": { "spec": { "kind": "review" } } }),
                ),
            )
        };

    // The world axis alone refuses, with NO facet narrowing in the fixture.
    let world_refusal = mcp_refusal(
        &server,
        create("one-1704-world-only", "axis-world", &world_only),
    )
    .await;
    assert_mcp_structured_error(&world_refusal, "mcp_scope_refused");
    assert_scoped_refusal(
        &world_refusal,
        &crate::mcp::mcp_effective_scope_value(&world_only),
        "world-only tasks.create",
    );

    // The facet axis alone refuses, with NO world narrowing in the fixture.
    let facet_refusal = mcp_refusal(
        &server,
        create("one-1704-facet-only", "axis-facet", &facet_only),
    )
    .await;
    assert_mcp_structured_error(&facet_refusal, "mcp_scope_refused");
    assert_scoped_refusal(
        &facet_refusal,
        &crate::mcp::mcp_effective_scope_value(&facet_only),
        "facet-only tasks.create",
    );

    // A vault-wide credential is NOT scope-refused: an actor-wide create is
    // exactly its ceiling, whatever the facade then decides.
    let (_, wide_create) = route_json(
        server.clone(),
        create("one-1704-axis-wide", "axis-wide", &vault_wide),
    )
    .await;
    assert_ne!(
        wide_create["error"]["data"]["error_code"],
        Value::from("mcp_scope_refused"),
        "a vault-wide credential must clear the admission: {wide_create:?}"
    );

    // The same admission refuses `execute_code` on each axis on its own. The
    // wire never reaches this — B2 refuses the name first — so the admission
    // itself is exercised directly, which is the door a future scoped-positive
    // program would have to open.
    let args = crate::mcp::validate_mcp_endpoint_tool_args(
        crate::mcp::McpEndpointTool::ExecuteCode,
        mcp_merge_args(
            mcp_scoped_envelope(actor_ref, "run_code", &world_only),
            json!({ "run_ref": "axis-run", "task": "read the board" }),
        ),
    )
    .expect("the retired argument shape still decodes");
    for (label, credential, scope) in [
        ("world-only", "one-1704-world-only", &world_only),
        ("facet-only", "one-1704-facet-only", &facet_only),
        ("vault-wide", "one-1704-axis-wide", &vault_wide),
    ] {
        let context = crate::api::resolve_mcp_gateway_actor(
            crate::mcp::McpSurfaceMode::Primary,
            "axis-admission",
            &mcp_credential_headers(credential),
            &server,
        )
        .await
        .expect("credential resolves");
        let admitted = crate::api::mcp_admit_scoped_call(&server, &args, &context);
        if scope.is_narrow() {
            let error = admitted.expect_err(&format!("{label} must be refused"));
            assert!(
                format!("{error:?}").contains("mcp_scope_refused"),
                "{label}: {error:?}"
            );
        } else {
            admitted.unwrap_or_else(|error| {
                panic!("{label} must clear the admission: {error:?}");
            });
        }
    }
}

/// ONE-1704 / Codex 3907570260: a JSON number's own TEXT survives the HTTP
/// request boundary, so the wire admits exactly what the schema advertises.
///
/// `18446744073709551615.0` is the mathematical `u64::MAX` that Draft 2020-12
/// `type: integer` accepts. The gateway routes the JSON-RPC envelope through a
/// `serde_json::Value`, which — on this build's feature set — rounds that
/// number through `f64` into a value printing ABOVE the advertised ceiling.
/// The arguments are therefore read back out of the REQUEST BYTES, so the
/// decoder still sees the spelling the caller actually sent.
#[tokio::test]
async fn mcp_tool_call_preserves_request_number_text_at_advertised_integers() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0052);
    let credential = "one-1704-raw-number";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    // The candidate is substituted as TEXT, so it never becomes a `Value` on
    // the way out either: these are the exact bytes a client would put on the
    // wire.
    let call = |id: &str, ttl_ms: &str| {
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": "tasks.check",
                "arguments": mcp_merge_args(
                    mcp_endpoint_envelope(actor_ref, "read_tasks"),
                    json!({ "cache": { "ttl_ms": "__oneiron_raw_ttl__" } }),
                ),
            },
        })
        .to_string()
        .replace("\"__oneiron_raw_ttl__\"", ttl_ms);
        Request::builder()
            .method("POST")
            .uri(MCP_TOOL_FIRST_PATH)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {credential}"))
            .body(Body::from(body))
            .expect("raw mcp endpoint request")
    };

    // The exact advertised ceiling, spelled with a fraction, is ADMITTED.
    let (status, body) = route_json(
        server.clone(),
        call("raw-ceiling", "18446744073709551615.0"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "the advertised integer ceiling must decode over the wire: {body:?}"
    );
    assert_eq!(
        body["result"]["structuredContent"]["tool"],
        Value::from("tasks.check")
    );

    // One above the ceiling, and a value that is not an integer at all, are
    // still refused at the same door: the repair moved a spelling, not a bound.
    for (id, ttl_ms) in [
        ("raw-above", "18446744073709551616"),
        ("raw-above-fraction", "18446744073709551615.5"),
        ("raw-fraction", "1.5"),
        ("raw-negative", "-1.0"),
    ] {
        let refusal = mcp_refusal(&server, call(id, ttl_ms)).await;
        assert_eq!(
            refusal["error"]["data"]["kind"],
            Value::from("tool_args_invalid"),
            "cache.ttl_ms {ttl_ms} must stay refused: {refusal:?}"
        );
    }
}

#[tokio::test]
async fn mcp_tool_first_verb_call_carries_scope_page_and_cache_metadata() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0051);
    let credential = "one-1704-verb-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (status, body) = route_json(
        server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "verb-1",
            "tasks.check",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_tasks"),
                json!({ "page": { "limit": 7 }, "cache": { "ttl_ms": 60_000 } }),
            ),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "unexpected MCP error: {body:?}"
    );
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["tool"], Value::from("tasks.check"));
    assert_eq!(structured["family"], Value::from("tasks"));
    assert_eq!(structured["verb"], Value::from("check"));
    assert_eq!(structured["output"]["kind"], Value::from("tasks_section"));
    assert_mcp_result_metadata(&structured["meta"]);
    assert_eq!(structured["meta"]["page"]["granted"], Value::from(7));
    assert_eq!(
        structured["meta"]["surface_mode"],
        Value::from("tool_first")
    );
}

#[tokio::test]
async fn mcp_missing_credential_returns_the_structured_error_contract() {
    let (_dir, server) = test_server();
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "jsonrpc": "2.0", "id": "no-credential", "method": "tools/list" }).to_string(),
        ))
        .expect("uncredentialed MCP request");

    let (status, body) = route_json(server, request).await;

    assert_eq!(status, StatusCode::OK);
    assert_mcp_structured_error(&body, "mcp_auth_required");
    assert_eq!(
        body["error"]["data"]["request_id"],
        Value::from("no-credential")
    );
}

#[tokio::test]
async fn mcp_endpoint_tool_args_are_gated_before_execution() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0061);
    let credential = "one-1704-args-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (status, body) = route_json(
        server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "args-1",
            "board.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "arguments": { "frame_epoch": 3 } }),
            ),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_mcp_structured_error(&body, "tool_args_invalid");
    assert_eq!(body["error"]["data"]["field"], Value::from("key"));
}

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

/// A fixture backend that always answers with the same plain-JS step.
struct McpFixtureCodeBackend;

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
struct McpFixtureCodeRuntime;

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

struct McpFixtureCodeProvider {
    backend: McpFixtureCodeBackend,
    lease: oneiron::BudgetLease,
}

/// How many times the bound fixture host was ENTERED for a run.
///
/// ONE-1704 B2 reads this to prove ZERO runs are created by a refused
/// `execute_code` call: the host is bound in this process, and the counter is
/// the run-creation witness rather than an absence someone has to infer.
static MCP_FIXTURE_CODE_RUNS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn mcp_fixture_code_runs() -> usize {
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
fn bind_mcp_test_code_host() {
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

// ═══════════════════════════════════════════════════════════════════════════
// ONE-1704 MATERIAL7 — fail-closed acceptance
// ═══════════════════════════════════════════════════════════════════════════

/// An envelope whose claimed actor scope MATCHES a narrowed registration.
fn mcp_scoped_envelope(
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
async fn register_bound_verb_mcp_actor(
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
async fn mcp_refusal(server: &Arc<SyncServer>, request: Request<Body>) -> Value {
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
fn assert_scoped_refusal(body: &Value, expected_scope: &Value, label: &str) {
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

#[tokio::test]
async fn mcp_legacy_catalog_is_unknown_tool_on_both_endpoints() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0071);
    let credential = "one-1704-legacy-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let scope = crate::mcp::mcp_effective_scope_value(&crate::mcp::McpConnectorScope::vault_wide());

    let legacy = crate::mcp::McpToolName::all()
        .iter()
        .map(|tool| tool.as_str())
        .collect::<Vec<_>>();
    assert_eq!(legacy.len(), 7, "the retired census is seven names");

    for (index, name) in legacy.iter().enumerate() {
        for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
            let body = mcp_refusal(
                &server,
                mcp_endpoint_call_request(
                    path,
                    credential,
                    &format!("legacy-{index}"),
                    name,
                    mcp_merge_args(
                        mcp_endpoint_envelope(actor_ref, "read_board"),
                        json!({ "target": { "entity_ref": actor_ref.to_hex() } }),
                    ),
                ),
            )
            .await;
            assert_mcp_structured_error(&body, "unknown_tool");
            assert_scoped_refusal(&body, &scope, &format!("{name} on {path}"));
        }
    }

    // Neither frozen listing names them either.
    for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
        let (_, listing) = route_json(
            server.clone(),
            mcp_list_request(path, credential, "legacy-list"),
        )
        .await;
        let names = mcp_listed_tool_names(&listing);
        for name in &legacy {
            assert!(!names.contains(name), "{name} must not be listed on {path}");
        }
    }
}

#[tokio::test]
async fn mcp_actor_derived_errors_all_carry_effective_scope() {
    let (_dir, server) = test_server();
    let wide_actor = seeded_test_entity_id(0x1704_0081);
    let wide = "one-1704-scope-error-credential";
    register_mcp_actor(&server, wide, wide_actor, oneiron::EdgeActorClass::Human).await;
    let wide_scope =
        crate::mcp::mcp_effective_scope_value(&crate::mcp::McpConnectorScope::vault_wide());

    // 1. Decode/validation, after the credential resolved.
    let body = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            wide,
            "scope-args",
            "board.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(wide_actor, "read_board"),
                json!({ "arguments": { "frame_epoch": 3 } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&body, "tool_args_invalid");
    assert_scoped_refusal(&body, &wide_scope, "tool_args_invalid");

    // 2. Actor mismatch.
    let body = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            wide,
            "scope-mismatch",
            "tasks.check",
            mcp_endpoint_envelope(seeded_test_entity_id(0x1704_0082), "read_tasks"),
        ),
    )
    .await;
    assert_mcp_structured_error(&body, "mcp_actor_mismatch");
    assert_scoped_refusal(&body, &wide_scope, "mcp_actor_mismatch");

    // 3. Board/task dispatch refusal from the engine's own verb dispatcher.
    for (id, arguments, label) in [
        (
            "scope-stale",
            json!({ "arguments": { "key": "TASKS", "frame_epoch": 9_999 } }),
            "stale frame",
        ),
        (
            "scope-missing",
            json!({ "arguments": { "key": "NO_SUCH_SECTION" } }),
            "missing target",
        ),
    ] {
        let body = mcp_refusal(
            &server,
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                wide,
                id,
                "board.expand",
                mcp_merge_args(mcp_endpoint_envelope(wide_actor, "read_board"), arguments),
            ),
        )
        .await;
        assert_mcp_structured_error(&body, "verb_dispatch_failed");
        assert_scoped_refusal(&body, &wide_scope, label);
    }

    // 4. Facade/engine failure behind an admitted call.
    let stray = seeded_test_entity_id(0x1704_0083);
    server
        .vault
        .put_entity(
            &stray,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            101,
            b"not a task",
        )
        .expect("seed a non-task entity");
    let body = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            wide,
            "scope-facade",
            "tasks.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(wide_actor, "read_tasks"),
                json!({ "arguments": { "task_ref": stray.to_hex() } }),
            ),
        ),
    )
    .await;
    assert_scoped_refusal(&body, &wide_scope, "facade failure");

    // 5. Bound-verb ceiling refusal.
    let bound_actor = seeded_test_entity_id(0x1704_0084);
    let bound = "one-1704-bound-verb-credential";
    register_bound_verb_mcp_actor(&server, bound, bound_actor, &["tasks.check"]).await;
    let body = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            bound,
            "scope-unbound",
            "board.refresh",
            mcp_endpoint_envelope(bound_actor, "read_board"),
        ),
    )
    .await;
    assert_mcp_structured_error(&body, "mcp_verb_not_bound");
    assert_scoped_refusal(&body, &wide_scope, "mcp_verb_not_bound");

    // 6. Scope refusal on a narrowed credential's STREAM routing request.
    let narrow_actor = seeded_test_entity_id(0x1704_0085);
    let narrow_scope_value =
        crate::mcp::McpConnectorScope::scoped(Some(seeded_test_entity_id(0x1704_0086)), None);
    let narrow = "one-1704-narrow-scope-credential";
    register_scoped_mcp_actor(&server, narrow, narrow_actor, narrow_scope_value.clone()).await;
    let body = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            narrow,
            "scope-stream",
            "board.subscribe",
            mcp_merge_args(
                mcp_scoped_envelope(narrow_actor, "read_board", &narrow_scope_value),
                json!({ "arguments": { "scopes": ["memories"] } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&body, "mcp_scope_refused");
    assert_scoped_refusal(
        &body,
        &crate::mcp::mcp_effective_scope_value(&narrow_scope_value),
        "mcp_scope_refused",
    );

    // Only a failure BEFORE the credential resolved is legitimately scope-less.
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "jsonrpc": "2.0", "id": "no-cred", "method": "tools/list" }).to_string(),
        ))
        .expect("uncredentialed MCP request");
    let body = mcp_refusal(&server, request).await;
    assert_mcp_structured_error(&body, "mcp_auth_required");
    assert!(
        body["error"]["data"].get("effective_scope").is_none(),
        "a pre-credential refusal has no scope to state: {body:?}"
    );
}

/// Seeds one CLAIM row whose own `world` key is `world`.
///
/// Only a CLAIM carries a world key, so this is the row shape the world ceiling
/// can actually answer for. `Auto`/`Active` is the surfaceable pair the engine's
/// own read admission requires.
fn seed_world_claim(
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

/// ONE-1704 M3/B3/B4/B5: the world and facet axes are enforced INDEPENDENTLY,
/// the world ceiling reaches non-CLAIM rows, and a narrowed connection receives
/// no carrier frame at all while a vault-wide one is unchanged.
#[tokio::test]
async fn mcp_narrow_credential_cannot_cross_world_or_facet() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0091);
    let facet_a = seeded_test_entity_id(0x1704_0092);
    let facet_b = seeded_test_entity_id(0x1704_0093);
    let world_a = seeded_test_entity_id(0x1704_0094);
    let world_b = seeded_test_entity_id(0x1704_0095);
    // Each axis gets its OWN fixture: a facet-only credential carries no world
    // narrowing and a world-only credential carries no facet narrowing, so
    // neither refusal can be inferred from the other.
    let facet_only_a = crate::mcp::McpConnectorScope::scoped(None, Some(facet_a));
    let facet_only_b = crate::mcp::McpConnectorScope::scoped(None, Some(facet_b));
    let world_only_a = crate::mcp::McpConnectorScope::scoped(Some(world_a), None);
    let vault_wide = crate::mcp::McpConnectorScope::vault_wide();
    let cred_facet_a = "one-1704-facet-a";
    let cred_facet_b = "one-1704-facet-b";
    let cred_world_a = "one-1704-world-a";
    let cred_wide = "one-1704-cross-wide";
    // ONE actor, FOUR credentials, disjoint registered scopes.
    register_scoped_mcp_actor(&server, cred_facet_a, actor_ref, facet_only_a.clone()).await;
    register_scoped_mcp_actor(&server, cred_facet_b, actor_ref, facet_only_b.clone()).await;
    register_scoped_mcp_actor(&server, cred_world_a, actor_ref, world_only_a.clone()).await;
    register_mcp_actor(
        &server,
        cred_wide,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    // A row that belongs to facet A and to nothing else. It carries no world
    // key, because only a CLAIM can.
    let owned = seeded_test_entity_id(0x1704_0096);
    server
        .vault
        .put_entity(
            &owned,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            101,
            b"facet-a row",
        )
        .expect("seed a facet-scoped row");
    // ONE-1645's write-time `FacetOf` table admits CLAIM|TURN|EVENT -> FACET
    // only, and reads BOTH endpoint types from STORED rows: an endpoint with no
    // entity row is unknowable-typed and fails closed exactly like a wrong one.
    // The facet this scope names must therefore be an established FACET fact
    // before anything stamps it.
    server
        .vault
        .put_entity(
            &facet_a,
            oneiron::registry::ENTITY_TYPE_FACET,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            101,
            b"facet a",
        )
        .expect("seed the facet the edge points at");
    server
        .vault
        .put_edge(&owned, oneiron::EdgeKind::FacetOf, &facet_a, 1.0)
        .expect("seed the facet edge");

    // Two CLAIM rows, one in each world.
    let in_world = seeded_test_entity_id(0x1704_0097);
    let other_world = seeded_test_entity_id(0x1704_0098);
    seed_world_claim(&server, in_world, actor_ref, world_a);
    seed_world_claim(&server, other_world, actor_ref, world_b);

    let read = |credential: &'static str,
                id: &'static str,
                scope: &crate::mcp::McpConnectorScope,
                target: oneiron::EntityId| {
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            id,
            "tasks.expand",
            mcp_merge_args(
                mcp_scoped_envelope(actor_ref, "read_tasks", scope),
                json!({ "arguments": { "task_ref": target.to_hex() } }),
            ),
        )
    };

    // FACET axis, with no world narrowing anywhere in the fixture: the owning
    // credential clears the gate and fails downstream on the row's TYPE, and
    // the other facet never reaches the facade at all.
    let own = mcp_refusal(
        &server,
        read(cred_facet_a, "facet-read-a", &facet_only_a, owned),
    )
    .await;
    assert_ne!(
        own["error"]["data"]["error_code"],
        Value::from("mcp_scope_refused"),
        "the owning facet credential must clear the scope gate: {own:?}"
    );
    let cross_facet = mcp_refusal(
        &server,
        read(cred_facet_b, "facet-read-b", &facet_only_b, owned),
    )
    .await;
    assert_mcp_structured_error(&cross_facet, "mcp_scope_refused");

    // WORLD axis, with no facet narrowing anywhere in the fixture.
    // 1. A non-CLAIM row carries no world key, so it cannot be proven in-world
    //    and is refused fail-closed — symmetric with the facet axis.
    let no_world_key = mcp_refusal(
        &server,
        read(cred_world_a, "world-read-turn", &world_only_a, owned),
    )
    .await;
    assert_mcp_structured_error(&no_world_key, "mcp_scope_refused");
    // 2. A CLAIM in another world stays refused.
    let cross_world = mcp_refusal(
        &server,
        read(cred_world_a, "world-read-other", &world_only_a, other_world),
    )
    .await;
    assert_mcp_structured_error(&cross_world, "mcp_scope_refused");
    // 3. An IN-WORLD claim is still admitted: the ceiling narrows, it does not
    //    close. The call then fails downstream on the row's type, as it should.
    let in_world_read = mcp_refusal(
        &server,
        read(cred_world_a, "world-read-own", &world_only_a, in_world),
    )
    .await;
    assert_ne!(
        in_world_read["error"]["data"]["error_code"],
        Value::from("mcp_scope_refused"),
        "an in-world claim must clear the world ceiling: {in_world_read:?}"
    );

    // No cross WRITE: the refusal happens BEFORE the ack ever dispatches.
    let foreign_write = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            cred_facet_b,
            "cross-write-b",
            "tasks.ack",
            mcp_merge_args(
                mcp_scoped_envelope(actor_ref, "ack_task", &facet_only_b),
                json!({ "arguments": { "task_ref": owned.to_hex() } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&foreign_write, "mcp_scope_refused");

    // ONE-1704 B4: a queued frame is delivered to a VAULT-WIDE connection and
    // to no narrowed one, however same-actor and however queued.
    let (conn_facet_a, conn_facet_b, conn_wide, run_a, run_b) = {
        let mut registry = server.mcp_registry.lock().await;
        let a = registry
            .resolve(cred_facet_a, 1, |_, _| true)
            .expect("facet credential a resolves");
        let b = registry
            .resolve(cred_facet_b, 1, |_, _| true)
            .expect("facet credential b resolves");
        let wide = registry
            .resolve(cred_wide, 1, |_, _| true)
            .expect("the vault-wide credential resolves");
        for connection in [&a.stream_connection, &wide.stream_connection] {
            registry.enqueue_stream_frame(
                connection,
                oneiron::context_board::BoardStreamFrame {
                    epoch: 3,
                    kind: oneiron::context_board::FrameKind::Keyframe("queued".to_owned()),
                },
            );
        }
        (
            a.stream_connection.clone(),
            b.stream_connection.clone(),
            wide.stream_connection,
            crate::mcp::mcp_code_run_id("shared-run", &a),
            crate::mcp::mcp_code_run_id("shared-run", &b),
        )
    };
    assert_ne!(
        conn_facet_a, conn_facet_b,
        "two credentials own two connections"
    );
    assert_ne!(conn_facet_a, conn_wide);

    let check =
        |credential: &'static str, id: &'static str, scope: &crate::mcp::McpConnectorScope| {
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                id,
                "tasks.check",
                mcp_scoped_envelope(actor_ref, "read_tasks", scope),
            )
        };
    let (_, b_first) = route_json(
        server.clone(),
        check(cred_facet_b, "carrier-b", &facet_only_b),
    )
    .await;
    assert!(
        b_first["result"].get("carrier").is_none(),
        "a frame queued for another credential must not ride here: {b_first:?}"
    );
    // The narrowed connection the frame WAS queued for still receives nothing:
    // the engine's router cannot filter world/facet, so the fail-closed
    // delivery for a narrowed connection is none at all.
    for id in ["carrier-a1", "carrier-a2"] {
        let (_, narrowed) =
            route_json(server.clone(), check(cred_facet_a, id, &facet_only_a)).await;
        assert!(
            narrowed["result"].get("carrier").is_none(),
            "a narrowed connection receives zero carrier frames: {narrowed:?}"
        );
    }
    // Vault-wide delivery is untouched: exactly one frame, exactly once.
    let (_, wide_first) = route_json(
        server.clone(),
        check(cred_wide, "carrier-wide-1", &vault_wide),
    )
    .await;
    assert_eq!(
        wide_first["result"]["carrier"]["class"],
        Value::from("carrier"),
        "a vault-wide connection carries its own queued frame: {wide_first:?}"
    );
    let (_, wide_second) = route_json(
        server.clone(),
        check(cred_wide, "carrier-wide-2", &vault_wide),
    )
    .await;
    assert!(
        wide_second["result"].get("carrier").is_none(),
        "one queued frame rides exactly once: {wide_second:?}"
    );

    // No claim-id COLLISION: one actor, one reused handle, two credentials.
    assert_ne!(run_a, run_b);
}

#[tokio::test]
async fn mcp_board_epoch_is_state_monotonic() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00a1);
    let credential = "one-1704-epoch-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let setup = |id: &'static str| {
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            id,
            "setup_oneiron",
            mcp_endpoint_envelope(actor_ref, "read_board"),
        )
    };
    let (_, first) = route_json(server.clone(), setup("epoch-1")).await;
    let epoch = first["result"]["structuredContent"]["board"]["epoch"]
        .as_u64()
        .expect("setup states a board epoch");

    // A second call with NO state change keeps the same epoch, however much
    // wall-clock time passed between them: the epoch is state, not a timer.
    let (_, second) = route_json(server.clone(), setup("epoch-2")).await;
    assert_eq!(
        second["result"]["structuredContent"]["board"]["epoch"],
        Value::from(epoch),
        "an unchanged board keeps its epoch: {second:?}"
    );

    // The registry RETAINS the exact snapshot setup returned, and that is what
    // a later expand fences against.
    let connection = {
        let registry = server.mcp_registry.lock().await;
        let actor = registry
            .resolve(credential, 1, |_, _| true)
            .expect("credential resolves");
        assert_eq!(
            registry
                .board_snapshot(&actor.stream_connection)
                .expect("the registry retains the snapshot")
                .epoch,
            epoch,
        );
        actor.stream_connection.clone()
    };

    // A frame at the retained epoch is NOT stale.
    let (_, fresh) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "epoch-expand",
            "board.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "arguments": { "key": "VERBS", "frame_epoch": epoch } }),
            ),
        ),
    )
    .await;
    assert!(
        fresh.get("error").is_none(),
        "a clock that moved must not stale a fresh frame: {fresh:?}"
    );

    // A frame at any other epoch IS stale — the fence still fires.
    let stale = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "epoch-stale",
            "board.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "arguments": { "key": "VERBS", "frame_epoch": epoch + 1 } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&stale, "verb_dispatch_failed");

    // The production epoch minter itself: a state change advances by exactly
    // one however little wall-clock time passed, and NOTHING can make it go
    // back — it reads no clock at all, so a rollback has nothing to regress.
    let mut registry = server.mcp_registry.lock().await;
    let state_a = crate::mcp::mcp_board_state_hash("VaultWide", &["row-a".to_owned()]);
    let state_b = crate::mcp::mcp_board_state_hash("VaultWide", &["row-b".to_owned()]);
    let base = registry.board_snapshot_epoch(&connection, state_a);
    assert_eq!(
        registry.board_snapshot_epoch(&connection, state_a),
        base,
        "an unchanged state never advances",
    );
    let advanced = registry.board_snapshot_epoch(&connection, state_b);
    assert_eq!(advanced, base + 1, "a state change advances by exactly one");
    assert_eq!(
        registry.board_snapshot_epoch(&connection, state_a),
        advanced + 1,
        "returning to an earlier STATE still moves forward: the epoch never regresses",
    );
}

#[tokio::test]
async fn mcp_page_budget_enforces_limit_end_marker_and_cursor() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00b1);
    let credential = "one-1704-page-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    // limit = 1 CAPS the grammar the setup result pages over, states `More`,
    // and carries an opaque successor.
    let (_, capped) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "page-1",
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "page": { "limit": 1 } }),
            ),
        ),
    )
    .await;
    let structured = &capped["result"]["structuredContent"];
    assert_eq!(
        structured["verb_grammar"]["verbs"].as_array().map(Vec::len),
        Some(1),
        "the granted budget is ENFORCED, not merely reported: {structured:?}"
    );
    let meta = &structured["meta"];
    assert_eq!(meta["page"]["granted"], Value::from(1));
    assert_eq!(meta["page"]["returned"], Value::from(1));
    assert_eq!(
        meta["page"]["hidden"],
        Value::from(mcp_expected_generated_names().len() - 1)
    );
    // ONE-1704 repair: the two axes are stated apart. Rows this transport page
    // window did not return are a WINDOW fact; the requested actor scope
    // removed none of them.
    assert_eq!(
        meta["page"]["window_truncated"],
        Value::from(mcp_expected_generated_names().len() - 1)
    );
    assert_eq!(
        meta["page"]["scope_omitted"],
        Value::from(0),
        "a page window is never counted as a requested-scope omission: {meta:?}"
    );
    assert_eq!(meta["end"], Value::from("More"));
    assert!(
        meta["page"]["cursor"]
            .as_str()
            .is_some_and(|cursor| cursor.starts_with("mcpc1:")),
        "a non-terminal page carries an opaque successor: {meta:?}"
    );

    // No caller limit: the whole grammar, an explicit `Complete`, no cursor.
    let (_, whole) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "page-2",
            "setup_oneiron",
            mcp_endpoint_envelope(actor_ref, "read_board"),
        ),
    )
    .await;
    let meta = &whole["result"]["structuredContent"]["meta"];
    assert_eq!(meta["end"], Value::from("Complete"));
    assert!(meta["page"].get("cursor").is_none(), "{meta:?}");
    assert!(
        !meta["page"]["forceful_override_honoured"]
            .as_bool()
            .expect("the override record is always stated")
    );

    // An EMPTY terminal page states `Complete` explicitly rather than leaving
    // exhaustion to be inferred from an empty cursor.
    let (_, empty) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "page-3",
            "tasks.check",
            mcp_endpoint_envelope(actor_ref, "read_tasks"),
        ),
    )
    .await;
    let empty = &empty["result"]["structuredContent"];
    assert_eq!(empty["output"]["count"], Value::from(0));
    assert_eq!(empty["meta"]["end"], Value::from("Complete"));
    assert_eq!(empty["meta"]["retrieval_health"], Value::from("healthy"));
    assert_eq!(empty["meta"]["page"]["returned"], Value::from(0));

    // A forceful override may exceed the harness ceiling, and the record says
    // it did.
    let (_, forced) = route_json(
        server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "page-4",
            "tasks.check",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_tasks"),
                json!({ "page": { "limit": 200, "forceful_override": true } }),
            ),
        ),
    )
    .await;
    let meta = &forced["result"]["structuredContent"]["meta"];
    assert_eq!(meta["page"]["granted"], Value::from(200));
    assert_eq!(
        meta["page"]["forceful_override_honoured"],
        Value::Bool(true)
    );
}

/// The verb names one setup result actually returned, in listing order.
fn mcp_setup_verb_names(structured: &Value) -> Vec<String> {
    structured["verb_grammar"]["verbs"]
        .as_array()
        .expect("the setup result pages over the verb grammar")
        .iter()
        .map(|verb| verb["name"].as_str().expect("a verb name").to_owned())
        .collect()
}

/// ONE-1704 M6: a `More` page's handle is CONSUMABLE — page one plus the page
/// it continues are exactly the producer's set — and it is BOUND to the
/// connector, tool, arguments, and snapshot it was minted under.
#[tokio::test]
async fn mcp_page_cursor_continues_exactly_once_and_is_bound() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00e1);
    let credential = "one-1704-cursor-credential";
    let other = "one-1704-cursor-other-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    register_mcp_actor(&server, other, actor_ref, oneiron::EdgeActorClass::Human).await;

    let setup = |credential: &'static str, id: &'static str, page: Value| {
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            id,
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "page": page }),
            ),
        )
    };

    // Page one: the first five verbs, an explicit `More`, and an opaque handle.
    let (_, first) = route_json(
        server.clone(),
        setup(credential, "cursor-1", json!({ "limit": 5 })),
    )
    .await;
    let first = &first["result"]["structuredContent"];
    let page_one = mcp_setup_verb_names(first);
    assert_eq!(page_one.len(), 5, "{first:?}");
    assert_eq!(first["meta"]["end"], Value::from("More"));
    assert!(
        first["meta"]["page"]
            .get("continuation_unavailable")
            .is_none(),
        "a continuable More names no unavailability: {first:?}"
    );
    let cursor = first["meta"]["page"]["cursor"]
        .as_str()
        .expect("a non-terminal page carries an opaque successor")
        .to_owned();
    assert!(cursor.starts_with("mcpc1:"), "{cursor}");

    // BOUND: another connector, another tool, and another argument set are each
    // refused fail-closed, and none of them consumes the live handle.
    let wrong_connector = mcp_refusal(
        &server,
        setup(
            other,
            "cursor-connector",
            json!({ "limit": 5, "cursor": cursor.clone() }),
        ),
    )
    .await;
    assert_mcp_structured_error(&wrong_connector, "mcp_page_cursor_invalid");
    assert_eq!(
        wrong_connector["error"]["data"]["field"],
        Value::from("page.cursor")
    );

    let wrong_tool = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "cursor-tool",
            "tasks.check",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_tasks"),
                json!({ "page": { "limit": 5, "cursor": cursor.clone() } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&wrong_tool, "mcp_page_cursor_invalid");

    // A real producer-query mismatch is refused, while changing only the page
    // window is allowed. `cache` is outside the transport-only page member and
    // therefore remains part of the bound identity.
    let wrong_arguments = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "cursor-args",
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({
                    "cache": { "ttl_ms": 1 },
                    "page": { "limit": 5, "cursor": cursor.clone() },
                }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&wrong_arguments, "mcp_page_cursor_invalid");

    // Page two may choose a DIFFERENT transport page limit. The retained
    // producer snapshot still supplies exactly the rows page one left behind,
    // with an explicit `Complete` and no further handle.
    let (_, second) = route_json(
        server.clone(),
        setup(
            credential,
            "cursor-2",
            json!({ "limit": 7, "cursor": cursor.clone() }),
        ),
    )
    .await;
    let second = &second["result"]["structuredContent"];
    let page_two = mcp_setup_verb_names(second);
    assert_eq!(second["meta"]["end"], Value::from("Complete"));
    assert!(second["meta"]["page"].get("cursor").is_none(), "{second:?}");
    assert_eq!(second["meta"]["page"]["hidden"], Value::from(0));

    let whole = mcp_expected_generated_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(page_two.len(), whole.len() - 5, "{second:?}");
    let mut union = page_one.clone();
    union.extend(page_two.clone());
    assert_eq!(
        union, whole,
        "page one plus the continued page IS the uncapped producer set"
    );
    for name in &page_two {
        assert!(
            !page_one.contains(name),
            "the pages must be disjoint: {name}"
        );
    }

    // ONE-TIME: the consumed handle is refused on replay, never silently
    // restarted at page one.
    let replay = mcp_refusal(
        &server,
        setup(
            credential,
            "cursor-replay",
            json!({ "limit": 5, "cursor": cursor }),
        ),
    )
    .await;
    assert_mcp_structured_error(&replay, "mcp_page_cursor_invalid");

    // SNAPSHOT-RETAINED (ONE-1704 repair): a continuation is a continuation of
    // the IMMUTABLE producer snapshot its handle carries. An unrelated later
    // board epoch cannot make those retained rows wrong, so it does not destroy
    // the enumeration either — while every producer-identity axis above
    // (connector, tool, arguments) stays refused.
    let (_, fresh) = route_json(
        server.clone(),
        setup(credential, "cursor-4", json!({ "limit": 5 })),
    )
    .await;
    let retained_cursor = fresh["result"]["structuredContent"]["meta"]["page"]["cursor"]
        .as_str()
        .expect("a fresh successor handle")
        .to_owned();
    {
        let mut registry = server.mcp_registry.lock().await;
        let connection = registry
            .resolve(credential, 1, |_, _| true)
            .expect("credential resolves")
            .stream_connection;
        // A different board STATE advances the snapshot epoch by exactly one,
        // reading no clock at all.
        let moved = crate::mcp::mcp_board_state_hash("VaultWide", &["moved".to_owned()]);
        let latest = registry.board_snapshot_epoch(&connection, moved);
        assert!(
            latest > 1,
            "an unrelated board state moved this connection's latest epoch",
        );
    }
    let (_, continued) = route_json(
        server.clone(),
        setup(
            credential,
            "cursor-epoch-moved",
            json!({ "limit": 7, "cursor": retained_cursor.clone() }),
        ),
    )
    .await;
    assert!(
        continued.get("error").is_none(),
        "a moved unrelated board epoch must not refuse a retained continuation: {continued:?}"
    );
    let continued = &continued["result"]["structuredContent"];
    assert_eq!(
        mcp_setup_verb_names(continued),
        whole[5..].to_vec(),
        "the continuation returns exactly the retained producer remainder: {continued:?}"
    );
    assert_eq!(continued["meta"]["end"], Value::from("Complete"));
    // Still one-time: the handle the moved epoch did not invalidate is spent.
    let replayed = mcp_refusal(
        &server,
        setup(
            credential,
            "cursor-epoch-replay",
            json!({ "limit": 7, "cursor": retained_cursor }),
        ),
    )
    .await;
    assert_mcp_structured_error(&replayed, "mcp_page_cursor_invalid");
}

/// ONE-1704 M6: a live cursor from a read producer cannot reach a mutating
/// or subscription producer. The typed refusal happens before either facade or
/// dispatcher, and the retained cursor/stream state stays untouched.
#[tokio::test]
async fn mcp_cursor_refusal_precedes_mutating_and_subscription_dispatch() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00f1);
    let credential = "one-1704-cursor-pre-dispatch";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (_, first) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "preflight-setup",
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "page": { "limit": 1 } }),
            ),
        ),
    )
    .await;
    let cursor = first["result"]["structuredContent"]["meta"]["page"]["cursor"]
        .as_str()
        .expect("page one minted a live setup continuation")
        .to_owned();
    let cursor_handle = cursor.clone();
    let connection = {
        let registry = server.mcp_registry.lock().await;
        registry
            .resolve(credential, 1, |_, _| true)
            .expect("credential resolves")
            .stream_connection
    };
    let subscribed_before = {
        let mut registry = server.mcp_registry.lock().await;
        registry
            .streams_mut()
            .connection_state(&connection)
            .expect("the connector owns a stream connection")
            .subscribed
            .clone()
    };
    let task_ids_before = server
        .vault
        .memory(actor_ref, oneiron::EdgeActorClass::Human)
        .tasks_check()
        .expect("the task producer is readable")
        .rows
        .into_iter()
        .map(|row| row.id)
        .collect::<Vec<_>>();

    let create_refusal = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "preflight-create",
            "tasks.create",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "write_tasks"),
                json!({
                    "arguments": { "spec": { "kind": "review" } },
                    "page": { "cursor": cursor.clone() },
                }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&create_refusal, "mcp_page_cursor_invalid");

    let cancel_refusal = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "preflight-cancel",
            "tasks.cancel",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "write_tasks"),
                json!({
                    "arguments": { "task_ref": actor_ref.to_hex() },
                    "page": { "cursor": cursor.clone() },
                }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&cancel_refusal, "mcp_page_cursor_invalid");

    let subscribe_refusal = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "preflight-subscribe",
            "board.subscribe",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({
                    "arguments": { "scopes": ["my_tasks"] },
                    "page": { "cursor": cursor },
                }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&subscribe_refusal, "mcp_page_cursor_invalid");

    let task_ids_after = server
        .vault
        .memory(actor_ref, oneiron::EdgeActorClass::Human)
        .tasks_check()
        .expect("the task producer remains readable")
        .rows
        .into_iter()
        .map(|row| row.id)
        .collect::<Vec<_>>();
    assert_eq!(
        task_ids_after, task_ids_before,
        "cursor refusal did not create/cancel a task"
    );
    let mut registry = server.mcp_registry.lock().await;
    assert!(
        registry.page_continuation_live(&connection),
        "unsupported cursor presentations do not consume the live read continuation"
    );
    assert!(
        registry.page_continuation_live_cursor(&connection, &cursor_handle),
        "the refused presentations consumed no cursor at all, this one included"
    );
    assert_eq!(
        registry.live_page_continuations(&connection),
        1,
        "exactly the one live read continuation remains"
    );
    assert_eq!(
        registry
            .streams_mut()
            .connection_state(&connection)
            .expect("the stream connection remains attached")
            .subscribed,
        subscribed_before,
        "cursor refusal did not change board subscriptions",
    );
}

/// ONE-1704 repair: `tasks.expand` is a continuable READ producer.
///
/// Its continuation is served from the retained producer rows — proven by a
/// target the facade itself refuses — and a mutating verb still cannot use the
/// handle, which the untouched live continuation proves happened before
/// dispatch.
#[tokio::test]
async fn mcp_tasks_expand_continues_retained_rows_and_refuses_mutating_cursor_use() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0103);
    let credential = "one-1704-tasks-expand-cursor";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    // An entity that exists — so the scope gate admits it — but is not a TASK,
    // so the expand FACADE refuses it. A result that nevertheless returns rows
    // can only have come from the retained snapshot.
    let expand_args = mcp_merge_args(
        mcp_endpoint_envelope(actor_ref, "read_tasks"),
        json!({ "arguments": { "task_ref": actor_ref.to_hex() } }),
    );
    let direct = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "expand-direct",
            "tasks.expand",
            expand_args.clone(),
        ),
    )
    .await;
    assert_eq!(
        direct["error"]["data"]["error_code"],
        Value::from("facade_error"),
        "a cursorless expand of a non-task row reaches the facade and is refused: {direct:?}"
    );

    // The handle is minted for the EXACT payload this call carries: the digest
    // comes from the production binding, never a hand-built copy.
    let tool = crate::mcp::registered_surface(crate::mcp::McpSurfaceMode::ToolFirst)
        .resolve("tasks.expand")
        .expect("tasks.expand is registered on the tool-first endpoint");
    let crate::mcp::McpValidatedToolArgs::Verb(validated) =
        crate::mcp::validate_mcp_endpoint_tool_args(tool, expand_args.clone())
            .expect("the expand payload validates")
    else {
        panic!("tasks.expand must validate into the generated verb arm");
    };
    let digest = crate::mcp::mcp_page_argument_digest(&validated.payload);
    let retained = json!({
        "kind": "expanded",
        "lines": ["task line", "  realizing job", "  result=abc"],
    });
    let (connection, cursor) = {
        let mut registry = server.mcp_registry.lock().await;
        let connection = registry
            .resolve(credential, 1, |_, _| true)
            .expect("credential resolves")
            .stream_connection;
        let cursor = registry.mint_page_cursor_with_snapshot(
            &connection,
            "tasks.expand",
            digest,
            7,
            1,
            Some(crate::mcp::McpPageSnapshot {
                output: retained.clone(),
                source: crate::mcp::McpPageSource::complete(3),
                health: crate::mcp::McpRetrievalHealth::Healthy,
                keyframe: None,
            }),
        );
        (connection, cursor)
    };

    // A MUTATING verb is refused before dispatch and consumes nothing.
    let ack_refusal = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "expand-cursor-ack",
            "tasks.ack",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "ack_task"),
                json!({
                    "arguments": { "task_ref": actor_ref.to_hex() },
                    "page": { "cursor": cursor.clone() },
                }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&ack_refusal, "mcp_page_cursor_invalid");
    {
        let registry = server.mcp_registry.lock().await;
        assert!(
            registry.page_continuation_live_cursor(&connection, &cursor),
            "a mutating verb's refused cursor use consumes no live read continuation"
        );
    }

    let continued = mcp_endpoint_call_request(
        MCP_TOOL_FIRST_PATH,
        credential,
        "expand-cursor-continue",
        "tasks.expand",
        mcp_merge_args(
            expand_args.clone(),
            json!({ "page": { "limit": 50, "cursor": cursor.clone() } }),
        ),
    );
    let (status, continued) = route_json(server.clone(), continued).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        continued.get("error").is_none(),
        "the continuation is served from retained rows, not a second facade read: {continued:?}"
    );
    let structured = &continued["result"]["structuredContent"];
    assert_eq!(
        structured["output"]["lines"],
        json!(["  realizing job", "  result=abc"]),
        "page two is exactly the retained producer remainder: {structured:?}"
    );
    assert_eq!(structured["meta"]["end"], Value::from("Complete"));
    assert_eq!(structured["meta"]["page"]["returned"], Value::from(2));
    assert_eq!(structured["meta"]["page"]["scope_omitted"], Value::from(0));
    assert_eq!(
        structured["meta"]["page"]["window_truncated"],
        Value::from(0)
    );

    // ONE-TIME, exactly like every other continuation.
    let replay = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "expand-cursor-replay",
            "tasks.expand",
            mcp_merge_args(
                expand_args,
                json!({ "page": { "limit": 50, "cursor": cursor } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&replay, "mcp_page_cursor_invalid");
}

/// ONE-1704 repair: one connection holds SEVERAL live continuations and
/// consumes them independently.
#[tokio::test]
async fn mcp_two_live_cursors_on_one_connection_continue_independently() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0101);
    let credential = "one-1704-two-cursor-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    // Two different producer QUERIES on one connection: `board_budget_tok` is
    // bound argument identity, the page member is not.
    let setup = |id: &'static str, budget: u32, page: Value| {
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            id,
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "board_budget_tok": budget, "page": page }),
            ),
        )
    };
    let cursor_of = |body: &Value| {
        body["result"]["structuredContent"]["meta"]["page"]["cursor"]
            .as_str()
            .expect("a non-terminal page carries an opaque successor")
            .to_owned()
    };

    let (_, first) = route_json(
        server.clone(),
        setup("two-cursor-a1", 900, json!({ "limit": 2 })),
    )
    .await;
    let (_, second) = route_json(
        server.clone(),
        setup("two-cursor-b1", 1000, json!({ "limit": 3 })),
    )
    .await;
    let first_cursor = cursor_of(&first);
    let second_cursor = cursor_of(&second);
    assert_ne!(first_cursor, second_cursor);

    let connection = {
        let registry = server.mcp_registry.lock().await;
        let connection = registry
            .resolve(credential, 1, |_, _| true)
            .expect("credential resolves")
            .stream_connection;
        assert_eq!(
            registry.live_page_continuations(&connection),
            2,
            "a second More page does not destroy the first page's handle"
        );
        assert!(registry.page_continuation_live_cursor(&connection, &first_cursor));
        assert!(registry.page_continuation_live_cursor(&connection, &second_cursor));
        connection
    };

    let whole = mcp_expected_generated_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    // Consuming the SECOND handle consumes exactly that handle.
    let (_, second_page) = route_json(
        server.clone(),
        setup(
            "two-cursor-b2",
            1000,
            json!({ "limit": 50, "cursor": second_cursor }),
        ),
    )
    .await;
    let second_page = &second_page["result"]["structuredContent"];
    assert_eq!(mcp_setup_verb_names(second_page), whole[3..].to_vec());
    assert_eq!(second_page["meta"]["end"], Value::from("Complete"));
    {
        let registry = server.mcp_registry.lock().await;
        assert_eq!(
            registry.live_page_continuations(&connection),
            1,
            "consuming one cursor consumed only that cursor"
        );
        assert!(registry.page_continuation_live_cursor(&connection, &first_cursor));
    }

    // The first is still exactly where page one left it.
    let (_, first_page) = route_json(
        server.clone(),
        setup(
            "two-cursor-a2",
            900,
            json!({ "limit": 50, "cursor": first_cursor }),
        ),
    )
    .await;
    let first_page = &first_page["result"]["structuredContent"];
    assert_eq!(mcp_setup_verb_names(first_page), whole[2..].to_vec());
    assert_eq!(first_page["meta"]["end"], Value::from("Complete"));
    let registry = server.mcp_registry.lock().await;
    assert_eq!(registry.live_page_continuations(&connection), 0);
}

/// ONE-1704 repair: a client on the NEGOTIATED protocol receives usable result
/// data in `content`, not only through the `structuredContent` side channel.
#[tokio::test]
async fn mcp_results_carry_usable_data_in_negotiated_content() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0105);
    let credential = "one-1704-negotiated-content";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (_, handshake) = route_json(
        server.clone(),
        mcp_endpoint_request(
            "/mcp",
            credential,
            json!({ "jsonrpc": "2.0", "id": "negotiated-init", "method": "initialize" }),
        ),
    )
    .await;
    assert_eq!(
        handshake["result"]["protocolVersion"],
        Value::from(MCP_PROTOCOL_VERSION),
        "the content contract below is the one this handshake negotiates"
    );

    let (_, setup) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "negotiated-setup",
            "setup_oneiron",
            mcp_endpoint_envelope(actor_ref, "read_board"),
        ),
    )
    .await;
    let result = &setup["result"];
    let content = result["content"]
        .as_array()
        .expect("the negotiated result carries content");
    assert_eq!(content.len(), 2, "{result:?}");
    assert_eq!(content[0]["type"], Value::from("text"));
    assert_eq!(content[1]["type"], Value::from("text"));
    let data = serde_json::from_str::<Value>(
        content[1]["text"]
            .as_str()
            .expect("the data content item is text"),
    )
    .expect("the negotiated content item states the result data as JSON");
    assert_eq!(
        data, result["structuredContent"],
        "the negotiated content and the structured side channel state the SAME data"
    );
    assert_eq!(data["tool"], Value::from("setup_oneiron"));
    assert!(
        data["board"]["keyframe"]
            .as_str()
            .is_some_and(|text| !text.trim().is_empty()),
        "{data:?}"
    );
    assert_eq!(
        data["verb_grammar"]["verbs"].as_array().map(Vec::len),
        Some(mcp_expected_generated_names().len()),
    );
    assert_eq!(data["meta"]["end"], Value::from("Complete"));

    // A carrier frame stays BESIDE the result: it is not folded into the
    // negotiated content, and the content still states the tool's own data.
    let connection = {
        let registry = server.mcp_registry.lock().await;
        registry
            .resolve(credential, 1, |_, _| true)
            .expect("credential resolves")
            .stream_connection
    };
    {
        let mut registry = server.mcp_registry.lock().await;
        registry.enqueue_stream_frame(
            &connection,
            oneiron::context_board::BoardStreamFrame {
                epoch: 4,
                kind: oneiron::context_board::FrameKind::Keyframe("queued board".to_owned()),
            },
        );
    }
    let (_, checked) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "negotiated-check",
            "tasks.check",
            mcp_endpoint_envelope(actor_ref, "read_tasks"),
        ),
    )
    .await;
    let result = &checked["result"];
    assert_eq!(result["carrier"]["class"], Value::from("carrier"));
    let content = result["content"]
        .as_array()
        .expect("the negotiated result carries content");
    assert_eq!(content.len(), 2, "{result:?}");
    let data = serde_json::from_str::<Value>(
        content[1]["text"]
            .as_str()
            .expect("the data content item is text"),
    )
    .expect("the negotiated content item states the result data as JSON");
    assert_eq!(data, result["structuredContent"]);
    assert_eq!(data["tool"], Value::from("tasks.check"));
    assert_eq!(data["output"]["kind"], Value::from("tasks_section"));
    assert!(
        data.get("carrier").is_none(),
        "a carrier frame is never folded into the tool's own content: {data:?}"
    );
}

/// ONE-1704 repair: a board page's omission count is the REQUESTED SCOPE's
/// filtering only. A render window's truncation is stated on its own axis, and
/// a section the scope did not narrow is not reported partial because another
/// section was.
#[test]
fn mcp_board_page_omissions_count_requested_scope_only() {
    let expand = crate::mcp::McpVerbBinding::BoardExpand;
    let refresh = crate::mcp::McpVerbBinding::BoardRefresh;
    let subscribe = crate::mcp::McpVerbBinding::BoardSubscribe;
    let healthy = crate::mcp::McpRetrievalHealth::Healthy;
    let omissions = McpBoardOmissions {
        scope_omitted: 3,
        window_truncated: 2,
        source_exhausted: true,
    };

    let tasks = json!({ "kind": "expanded", "key": "TASKS", "lines": ["a", "b"] });
    let source = mcp_board_verb_page_source(expand, &tasks, omissions);
    assert_eq!(source.produced, 2);
    assert_eq!(source.scope_omitted, 3);
    assert_eq!(source.window_truncated, 2);
    assert_eq!(source.withheld(), 5);
    assert_eq!(source.health(), crate::mcp::McpRetrievalHealth::Partial);

    // Another section's page is not partial because a TASKS row was outside
    // the credential's ceiling.
    let verbs = json!({ "kind": "expanded", "key": "VERBS", "lines": ["board.expand"] });
    let source = mcp_board_verb_page_source(expand, &verbs, omissions);
    assert_eq!(source.produced, 1);
    assert_eq!(source.scope_omitted, 0);
    assert_eq!(source.window_truncated, 0);
    assert_eq!(source.health(), healthy);

    // A refresh renders the whole board, so both axes ride it — apart.
    let frame = json!({ "kind": "frame", "frame": { "epoch": 1 } });
    let source = mcp_board_verb_page_source(refresh, &frame, omissions);
    assert_eq!(source.produced, 1);
    assert_eq!(source.scope_omitted, 3);
    assert_eq!(source.window_truncated, 2);

    // A capped scan is a WINDOW fact and is degraded, never a scope omission.
    let capped_scan = McpBoardOmissions {
        scope_omitted: 0,
        window_truncated: 4,
        source_exhausted: false,
    };
    let capped = mcp_board_verb_page_source(refresh, &frame, capped_scan);
    assert_eq!(capped.scope_omitted, 0);
    assert_eq!(capped.window_truncated, 4);
    assert_eq!(capped.health(), crate::mcp::McpRetrievalHealth::Degraded);

    // A subscription receipt states itself completely on both axes.
    let receipt = json!({ "kind": "subscription", "active": [] });
    let source = mcp_board_verb_page_source(subscribe, &receipt, omissions);
    assert_eq!(source.scope_omitted, 0);
    assert_eq!(source.window_truncated, 0);
    assert_eq!(source.health(), healthy);
}

/// ONE-1704 repair: setup health is derived from the board's COMPLETE omission
/// facts, not from the requested scope's filtering alone.
///
/// A vault-wide connector omits no row by scope, so the old derivation called
/// EVERY board it rendered healthy — including one whose render WINDOW had
/// truncated rows away, and one whose own TASK scan stopped at its cap and so
/// cannot say what it skipped. Both are incomplete boards, and setup said
/// `healthy` over them.
#[test]
fn mcp_setup_health_reads_every_board_omission_axis() {
    let omissions = |scope_omitted, window_truncated, source_exhausted| McpBoardOmissions {
        scope_omitted,
        window_truncated,
        source_exhausted,
    };
    let healthy = crate::mcp::McpRetrievalHealth::Healthy;
    let partial = crate::mcp::McpRetrievalHealth::Partial;
    let degraded = crate::mcp::McpRetrievalHealth::Degraded;

    // A complete board is the only healthy one.
    assert_eq!(omissions(0, 0, true).health(), healthy);

    // The exact defect: a vault-wide connector's board whose bounded renderer
    // could not return every TASKS row. Nothing was omitted by scope, and the
    // board is still incomplete.
    assert_eq!(omissions(0, 7, true).health(), partial);

    // A scan that stopped at its own cap does not know what it skipped, so it
    // is degraded even with nothing counted on either axis.
    assert_eq!(omissions(0, 0, false).health(), degraded);
    assert_eq!(omissions(0, 7, false).health(), degraded);

    // The scope axis keeps its settled meaning, and the two axes together
    // never read healthier than either alone.
    assert_eq!(omissions(3, 0, true).health(), partial);
    assert_eq!(omissions(3, 7, true).health(), partial);
    assert_eq!(omissions(3, 0, false).health(), degraded);

    // It is the SAME derivation every other producer states, so a board's
    // health and a page's health cannot drift apart.
    for (scope_omitted, window_truncated, source_exhausted) in [
        (0, 0, true),
        (0, 7, true),
        (3, 0, true),
        (3, 7, true),
        (0, 0, false),
        (3, 7, false),
    ] {
        assert_eq!(
            omissions(scope_omitted, window_truncated, source_exhausted).health(),
            crate::mcp::McpPageSource::scoped_window(
                0,
                scope_omitted,
                window_truncated,
                source_exhausted,
            )
            .health(),
            "board health and producer health must be one meaning",
        );
    }
}

/// ONE-1704 repair: `/api/core/discover` describes the MCP surfaces this
/// process actually REGISTERS, and says which endpoint each name is callable
/// on.
///
/// The capability vocabulary used to be derived from the retired plain-verb
/// catalog alone, so discovery advertised names both endpoints answer
/// `unknown_tool` for and advertised none of the names they do accept.
#[test]
fn discovery_states_the_registered_mcp_surfaces_and_their_endpoints() {
    let flags = serde_json::to_value(feature_flags()).expect("feature flags serialize");
    let capabilities = flags["capabilities"]
        .as_array()
        .expect("capabilities is an array")
        .iter()
        .map(|token| token.as_str().expect("a capability is a string").to_owned())
        .collect::<Vec<_>>();

    // Every REGISTERED tool is advertised, and its endpoint is named beside it.
    let mut expected_endpoint_tokens = std::collections::BTreeSet::new();
    for mode in crate::mcp::McpSurfaceMode::ALL {
        let surface = crate::mcp::registered_surface(mode);
        assert!(
            !surface.tool_names().is_empty(),
            "{} registers at least one tool",
            mode.as_str()
        );
        for name in surface.tool_names() {
            assert!(
                surface.resolve(name).is_some(),
                "{name} is advertised only because {} accepts it",
                mode.as_str(),
            );
            assert!(
                capabilities.contains(&format!("{MCP_TOOL_CAPABILITY_PREFIX}{name}")),
                "discovery advertises the registered tool {name}",
            );
            expected_endpoint_tokens.insert(format!(
                "{MCP_ENDPOINT_CAPABILITY_PREFIX}{mode}.{name}",
                mode = mode.as_str(),
            ));
        }
    }

    // The endpoint vocabulary is EXACTLY the registrations: nothing advertised
    // that a surface would reject, and nothing registered left unstated.
    let advertised_endpoint_tokens = capabilities
        .iter()
        .filter(|token| token.starts_with(MCP_ENDPOINT_CAPABILITY_PREFIX))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(advertised_endpoint_tokens, expected_endpoint_tokens);
    assert_eq!(
        capabilities
            .iter()
            .filter(|token| token.starts_with(MCP_ENDPOINT_CAPABILITY_PREFIX))
            .count(),
        expected_endpoint_tokens.len(),
        "each endpoint token is advertised exactly once",
    );

    // The primary endpoint is the ONE setup tool, and the verbs live on the
    // tool-first endpoint. A caller can tell them apart from discovery alone.
    assert!(capabilities.contains(&format!(
        "{MCP_ENDPOINT_CAPABILITY_PREFIX}primary.{}",
        crate::mcp::MCP_SETUP_TOOL
    )));
    assert!(capabilities.contains(&format!(
        "{MCP_ENDPOINT_CAPABILITY_PREFIX}tool_first.tasks.create"
    )));
    assert!(
        !capabilities.contains(&format!(
            "{MCP_ENDPOINT_CAPABILITY_PREFIX}tool_first.{}",
            crate::mcp::MCP_SETUP_TOOL
        )),
        "a tool one endpoint registers is not advertised on the other",
    );

    // `execute_code` is registered on neither endpoint in this release, so no
    // endpoint token names it.
    for mode in crate::mcp::McpSurfaceMode::ALL {
        assert!(
            crate::mcp::registered_surface(mode)
                .resolve(crate::mcp::MCP_EXECUTE_CODE_TOOL)
                .is_none(),
        );
        assert!(!capabilities.contains(&format!(
            "{MCP_ENDPOINT_CAPABILITY_PREFIX}{mode}.{tool}",
            mode = mode.as_str(),
            tool = crate::mcp::MCP_EXECUTE_CODE_TOOL,
        )));
    }

    // Discovery stays deterministic: the same registrations, the same bytes.
    assert_eq!(
        serde_json::to_value(feature_flags()).expect("feature flags serialize"),
        flags,
    );
}

#[tokio::test]
async fn mcp_carrier_drains_exactly_once_on_next_arbitrary_result() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00c1);
    let credential = "one-1704-carrier-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let connection = {
        let registry = server.mcp_registry.lock().await;
        registry
            .resolve(credential, 1, |_, _| true)
            .expect("credential resolves")
            .stream_connection
    };
    {
        let mut registry = server.mcp_registry.lock().await;
        registry.enqueue_stream_frame(
            &connection,
            oneiron::context_board::BoardStreamFrame {
                epoch: 5,
                kind: oneiron::context_board::FrameKind::Keyframe("queued board".to_owned()),
            },
        );
        registry.enqueue_stream_frame(
            &connection,
            oneiron::context_board::BoardStreamFrame {
                epoch: 5,
                kind: oneiron::context_board::FrameKind::Delta(vec![
                    oneiron::context_board::DeltaRow {
                        key: "TASKS:0".to_owned(),
                        line: "queued".to_owned(),
                    },
                ]),
            },
        );
    }

    let check = |id: &'static str| {
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            id,
            "tasks.check",
            mcp_endpoint_envelope(actor_ref, "read_tasks"),
        )
    };

    // The NEXT arbitrary successful result — a `tasks.*` one, which used to
    // strand the queue forever — carries exactly one top-level carrier frame,
    // beside the semantic content and never inside it. The engine hands back
    // the pending KEYFRAME first.
    let (status, first) = route_json(server.clone(), check("carrier-1")).await;
    assert_eq!(status, StatusCode::OK);
    let result = &first["result"];
    assert_eq!(result["carrier"]["class"], Value::from("carrier"));
    assert!(result["carrier"]["frame"].is_object(), "{result:?}");
    assert_eq!(
        result["carrier"]["frame"]["epoch"],
        Value::from(5),
        "{result:?}"
    );
    assert_eq!(
        result["carrier"]["frame"]["kind"]["kind"],
        Value::from("keyframe"),
        "result one carries the keyframe: {result:?}"
    );
    assert_eq!(
        result["carrier"]["frame"]["kind"]["payload"],
        Value::from("queued board"),
        "{result:?}"
    );
    assert!(
        result["structuredContent"].get("carrier").is_none(),
        "a frame is data BESIDE the result, never inside it: {result:?}"
    );

    // ONE-1704 M7: the same-epoch delta the engine kept behind that keyframe is
    // a NEWER transition, so it rides the NEXT result instead of being drained
    // away. Exactly one frame per result, and zero transitions lost.
    let (_, second) = route_json(server.clone(), check("carrier-2")).await;
    let second_frame = &second["result"]["carrier"]["frame"];
    assert_eq!(second["result"]["carrier"]["class"], Value::from("carrier"));
    assert_eq!(second_frame["epoch"], Value::from(5), "{second:?}");
    assert_eq!(
        second_frame["kind"]["kind"],
        Value::from("delta"),
        "result two carries the same-epoch delta: {second:?}"
    );
    assert_eq!(
        second_frame["kind"]["payload"][0]["key"],
        Value::from("TASKS:0"),
        "{second:?}"
    );
    assert_eq!(
        second_frame["kind"]["payload"][0]["line"],
        Value::from("queued"),
        "{second:?}"
    );

    // And the call after THAT carries none: nothing is replayed.
    let (_, third) = route_json(server.clone(), check("carrier-3a")).await;
    assert!(
        third["result"].get("carrier").is_none(),
        "the queue drains exactly once per frame: {third:?}"
    );

    // A setup keyframe supersedes and DRAINS what is queued behind it, so a
    // fresh keyframe never rides beside an older carrier and the next result
    // does not inherit one either.
    {
        let mut registry = server.mcp_registry.lock().await;
        registry.enqueue_stream_frame(
            &connection,
            oneiron::context_board::BoardStreamFrame {
                epoch: 6,
                kind: oneiron::context_board::FrameKind::Keyframe("stale board".to_owned()),
            },
        );
    }
    let (_, setup) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "carrier-setup",
            "setup_oneiron",
            mcp_endpoint_envelope(actor_ref, "read_board"),
        ),
    )
    .await;
    assert!(setup["result"].get("carrier").is_none(), "{setup:?}");
    let (_, after_setup) = route_json(server, check("carrier-3")).await;
    assert!(
        after_setup["result"].get("carrier").is_none(),
        "setup superseded and drained the older queue: {after_setup:?}"
    );
}
