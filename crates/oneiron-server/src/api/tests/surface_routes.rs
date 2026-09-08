//! Health/runtime/discover redaction, outbound capability contracts, local artifact serving, context-board seed check.

use super::*;

#[tokio::test]
async fn context_board_hides_fresh_default_policy_manifest() {
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

    let request = json_request("POST", "/v1/core/context-board", json!({}));
    let (status, body) = route_json(server, request).await;

    assert_eq!(status, StatusCode::OK);
    // The engine-seeded POLICY MANIFEST stays hidden (it is the one
    // agent-invisible type). The seeded AGENT_DEF rows (six from ONE-1890,
    // plus ONE-1709's sys.team_lead — seven) are ordinary
    // agent-visible entities and DO appear — they are real dispatchable agents
    // a hydrating caller must see — so `last_activity` carries their pinned
    // seed timestamp rather than staying null.
    let counts = body["session"]["counts"]
        .as_object()
        .expect("session counts");
    assert_eq!(
        counts.get(&ENTITY_TYPE_POLICY_MANIFEST.to_string()),
        None,
        "the engine-seeded policy manifest must stay out of context-board counts"
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
