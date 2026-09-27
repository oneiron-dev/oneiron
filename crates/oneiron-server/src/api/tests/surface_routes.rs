//! Health/runtime/discover redaction, outbound capability contracts, local artifact serving, context-board seed check.

use super::*;
use axum::http::header::{CONTENT_DISPOSITION, X_CONTENT_TYPE_OPTIONS};

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
        &serde_json::Map::from_iter([
            (
                oneiron::registry::ENTITY_TYPE_CLAIM.to_string(),
                Value::from(8)
            ),
            (
                oneiron::registry::ENTITY_TYPE_SKILL_CONTENT_ANCHOR.to_string(),
                Value::from(4)
            ),
            (
                oneiron::registry::ENTITY_TYPE_SKILL_HUB.to_string(),
                Value::from(1)
            ),
            (
                oneiron::registry::ENTITY_TYPE_AGENT_DEF.to_string(),
                Value::from(7)
            ),
            (
                oneiron::registry::ENTITY_TYPE_SKILL.to_string(),
                Value::from(4)
            ),
            (
                oneiron::registry::ENTITY_TYPE_ASSET.to_string(),
                Value::from(4)
            ),
            (
                oneiron::registry::ENTITY_TYPE_CONVERSATION.to_string(),
                Value::from(1)
            ),
            (
                oneiron::workspace_roster::PROJECT_TYPE_BYTE.to_string(),
                Value::from(1)
            ),
            (
                oneiron::registry::ENTITY_TYPE_PERSON.to_string(),
                Value::from(1)
            ),
            (
                oneiron::registry::ENTITY_TYPE_FACET.to_string(),
                Value::from(1)
            ),
        ]),
        "a fresh vault exposes its agents, bootstrap skills, root project room and owner"
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
    let mut advertised_fields: Vec<&str> = outbound["field_contract"]
        .as_array()
        .expect("field contract")
        .iter()
        .map(|field| field.as_str().expect("field name"))
        .collect();
    let mut expected_fields = oneiron::OUTBOUND_VERB_FIELD_CONTRACT.to_vec();
    advertised_fields.sort_unstable();
    expected_fields.sort_unstable();
    assert_eq!(advertised_fields, expected_fields);
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
        .publish_artifact_pointer_with_tier(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &first.snapshot.fork_hash,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("publish first artifact pointer");

    let (status, headers, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/_s/c/published/")
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
            .uri("/a/site/_s/c/published/")
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
        Some("/a/site/_s/c/published/")
    );

    commit_artifact_index(repo.path(), b"<h1>v2</h1>\n", "second");
    let second = ingest_artifact_snapshot(&server, repo.path(), "site", 20);

    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/_s/c/published/index.html")
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<h1>v1</h1>\n");

    let direct_fork_uri = format!(
        "/a/site/_s/f/{}/index.html",
        oneiron::artifact_hex(&second.snapshot.fork_hash)
    );
    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(direct_fork_uri)
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.is_empty());

    server
        .vault
        .publish_artifact_pointer_with_tier(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &second.snapshot.fork_hash,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("repoint artifact pointer");
    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/_s/c/published/")
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
            .uri("/a/site/_s/c/published/")
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let old_fork_uri = format!(
        "/a/site/_s/f/{}/index.html",
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
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.is_empty());
}

#[tokio::test]
async fn local_blob_artifact_route_serves_pinned_and_direct_versions() {
    let (_dir, server) = test_server();
    let artifact_id = oneiron::EntityId::now();
    let artifact_body =
        oneiron::blob_artifact::BlobArtifactBody::new("report.pdf", "application/pdf");
    server
        .vault
        .put_blob_artifact(
            &artifact_id,
            &artifact_body,
            oneiron::TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("create blob artifact");

    let actor_id = oneiron::EntityId::now();
    server
        .vault
        .put_entity(
            &actor_id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 10, end: 10 },
            10,
            b"uploader",
        )
        .expect("create blob uploader");
    let actor = oneiron::WriteActor::new(actor_id, oneiron::EdgeActorClass::Human);
    let first = server
        .vault
        .append_blob_artifact_version(
            &artifact_id,
            b"%PDF-1.7\nfirst version",
            &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
            actor,
            oneiron::TimeRange { start: 11, end: 11 },
            11,
        )
        .expect("append first blob version");
    let second = server
        .vault
        .append_blob_artifact_version(
            &artifact_id,
            b"%PDF-1.7\nsecond version",
            &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
            actor,
            oneiron::TimeRange { start: 12, end: 12 },
            12,
        )
        .expect("append second blob version");
    assert_eq!((first.version, second.version), (1, 2));

    let unpublished_route = format!("/a/{}/_s/c/published/export", artifact_id.to_hex());
    let (status, _, _) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&unpublished_route)
            .body(Body::empty())
            .expect("unpublished blob request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &artifact_id,
            oneiron::ArtifactPointerChannel::Published,
            first.version,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("pin published blob version");
    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &artifact_id,
            oneiron::ArtifactPointerChannel::Preview,
            second.version,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("pin preview blob version");

    let route = format!("/a/{}/_s/c/published/report.pdf", artifact_id.to_hex());
    let (status, headers, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&route)
            .body(Body::empty())
            .expect("published blob request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"%PDF-1.7\nfirst version");
    assert_eq!(
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/pdf")
    );
    assert_eq!(
        headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some(BLOB_POINTER_CACHE_CONTROL)
    );

    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/{}/_s/c/published/export", artifact_id.to_hex()))
            .body(Body::empty())
            .expect("stable export request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"%PDF-1.7\nfirst version");

    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/{}/_s/c/published/", artifact_id.to_hex()))
            .body(Body::empty())
            .expect("blob root request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"%PDF-1.7\nfirst version");

    let preview_route = format!("/a/{}/_s/c/preview/report.pdf", artifact_id.to_hex());
    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&preview_route)
            .body(Body::empty())
            .expect("preview blob request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"%PDF-1.7\nsecond version");

    let direct_route = format!(
        "/a/{}/_s/b/{}/report.pdf",
        artifact_id.to_hex(),
        first.version
    );
    let (status, headers, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&direct_route)
            .body(Body::empty())
            .expect("direct blob version request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"%PDF-1.7\nfirst version");
    assert_eq!(
        headers
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some(BLOB_IMMUTABLE_CACHE_CONTROL)
    );

    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &artifact_id,
            oneiron::ArtifactPointerChannel::Published,
            second.version,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("repoint published blob version");
    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &artifact_id,
            oneiron::ArtifactPointerChannel::Preview,
            first.version,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("repoint preview blob version");
    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&route)
            .body(Body::empty())
            .expect("repointed published blob request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"%PDF-1.7\nsecond version");
    let repointed_preview_route = format!("/a/{}/_s/c/preview/report.pdf", artifact_id.to_hex());
    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&repointed_preview_route)
            .body(Body::empty())
            .expect("repointed preview blob request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"%PDF-1.7\nfirst version");

    server
        .vault
        .unpublish_blob_artifact_pointer(&artifact_id, oneiron::ArtifactPointerChannel::Published)
        .expect("unpublish published blob version");
    let (status, _, _) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&route)
            .body(Body::empty())
            .expect("unpublished default blob request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&repointed_preview_route)
            .body(Body::empty())
            .expect("preview remains published request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"%PDF-1.7\nfirst version");
    server
        .vault
        .unpublish_blob_artifact_pointer(&artifact_id, oneiron::ArtifactPointerChannel::Preview)
        .expect("unpublish preview blob version");

    let (status, _, _) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&repointed_preview_route)
            .body(Body::empty())
            .expect("unpublished preview blob request"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&direct_route)
            .body(Body::empty())
            .expect("direct blob version after unpublish"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.is_empty());

    for invalid_route in [
        format!("/a/{}/report.pdf?blobVersion=0", artifact_id.to_hex()),
        format!(
            "/a/{}/report.pdf?blobVersion={}&channel=published",
            artifact_id.to_hex(),
            first.version
        ),
        format!(
            "/a/{}/report.pdf?blobVersion={}&forkHash={}",
            artifact_id.to_hex(),
            first.version,
            "00".repeat(32)
        ),
    ] {
        let (status, _, body) = route_bytes(
            server.clone(),
            Request::builder()
                .uri(&invalid_route)
                .body(Body::empty())
                .expect("invalid blob selector request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid_route}");
        let error: Value = serde_json::from_slice(&body).expect("error JSON");
        assert_error_envelope(&error, "BAD_REQUEST");
    }

    // An exported HTML blob is not a trusted site bundle: serving its bytes
    // must not execute same-origin script, even with a forged active MIME.
    let active_id = oneiron::EntityId::now();
    server
        .vault
        .put_blob_artifact(
            &active_id,
            &oneiron::blob_artifact::BlobArtifactBody::new("report.html", "text/html"),
            oneiron::TimeRange { start: 20, end: 20 },
            20,
        )
        .expect("create active-media blob");
    server
        .vault
        .append_blob_artifact_version(
            &active_id,
            b"<script>alert(1)</script>",
            &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
            actor,
            oneiron::TimeRange { start: 21, end: 21 },
            21,
        )
        .expect("append active-media blob");
    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &active_id,
            oneiron::ArtifactPointerChannel::Published,
            1,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("publish active-media blob");
    let (status, headers, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/{}/_s/c/published/export", active_id.to_hex()))
            .body(Body::empty())
            .expect("active-media request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<script>alert(1)</script>");
    assert_eq!(headers[CONTENT_TYPE], "application/octet-stream");
    assert_eq!(headers[CONTENT_DISPOSITION], "attachment");
    assert_eq!(headers[X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(headers[CACHE_CONTROL], BLOB_POINTER_CACHE_CONTROL);
    let attachment_etag = headers[ETAG].clone();

    // Direct export URLs require a live pin. Re-pin this immutable version
    // before testing that a later mutable body edit cannot change its bytes
    // or presentation.
    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &artifact_id,
            oneiron::ArtifactPointerChannel::Published,
            first.version,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("re-pin first blob version");
    // The blob body is mutable, but this URL and its response headers are not.
    server
        .vault
        .put_blob_artifact(
            &artifact_id,
            &oneiron::blob_artifact::BlobArtifactBody::new("renamed.txt", "text/plain"),
            oneiron::TimeRange { start: 30, end: 30 },
            30,
        )
        .expect("re-put mutable artifact body");
    let (status, headers, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&direct_route)
            .body(Body::empty())
            .expect("pinned version after body re-put"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"%PDF-1.7\nfirst version");
    assert_eq!(headers[CONTENT_TYPE], "application/pdf");
    assert_eq!(headers[CACHE_CONTROL], BLOB_IMMUTABLE_CACHE_CONTROL);
    assert_eq!(
        headers[ETAG],
        format!(
            "\"blob-{}-{}-{}\"",
            artifact_id.to_hex(),
            first.version,
            oneiron::artifact_hex(blake3::hash(b"%PDF-1.7\nfirst version").as_bytes())
        )
    );
    let old_pdf_etag = headers[ETAG].clone();
    let renamed_direct = format!(
        "/a/{}/_s/b/{}/renamed.txt",
        artifact_id.to_hex(),
        first.version
    );
    let (status, _, _) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(renamed_direct)
            .body(Body::empty())
            .expect("new name must not replace pinned name"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A same-byte fork with a different pinned media type must revalidate as
    // a new representation, not replay a stale 304 from the previous version.
    let plain = server
        .vault
        .fork_blob_artifact_version(
            &artifact_id,
            first.version,
            b"%PDF-1.7\nfirst version",
            &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
            actor,
            oneiron::TimeRange { start: 31, end: 31 },
            31,
        )
        .expect("same-byte plain-text fork");
    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &artifact_id,
            oneiron::ArtifactPointerChannel::Published,
            plain.version,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("repoint to plain-text fork");
    let (status, headers, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/{}/_s/c/published/export", artifact_id.to_hex()))
            .header(IF_NONE_MATCH, old_pdf_etag.clone())
            .body(Body::empty())
            .expect("conditional MIME repoint"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"%PDF-1.7\nfirst version");
    assert_eq!(headers[CONTENT_TYPE], "text/plain; charset=utf-8");
    assert_ne!(headers[ETAG], old_pdf_etag);

    // Moving from an attachment to inline PDF with identical bytes must also
    // return 200, so an old Content-Disposition cannot stick in a cache.
    server
        .vault
        .put_blob_artifact(
            &active_id,
            &oneiron::blob_artifact::BlobArtifactBody::new("report.pdf", "application/pdf"),
            oneiron::TimeRange { start: 32, end: 32 },
            32,
        )
        .expect("re-put active blob presentation");
    let inline = server
        .vault
        .fork_blob_artifact_version(
            &active_id,
            1,
            b"<script>alert(1)</script>",
            &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
            actor,
            oneiron::TimeRange { start: 33, end: 33 },
            33,
        )
        .expect("same-byte inline fork");
    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &active_id,
            oneiron::ArtifactPointerChannel::Published,
            inline.version,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("repoint from attachment to inline");
    let (status, headers, body) = route_bytes(
        server,
        Request::builder()
            .uri(format!("/a/{}/_s/c/published/export", active_id.to_hex()))
            .header(IF_NONE_MATCH, attachment_etag.clone())
            .body(Body::empty())
            .expect("conditional attachment repoint"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<script>alert(1)</script>");
    assert_eq!(headers[CONTENT_TYPE], "application/pdf");
    assert!(!headers.contains_key(CONTENT_DISPOSITION));
    assert_ne!(headers[ETAG], attachment_etag);
}

#[tokio::test]
async fn local_artifact_route_public_bypasses_api_auth_when_configured() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        allow_unauthenticated: false,
        ..Default::default()
    });
    let repo = create_artifact_repo(b"<h1>public</h1>\n");
    let snapshot = ingest_artifact_snapshot(&server, repo.path(), "site", 10);
    server
        .vault
        .publish_artifact_pointer_with_tier(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &snapshot.snapshot.fork_hash,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("publish artifact pointer");

    let (status, _, _) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/_s/c/published/")
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = route_bytes(
        server,
        Request::builder()
            .uri("/a/site/_s/c/published/")
            .header(AUTHORIZATION, owner_bearer())
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"<h1>public</h1>\n");
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
        .publish_artifact_pointer_with_tier(
            "site",
            oneiron::ArtifactPointerChannel::Preview,
            &ingest.snapshot.fork_hash,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .expect("publish preview pointer");

    let (status, _, body) = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/_s/c/preview/index.html")
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

#[tokio::test]
async fn configured_cimd_documents_are_served_without_client_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                oauth_resource_indicator: Some("https://oneiron.test".into()),
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    for application in ["native", "web"] {
        let path = format!("/oauth/client/{application}.json");
        let request = Request::builder().uri(&path).body(Body::empty()).unwrap();
        let (status, body) = route_json(server.clone(), request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["application_type"], application);
        assert_eq!(body["client_id"], format!("https://oneiron.test{path}"));
        assert!(body.get("sampling").is_none());
        assert!(body.get("roots").is_none());
    }
}

/// Build a real signed authority DAG: P bound to G and H concurrently, Q
/// bound to G. P elects H, so G's Q pact is Active while its historical P
/// binding is discarded and suspended. Disconnecting P must keep G denied.
fn bind_artifact_member_to_divergent_pacts(
    vault: &oneiron::Vault,
    grant_g: oneiron::EntityId,
) -> oneiron::authority::AuthorityLogEntry {
    use ed25519_dalek::{Signer, SigningKey};
    use oneiron::authority::{
        AUTHORITY_LOG_SCHEMA_VERSION, AuthorityKey, AuthorityLogEntry, AuthorityOp,
        AuthoritySignature, FederationLifecycleAction, FederationLifecycleKind,
        authority_entry_hash, authority_transcript, federation_scope_digest,
        sign_federation_pact_gesture,
    };
    use oneiron::federation::{
        FederationDirectionScope, FederationPactScope, FederationScopeBands, FederationScopeFacets,
        FederationScopeWorlds, encode_federation_pact_scope,
    };
    let signing = SigningKey::from_bytes(&blake3::derive_key(
        "oneiron/host-authority-signing/v2",
        b"secret",
    ));
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(b"secret").unwrap();
    let host_key = issuer.public_key();
    assert_eq!(signing.verifying_key().to_bytes(), issuer.binding_key());
    let fold = vault.authority_fold().unwrap();
    let vault_id = fold.vault_id.unwrap();
    let mut heads = fold.valid_entries.clone();
    let mut seq = 0_u64;
    for id in vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap()
    {
        let row = vault.get_authority_log_entry(&id).unwrap().unwrap();
        let hash = authority_entry_hash(&row).unwrap();
        if !fold.valid_entries.contains(&hash) {
            continue;
        }
        for parent in &row.parent_hashes {
            heads.remove(parent);
        }
        if row.signer.public_key == host_key {
            seq = seq.max(row.seq + 1);
        }
    }
    let peer = SigningKey::from_bytes(&[0x6d; 32]);
    let peer_key = AuthorityKey::Ed25519(peer.verifying_key().to_bytes());
    let peer_id = [0x6e; 32];
    let half = FederationDirectionScope {
        worlds: FederationScopeWorlds::All,
        facets: FederationScopeFacets::All,
        bands: FederationScopeBands::All,
    };
    let scope = FederationPactScope {
        lo_to_hi: half.clone(),
        hi_to_lo: half,
    };
    let grant_h =
        oneiron::EntityId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
    assert!(
        grant_h < grant_g,
        "fixture needs H < G for the divergent winner"
    );
    let p = [0xd4; 32];
    let q = [0xd5; 32];
    let nonce_p = [0x77; 16];
    let nonce_q = [0x78; 16];
    let entry = |seq: u64, parents: Vec<[u8; 32]>, action: FederationLifecycleAction| {
        let mut row = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq,
            parent_hashes: parents,
            op: AuthorityOp::FederationLifecycle(action),
            signer: AuthoritySignature {
                suite: host_key.suite(),
                public_key: host_key.clone(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: vault.now_recorded_at(),
        };
        row.signer.signature = signing
            .sign(&authority_transcript(&row).unwrap())
            .to_bytes()
            .to_vec();
        row
    };
    let connect = |pact_id: [u8; 32], grant: oneiron::EntityId, nonce: [u8; 16]| {
        let digest =
            federation_scope_digest(&nonce, &encode_federation_pact_scope(&scope).unwrap());
        let gesture = sign_federation_pact_gesture(
            FederationLifecycleKind::Connect,
            &pact_id,
            &vault_id,
            &peer_id,
            1,
            &digest,
            None,
            &nonce,
            peer_key.clone(),
            |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
        )
        .unwrap();
        FederationLifecycleAction {
            kind: FederationLifecycleKind::Connect,
            pact_id,
            grant_ref: grant,
            peer_vault_id: peer_id,
            pact_epoch: 1,
            pact_scope: Some(scope.clone()),
            effective_scope: None,
            scope_digest: Some(digest),
            gesture: Some(gesture),
            successor_vault_id: None,
            pact_nonce: nonce,
        }
    };
    let parents: Vec<_> = heads.into_iter().collect();
    let pg = entry(seq, parents.clone(), connect(p, grant_g, nonce_p));
    let ph = entry(seq + 1, parents.clone(), connect(p, grant_h, nonce_p));
    let qg = entry(seq + 2, parents, connect(q, grant_g, nonce_q));
    let pg_hash = authority_entry_hash(&pg).unwrap();
    let ph_hash = authority_entry_hash(&ph).unwrap();
    let now = vault.now_recorded_at();
    for row in [&pg, &ph, &qg] {
        vault
            .put_authority_log_entry(
                row,
                oneiron::TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .unwrap();
    }
    let fold = vault.authority_fold().unwrap();
    assert_eq!(
        fold.pact_for_grant(&grant_g).map(|p| p.status),
        Some(oneiron::authority::FederationPactStatus::Active)
    );
    assert!(matches!(
        oneiron::authority::federation_grant_activation(&fold, &grant_g),
        oneiron::authority::FederationGrantActivation::Inactive(
            oneiron::authority::FederationPactStatus::Suspended
        )
    ));
    entry(
        seq + 3,
        vec![pg_hash, ph_hash],
        FederationLifecycleAction {
            kind: FederationLifecycleKind::Disconnect,
            pact_id: p,
            grant_ref: grant_h,
            peer_vault_id: peer_id,
            pact_epoch: 1,
            pact_scope: None,
            effective_scope: None,
            scope_digest: None,
            gesture: None,
            successor_vault_id: None,
            pact_nonce: nonce_p,
        },
    )
}

#[tokio::test]
async fn artifact_tiers_bind_tokens_and_live_world_grants_without_an_existence_oracle() {
    fn stable_error(bytes: &Bytes) -> Value {
        let mut body: Value = serde_json::from_slice(bytes).expect("error envelope");
        body["error"].as_object_mut().unwrap().remove("requestId");
        body
    }
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        allow_unauthenticated: false,
        ..Default::default()
    });
    let repo = create_artifact_repo(
        b"<link rel=\"stylesheet\" href=\"style.css\"><script src=\"app.js\"></script><a href=\"next.html\">next</a>\n",
    );
    std::fs::write(repo.path().join("style.css"), b"body { color: red; }\n").unwrap();
    std::fs::write(repo.path().join("next.html"), b"<h1>next</h1>\n").unwrap();
    run_artifact_git(repo.path(), &["add", "."]);
    run_artifact_git(repo.path(), &["commit", "-m", "bundle resources"]);
    let snapshot = ingest_artifact_snapshot(&server, repo.path(), "site", 10);
    let hash = snapshot.snapshot.fork_hash;
    let (tier, token) = oneiron::artifact_hosting::ArtifactServeTier::mint_link_token();
    server
        .vault
        .publish_artifact_pointer_with_tier(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &hash,
            tier,
        )
        .unwrap();
    let denied = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/_s/c/published/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let missing = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/missing/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(denied.0, StatusCode::NOT_FOUND);
    assert_eq!(
        (denied.0, stable_error(&denied.2)),
        (missing.0, stable_error(&missing.2))
    );
    let wrong = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/site/_t/{}/", "a".repeat(64)))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        (wrong.0, stable_error(&wrong.2)),
        (missing.0, stable_error(&missing.2))
    );
    let query_only = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/site/?token={token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        (query_only.0, stable_error(&query_only.2)),
        (missing.0, stable_error(&missing.2)),
        "a query token cannot carry into relative resources"
    );
    let requested_root = format!("/a/site/_t/{token}/");
    let redirect = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&requested_root)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(redirect.0, StatusCode::PERMANENT_REDIRECT);
    let link_root = format!("/a/site/_t/{token}/_s/c/published/");
    assert_eq!(redirect.1.get(LOCATION).unwrap(), link_root.as_str());
    let linked = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&link_root)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(linked.0, StatusCode::OK);
    assert!(
        std::str::from_utf8(&linked.2)
            .unwrap()
            .contains("src=\"app.js\"")
    );
    for (relative, expected) in [
        (
            "app.js",
            b"document.body.dataset.bundle = 'served';\n".as_slice(),
        ),
        ("style.css", b"body { color: red; }\n".as_slice()),
        ("next.html", b"<h1>next</h1>\n".as_slice()),
    ] {
        // A browser resolves each relative URL below the token-bearing root.
        let resource = route_bytes(
            server.clone(),
            Request::builder()
                .uri(format!("{link_root}{relative}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(resource.0, StatusCode::OK, "{relative}");
        assert_eq!(resource.2.as_ref(), expected);
        assert_eq!(resource.1.get(CACHE_CONTROL).unwrap(), "private, no-store");
    }
    let uncredentialed_asset = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/_s/c/published/app.js")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        (
            uncredentialed_asset.0,
            stable_error(&uncredentialed_asset.2)
        ),
        (missing.0, stable_error(&missing.2))
    );
    assert_eq!(linked.1.get(CACHE_CONTROL).unwrap(), "private, no-store");
    assert_eq!(
        linked.1.get(axum::http::header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    let (status, headers, _) = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/site/_t/{token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(headers.get(LOCATION).unwrap(), link_root.as_str());
    assert_eq!(
        headers.get(axum::http::header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    let direct = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/a/site/_t/{token}/index.html?forkHash={}",
                oneiron::artifact_hex(&hash)
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(direct.0, StatusCode::PERMANENT_REDIRECT);
    let direct_url = direct.1.get(LOCATION).unwrap().to_str().unwrap();
    assert_eq!(
        direct_url,
        format!(
            "/a/site/_t/{token}/_s/f/{}/index.html",
            oneiron::artifact_hex(&hash)
        )
    );
    let direct = route_bytes(
        server.clone(),
        Request::builder()
            .uri(direct_url)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(direct.0, StatusCode::OK);
    assert_eq!(direct.1.get(CACHE_CONTROL).unwrap(), "private, no-store");

    let owner = oneiron::EntityId::now();
    let member = oneiron::EntityId::now();
    let stranger = oneiron::EntityId::now();
    for id in [owner, member, stranger] {
        server
            .vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .unwrap();
    }
    let authenticated_owner = server
        .vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let creation = server
        .vault
        .initialize_shared_vault(
            &authenticated_owner,
            42,
            None,
            &[oneiron::federation::InitialSharedMember {
                member_ref: member,
                role: Some(oneiron::federation::FederationGrantRole::Viewer),
            }],
            10,
        )
        .unwrap();
    server
        .vault
        .publish_artifact_pointer_with_tier(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &hash,
            oneiron::artifact_hosting::ArtifactServeTier::WorldMembers(42),
        )
        .unwrap();
    let permitted = route_bytes(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            "/a/site/_s/c/published/",
            "core:read",
            &member.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(permitted.0, StatusCode::OK);
    assert_eq!(permitted.1.get(CACHE_CONTROL).unwrap(), "private, no-store");
    let write_only = route_bytes(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            "/a/site/_s/c/published/",
            "core:write",
            &member.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(
        (write_only.0, stable_error(&write_only.2)),
        (missing.0, stable_error(&missing.2))
    );
    let (mut narrowed, holder) = slip_credentials::credential(
        &server,
        &format!(
            "scope=core:read;principal_ref={};jti=artifact-narrow",
            member.to_hex()
        ),
    );
    let mut scope = oneiron::federation::Scope::top();
    scope.worlds = oneiron::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
        oneiron::federation::ScopeId(stranger),
    ]));
    narrowed
        .attenuate(
            oneiron::authority::SlipCaveat {
                scope: Some(scope),
                ..Default::default()
            },
            &holder,
        )
        .unwrap();
    let narrowed_req = slip_credentials::bind_slip_request(
        &server,
        &narrowed,
        &holder,
        Request::builder()
            .uri("/a/site/_s/c/published/")
            .body(Body::empty())
            .unwrap(),
    );
    let narrowed_denied = route_bytes(server.clone(), narrowed_req).await;
    assert_eq!(
        (narrowed_denied.0, stable_error(&narrowed_denied.2)),
        (missing.0, stable_error(&missing.2))
    );

    for request in [
        Request::builder()
            .uri("/a/site/_s/c/published/")
            .body(Body::empty())
            .unwrap(),
        core_request_with_principal_ref(
            "GET",
            "/a/site/_s/c/published/",
            "core:read",
            &stranger.to_hex(),
            None,
        ),
        Request::builder()
            .uri(&link_root)
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/a/site/_s/c/published/")
            .header(AUTHORIZATION, owner_bearer())
            .body(Body::empty())
            .unwrap(),
    ] {
        let denied = route_bytes(server.clone(), request).await;
        assert_eq!(
            (denied.0, stable_error(&denied.2)),
            (missing.0, stable_error(&missing.2))
        );
    }
    let member_grant = oneiron::EntityId::from_hex(&creation.grant_refs[0]).unwrap();
    let disconnect = bind_artifact_member_to_divergent_pacts(&server.vault, member_grant);
    let discarded = route_bytes(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            "/a/site/_s/c/published/",
            "core:read",
            &member.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(
        (discarded.0, stable_error(&discarded.2)),
        (missing.0, stable_error(&missing.2))
    );
    let now = server.vault.now_recorded_at();
    server
        .vault
        .put_authority_log_entry(
            &disconnect,
            oneiron::TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .unwrap();
    assert!(matches!(
        oneiron::authority::federation_grant_activation(
            &server.vault.authority_fold().unwrap(),
            &member_grant
        ),
        oneiron::authority::FederationGrantActivation::Inactive(
            oneiron::authority::FederationPactStatus::Disconnected
        )
    ));
    let terminated = route_bytes(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            "/a/site/_s/c/published/",
            "core:read",
            &member.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(
        (terminated.0, stable_error(&terminated.2)),
        (missing.0, stable_error(&missing.2))
    );
    server
        .vault
        .unpublish_artifact_pointer("site", oneiron::ArtifactPointerChannel::Published)
        .unwrap();
    let revoked = route_bytes(
        server,
        core_request_with_principal_ref(
            "GET",
            &format!("/a/site/_s/f/{}/index.html", oneiron::artifact_hex(&hash)),
            "core:read",
            &member.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(
        (revoked.0, stable_error(&revoked.2)),
        (missing.0, stable_error(&missing.2))
    );
}

#[tokio::test]
async fn preview_link_bundle_keeps_its_selector_for_relative_assets_and_navigation() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".into()),
        allow_unauthenticated: false,
        ..Default::default()
    });
    let repo = create_artifact_repo(
        b"<script src=\"app.js\"></script><link rel=\"stylesheet\" href=\"style.css\"><a href=\"next.html\">next</a>",
    );
    std::fs::write(repo.path().join("app.js"), b"window.preview = true;\n").unwrap();
    std::fs::write(repo.path().join("style.css"), b"body { color: blue; }\n").unwrap();
    std::fs::write(repo.path().join("next.html"), b"preview next\n").unwrap();
    run_artifact_git(repo.path(), &["add", "."]);
    run_artifact_git(repo.path(), &["commit", "-m", "preview bundle"]);
    let preview = ingest_artifact_snapshot(&server, repo.path(), "site", 10);
    let (tier, token) = oneiron::artifact_hosting::ArtifactServeTier::mint_link_token();
    server
        .vault
        .publish_artifact_pointer_with_tier(
            "site",
            oneiron::ArtifactPointerChannel::Preview,
            &preview.snapshot.fork_hash,
            tier,
        )
        .unwrap();
    let missing = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/missing/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let requested = format!("/a/site/_t/{token}/?channel=preview");
    let landing = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&requested)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(landing.0, StatusCode::PERMANENT_REDIRECT);
    let target = landing.1.get(LOCATION).unwrap().to_str().unwrap();
    assert_eq!(target, format!("/a/site/_t/{token}/_s/c/preview/"));
    let loaded = route_bytes(
        server.clone(),
        Request::builder().uri(target).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(loaded.0, StatusCode::OK);
    assert!(
        std::str::from_utf8(&loaded.2)
            .unwrap()
            .contains("src=\"app.js\"")
    );
    for (relative, preview_bytes) in [
        ("app.js", b"window.preview = true;\n".as_slice()),
        ("style.css", b"body { color: blue; }\n".as_slice()),
        ("next.html", b"preview next\n".as_slice()),
    ] {
        let asset = route_bytes(
            server.clone(),
            Request::builder()
                .uri(format!("{target}{relative}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(asset.0, StatusCode::OK, "{relative}");
        assert_eq!(asset.2.as_ref(), preview_bytes, "{relative}");
        assert_eq!(asset.1.get(CACHE_CONTROL).unwrap(), "private, no-store");
    }
    let absent_published = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/site/_t/{token}/app.js"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(absent_published.0, missing.0);

    std::fs::write(
        repo.path().join("index.html"),
        b"<script src=\"app.js\"></script>public",
    )
    .unwrap();
    std::fs::write(repo.path().join("app.js"), b"window.published = true;\n").unwrap();
    std::fs::write(repo.path().join("style.css"), b"body { color: red; }\n").unwrap();
    std::fs::write(repo.path().join("next.html"), b"published next\n").unwrap();
    run_artifact_git(repo.path(), &["add", "."]);
    run_artifact_git(repo.path(), &["commit", "-m", "published bundle"]);
    let published = ingest_artifact_snapshot(&server, repo.path(), "site", 20);
    server
        .vault
        .publish_artifact_pointer_with_tier(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &published.snapshot.fork_hash,
            oneiron::artifact_hosting::ArtifactServeTier::Public,
        )
        .unwrap();
    let published_asset = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/site/_s/c/published/app.js")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(published_asset.2.as_ref(), b"window.published = true;\n");
    for (relative, preview_bytes) in [
        ("app.js", b"window.preview = true;\n".as_slice()),
        ("style.css", b"body { color: blue; }\n".as_slice()),
        ("next.html", b"preview next\n".as_slice()),
    ] {
        let asset = route_bytes(
            server.clone(),
            Request::builder()
                .uri(format!("{target}{relative}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(asset.0, StatusCode::OK);
        assert_eq!(asset.2.as_ref(), preview_bytes);
    }
    let hash_landing = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/a/site/_t/{token}/?forkHash={}",
                oneiron::artifact_hex(&preview.snapshot.fork_hash)
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(hash_landing.0, StatusCode::PERMANENT_REDIRECT);
    let hash_root = hash_landing.1.get(LOCATION).unwrap().to_str().unwrap();
    assert_eq!(
        hash_root,
        format!(
            "/a/site/_t/{token}/_s/f/{}/",
            oneiron::artifact_hex(&preview.snapshot.fork_hash)
        )
    );
    let hash_asset = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("{hash_root}app.js"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(hash_asset.0, StatusCode::OK);
    assert_eq!(hash_asset.2.as_ref(), b"window.preview = true;\n");
    let wrong = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/site/_t/{}/_s/c/preview/app.js", "0".repeat(64)))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(wrong.0, missing.0);
    server
        .vault
        .unpublish_artifact_pointer("site", oneiron::ArtifactPointerChannel::Preview)
        .unwrap();
    let dead_hash = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("{hash_root}app.js"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(dead_hash.0, missing.0);
    let dead = route_bytes(
        server,
        Request::builder()
            .uri(format!("{target}app.js"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(dead.0, missing.0);
}

#[tokio::test]
async fn blob_link_and_member_tiers_follow_pact_revocation_and_pointer_death() {
    fn stable_error(bytes: &Bytes) -> Value {
        let mut body: Value = serde_json::from_slice(bytes).unwrap();
        body["error"].as_object_mut().unwrap().remove("requestId");
        body
    }
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        allow_unauthenticated: false,
        ..Default::default()
    });
    let owner = oneiron::EntityId::now();
    let member = oneiron::EntityId::now();
    let stranger = oneiron::EntityId::now();
    for id in [owner, member, stranger] {
        server
            .vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .unwrap();
    }
    let authenticated_owner = server
        .vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let creation = server
        .vault
        .initialize_shared_vault(
            &authenticated_owner,
            42,
            None,
            &[oneiron::federation::InitialSharedMember {
                member_ref: member,
                role: Some(oneiron::federation::FederationGrantRole::Viewer),
            }],
            10,
        )
        .unwrap();
    let missing = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/missing/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    // The same grant law applies to pinned blob exports and their immutable
    // version URL, not just CODE_ARTIFACT bundles.
    let blob = oneiron::EntityId::now();
    server
        .vault
        .put_blob_artifact(
            &blob,
            &oneiron::blob_artifact::BlobArtifactBody::new("report.pdf", "application/pdf"),
            oneiron::TimeRange { start: 10, end: 10 },
            10,
        )
        .unwrap();
    let version = server
        .vault
        .append_blob_artifact_version(
            &blob,
            b"%PDF-1.7\ntiered",
            &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
            oneiron::WriteActor::new(member, oneiron::EdgeActorClass::Human),
            oneiron::TimeRange { start: 11, end: 11 },
            11,
        )
        .unwrap()
        .version;
    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &blob,
            oneiron::ArtifactPointerChannel::Published,
            version,
            oneiron::artifact_hosting::ArtifactServeTier::WorldMembers(42),
        )
        .unwrap();
    let blob_route = format!("/a/{}/_s/c/published/export", blob.to_hex());
    let blob_version_route = format!("/a/{}/_s/b/{version}/export", blob.to_hex());
    for route in [&blob_route, &blob_version_route] {
        let served = route_bytes(
            server.clone(),
            core_request_with_principal_ref("GET", route, "core:read", &member.to_hex(), None),
        )
        .await;
        assert_eq!(served.0, StatusCode::OK);
        assert_eq!(served.2.as_ref(), b"%PDF-1.7\ntiered");
        assert_eq!(served.1.get(CACHE_CONTROL).unwrap(), "private, no-store");
        let denied = route_bytes(
            server.clone(),
            core_request_with_principal_ref("GET", route, "core:read", &stranger.to_hex(), None),
        )
        .await;
        assert_eq!(
            (denied.0, stable_error(&denied.2)),
            (missing.0, stable_error(&missing.2))
        );
    }
    let (blob_tier, blob_token) = oneiron::artifact_hosting::ArtifactServeTier::mint_link_token();
    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &blob,
            oneiron::ArtifactPointerChannel::Published,
            version,
            blob_tier,
        )
        .unwrap();
    let linked_blob = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/a/{}/_t/{blob_token}/export?blobVersion={version}",
                blob.to_hex()
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(linked_blob.0, StatusCode::PERMANENT_REDIRECT);
    let blob_target = linked_blob.1.get(LOCATION).unwrap().to_str().unwrap();
    assert_eq!(
        blob_target,
        format!("/a/{}/_t/{blob_token}/_s/b/{version}/export", blob.to_hex())
    );
    let linked_blob = route_bytes(
        server.clone(),
        Request::builder()
            .uri(blob_target)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(linked_blob.0, StatusCode::OK);
    assert_eq!(
        linked_blob.1.get(CACHE_CONTROL).unwrap(),
        "private, no-store"
    );
    let no_token_blob = route_bytes(
        server.clone(),
        Request::builder()
            .uri(&blob_version_route)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        (no_token_blob.0, stable_error(&no_token_blob.2)),
        (missing.0, stable_error(&missing.2))
    );
    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &blob,
            oneiron::ArtifactPointerChannel::Published,
            version,
            oneiron::artifact_hosting::ArtifactServeTier::WorldMembers(42),
        )
        .unwrap();

    let member_grant = oneiron::EntityId::from_hex(&creation.grant_refs[0]).unwrap();
    let disconnect = bind_artifact_member_to_divergent_pacts(&server.vault, member_grant);
    let blob_discarded = route_bytes(
        server.clone(),
        core_request_with_principal_ref(
            "GET",
            &blob_version_route,
            "core:read",
            &member.to_hex(),
            None,
        ),
    )
    .await;
    assert_eq!(
        (blob_discarded.0, stable_error(&blob_discarded.2)),
        (missing.0, stable_error(&missing.2))
    );
    let now = server.vault.now_recorded_at();
    server
        .vault
        .put_authority_log_entry(
            &disconnect,
            oneiron::TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .unwrap();
    let blob_terminated = route_bytes(
        server.clone(),
        core_request_with_principal_ref("GET", &blob_route, "core:read", &member.to_hex(), None),
    )
    .await;
    assert_eq!(
        (blob_terminated.0, stable_error(&blob_terminated.2)),
        (missing.0, stable_error(&missing.2))
    );
    server
        .vault
        .unpublish_blob_artifact_pointer(&blob, oneiron::ArtifactPointerChannel::Published)
        .unwrap();
    let dead_blob = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!(
                "/a/{}/_t/{blob_token}/export?blobVersion={version}",
                blob.to_hex()
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        (dead_blob.0, stable_error(&dead_blob.2)),
        (missing.0, stable_error(&missing.2))
    );
}

#[tokio::test]
async fn published_token_root_keeps_reserved_directories_and_encoded_code_names() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".into()),
        allow_unauthenticated: false,
        ..Default::default()
    });
    let repo = create_artifact_repo(
        b"<script src=\"c/app.js\"></script><link rel=\"stylesheet\" href=\"f/style.css\"><a href=\"b/next.html\">next</a><script src=\"_s/nested/app.js\"></script><link rel=\"stylesheet\" href=\"_t/nested/style.css\">",
    );
    for dir in ["c", "f", "b", "_s/nested", "_t/nested"] {
        std::fs::create_dir_all(repo.path().join(dir)).unwrap();
    }
    for (path, bytes) in [
        ("c/app.js", b"window.c = true;".as_slice()),
        ("f/style.css", b"body { color: green; }".as_slice()),
        ("b/next.html", b"<h1>next</h1>".as_slice()),
        ("_s/nested/app.js", b"window.marker = true;".as_slice()),
        ("_t/nested/style.css", b"body { color: orange; }".as_slice()),
        ("report#1.js", b"hash name".as_slice()),
        ("report?2.js", b"query name".as_slice()),
        ("literal%20.js", b"percent name".as_slice()),
    ] {
        std::fs::write(repo.path().join(path), bytes).unwrap();
    }
    run_artifact_git(repo.path(), &["add", "."]);
    run_artifact_git(
        repo.path(),
        &["commit", "-m", "reserved path and encoded names"],
    );
    let snapshot = ingest_artifact_snapshot(&server, repo.path(), "site", 10);
    let (tier, token) = oneiron::artifact_hosting::ArtifactServeTier::mint_link_token();
    server
        .vault
        .publish_artifact_pointer_with_tier(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &snapshot.snapshot.fork_hash,
            tier,
        )
        .unwrap();
    let root = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/site/_t/{token}/"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(root.0, StatusCode::PERMANENT_REDIRECT);
    let base = root.1.get(LOCATION).unwrap().to_str().unwrap().to_owned();
    assert_eq!(base, format!("/a/site/_t/{token}/_s/c/published/"));
    let html = route_bytes(
        server.clone(),
        Request::builder().uri(&base).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(html.0, StatusCode::OK);
    assert!(
        std::str::from_utf8(&html.2)
            .unwrap()
            .contains("src=\"c/app.js\"")
    );
    for (relative, expected) in [
        ("c/app.js", b"window.c = true;".as_slice()),
        ("f/style.css", b"body { color: green; }".as_slice()),
        ("b/next.html", b"<h1>next</h1>".as_slice()),
        ("_s/nested/app.js", b"window.marker = true;".as_slice()),
        ("_t/nested/style.css", b"body { color: orange; }".as_slice()),
    ] {
        // These are the browser's normal relative URLs from the redirected HTML.
        let asset = route_bytes(
            server.clone(),
            Request::builder()
                .uri(format!("{base}{relative}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(asset.0, StatusCode::OK, "{relative}");
        assert_eq!(asset.2.as_ref(), expected, "{relative}");
    }
    // The unselected legacy prefix also treats c/f/b as stored file paths.
    for relative in [
        "c/app.js",
        "f/style.css",
        "b/next.html",
        "_t/nested/style.css",
    ] {
        let asset = route_bytes(
            server.clone(),
            Request::builder()
                .uri(format!("/a/site/_t/{token}/{relative}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(asset.0, StatusCode::PERMANENT_REDIRECT, "{relative}");
        let target = asset.1.get(LOCATION).unwrap().to_str().unwrap();
        let followed = route_bytes(
            server.clone(),
            Request::builder().uri(target).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(followed.0, StatusCode::OK, "{relative}");
    }
    let hash = oneiron::artifact_hex(&snapshot.snapshot.fork_hash);
    for (encoded, expected) in [
        ("report%231.js", b"hash name".as_slice()),
        ("report%3F2.js", b"query name".as_slice()),
        ("literal%2520.js", b"percent name".as_slice()),
    ] {
        let requested = format!("/a/site/_t/{token}/{encoded}?forkHash={hash}");
        let first = route_bytes(
            server.clone(),
            Request::builder()
                .uri(requested)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(first.0, StatusCode::PERMANENT_REDIRECT, "{encoded}");
        let target = first.1.get(LOCATION).unwrap().to_str().unwrap();
        assert_eq!(target, format!("/a/site/_t/{token}/_s/f/{hash}/{encoded}"));
        let followed = route_bytes(
            server.clone(),
            Request::builder().uri(target).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(followed.0, StatusCode::OK, "{encoded}");
        assert_eq!(followed.2.as_ref(), expected, "{encoded}");
    }
}

#[tokio::test]
async fn blob_token_redirect_round_trips_escaped_export_names() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".into()),
        allow_unauthenticated: false,
        ..Default::default()
    });
    let actor = oneiron::EntityId::now();
    server
        .vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"publisher",
        )
        .unwrap();
    for (name, encoded, bytes) in [
        ("report#1.pdf", "report%231.pdf", b"hash blob".as_slice()),
        ("report?2.pdf", "report%3F2.pdf", b"query blob".as_slice()),
        (
            "literal%20.pdf",
            "literal%2520.pdf",
            b"percent blob".as_slice(),
        ),
    ] {
        let id = oneiron::EntityId::now();
        server
            .vault
            .put_blob_artifact(
                &id,
                &oneiron::blob_artifact::BlobArtifactBody::new(name, "application/pdf"),
                oneiron::TimeRange { start: 1, end: 1 },
                1,
            )
            .unwrap();
        let version = server
            .vault
            .append_blob_artifact_version(
                &id,
                bytes,
                &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
                oneiron::WriteActor::new(actor, oneiron::EdgeActorClass::Human),
                oneiron::TimeRange { start: 2, end: 2 },
                2,
            )
            .unwrap()
            .version;
        let (tier, token) = oneiron::artifact_hosting::ArtifactServeTier::mint_link_token();
        server
            .vault
            .publish_blob_artifact_pointer_with_tier(
                &id,
                oneiron::ArtifactPointerChannel::Published,
                version,
                tier,
            )
            .unwrap();
        let requested = format!(
            "/a/{}/_t/{token}/{encoded}?blobVersion={version}",
            id.to_hex()
        );
        let first = route_bytes(
            server.clone(),
            Request::builder()
                .uri(requested)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(first.0, StatusCode::PERMANENT_REDIRECT, "{name}");
        let target = first.1.get(LOCATION).unwrap().to_str().unwrap();
        assert_eq!(
            target,
            format!("/a/{}/_t/{token}/_s/b/{version}/{encoded}", id.to_hex())
        );
        let followed = route_bytes(
            server.clone(),
            Request::builder().uri(target).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(followed.0, StatusCode::OK, "{name}");
        assert_eq!(followed.2.as_ref(), bytes, "{name}");
        assert_eq!(followed.1.get(CACHE_CONTROL).unwrap(), "private, no-store");
    }
}

#[tokio::test]
async fn member_grant_scope_must_admit_the_exact_code_or_blob_export() {
    use oneiron::federation::{ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
    use std::collections::BTreeSet;
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".into()),
        allow_unauthenticated: false,
        ..Default::default()
    });
    let repo = create_artifact_repo(b"<h1>code</h1>");
    let snapshot = ingest_artifact_snapshot(&server, repo.path(), "site", 10);
    let blob = oneiron::EntityId::now();
    server
        .vault
        .put_blob_artifact(
            &blob,
            &oneiron::blob_artifact::BlobArtifactBody::new("report.pdf", "application/pdf"),
            oneiron::TimeRange { start: 10, end: 10 },
            10,
        )
        .unwrap();
    let owner = oneiron::EntityId::now();
    let member = oneiron::EntityId::now();
    for id in [owner, member] {
        server
            .vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .unwrap();
    }
    server
        .vault
        .append_blob_artifact_version(
            &blob,
            b"%PDF-scope",
            &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
            oneiron::WriteActor::new(owner, oneiron::EdgeActorClass::Human),
            oneiron::TimeRange { start: 11, end: 11 },
            11,
        )
        .unwrap();
    let authenticated = server
        .vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let creation = server
        .vault
        .initialize_shared_vault(
            &authenticated,
            42,
            None,
            &[oneiron::federation::InitialSharedMember {
                member_ref: member,
                role: Some(oneiron::federation::FederationGrantRole::Viewer),
            }],
            10,
        )
        .unwrap();
    let grant_id = oneiron::EntityId::from_hex(&creation.grant_refs[0]).unwrap();
    let grant = oneiron::federation::FederationGrant::new(
        oneiron::federation::FederationGrantScope::vault(42),
        member,
        oneiron::federation::FederationGrantRole::Viewer,
        oneiron::federation::FederationGrantPreset::ReadOnly,
    );
    server
        .vault
        .publish_artifact_pointer_with_tier(
            "site",
            oneiron::ArtifactPointerChannel::Published,
            &snapshot.snapshot.fork_hash,
            oneiron::artifact_hosting::ArtifactServeTier::WorldMembers(42),
        )
        .unwrap();
    server
        .vault
        .publish_blob_artifact_pointer_with_tier(
            &blob,
            oneiron::ArtifactPointerChannel::Published,
            1,
            oneiron::artifact_hosting::ArtifactServeTier::WorldMembers(42),
        )
        .unwrap();
    let code = "/a/site/_s/c/published/index.html";
    let blob_uri = format!("/a/{}/_s/b/1/export", blob.to_hex());
    let code_scope = server
        .vault
        .record_scope(&snapshot.code_artifact_id)
        .unwrap()
        .unwrap();
    let blob_scope = server.vault.record_scope(&blob).unwrap().unwrap();
    assert!(
        code_scope
            .bands
            .contains(&oneiron::registry::ENTITY_TYPE_CODE_ARTIFACT)
    );
    assert!(
        blob_scope
            .bands
            .contains(&oneiron::registry::ENTITY_TYPE_BLOB_ARTIFACT)
    );
    let request = |uri: &str| {
        core_request_with_principal_ref("GET", uri, "core:read", &member.to_hex(), None)
    };
    let baseline_code = route_bytes(server.clone(), request(code)).await;
    let baseline_blob = route_bytes(server.clone(), request(&blob_uri)).await;
    assert_eq!(baseline_code.0, StatusCode::OK);
    assert_eq!(baseline_blob.0, StatusCode::OK);
    let etag = baseline_code.1.get(ETAG).unwrap().clone();
    let missing = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/missing/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let stable = |body: &Bytes| {
        let mut value: Value = serde_json::from_slice(body).unwrap();
        value["error"].as_object_mut().unwrap().remove("requestId");
        value
    };
    for (index, narrowed) in [
        {
            let mut scope = grant.authority_scope.clone();
            scope.bands = ScopeAxis::Some(BTreeSet::from([oneiron::registry::ENTITY_TYPE_NOTE]));
            scope
        },
        {
            let mut scope = grant.authority_scope.clone();
            scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(oneiron::EntityId::now())]));
            scope
        },
        {
            let mut scope = grant.authority_scope.clone();
            scope.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(oneiron::EntityId::now())]));
            scope
        },
        {
            let mut scope = grant.authority_scope.clone();
            scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Public);
            scope
        },
    ]
    .into_iter()
    .enumerate()
    {
        let mut changed = grant.clone();
        changed.authority_scope = narrowed;
        oneiron::sync::put_selector_test_federation_grant(
            &server.vault,
            &grant_id,
            &changed,
            20 + index as u64,
        )
        .unwrap();
        if index == 0 {
            let mut conditional = request(code);
            conditional
                .headers_mut()
                .insert(IF_NONE_MATCH, etag.clone());
            let denied = route_bytes(server.clone(), conditional).await;
            assert_eq!(
                (denied.0, stable(&denied.2)),
                (missing.0, stable(&missing.2)),
                "a 304 must not bypass grant scope"
            );
        }
        for uri in [code, blob_uri.as_str()] {
            let refused = route_bytes(server.clone(), request(uri)).await;
            assert_eq!(
                (refused.0, stable(&refused.2)),
                (missing.0, stable(&missing.2)),
                "case {index}: {uri}"
            );
        }
    }
    for (band, allowed, denied) in [
        (
            oneiron::registry::ENTITY_TYPE_CODE_ARTIFACT,
            code,
            blob_uri.as_str(),
        ),
        (
            oneiron::registry::ENTITY_TYPE_BLOB_ARTIFACT,
            blob_uri.as_str(),
            code,
        ),
    ] {
        let mut changed = grant.clone();
        changed.authority_scope.bands = ScopeAxis::Some(BTreeSet::from([band]));
        oneiron::sync::put_selector_test_federation_grant(
            &server.vault,
            &grant_id,
            &changed,
            30 + band as u64,
        )
        .unwrap();
        assert_eq!(
            route_bytes(server.clone(), request(allowed)).await.0,
            StatusCode::OK
        );
        let refused = route_bytes(server.clone(), request(denied)).await;
        assert_eq!(
            (refused.0, stable(&refused.2)),
            (missing.0, stable(&missing.2))
        );
    }
    oneiron::sync::put_selector_test_federation_grant(&server.vault, &grant_id, &grant, 99)
        .unwrap();
    let mut conditional = request(code);
    conditional.headers_mut().insert(IF_NONE_MATCH, etag);
    assert_eq!(
        route_bytes(server.clone(), conditional).await.0,
        StatusCode::NOT_MODIFIED
    );
}

#[tokio::test]
async fn token_bundle_address_round_trips_artifact_named_control_marker() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".into()),
        allow_unauthenticated: false,
        ..Default::default()
    });
    let repo = create_artifact_repo(b"<script src=\"app.js\"></script>");
    std::fs::write(repo.path().join("report#1.js"), b"encoded export").unwrap();
    run_artifact_git(repo.path(), &["add", "."]);
    run_artifact_git(repo.path(), &["commit", "-m", "encoded resource"]);
    let snapshot = ingest_artifact_snapshot(&server, repo.path(), "_t", 10);
    let (tier, token) = oneiron::artifact_hosting::ArtifactServeTier::mint_link_token();
    server
        .vault
        .publish_artifact_pointer_with_tier(
            "_t",
            oneiron::ArtifactPointerChannel::Published,
            &snapshot.snapshot.fork_hash,
            tier,
        )
        .unwrap();
    let missing = route_bytes(
        server.clone(),
        Request::builder()
            .uri("/a/missing/")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let root = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/_t/_t/{token}/"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(root.0, StatusCode::PERMANENT_REDIRECT);
    let canonical = root.1.get(LOCATION).unwrap().to_str().unwrap();
    assert_eq!(canonical, format!("/a/_t/_t/{token}/_s/c/published/"));
    let html = route_bytes(
        server.clone(),
        Request::builder()
            .uri(canonical)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(html.0, StatusCode::OK);
    let no_slash = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/_t/_t/{token}/_s/c/published"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(no_slash.0, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(no_slash.1.get(LOCATION).unwrap(), canonical);
    let asset = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("{canonical}app.js"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(asset.0, StatusCode::OK);
    let old = format!(
        "/a/_t/_t/{token}/report%231.js?forkHash={}",
        oneiron::artifact_hex(&snapshot.snapshot.fork_hash)
    );
    let redirect = route_bytes(
        server.clone(),
        Request::builder().uri(old).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(redirect.0, StatusCode::PERMANENT_REDIRECT);
    let target = redirect.1.get(LOCATION).unwrap().to_str().unwrap();
    assert_eq!(
        target,
        format!(
            "/a/_t/_t/{token}/_s/f/{}/report%231.js",
            oneiron::artifact_hex(&snapshot.snapshot.fork_hash)
        )
    );
    let followed = route_bytes(
        server.clone(),
        Request::builder().uri(target).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(followed.0, StatusCode::OK);
    assert_eq!(followed.2.as_ref(), b"encoded export");
    let wrong = route_bytes(
        server.clone(),
        Request::builder()
            .uri(format!("/a/_t/_t/{}/_s/c/published/app.js", "0".repeat(64)))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(wrong.0, missing.0);
    server
        .vault
        .unpublish_artifact_pointer("_t", oneiron::ArtifactPointerChannel::Published)
        .unwrap();
    let dead = route_bytes(
        server,
        Request::builder().uri(target).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(dead.0, missing.0);
}
