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
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.is_empty());
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
            .uri("/a/site/")
            .body(Body::empty())
            .expect("artifact request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

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
            .uri("/a/site/")
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
    let link_root = format!("/a/site/_t/{token}/");
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
            .uri("/a/site/app.js")
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
        core_request_with_principal_ref("GET", "/a/site/", "core:read", &member.to_hex(), None),
    )
    .await;
    assert_eq!(permitted.0, StatusCode::OK);
    assert_eq!(permitted.1.get(CACHE_CONTROL).unwrap(), "private, no-store");
    let write_only = route_bytes(
        server.clone(),
        core_request_with_principal_ref("GET", "/a/site/", "core:write", &member.to_hex(), None),
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
            .uri("/a/site/")
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
            .uri("/a/site/")
            .body(Body::empty())
            .unwrap(),
        core_request_with_principal_ref("GET", "/a/site/", "core:read", &stranger.to_hex(), None),
        Request::builder()
            .uri(&link_root)
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/a/site/")
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
        core_request_with_principal_ref("GET", "/a/site/", "core:read", &member.to_hex(), None),
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
        core_request_with_principal_ref("GET", "/a/site/", "core:read", &member.to_hex(), None),
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
            &format!(
                "/a/site/index.html?forkHash={}",
                oneiron::artifact_hex(&hash)
            ),
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
