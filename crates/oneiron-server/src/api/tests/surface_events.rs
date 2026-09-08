//! Surface-event submit/replay/receipts, scope enforcement, idempotency + durability, malformed-input mapping.

use super::*;

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
        oneiron::channel_identity::SelfHeldShape::DedicatedAddress,
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
                oneiron::channel_identity::SelfHeldShape::DedicatedAddress,
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
