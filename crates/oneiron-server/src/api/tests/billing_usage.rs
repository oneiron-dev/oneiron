//! Provider money facts, runtime metering boundaries, and removed wallet routes.

use super::*;

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
        "owner": "owner-a",
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
        "costRates": { "currency": "USD", "priceTableSnapshot": "fixture",
            "inputPerMillion": 2000000000,
            "outputPerMillion": 4000000000_u64,
            "cacheReadPerMillion": 0,
            "cacheWritePerMillion": 0
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
        "owner": "owner-a",
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
        "costRates": { "currency": "USD", "priceTableSnapshot": "fixture",
            "inputPerMillion": 2000000000,
            "outputPerMillion": 4000000000_u64,
            "cacheReadPerMillion": 0,
            "cacheWritePerMillion": 0
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
    assert!(body["vaultRollup"].is_object());
    assert_eq!(body["cost"]["currency"], "USD");
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
        "owner": "owner-a",
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
        "costRates": { "currency": "USD", "priceTableSnapshot": "fixture",
            "inputPerMillion": 2000000000,
            "outputPerMillion": 4000000000_u64,
            "cacheReadPerMillion": 0,
            "cacheWritePerMillion": 0
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
    // 37c638d3a6e (#1723, OF-310): a meter records facts for every payer;
    // `recorded` is the first-write flag, and a local source is never debited.
    assert_eq!(body["recorded"], Value::from(true));
    assert_eq!(body["replayed"], Value::from(false));
    assert!(body.get("debit").is_none());
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
        "owner": "owner-a",
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
        "costRates": { "currency": "USD", "priceTableSnapshot": "fixture",
            "inputPerMillion": 2000000000,
            "outputPerMillion": 4000000000_u64,
            "cacheReadPerMillion": 0,
            "cacheWritePerMillion": 0
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
async fn oversized_usage_money_is_recorded_with_price_overflow() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        runtime: crate::runtime::RuntimeConfig::for_mode(RuntimeMode::OneironCloud),
        ..Default::default()
    });
    let payload = json!({
        "owner": "owner-a", "vaultId": "vault-a", "idempotencyKey": "overflow",
        "tokenCounts": { "inputTokens": 1, "outputTokens": 0, "cacheReadTokens": 0, "cacheWriteTokens": 0 },
        "costRates": { "currency": "USD", "priceTableSnapshot": "list",
            "inputPerMillion": 1000000, "outputPerMillion": 0,
            "cacheReadPerMillion": 0, "cacheWritePerMillion": 0 },
        "serviceAmount": u64::MAX
    });
    let response = api_routes(server.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/usage/events")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    // FIX 6407: an overflowing price keeps the call's counts and frozen rates;
    // the event is recorded with price_overflow and no money amount, not refused.
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("usage response body");
    let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
    assert_eq!(body["recorded"], Value::from(true));
    assert_eq!(body["replayed"], Value::from(false));
    assert_eq!(body["source"], Value::from("oneiron_cloud"));
    assert!(body["cost"].is_null());
    assert_eq!(body["unpriced"], Value::from("price_overflow"));
    assert_eq!(body["rollupStatus"], Value::from("current"));
    // The key is the hex encoding of owner-a, vault-a, and overflow.
    let raw = server
        .vault
        .sync_state_get("usage:event:6f776e65722d61:7661756c742d61:6f766572666c6f77")
        .expect("read stored usage event")
        .expect("usage event was recorded");
    let stored: Value = rmp_serde::from_slice(&raw).expect("stored usage event");
    assert!(stored["recordedAt"].as_u64().unwrap() > 0);
    assert_eq!(
        stored,
        json!({
            "event": {
                "owner": "owner-a",
                "vaultId": "vault-a",
                "idempotencyKey": "overflow",
                "source": null,
                "eventType": "inference",
                "role": null,
                "occurredAt": null,
                "agentId": null,
                "model": null,
                "service": null,
                "tokenCounts": payload["tokenCounts"],
                "costRates": payload["costRates"],
                "unpriced": "price_overflow",
                "serviceAmount": u64::MAX,
                "run": null
            },
            "source": "oneiron_cloud",
            "origin": "posted",
            "cost": null,
            "recordedAt": stored["recordedAt"]
        })
    );
}
