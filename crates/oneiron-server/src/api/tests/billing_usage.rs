//! Usage-event runtime debit boundaries, consumer top-up idempotency/validation, usage allowance + breakdowns.

use super::*;

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
