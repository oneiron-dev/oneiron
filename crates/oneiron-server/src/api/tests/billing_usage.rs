//! Provider money facts, runtime metering boundaries, and removed wallet routes.

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
        "owner": "owner-a",
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
    assert_eq!(body["source"], Value::from("byo"));
    assert!(body.get("debit").is_none());
    assert_eq!(body["recorded"], Value::from(false));
}

#[tokio::test]
async fn usage_event_on_default_runtime_resolves_local_no_debit() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        allow_unauthenticated: true,
        ..Default::default()
    });
    let payload = json!({
        "owner": "owner-a",
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
    assert_eq!(body["recorded"], Value::from(false));
    assert!(body.get("debit").is_none());
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
        "owner": "owner-a",
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
        "owner": "owner-a",
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
    assert_eq!(body["recorded"], Value::from(false));
    assert!(body.get("debit").is_none());
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
    assert_eq!(body["recorded"], Value::from(false));
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
        "owner": "owner-a",
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
        "owner": "owner-a",
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
    assert_eq!(body["recorded"], Value::from(false));
    assert!(body.get("debit").is_none());
}

#[tokio::test]
async fn cloud_wallet_and_unscoped_rollup_routes_are_absent() {
    let (_dir, server) = test_server();
    for (method, path) in [
        ("POST", "/v1/consumer/top-up"),
        ("GET", "/v1/usage/tenants/x/rollup"),
    ] {
        let response = api_routes(server.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn oversized_usage_money_is_a_client_error() {
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
    let response = api_routes(server)
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
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
