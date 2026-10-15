use super::*;

#[tokio::test]
async fn retrieval_quality_depth_reason_requires_read_auth_before_admission() {
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    });
    let body = json!({"query": "qualitydepth", "depth": "max"});
    let (status, response) = route_json(
        server.clone(),
        json_request("POST", "/v1/companion/memory/reason", body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(response["error"]["code"], "UNAUTHORIZED");
    let (status, response) = route_json(
        server.clone(),
        core_request(
            "POST",
            "/v1/companion/memory/reason",
            "core:write",
            Some(&body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(response["error"]["code"], "FORBIDDEN");
    let (status, response) = route_json(
        server,
        core_request(
            "POST",
            "/v1/companion/memory/reason",
            "core:read",
            Some(&body),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response["error"]["code"], "DEEP_RETRIEVAL_UNAVAILABLE");
}
