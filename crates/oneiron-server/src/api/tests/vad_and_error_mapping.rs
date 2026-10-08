//! Turn/message VAD annotate routes plus core-engine-error to HTTP status mapping matrix.

use super::*;

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
