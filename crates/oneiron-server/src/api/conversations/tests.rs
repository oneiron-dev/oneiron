//! The conversation list reads as a named reader, on the read lane recall and
//! the transcript use (ARCH-0006a, DEC-0005), and says what that read
//! withheld. (In a vault with no authority root every human PERSON reads as
//! its owner, so a scoped reader's list is checked in the engine, on a rooted
//! vault.)

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use serde_json::json;

use super::ROOM_TURN_HEADER;
use crate::api::tests::{json_request, owner_reader_bearer, route_json, test_server};

#[tokio::test]
async fn the_list_reads_as_a_named_reader_and_returns_its_receipt() {
    let (_dir, server) = test_server();
    let (status, created) = route_json(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/conversations",
            json!({"body": {"name": "garden"}}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let list = |authorization: Option<String>, room_turn: bool| {
        let mut request = Request::builder().uri("/v1/core/conversations?view=full");
        if let Some(authorization) = authorization {
            request = request.header(AUTHORIZATION, authorization);
        }
        if room_turn {
            request = request.header(ROOM_TURN_HEADER, created["id"].as_str().expect("id"));
        }
        request.body(Body::empty()).expect("request")
    };

    // A credential that names no reader reads nothing.
    let (status, body) = route_json(server.clone(), list(None, false)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // Inside a room turn the list is refused, not read outside the room.
    let bearer = owner_reader_bearer(&server);
    let (status, body) = route_json(server.clone(), list(Some(bearer.clone()), true)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = route_json(server.clone(), list(Some(bearer), false)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["items"].as_array().expect("items");
    assert!(rows.iter().any(|row| row["id"] == created["id"]), "{body}");
    assert_eq!(body["narrowing"]["suppressed_count"], 0, "{body}");
}
