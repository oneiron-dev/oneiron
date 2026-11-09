//! Raw search under a request's hard deadline, `deadlineMs` (retrieval hub
//! #call-mode).

use super::*;
use std::time::{Duration, Instant};

fn search_request(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, owner_bearer());
    match body {
        Some(body) => request
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .expect("search request")
}

/// Every raw search door takes `deadlineMs` and refuses one outside
/// 1..=60000 with a typed 400 naming the field.
#[tokio::test]
async fn raw_search_takes_a_deadline_and_refuses_one_out_of_range() {
    let (_dir, server) = auth_test_server();
    seed_turn(&server, "The night ferry leaves at nine.");
    for deadline_ms in [1, 60_000] {
        let uri = format!("/api/search/text?query=ferry&deadlineMs={deadline_ms}");
        let (status, page) =
            route_json_auth(server.clone(), search_request("GET", &uri, None)).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {page}");
    }
    for deadline_ms in [0, 60_001] {
        for request in [
            search_request(
                "GET",
                &format!("/api/search/text?query=ferry&deadlineMs={deadline_ms}"),
                None,
            ),
            search_request(
                "GET",
                &format!("/api/search/vector?query=0.1,0.2,0.3&deadlineMs={deadline_ms}"),
                None,
            ),
            search_request(
                "POST",
                "/api/search/semantic",
                Some(json!({"text": "ferry", "deadlineMs": deadline_ms})),
            ),
        ] {
            let uri = request.uri().to_string();
            let (status, body) = route_json_auth(server.clone(), request).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
            assert_eq!(body["code"], "BAD_REQUEST", "{uri}: {body}");
            assert_eq!(body["details"]["field"], "deadlineMs", "{uri}: {body}");
            assert_eq!(
                body["message"], "deadline_ms must be a whole number between 1 and 60000",
                "{uri}: {body}"
            );
        }
    }
}

