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

/// Bug repro (Sol R2-1): a search whose deadline comes due before it read
/// anything, here because the blocking pool is busy, answers by the deadline
/// with an empty partial page and no receipt, not with an error.
#[test]
fn raw_search_answers_by_its_deadline_when_it_could_not_read_yet() {
    const DEADLINE_MS: u64 = 200;
    const BUSY: Duration = Duration::from_secs(3);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let (dir, server) = runtime.block_on(async { auth_test_server() });
    seed_turn(&server, "The night ferry leaves at nine.");
    let (started, busy) = std::sync::mpsc::channel();
    runtime.spawn_blocking(move || {
        started.send(()).expect("busy pool signal");
        std::thread::sleep(BUSY);
    });
    busy.recv().expect("the blocking pool is busy");
    let arrived = Instant::now();
    let (status, page) = runtime.block_on(route_json_auth(
        server,
        search_request(
            "GET",
            &format!("/api/search/text?query=ferry&deadlineMs={DEADLINE_MS}"),
            None,
        ),
    ));
    let took = arrived.elapsed();
    // The cut read finishes once the pool frees, before the vault goes.
    drop(runtime);
    drop(dir);
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(took < BUSY, "the busy pool held the answer {took:?}");
    assert_eq!(page["items"], json!([]), "{page}");
    assert_eq!(page["meta"]["partial"], true, "{page}");
    assert_eq!(page["narrowing"], json!([]), "{page}");
}
