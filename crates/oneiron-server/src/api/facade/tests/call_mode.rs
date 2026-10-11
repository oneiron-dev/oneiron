//! Call mode at the HTTP recall door (retrieval hub #call-mode).

use super::*;
use oneiron::memory::caps::MAX_RECALL_DEADLINE_MS;
use oneiron::retrieval_depth::SlowRetrievalStage;
use oneiron::store::RetrievalSignal;
use std::time::{Duration, Instant};

/// The door takes `effort: "call"` and a `deadline_ms`, and refuses a
/// deadline outside 1..=60000 with a typed 400 before recall runs.
#[tokio::test]
async fn http_recall_takes_call_mode_and_refuses_a_deadline_out_of_range() {
    let facade = OwnerFacade::new("facade-call-mode-range-secret");
    facade
        .witness(
            "81818181818181818181818181818181",
            &[(1_767_225_600, "The night train leaves at nine.")],
        )
        .await;
    for request in [
        json!({"query": "night train", "effort": "call", "deadline_ms": 30_000}),
        json!({"query": "night train", "deadline_ms": MAX_RECALL_DEADLINE_MS}),
    ] {
        let (found, _) = facade.recall(request.clone()).await;
        assert!(!found.is_empty(), "{request}");
    }
    let (status, _) = facade
        .post("recall", json!({"query": "night train", "effort": "call"}))
        .await;
    assert_eq!(status, StatusCode::OK);
    for deadline_ms in [0, MAX_RECALL_DEADLINE_MS + 1] {
        for effort in ["call", "light"] {
            let (status, body) = facade
                .post(
                    "recall",
                    json!({"query": "night train", "effort": effort, "deadline_ms": deadline_ms}),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{deadline_ms}: {body}");
            assert_eq!(body["error"]["code"], MEMORY_CODE_BAD_REQUEST);
            assert_eq!(
                body["error"]["message"],
                "deadline_ms must be a whole number between 1 and 60000"
            );
        }
    }
}

/// A stage that never yields cannot hold the turn: at the deadline the door
/// answers with the pack recall published before its retrieval ran, empty,
/// partial, and under the reader's receipt.
#[tokio::test]
async fn http_call_mode_answers_by_its_deadline_past_a_stalled_stage() {
    const DEADLINE_MS: u64 = 300;
    let facade = OwnerFacade::new("facade-call-mode-stall-secret");
    facade
        .witness(
            "82828282828282828282828282828282",
            &[(1_767_225_600, "The night ferry has no seats left.")],
        )
        .await;
    facade
        .server
        .vault
        .arm_slow_retrieval_stage_for_test(Some(SlowRetrievalStage {
            signal: RetrievalSignal::Text,
            duration: Duration::from_secs(3),
            yields: false,
        }));
    let started = Instant::now();
    let (status, pack) = facade
        .post(
            "recall",
            json!({"query": "night ferry", "effort": "call", "deadline_ms": DEADLINE_MS}),
        )
        .await;
    let took = started.elapsed();
    facade.server.vault.arm_slow_retrieval_stage_for_test(None);
    assert_eq!(status, StatusCode::OK, "{pack}");
    // The deadline counts from the door, after the router authenticates the
    // request; the slack is that, on a loaded host, and still far short of
    // the stall.
    assert!(
        took < Duration::from_millis(DEADLINE_MS + 1_000),
        "the stalled stage held the answer {took:?}"
    );
    assert_eq!(pack["items"], json!([]), "{pack}");
    assert_eq!(pack["retrieval_meta"]["partial"], true, "{pack}");
    assert_eq!(pack["scope_honesty"]["census_capped"], true, "{pack}");
    assert!(pack["narrowing"]["applied"].is_object(), "{pack}");
}
