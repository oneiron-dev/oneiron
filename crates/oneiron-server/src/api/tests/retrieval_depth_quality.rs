//! Memory-reason route depths/spend/validation, raw-search depth tiers, retrieval-quality markers + snapshots.

use super::*;

/// A composer citing something the retrieval never returned does not get to
/// speak: the read falls back to the evidence and says so.
#[tokio::test]
async fn memory_reason_refuses_an_answer_citing_evidence_it_never_retrieved() {
    let mut stub = StubReasonBackend::answering("invented recollection");
    stub.sources = Some(vec!["not-a-retrieved-short-id".to_owned()]);
    let (_dir, server) = memory_reason_server_auth(Some(Arc::new(stub)));

    let (status, body) = route_json_auth(
        server,
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({ "query": "launch date", "depth": "max" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_ne!(
        body["answer"],
        Value::from("invented recollection"),
        "an unsourced answer must not reach the wire: {body:?}"
    );
    let gaps: Vec<&str> = body["gaps"]
        .as_array()
        .expect("gaps array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        gaps.iter().any(|gap| gap.contains("not usable")),
        "the refusal is reported, not hidden: {gaps:?}"
    );
    assert_eq!(
        body["tokensUsed"],
        Value::from(3 + 5 + 9),
        "the tokens were spent whether or not the answer was usable"
    );
}
