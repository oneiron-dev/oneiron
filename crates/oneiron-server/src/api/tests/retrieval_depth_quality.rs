//! Memory-reason route depths/spend/validation, raw-search depth tiers, retrieval-quality markers + snapshots.

use super::*;

/// Required response fields and camelCase names are a contract; unrelated
/// additive fields do not change the default-tier behavior.
#[tokio::test]
async fn memory_reason_defaults_to_standard_and_answers_from_the_evidence() {
    let (_dir, server) = memory_reason_server_auth(None);

    let (status, body) = route_json_auth(
        server,
        json_request(
            "POST",
            "/v1/companion/memory/reason",
            json!({ "query": "launch date", "format": "markdown" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body:?}");
    let keys: BTreeSet<&str> = body
        .as_object()
        .expect("reason response object")
        .keys()
        .map(String::as_str)
        .collect();
    assert!(
        BTreeSet::from([
            "answer",
            "sources",
            "confidence",
            "gaps",
            "reasoning",
            "tokensUsed",
            "quality",
            "confidenceAdjustment",
        ])
        .is_subset(&keys),
        "required camelCase response fields: {body:?}"
    );
    for alias in ["tokens_used", "confidence_adjustment"] {
        assert!(!keys.contains(alias), "forbidden alias {alias}: {body:?}");
    }
    assert!(
        body["answer"]
            .as_str()
            .is_some_and(|answer| !answer.is_empty()),
        "{body:?}"
    );
    assert!(
        body["sources"]
            .as_array()
            .is_some_and(|sources| !sources.is_empty()),
        "an extractive answer cites the evidence it shows: {body:?}"
    );
    assert_eq!(
        body["tokensUsed"],
        Value::from(0),
        "the omitted-depth default is model-free and spends nothing"
    );

    // Omitted `depth` means standard, which is the tier that expands.
    let trace_keys: BTreeSet<&str> = body["reasoning"]
        .as_object()
        .expect("standard reports a trace")
        .keys()
        .map(String::as_str)
        .collect();
    assert!(
        BTreeSet::from(["queriesRun", "signalsUsed", "candidatesScanned"]).is_subset(&trace_keys),
        "required trace fields: {body:?}"
    );
    for alias in ["queries_run", "signals_used", "candidates_scanned"] {
        assert!(
            !trace_keys.contains(alias),
            "forbidden trace alias {alias}: {body:?}"
        );
    }
    let signals: Vec<&str> = body["reasoning"]["signalsUsed"]
        .as_array()
        .expect("signals array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        signals.contains(&"ppr"),
        "standard expands the graph: {signals:?}"
    );
    let queries: Vec<&str> = body["reasoning"]["queriesRun"]
        .as_array()
        .expect("queries array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        queries.first(),
        Some(&"launch date"),
        "the trace opens with the caller's own question: {queries:?}"
    );
}

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
