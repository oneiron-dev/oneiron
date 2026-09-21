use super::*;
pub(in crate::beam) mod support;
#[test]
fn chroma_wire_fixture_is_independent_and_cannot_read_gold() {
    let mock = support::MockChroma::start(1);
    let record: super::super::report_model::RunContractRecord = serde_json::from_str(include_str!(
        "../../../fixtures/beam_128k_contract.run.jsonl"
    ))
    .unwrap();
    let config = ChromaConfig {
        endpoint: mock.endpoint.clone(),
        retrieval_k: 1,
        card_id: "chroma-vanilla@v2".into(),
    };
    let arm = ChromaArm::ingest(&config, &record.corpus).unwrap();
    assert_eq!(
        arm.retrieve(&[1.0, 0.0, 0.0, 0.0]).unwrap(),
        format!("{}\n", record.corpus[0].text)
    );
    drop(arm);
    let requests = mock.finish();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[1].1["ids"],
        serde_json::json!(["turn-1", "turn-2"])
    );
    assert!(requests.iter().all(|(_, body)| body.get("gold").is_none()));
    assert!(requests[2].0.contains("/query"));
}
