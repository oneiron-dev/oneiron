use super::*;
use crate::store::RetrievalSignal;

#[test]
fn rerank_options_default_uses_top_n_constant() {
    let options = RerankOptions::default();
    assert_eq!(options.top_n, RERANK_TOP_N_DEFAULT);
    assert_eq!(options.top_n, 30);
    assert!(options.query.is_none());
}

#[test]
fn rerank_signal_is_not_a_blend_signal() {
    assert_eq!(RetrievalSignal::Rerank.as_blend_signal(), None);
}

#[test]
fn rerank_signal_serde_snake_case_round_trip() {
    let encoded = serde_json::to_string(&RetrievalSignal::Rerank).expect("encode");
    assert_eq!(encoded, "\"rerank\"");
    let decoded: RetrievalSignal = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, RetrievalSignal::Rerank);
}
