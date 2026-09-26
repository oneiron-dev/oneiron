//! Deterministic BEAM seam sweep; this is not a learned-model quality claim.
use oneiron::rerank::{RerankCandidate, RerankOptions, Reranker};
use oneiron::{EntityId, TimeRange, Vault};

struct ReverseBlock;
impl Reranker for ReverseBlock {
    fn id(&self) -> &str {
        "beam/reverse-rank@v1"
    }
    fn rerank(&self, _: &str, candidates: &[RerankCandidate<'_>]) -> oneiron::Result<Vec<f32>> {
        Ok(candidates.iter().map(|row| row.rank as f32).collect())
    }
}

#[test]
fn beam_top_n_sweep_30_vs_50_keeps_membership_scale_and_trace_forks() -> super::BeamResult<()> {
    let dir = tempfile::tempdir()?;
    let mut config = super::util::beam_vault_config();
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config)?;
    for index in 0_u8..60 {
        let mut bytes = [0x73; 16];
        bytes[15] = index;
        let id = EntityId::from_bytes(bytes)?;
        let body =
            rmp_serde::to_vec_named(&serde_json::json!({"txt":"beam rerank needle","at":1}))?;
        vault
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                &body,
            )
            .text(&id, &[("body", "beam rerank needle")])
            .commit()?;
    }
    let baseline = vault
        .query()
        .search_text("beam rerank needle", 60)
        .with_temporal_now(10)
        .limit(60)
        .run()?;
    assert_eq!(baseline.len(), 60);
    let mut hashes = Vec::new();
    for top_n in [30, 50] {
        let output = vault
            .query()
            .search_text("beam rerank needle", 60)
            .with_temporal_now(10)
            .limit(60)
            .rerank(&ReverseBlock, RerankOptions { top_n, query: None })
            .capture_retrieval_trace(true)
            .run_with_telemetry()?;
        let hits = &output.value;
        assert_eq!(hits.len(), baseline.len());
        assert_eq!(hits[0].id, baseline[top_n - 1].id);
        assert_eq!(
            hits.iter()
                .map(|row| row.score.to_bits())
                .collect::<Vec<_>>(),
            baseline
                .iter()
                .map(|row| row.score.to_bits())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            hits[top_n..].iter().map(|row| row.id).collect::<Vec<_>>(),
            baseline[top_n..]
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>()
        );
        let mut before = baseline.iter().map(|row| row.id).collect::<Vec<_>>();
        let mut after = hits.iter().map(|row| row.id).collect::<Vec<_>>();
        before.sort();
        after.sort();
        assert_eq!(before, after);
        let trace = vault
            .retrieval_run(output.run_id.expect("captured run"))?
            .expect("stored run")
            .trace
            .expect("trace");
        hashes.push(trace.fork_hash);
    }
    assert_ne!(hashes[0], hashes[1], "top-N is part of the replay fork");
    Ok(())
}
