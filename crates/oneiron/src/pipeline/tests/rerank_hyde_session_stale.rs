//! Rerank blocks, Hyde recall, session staging, and stale-world federation.

use super::*;

// ===== RET-010 (ONE-1292) host-injected rerank hook =====

/// Scores candidates ascending by engine rank, so the rerank order is the
/// exact reversal of the engine block order.
pub(super) struct ReversingReranker;

impl Reranker for ReversingReranker {
    fn id(&self) -> &str {
        "test/reranker-reversing@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        Ok((0..candidates.len()).map(|index| index as f32).collect())
    }
}

// ===== EMB-2 (ONE-1334) funnel fork-hash segments =====

#[derive(Default)]
struct CountingErroringReranker {
    calls: std::sync::Mutex<usize>,
}

impl Reranker for CountingErroringReranker {
    fn id(&self) -> &str {
        "test/reranker-counting-erroring@v1"
    }

    fn rerank(&self, _query: &str, _candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        *self.calls.lock().unwrap() += 1;
        Err(Error::InvalidConfig(
            "reranker must not run on an empty block".to_owned(),
        ))
    }
}

/// Qodo #472-F3: an empty rerank block is a semantic no-op — the host impl
/// must never be invoked, so an otherwise-empty retrieval cannot fail
/// solely on reranker behavior.
#[test]
fn rerank_skips_empty_block_without_invoking_reranker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_text(&vault, entity_id(0xE8), "indexed but unrelated")?;

    let reranker = CountingErroringReranker::default();
    let results = vault
        .query()
        .search_text("zeromatch query tokens", 10)
        .limit(10)
        .rerank(&reranker, RerankOptions::default())
        .run()?;

    assert!(results.is_empty(), "the retrieval itself is empty");
    assert_eq!(
        *reranker.calls.lock().unwrap(),
        0,
        "the reranker must never be invoked on an empty block"
    );
    Ok(())
}

/// K10: a session pipeline run's telemetry row lands IN THE ROOM.
///
/// The session arm STAGES its row through the room's registration door, and
/// overlay staging refuses without an active txn segment — so an arm that
/// opens only a base write txn fails on every call. This asserts the ROW
/// exists rather than that the run succeeded: with no row, the K8 pre-close
/// census counts zero context receipts and an in-room caller cannot see its
/// own runs.
#[test]
fn a_session_pipeline_run_stages_its_telemetry_row_in_the_room() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_text(&vault, entity_id(0x9A), "sessiontelemetryneedle")?;

    let session = vault.off_record_session_vault().enter(
        "sess-pipeline-telemetry",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    let base_runs_before = vault.retrieval_runs(16)?.len();

    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;
    let telemetry = vault
        .query()
        .search_text("sessiontelemetryneedle", 10)
        .in_session(&door)
        .run_with_telemetry()?;
    let run_id = telemetry
        .run_id
        .expect("a session run registers its telemetry row");

    {
        let view = session.read_view()?;
        let rtxn = vault.store.env.read_txn()?;
        let rows = view.retrieval_runs_in_txn(&rtxn, 16)?;
        assert!(
            rows.iter().any(|row| row.run_id == run_id),
            "the run row is readable through the room's composed view"
        );
    }
    assert_eq!(
        vault.retrieval_runs(16)?.len(),
        base_runs_before,
        "a session run adds ZERO base telemetry rows"
    );

    session.close()?;
    Ok(())
}
