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

struct MismatchReranker;

impl Reranker for MismatchReranker {
    fn id(&self) -> &str {
        "test/reranker-mismatch@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        Ok(vec![0.0; candidates.len() + 1])
    }
}

struct NanReranker;

impl Reranker for NanReranker {
    fn id(&self) -> &str {
        "test/reranker-nan@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        let mut scores = vec![0.0; candidates.len()];
        if let Some(first) = scores.first_mut() {
            *first = f32::NAN;
        }
        Ok(scores)
    }
}

struct FailingReranker;

impl Reranker for FailingReranker {
    fn id(&self) -> &str {
        "test/reranker-failing@v1"
    }

    fn rerank(&self, _query: &str, _candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        Err(Error::InvalidConfig("reranker offline".to_owned()))
    }
}

#[derive(Default)]
pub(super) struct ClaimProbeReranker {
    pub(super) seen: std::sync::Mutex<Vec<(EntityId, bool)>>,
}

impl Reranker for ClaimProbeReranker {
    fn id(&self) -> &str {
        "test/reranker-claim-probe@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        self.seen.lock().unwrap().extend(
            candidates
                .iter()
                .map(|candidate| (candidate.id, candidate.claim.is_some())),
        );
        Ok(vec![0.0; candidates.len()])
    }
}

/// Five entities with strictly decreasing cosine similarity to
/// `[1, 0, 0, 0]`, so the engine block order is e1..e5 deterministically.
fn rerank_fixture(vault: &Vault) -> Result<Vec<EntityId>> {
    let vectors = [
        [1.0, 0.0, 0.0, 0.0],
        [0.9, 0.1, 0.0, 0.0],
        [0.8, 0.2, 0.0, 0.0],
        [0.7, 0.3, 0.0, 0.0],
        [0.6, 0.4, 0.0, 0.0],
    ];
    let mut ids = Vec::new();
    for (index, vector) in vectors.iter().enumerate() {
        let id = entity_id(0x5E + index as u8);
        put_text_and_vector(vault, id, "rerank block fixture", *vector)?;
        ids.push(id);
    }
    Ok(ids)
}

fn rerank_query_vector() -> [f32; 4] {
    [1.0, 0.0, 0.0, 0.0]
}

#[test]
fn rerank_reorders_block_with_score_ladder_reassignment() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let ids = rerank_fixture(&vault)?;
    let query = rerank_query_vector();

    let baseline = vault.query().search_vector(&query, 10).limit(10).run()?;
    assert_eq!(
        baseline.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        ids,
        "fixture must produce the deterministic engine order"
    );

    let reranker = ReversingReranker;
    let reranked = vault
        .query()
        .search_vector(&query, 10)
        .limit(10)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: 5,
                query: Some("rerank probe".to_owned()),
            },
        )
        .run()?;

    let mut reversed_ids: Vec<EntityId> = baseline.iter().map(|scored| scored.id).collect();
    reversed_ids.reverse();
    assert_eq!(
        reranked.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        reversed_ids,
        "reversing reranker must reverse the block order"
    );
    // Score-ladder reassignment: position i keeps the i-th highest ENGINE
    // score; the score vector is unchanged even though ids permuted.
    assert_eq!(
        reranked
            .iter()
            .map(|scored| scored.score)
            .collect::<Vec<_>>(),
        baseline
            .iter()
            .map(|scored| scored.score)
            .collect::<Vec<_>>(),
    );
    assert!(
        reranked
            .windows(2)
            .all(|pair| pair[0].score >= pair[1].score),
        "scores must stay globally non-increasing"
    );
    Ok(())
}

/// A post-blend boost belongs to the positional score ladder, while decay
/// remains bound to whichever entity receives that rung after reranking.
#[test]
fn rerank_preserves_facet_prefer_boost_with_receiving_factor_once() -> Result<()> {
    const BOOST: f32 = 3.0;
    const FACTOR: f32 = 0.5;

    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;
    let overrides = HashMap::from([(fixture.claim_other, FACTOR)]);
    let baseline = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .with_access_factor_overrides(&overrides)
        .facet(&fixture.facet_a, FacetMode::Prefer { boost: BOOST })
        .limit(10)
        .run()?;
    assert_eq!(baseline[0].id, fixture.claim_active);
    assert_eq!(baseline[0].score, FACET_R1 * BOOST);
    assert_eq!(
        baseline.last().map(|scored| scored.id),
        Some(fixture.claim_other)
    );

    let reranker = ReversingReranker;
    let reranked = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .with_access_factor_overrides(&overrides)
        .facet(&fixture.facet_a, FacetMode::Prefer { boost: BOOST })
        .rerank(
            &reranker,
            RerankOptions {
                top_n: baseline.len(),
                query: Some("rerank boosted decay probe".to_owned()),
            },
        )
        .limit(10)
        .run()?;

    let expected_ids = baseline
        .iter()
        .rev()
        .map(|scored| scored.id)
        .collect::<Vec<_>>();
    assert_eq!(
        reranked.iter().map(|scored| scored.id).collect::<Vec<_>>(),
        expected_ids,
        "the reranker must reverse the full boosted block"
    );
    let promoted = &reranked[0];
    assert_eq!(promoted.id, fixture.claim_other);
    let expected = FACET_R1 * BOOST * FACTOR;
    assert!(
        approx_eq(promoted.score, expected, 1e-6),
        "the boosted top rung must survive and receive one factor: expected {expected}, got {}",
        promoted.score
    );
    assert!(
        !approx_eq(promoted.score, expected * FACTOR, 1e-6),
        "the receiving entity's factor must not be squared"
    );
    Ok(())
}

#[test]
fn rerank_top_n_two_reorders_only_top_block() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let ids = rerank_fixture(&vault)?;
    let query = rerank_query_vector();

    let baseline = vault.query().search_vector(&query, 10).limit(10).run()?;
    let reranker = ReversingReranker;
    let reranked = vault
        .query()
        .search_vector(&query, 10)
        .limit(10)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: 2,
                query: Some("rerank probe".to_owned()),
            },
        )
        .run()?;

    let reranked_ids: Vec<EntityId> = reranked.iter().map(|scored| scored.id).collect();
    assert_eq!(
        reranked_ids,
        vec![ids[1], ids[0], ids[2], ids[3], ids[4]],
        "only the top-2 block may reorder"
    );
    assert_eq!(
        reranked
            .iter()
            .map(|scored| scored.score)
            .collect::<Vec<_>>(),
        baseline
            .iter()
            .map(|scored| scored.score)
            .collect::<Vec<_>>(),
        "tail scores and ladder positions must be untouched"
    );
    Ok(())
}

#[test]
fn rerank_trace_and_telemetry_carry_rerank_components() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let ids = rerank_fixture(&vault)?;
    let query = rerank_query_vector();
    let reranker = ReversingReranker;

    let results = vault
        .query()
        .search_text("rerank block fixture", 10)
        .search_vector(&query, 10)
        .limit(10)
        .rerank(&reranker, RerankOptions::default())
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    let run_id = results.run_id.expect("rerank trace run id");
    let run = vault.retrieval_run(run_id)?.expect("rerank trace run");
    let trace = run.trace.clone().expect("rerank trace");

    let blended_ids: Vec<[u8; 16]> = trace
        .blended
        .candidates
        .iter()
        .map(|candidate| candidate.result_id)
        .collect();
    let reranked_ids: Vec<[u8; 16]> = trace
        .reranked
        .candidates
        .iter()
        .map(|candidate| candidate.result_id)
        .collect();
    assert_ne!(
        blended_ids, reranked_ids,
        "reranked stage must differ from blended under the reversing reranker"
    );
    let mut reversed = blended_ids;
    reversed.reverse();
    assert_eq!(reranked_ids, reversed);

    // Every reranked-stage candidate carries a raw Rerank component appended
    // after any blend components; the blended stage carries none.
    for candidate in &trace.reranked.candidates {
        let rerank_component = candidate
            .components
            .iter()
            .find(|component| component.signal == RetrievalSignal::Rerank)
            .expect("reranked stage candidate must carry a Rerank component");
        assert!(rerank_component.score.is_finite());
    }
    assert!(
        trace.blended.candidates.iter().all(|candidate| {
            candidate
                .components
                .iter()
                .all(|component| component.signal != RetrievalSignal::Rerank)
        }),
        "blended stage must stay rerank-free"
    );

    // `final` stays the post-truncate pack.
    assert_eq!(
        trace
            .final_stage
            .candidates
            .iter()
            .map(|candidate| candidate.result_id)
            .collect::<Vec<_>>(),
        run.result_ids
    );

    // Base telemetry: score_breakdown includes the rerank components for
    // block entries (always-on, not trace-gated).
    for id in &ids {
        let breakdown = run
            .score_breakdown
            .iter()
            .find(|breakdown| breakdown.result_id == *id.as_bytes())
            .expect("block entry in score breakdown");
        assert!(
            breakdown
                .components
                .iter()
                .any(|component| component.signal == RetrievalSignal::Rerank),
            "score_breakdown must carry rerank components for block entries"
        );
    }

    // `signals` stays channels-only.
    assert!(!run.signals.contains(&RetrievalSignal::Rerank));
    assert!(!results.value.is_empty());

    // Inactive passthrough: without rerank the reranked stage mirrors final.
    let passthrough = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("rerank block fixture", 10)
            .search_vector(&query, 10)
            .limit(10),
    )?;
    assert_eq!(
        passthrough.reranked.candidates,
        passthrough.final_stage.candidates
    );
    Ok(())
}

#[test]
fn rerank_fork_hash_distinguishes_configurations() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    rerank_fixture(&vault)?;
    let query = rerank_query_vector();
    let reranker = ReversingReranker;

    let build = |top_n: Option<usize>| {
        let builder = vault
            .query()
            .search_text("rerank block fixture", 10)
            .search_vector(&query, 10)
            .limit(10);
        match top_n {
            None => builder,
            Some(top_n) => builder.rerank(&reranker, RerankOptions { top_n, query: None }),
        }
    };

    let off = captured_retrieval_trace(&vault, build(None))?;
    let on_30 = captured_retrieval_trace(&vault, build(Some(30)))?;
    let on_50 = captured_retrieval_trace(&vault, build(Some(50)))?;
    let on_30_again = captured_retrieval_trace(&vault, build(Some(30)))?;

    assert_ne!(off.fork_hash, on_30.fork_hash, "off vs on must fork");
    assert_ne!(on_30.fork_hash, on_50.fork_hash, "top_n must fork");
    assert_eq!(
        on_30.fork_hash, on_30_again.fork_hash,
        "identical rerank-on runs must replay to the same fork hash"
    );
    Ok(())
}

#[test]
fn rerank_fail_closed_validation_and_invariants() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    rerank_fixture(&vault)?;
    let query = rerank_query_vector();
    let reversing = ReversingReranker;

    let err = vault
        .query()
        .search_vector(&query, 10)
        .rerank(
            &reversing,
            RerankOptions {
                top_n: 0,
                query: Some("q".to_owned()),
            },
        )
        .run()
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "rerank top_n must be greater than zero")
    );

    // No RerankOptions::query and no search_text: fails closed before any
    // channel work.
    let err = vault
        .query()
        .search_vector(&query, 10)
        .rerank(&reversing, RerankOptions::default())
        .run()
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "rerank requires a query: set RerankOptions::query or search_text")
    );

    let mismatch = MismatchReranker;
    let err = vault
        .query()
        .search_text("rerank block fixture", 10)
        .rerank(&mismatch, RerankOptions::default())
        .run()
        .unwrap_err();
    assert!(matches!(
        err,
        Error::InvariantViolation("reranker returned mismatched score count")
    ));

    let nan = NanReranker;
    let err = vault
        .query()
        .search_text("rerank block fixture", 10)
        .rerank(&nan, RerankOptions::default())
        .run()
        .unwrap_err();
    assert!(matches!(
        err,
        Error::InvariantViolation("reranker returned non-finite score")
    ));

    let failing = FailingReranker;
    let err = vault
        .query()
        .search_text("rerank block fixture", 10)
        .rerank(&failing, RerankOptions::default())
        .run()
        .unwrap_err();
    assert!(
        matches!(err, Error::InvalidConfig(ref msg) if msg == "reranker offline"),
        "a reranker Err must propagate, never degrade to passthrough"
    );
    Ok(())
}

#[test]
fn rerank_claim_candidates_carry_decoded_bodies() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim_id = entity_id(0xE6);
    let plain_id = entity_id(0xE7);
    put_claim_text(&vault, claim_id, "clamprobe fixture", None)?;
    put_text(&vault, plain_id, "clamprobe fixture")?;

    let probe = ClaimProbeReranker::default();
    vault
        .query()
        .search_text("clamprobe fixture", 10)
        .limit(10)
        .rerank(&probe, RerankOptions::default())
        .run()?;

    let seen = probe.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "both fixture entities must enter the block");
    assert!(
        seen.iter()
            .any(|(id, has_claim)| *id == claim_id && *has_claim),
        "gate-passing claim candidates must carry Some(claim)"
    );
    assert!(
        seen.iter()
            .any(|(id, has_claim)| *id == plain_id && !*has_claim),
        "non-claim candidates must carry None"
    );
    Ok(())
}

// ===== EMB-2 (ONE-1334) funnel fork-hash segments =====

#[test]
fn funnel_fork_hash_distinguishes_fast_dims_and_skip_rescore() -> Result<()> {
    let mut funnel_config = embedding_test_config();
    funnel_config.fast_dims = Some(2);
    let (_dir, vault) = crate::test_util::open_test_vault_with(funnel_config);
    let id = entity_id(0xEA);
    put_text_and_vector(&vault, id, "funnel forkhash fixture", [1.0, 0.0, 0.0, 0.0])?;
    let query = [1.0_f32, 0.0, 0.0, 0.0];

    let rescored =
        captured_retrieval_trace(&vault, vault.query().search_vector(&query, 10).limit(10))?;
    let hot_lane = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_vector(&query, 10)
            .skip_vector_rescore(true)
            .limit(10),
    )?;
    assert_ne!(
        rescored.fork_hash, hot_lane.fork_hash,
        "skip_vector_rescore must fork the replay key"
    );

    let (_dir_plain, plain_vault) = open_test_vault();
    put_text_and_vector(
        &plain_vault,
        id,
        "funnel forkhash fixture",
        [1.0, 0.0, 0.0, 0.0],
    )?;
    let plain = captured_retrieval_trace(
        &plain_vault,
        plain_vault.query().search_vector(&query, 10).limit(10),
    )?;
    assert_ne!(
        plain.fork_hash, rescored.fork_hash,
        "fast_dims None vs Some must fork the replay key"
    );
    Ok(())
}

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

/// Writes a stale stamp straight onto the `fedstale:` row.
///
/// The stamping SWEEP is proven end-to-end in `federation::tests`; what the
/// pipeline owes is behavior given a stamped world, so the fixture states that
/// premise directly instead of rebuilding a signed pact here.
fn stamp_world_stale(vault: &Vault, world: EntityId, reason: FederationStaleReason) -> Result<()> {
    let encoded = crate::federation::encode_world_stale_stamp(crate::federation::WorldStaleStamp {
        reason,
        disconnect_epoch: 4,
        stamped_at_secs: 7,
    });
    let key = crate::federation::federation_stale_key(world);
    vault.with_write_txn(|wtxn| {
        vault.store.sync_state.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

/// ONE-1411 done-means 3 + 4 — a stale-stamped world drops out of the scopes
/// that never named it (`All`, `Base`) and survives the scope that did
/// (`World(stamped)`); unstamped worlds and base reality move not at all, and
/// `WorldSet` is bit-for-bit stamp-insensitive.
#[test]
fn stale_stamped_world_drops_from_all_and_base_but_survives_explicit_scope() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let stale_world = entity_id(0xF1);
    let live_world = entity_id(0xF2);
    let claim_base = entity_id(0x61);
    let claim_stale = entity_id(0x62);
    let claim_live = entity_id(0x63);
    put_claim_with_vector_world(&vault, claim_base, [1.0, 0.0, 0.0, 0.0], None)?;
    put_claim_with_vector_world(&vault, claim_stale, [0.8, 0.6, 0.0, 0.0], Some(stale_world))?;
    put_claim_with_vector_world(&vault, claim_live, [0.6, 0.8, 0.0, 0.0], Some(live_world))?;

    let ids =
        |scores: &[ScoredEntity]| -> HashSet<EntityId> { scores.iter().map(|s| s.id).collect() };
    let scope_key: CodebaseScopeKey = [0x9A; CODEBASE_SCOPE_KEY_LEN];
    let run = |scope: Option<WorldScope>| -> Result<HashSet<EntityId>> {
        let mut query = vault.query().search_vector(&FACET_QUERY, 10);
        if let Some(scope) = scope {
            query = query.world(scope);
        }
        Ok(ids(&query.run()?))
    };

    let unstamped_all = run(None)?;
    assert_eq!(
        unstamped_all,
        HashSet::from([claim_base, claim_stale, claim_live]),
        "baseline: with no stamp, All spans every world"
    );
    let unstamped_world_set = run(Some(WorldScope::WorldSet(scope_key)))?;

    stamp_world_stale(&vault, stale_world, FederationStaleReason::Disconnected)?;

    assert_eq!(
        run(None)?,
        HashSet::from([claim_base, claim_live]),
        "All: the stamped world is gone, base reality and the live world are not"
    );
    assert_eq!(
        run(Some(WorldScope::Base))?,
        HashSet::from([claim_base]),
        "Base: every world-scoped claim is out, stamped or not"
    );
    assert_eq!(
        run(Some(WorldScope::World(stale_world)))?,
        HashSet::from([claim_base, claim_stale]),
        "World(stamped): naming a dead world is an explicit request to read it"
    );
    assert_eq!(
        run(Some(WorldScope::World(live_world)))?,
        HashSet::from([claim_base, claim_live]),
        "an unstamped world is untouched by the stale filter"
    );
    assert_eq!(
        run(Some(WorldScope::WorldSet(scope_key)))?,
        unstamped_world_set,
        "WorldSet takes no stale exclusion: identical output either side of the stamp"
    );
    Ok(())
}

/// A corrupt local `fedstale:` row fails the retrieval closed rather than
/// quietly reverting to the pre-ONE-1411 unscoped read.
#[test]
fn corrupt_stale_row_fails_the_unscoped_read_closed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim_base = entity_id(0x64);
    put_claim_with_vector_world(&vault, claim_base, [1.0, 0.0, 0.0, 0.0], None)?;

    let key = crate::federation::federation_stale_key(entity_id(0xF3));
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, &key, b"not a stale stamp")?;
        Ok(())
    })?;

    assert!(
        matches!(
            vault.query().search_vector(&FACET_QUERY, 10).run(),
            Err(Error::CorruptedIndex("federation world stale stamp"))
        ),
        "a corrupt stamp row must not degrade into an unfiltered result set"
    );
    Ok(())
}

// RET-03 / ONE-1401
pub(super) struct StubHyde {
    pub(super) embedding: Vec<f32>,
    pub(super) subqueries: Vec<String>,
    pub(super) insufficient: bool,
    pub(super) assess_calls: std::sync::atomic::AtomicUsize,
}
impl HydeExpander for StubHyde {
    fn id(&self) -> &str {
        "test/hyde"
    }
    fn expand(&self, request: &HydeRequest) -> Result<HydeExpansion> {
        Ok(HydeExpansion {
            grounded_query: request.query.clone(),
            hypothetical_answer: String::new(),
            embedding: self.embedding.clone(),
            subqueries: self.subqueries.clone(),
        })
    }
    fn assess_evidence(&self, _: &CompletionRequest) -> Result<EvidenceVerdict> {
        self.assess_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(if self.insufficient {
            EvidenceVerdict::Insufficient {
                gaps: vec!["gap".into()],
            }
        } else {
            EvidenceVerdict::Sufficient
        })
    }
}

#[test]
fn hyde_adds_recall_channel() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let only_hyde = entity_id(0x31);
    put_text_and_vector(&vault, only_hyde, "unrelated", [0.0, 1.0, 0.0, 0.0])?;
    let host = StubHyde {
        embedding: vec![0.0, 1.0, 0.0, 0.0],
        subqueries: vec![],
        insufficient: false,
        assess_calls: std::sync::atomic::AtomicUsize::new(0),
    };
    let scores = vault
        .query()
        .search_text("alpha", 10)
        .hyde(
            &host,
            GroundingContext::default(),
            HydeOptions {
                channel_limit: 10,
                retry_once: false,
            },
        )
        .run()?;
    assert!(scores.iter().any(|score| score.id == only_hyde));
    let runs = vault.retrieval_runs(1)?;
    assert!(runs[0].signals.contains(&RetrievalSignal::Hyde));
    assert!(runs[0].score_breakdown.iter().any(|row| {
        row.components
            .iter()
            .any(|component| component.signal == RetrievalSignal::Hyde)
    }));
    Ok(())
}

#[test]
fn retry_before_abstain() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_text_and_vector(&vault, entity_id(0x32), "retry", [1.0, 0.0, 0.0, 0.0])?;
    let host = StubHyde {
        embedding: vec![1.0, 0.0, 0.0, 0.0],
        subqueries: vec![
            "retry".into(),
            "retry".into(),
            String::new(),
            "other".into(),
        ],
        insufficient: true,
        assess_calls: std::sync::atomic::AtomicUsize::new(0),
    };
    let scores = vault
        .query()
        .search_text("retry", 1)
        .hyde(
            &host,
            GroundingContext::default(),
            HydeOptions {
                channel_limit: 150,
                retry_once: true,
            },
        )
        .run()?;
    assert!(scores.is_empty(), "a second insufficient verdict abstains");
    assert_eq!(
        host.assess_calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "an insufficient first verdict performs exactly one widened retry assessment"
    );
    assert!(host.assess_calls.load(std::sync::atomic::Ordering::SeqCst) <= 2);
    Ok(())
}

#[test]
fn insufficient_hyde_verdict_without_retry_abstains() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_text_and_vector(
        &vault,
        entity_id(0x33),
        "insufficient",
        [1.0, 0.0, 0.0, 0.0],
    )?;
    let host = StubHyde {
        embedding: vec![1.0, 0.0, 0.0, 0.0],
        subqueries: vec!["insufficient".into()],
        insufficient: true,
        assess_calls: std::sync::atomic::AtomicUsize::new(0),
    };

    let scores = vault
        .query()
        .search_text("insufficient", 10)
        .hyde(
            &host,
            GroundingContext::default(),
            HydeOptions {
                channel_limit: 10,
                retry_once: false,
            },
        )
        .run()?;

    assert!(
        scores.is_empty(),
        "an unretried insufficient verdict abstains"
    );
    assert_eq!(
        host.assess_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "retry_once=false must not request a second assessment"
    );
    Ok(())
}

#[test]
fn no_channel_run_preserves_empty_telemetry_fast_path() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let runs_before = vault.retrieval_runs(16)?.len();

    let result = vault.query().run_with_telemetry()?;

    assert!(result.value.is_empty());
    assert_eq!(result.run_id, None);
    assert_eq!(vault.retrieval_runs(16)?.len(), runs_before);
    Ok(())
}

#[test]
fn hyde_vector_validation_fails_closed() {
    let (_dir, vault) = open_test_vault();
    for embedding in [vec![], vec![1.0, f32::NAN, 0.0, 0.0], vec![1.0, 0.0]] {
        let host = StubHyde {
            embedding,
            subqueries: vec![],
            insufficient: false,
            assess_calls: std::sync::atomic::AtomicUsize::new(0),
        };
        assert!(
            vault
                .query()
                .search_text("query", 1)
                .hyde(
                    &host,
                    GroundingContext::default(),
                    HydeOptions {
                        channel_limit: 1,
                        retry_once: false
                    }
                )
                .run()
                .is_err()
        );
    }
}
