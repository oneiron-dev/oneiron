//! Observable stage-preset and temporal-window laws.
use super::*;
use crate::memory::Effort;

#[test]
fn five_effort_stage_sets_match_explicit_plans() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let seed = entity_id(0x71);
    let neighbor = entity_id(0x72);
    let now = 1_790_000_000;
    for id in [seed, neighbor] {
        put_text_and_vector(&vault, id, "preset probe", [1.0, 0.0, 0.0, 0.0])?;
    }
    vault
        .batch()
        .edge(&seed, EdgeKind::Mentions, &neighbor, 1.0)
        .commit()?;
    let vector = [1.0, 0.0, 0.0, 0.0];
    for (effort, depth, top_n) in [
        (Effort::Light, 0, 0),
        (Effort::Medium, 1, 0),
        (Effort::High, 2, 30),
        (Effort::Xhigh, 4, 50),
        (Effort::Max, 10, 50),
    ] {
        let base = || {
            vault
                .query()
                .search_text("preset", 10)
                .search_vector(&vector, 10)
                .search_phonetic(&["preset"])
                .with_temporal_now(now)
                .limit(10)
                .capture_retrieval_trace(true)
        };
        let mut preset = base().retrieval_effort(effort, &[seed]);
        let mut explicit = if effort == Effort::Max {
            base().search_temporal_bitemporal(now, now, 0, now, 86_400, 10)
        } else {
            base().search_temporal(now, now, 10)
        };
        if depth > 0 {
            explicit = explicit.search_ppr(&[seed], 1);
        }
        explicit = explicit
            .boost_recency(DEFAULT_RECENCY_HALF_LIFE_DAYS)
            .boost_salience()
            .boost_confidence();
        if depth > 1 {
            explicit = explicit.expand_ppr(&[seed], depth);
        }
        if top_n > 0 {
            let options = RerankOptions {
                top_n,
                query: Some("preset".into()),
            };
            preset = preset.rerank(
                &ReversingReranker,
                RerankOptions {
                    top_n: effort.rerank_top_n(),
                    query: Some("preset".into()),
                },
            );
            explicit = explicit.rerank(&ReversingReranker, options);
        }
        let actual = preset.run_with_telemetry()?;
        let expected = explicit.run_with_telemetry()?;
        assert_eq!(actual.value, expected.value, "{effort:?}");
        let actual = vault
            .retrieval_run(actual.run_id.unwrap())?
            .unwrap()
            .trace
            .unwrap();
        let expected = vault
            .retrieval_run(expected.run_id.unwrap())?
            .unwrap()
            .trace
            .unwrap();
        assert_eq!(actual.fork_hash, expected.fork_hash, "{effort:?}");
        assert_eq!(actual.per_channel, expected.per_channel, "{effort:?}");
    }
    Ok(())
}

#[test]
fn raw_light_effort_ranks_newer_identical_text_first() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let older = entity_id(0x10);
    let newer = entity_id(0x20);
    let now = crate::unix_seconds_now();
    for (id, learned_at) in [(older, now - 56 * 86_400), (newer, now - 28 * 86_400)] {
        put_text_at(&vault, id, "effortrecencyneedle", learned_at)?;
    }

    let baseline = vault.query().search_text("effortrecencyneedle", 10).run()?;
    assert_eq!(baseline[0].id, older, "equal text scores break ties by id");

    // The effort-generated now anchor is not a host-supplied temporal window.
    let ranked = vault
        .query()
        .search_text("effortrecencyneedle", 10)
        .with_temporal_now(now)
        .retrieval_effort(Effort::Light, &[])
        .run()?;
    assert_eq!(ranked.len(), 2);
    assert_eq!(ranked[0].id, newer);
    Ok(())
}
