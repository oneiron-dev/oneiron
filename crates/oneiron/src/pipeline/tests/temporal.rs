//! Temporal index scans, sigma scoring, widening, and contiguity pins.

use super::*;

#[test]
fn learned_overlap_tiebreak_uses_learned_axis() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let anchor_start = crate::unix_seconds_now() + 100;
    let anchor_end = anchor_start + 100;
    let closer = entity_id(142);
    let farther = entity_id(143);

    put_entity(
        &vault,
        closer,
        1,
        anchor_start,
        anchor_start + 10,
        anchor_start + 49,
    )?;
    put_entity(
        &vault,
        farther,
        1,
        anchor_start + 49,
        anchor_start + 50,
        anchor_start + 80,
    )?;

    let results = vault
        .query()
        .search_temporal_with_sigma(
            anchor_start,
            anchor_end,
            86_400,
            TemporalAnchorMode::Learned,
            10,
        )
        .run()?;

    assert_eq!(results[0].id, closer);
    Ok(())
}

#[test]
fn temporal_type_scope_does_not_spend_limit_on_excluded_hit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let anchor = crate::unix_seconds_now();
    let eligible = entity_id(0xB1);
    let excluded = entity_id(0xB2);
    put_entity(&vault, eligible, 1, anchor, anchor, anchor - 60 * 86_400)?;
    put_entity(&vault, excluded, 2, anchor, anchor, anchor)?;

    let hits = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .filter_types(&[1])
        .limit(1)
        .run()?;
    assert_eq!(
        hits.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        [eligible]
    );
    Ok(())
}

/// Under a deadline the temporal channel checks in at each row whose metadata
/// it reads, so a stage past its share stops there instead of finishing a
/// scan that can cover the whole vault.
#[test]
fn temporal_channel_stops_at_a_spent_stage() -> Result<()> {
    use crate::retrieval_depth::RetrievalDeadline;
    use crate::store::RetrievalSignal;

    let (_dir, vault) = open_test_vault();
    let anchor = crate::unix_seconds_now();
    put_entity(&vault, entity_id(0xC1), 1, anchor, anchor, anchor)?;
    let config = super::super::types::TemporalSearchConfig {
        anchor_start: anchor,
        anchor_end: anchor,
        learned_start: None,
        learned_end: None,
        sigma_secs: 86_400,
        anchor_mode: TemporalAnchorMode::Occurred,
        adaptive: false,
        limit: 10,
        query_occurred_range: None,
        effort_anchor: false,
    };
    let rtxn = vault.store.env.read_txn()?;
    let run = |deadline: Option<&RetrievalDeadline>| {
        super::super::channels::execute_temporal(
            &vault.store,
            &rtxn,
            &config,
            anchor,
            &mut super::super::types::EntityMetadataCache::default(),
            deadline,
        )
    };
    assert_eq!(run(None)?.len(), 1);
    let deadline = RetrievalDeadline::after(std::time::Duration::from_secs(60));
    assert!(deadline.open_stage(RetrievalSignal::Temporal, 1));
    // The stage's share is spent.
    deadline.cancel();
    assert!(matches!(
        run(Some(&deadline)),
        Err(crate::Error::RetrievalStageCut)
    ));
    assert!(deadline.was_cut_short());
    Ok(())
}
