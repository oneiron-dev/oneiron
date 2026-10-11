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

/// The golden test of the scoped temporal bound (ARCH-0004 #temporal-bound).
/// Under a strict scope the channel keeps the `temporal_widening_bound`
/// nearest rows of the whole vault before the scope narrows them: an
/// in-scope row ranked at the bound is found, one ranked past it is not,
/// though an unbounded scan finds both. Asking for more rows moves the bound
/// to its multiple of the request.
#[test]
fn scoped_temporal_widening_stops_at_its_bound() -> Result<()> {
    use super::super::channels::temporal_widening_bound;
    use super::super::types::{TEMPORAL_WIDENING_FLOOR, TEMPORAL_WIDENING_MULTIPLE};

    // Canon cites these numbers: a change here changes the page too.
    assert_eq!(
        (TEMPORAL_WIDENING_MULTIPLE, TEMPORAL_WIDENING_FLOOR),
        (8, 4_000)
    );
    let few = 2;
    let many = TEMPORAL_WIDENING_FLOOR / TEMPORAL_WIDENING_MULTIPLE + 1;
    let (near, far) = (temporal_widening_bound(few), temporal_widening_bound(many));
    assert_eq!((near, far), (4_000, 4_008));

    let (_dir, vault) = open_test_vault();
    // A month back, clear of the rows the vault seeds at its open.
    let anchor = crate::unix_seconds_now() - 30 * 86_400;
    let row = |rank: usize| {
        let mut bytes = [0x7e; 16];
        bytes[12..].copy_from_slice(&u32::try_from(rank).expect("rank").to_be_bytes());
        EntityId::from_bytes(bytes).expect("row id")
    };
    // The row ranked `rank` sits 10 * `rank` seconds before the anchor on
    // both axes. The scope, type 1, holds the rows ranked `near`, `far` and
    // `far + 1`; every other row is type 2.
    let in_scope = [near, far, far + 1];
    let mut batch = vault.batch();
    for rank in 1..=far + 1 {
        let at = anchor - 10 * rank as u64;
        let kind = if in_scope.contains(&rank) { 1 } else { 2 };
        batch = batch.put(
            &row(rank),
            kind,
            TimeRange { start: at, end: at },
            at,
            b"payload",
        );
    }
    batch.commit()?;

    let scoped = |limit: usize| -> Result<Vec<EntityId>> {
        Ok(vault
            .query()
            .search_temporal(anchor, anchor, limit)
            .filter_types(&[1])
            .limit(limit)
            .run()?
            .into_iter()
            .map(|hit| hit.id)
            .collect())
    };
    assert_eq!(scoped(few)?, [row(near)]);
    assert_eq!(scoped(many)?, [row(near), row(far)]);
    Ok(())
}

/// A scoped call's widening trims; it never moves sigma. Sigma settles once
/// the window can fill the request, with or without a widened scan, as an
/// unscoped call's does.
#[test]
fn a_widened_temporal_scan_keeps_the_requests_sigma() -> Result<()> {
    use super::super::types::{EntityMetadataCache, TemporalSearchConfig};

    let (_dir, vault) = open_test_vault();
    let now = crate::unix_seconds_now();
    // A month back, clear of the rows the vault seeds at its open.
    let anchor = now - 30 * 86_400;
    // Three rows within hours of the anchor fill a request for two; a row a
    // year back keeps even the widest window from holding the whole vault.
    for (byte, at) in [
        (0xC5, anchor - 3_600),
        (0xC6, anchor - 7_200),
        (0xC7, anchor - 10_800),
        (0xC8, anchor - 365 * 86_400),
    ] {
        put_entity(&vault, entity_id(byte), 1, at, at, at)?;
    }
    let config = |widened| TemporalSearchConfig {
        anchor_start: anchor,
        anchor_end: anchor,
        learned_start: None,
        learned_end: None,
        sigma_secs: 86_400,
        anchor_mode: TemporalAnchorMode::Auto,
        adaptive: true,
        limit: 2,
        widened,
        query_occurred_range: None,
        effort_anchor: false,
    };
    let rtxn = vault.store.env.read_txn()?;
    let run = |widened| {
        super::super::channels::execute_temporal(
            &vault.store,
            &rtxn,
            &config(widened),
            now,
            &mut EntityMetadataCache::default(),
            None,
        )
    };
    let requested = run(None)?;
    let widened = run(Some(1_000))?;
    assert_eq!(requested.len(), 2);
    assert_eq!(
        widened.len(),
        3,
        "the widened scan returns every row in the window"
    );
    // Same sigma, so the same scores for the rows both return.
    assert_eq!(&widened[..2], &requested[..]);
    Ok(())
}

/// Rows outside a scope can fill the first window by themselves. A scoped
/// call's window keeps growing until it could fill the widened rows, so the
/// in-scope row ten days out is still found, as it was before the bound.
#[test]
fn a_scoped_temporal_window_grows_past_rows_its_scope_drops() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    // A month back, clear of the rows the vault seeds at its open.
    let anchor = crate::unix_seconds_now() - 30 * 86_400;
    let (outside, inside) = (entity_id(0xD1), entity_id(0xD2));
    put_entity(&vault, outside, 2, anchor, anchor, anchor)?;
    let back = anchor - 10 * 86_400;
    put_entity(&vault, inside, 1, back, back, back)?;

    let hits = vault
        .query()
        .search_temporal(anchor, anchor, 1)
        .filter_types(&[1])
        .limit(1)
        .run()?;
    assert_eq!(hits.iter().map(|hit| hit.id).collect::<Vec<_>>(), [inside]);
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
        widened: None,
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
