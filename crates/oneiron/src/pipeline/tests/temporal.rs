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
    use super::super::temporal_bound::temporal_widening_bound;
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
            &vault.store.read(),
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

/// Rows a grown window adds can outscore an in-scope row under the
/// request's sigma, though the wider sigma of an unscoped call for the
/// widened rows keeps it. That call's sigma picks the rows the scope sees;
/// the request's sigma only scores and orders them.
#[test]
fn a_grown_temporal_window_keeps_the_rows_its_own_sigma_picks() -> Result<()> {
    use super::super::temporal_bound::temporal_widening_bound;

    let (_dir, vault) = open_test_vault();
    // A month back, clear of the rows the vault seeds at its open.
    let anchor = crate::unix_seconds_now() - 30 * 86_400;
    let row = |n: usize| {
        let mut bytes = [0x6d; 16];
        bytes[12..].copy_from_slice(&u32::try_from(n).expect("n").to_be_bytes());
        EntityId::from_bytes(bytes).expect("row id")
    };
    let at = |days_back: u64| {
        let occurred = anchor - days_back * 86_400;
        TimeRange {
            start: occurred,
            end: occurred,
        }
    };
    // Two rows short of the bound sit at the anchor, outside the scope, so
    // the first window cannot fill the widened rows and grows.
    let near = temporal_widening_bound(1) - 2;
    let mut batch = vault.batch();
    for n in 1..=near {
        batch = batch.put(&row(n), 2, at(0), anchor, b"payload");
    }
    // The in-scope row six days back, and two rows outside the scope, learned
    // an hour later, that only the grown window reaches.
    let inside = row(near + 1);
    batch = batch.put(&inside, 1, at(6), anchor, b"payload");
    for (n, days_back) in [(near + 2, 10), (near + 3, 11)] {
        batch = batch.put(&row(n), 2, at(days_back), anchor + 3_600, b"payload");
    }
    batch.commit()?;

    let hits = vault
        .query()
        .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
        .filter_types(&[1])
        .limit(1)
        .run()?;
    assert_eq!(hits.iter().map(|hit| hit.id).collect::<Vec<_>>(), [inside]);
    Ok(())
}

/// A row the reader may not read never takes a place in the bounded rows,
/// so whether it exists cannot move what the reader gets back (DEC-0005:
/// no name, no count). Astra's #1409 trigger: 3,999 readable rows outside
/// the scope and the in-scope row ranked 4,000th fill the bound; one row the
/// reader's predicate refuses, at the anchor, would push the in-scope row
/// past it.
#[test]
fn a_row_the_reader_may_not_read_takes_no_place_in_the_bound() -> Result<()> {
    use super::super::temporal_bound::temporal_widening_bound;

    let (_dir, vault) = open_test_vault();
    // A month back, clear of the rows the vault seeds at its open.
    let anchor = crate::unix_seconds_now() - 30 * 86_400;
    let row = |rank: usize| {
        let mut bytes = [0x5b; 16];
        bytes[12..].copy_from_slice(&u32::try_from(rank).expect("rank").to_be_bytes());
        EntityId::from_bytes(bytes).expect("row id")
    };
    let bound = temporal_widening_bound(1);
    // The row ranked `rank` sits 10 * `rank` seconds before the anchor on
    // both axes; the scope, type 1, holds only the last.
    let mut batch = vault.batch();
    for rank in 1..=bound {
        let at = anchor - 10 * rank as u64;
        let kind = if rank == bound { 1 } else { 2 };
        batch = batch.put(
            &row(rank),
            kind,
            TimeRange { start: at, end: at },
            at,
            b"payload",
        );
    }
    batch.commit()?;
    let (inside, hidden) = (row(bound), row(0));
    let reads =
        |_: &crate::store::StoreRead<'_>, _: &heed::RoTxn<'_>, id: &EntityId| Ok(*id != hidden);
    let found = || -> Result<Vec<EntityId>> {
        Ok(vault
            .query()
            .search_temporal(anchor, anchor, 1)
            .filter_types(&[1])
            .filter_candidates(&reads)
            .limit(1)
            .run()?
            .into_iter()
            .map(|hit| hit.id)
            .collect())
    };
    assert_eq!(found()?, [inside]);
    put_entity(&vault, hidden, 1, anchor, anchor, anchor)?;
    assert_eq!(found()?, [inside], "a row the reader may not read moved it");
    Ok(())
}

/// Nor does such a row count toward the round where sigma settles: alone at
/// the anchor it would settle sigma before the window reaches the reader's
/// only row, ten days back, and so rescore that row.
#[test]
fn a_row_the_reader_may_not_read_does_not_settle_sigma() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let now = crate::unix_seconds_now();
    let anchor = now - 30 * 86_400;
    let back = anchor - 10 * 86_400;
    put_entity(&vault, entity_id(0xE2), 1, back, back, back)?;
    let hidden = entity_id(0xE0);
    let reads = |_: &crate::store::StoreRead<'_>,
                 _: &heed::RoTxn<'_>,
                 id: &EntityId|
     -> Result<bool> { Ok(*id != hidden) };
    let config = reader_temporal_config(anchor, 1);
    let rows = |vault: &Vault| reader_temporal_rows(vault, &config, now, &reads);
    let absent = rows(&vault)?;
    put_entity(&vault, hidden, 1, anchor, anchor, anchor)?;
    assert_eq!(absent.len(), 1);
    assert_eq!(rows(&vault)?, absent);
    Ok(())
}

/// Nor toward the window's stop. 3,999 rows outside the scope sit at the
/// anchor and the in-scope row eight days back, past the first window. A
/// row the reader may not read, at the anchor, would fill the bound in the
/// first window and stop it there; it must not, and once the grown window
/// holds more rows than the bound, the in-scope row ranked past it under the
/// window's sigma is still inside the cut, since one row above it is one the
/// reader may not read.
#[test]
fn a_row_the_reader_may_not_read_does_not_stop_the_window() -> Result<()> {
    use super::super::temporal_bound::temporal_widening_bound;

    let (_dir, vault) = open_test_vault();
    let anchor = crate::unix_seconds_now() - 30 * 86_400;
    let row = |n: usize| {
        let mut bytes = [0x5d; 16];
        bytes[12..].copy_from_slice(&u32::try_from(n).expect("n").to_be_bytes());
        EntityId::from_bytes(bytes).expect("row id")
    };
    let mut batch = vault.batch();
    for n in 1..temporal_widening_bound(1) {
        let at = TimeRange {
            start: anchor,
            end: anchor,
        };
        batch = batch.put(&row(n), 2, at, anchor, b"payload");
    }
    batch.commit()?;
    let (inside, hidden) = (row(0), entity_id(0xE0));
    let back = anchor - 8 * 86_400;
    put_entity(&vault, inside, 1, back, back, back)?;
    let reads =
        |_: &crate::store::StoreRead<'_>, _: &heed::RoTxn<'_>, id: &EntityId| Ok(*id != hidden);
    let found = || -> Result<Vec<EntityId>> {
        Ok(vault
            .query()
            .search_temporal(anchor, anchor, 1)
            .filter_types(&[1])
            .filter_candidates(&reads)
            .limit(1)
            .run()?
            .into_iter()
            .map(|hit| hit.id)
            .collect())
    };
    assert_eq!(found()?, [inside]);
    put_entity(&vault, hidden, 1, anchor, anchor, anchor)?;
    assert_eq!(found()?, [inside], "a row the reader may not read moved it");
    Ok(())
}

/// The oracle for the reader's path: with a predicate that admits every
/// row, the channel and its cut return exactly what the plain channel
/// returns, rows and scores, whether the first window holds the bound with
/// no row beyond it, holds it with rows beyond it, holds more than the bound
/// and stops though a later round's sigma would pick other rows, grows past
/// the round where sigma settled, or never holds the request.
#[test]
fn a_reader_of_every_row_gets_what_the_plain_temporal_channel_returns() -> Result<()> {
    use super::super::temporal_bound::temporal_widening_bound;

    let bound = temporal_widening_bound(1);
    let now = crate::unix_seconds_now();
    let anchor = now - 30 * 86_400;
    let reads = |_: &crate::store::StoreRead<'_>,
                 _: &heed::RoTxn<'_>,
                 _: &EntityId|
     -> Result<bool> { Ok(true) };
    // (rows asked for, rows within minutes of the anchor, days back of the
    // rows past them; a negative day is after the anchor). Five days back
    // and six after: the first window's sigma ranks the newer row above the
    // older, the last round's the nearer.
    for (limit, near, beyond) in [
        (1, bound + 100, &[][..]),
        (1, bound + 100, &[8, 10][..]),
        (1, bound - 1, &[5, -6][..]),
        (1, bound - 2, &[8, 10, 11][..]),
        (2, 0, &[2][..]),
    ] {
        let (_dir, vault) = open_test_vault();
        let row = |n: usize| {
            let mut bytes = [0x5e; 16];
            bytes[12..].copy_from_slice(&u32::try_from(n).expect("n").to_be_bytes());
            EntityId::from_bytes(bytes).expect("row id")
        };
        let mut batch = vault.batch();
        for n in 0..near {
            let at = anchor - 60 * n as u64;
            batch = batch.put(&row(n), 1, TimeRange { start: at, end: at }, at, b"payload");
        }
        for (n, days) in beyond.iter().enumerate() {
            let at = anchor
                .checked_add_signed(-i64::from(*days) * 86_400)
                .expect("a day near the anchor");
            batch = batch.put(
                &row(near + n),
                1,
                TimeRange { start: at, end: at },
                at,
                b"payload",
            );
        }
        batch.commit()?;
        let config = reader_temporal_config(anchor, limit);
        let plain = {
            let rtxn = vault.store.env.read_txn()?;
            super::super::channels::execute_temporal(
                &vault.store.read(),
                &rtxn,
                &config,
                now,
                &mut super::super::types::EntityMetadataCache::default(),
                None,
            )?
        };
        assert_eq!(plain.len(), bound.min(near + beyond.len()));
        assert_eq!(
            reader_temporal_rows(&vault, &config, now, &reads)?,
            plain,
            "{limit} asked, {near} near, {beyond:?} beyond"
        );
    }
    Ok(())
}

/// A reader's channel probes the ring past its window, which no call that
/// stops in that window reads. A damaged index key there must not fail a
/// call the plain channel answers (Sol #1409 R4): the probe takes it for a
/// row, and the window, already holding the bound, stops anyway.
#[test]
fn a_damaged_key_past_a_full_window_fails_no_reader() -> Result<()> {
    use super::super::temporal_bound::temporal_widening_bound;

    let bound = temporal_widening_bound(1);
    let now = crate::unix_seconds_now();
    let anchor = now - 30 * 86_400;
    let (_dir, vault) = open_test_vault();
    let row = |n: usize| {
        let mut bytes = [0x5f; 16];
        bytes[12..].copy_from_slice(&u32::try_from(n).expect("n").to_be_bytes());
        EntityId::from_bytes(bytes).expect("row id")
    };
    let mut batch = vault.batch();
    for n in 0..bound {
        let at = TimeRange {
            start: anchor,
            end: anchor,
        };
        batch = batch.put(&row(n), 1, at, anchor, b"payload");
    }
    batch.commit()?;
    // A short occurred-start key eight days out: past the first window,
    // inside the last round's.
    let mut damaged = (anchor + 8 * 86_400).to_be_bytes().to_vec();
    damaged.extend_from_slice(b"short");
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .temporal_occurred_start
            .put(wtxn, &damaged, &[])?;
        Ok(())
    })?;
    let reads = |_: &crate::store::StoreRead<'_>,
                 _: &heed::RoTxn<'_>,
                 _: &EntityId|
     -> Result<bool> { Ok(true) };
    let config = reader_temporal_config(anchor, 1);
    let plain = {
        let rtxn = vault.store.env.read_txn()?;
        super::super::channels::execute_temporal(
            &vault.store.read(),
            &rtxn,
            &config,
            now,
            &mut super::super::types::EntityMetadataCache::default(),
            None,
        )?
    };
    assert_eq!(plain.len(), bound);
    assert_eq!(reader_temporal_rows(&vault, &config, now, &reads)?, plain);
    Ok(())
}

/// The scoped temporal call these tests make: `limit` rows asked for at a
/// point anchor, widened to the bound.
fn reader_temporal_config(anchor: u64, limit: usize) -> super::super::types::TemporalSearchConfig {
    super::super::types::TemporalSearchConfig {
        anchor_start: anchor,
        anchor_end: anchor,
        learned_start: None,
        learned_end: None,
        sigma_secs: 86_400,
        anchor_mode: TemporalAnchorMode::Auto,
        adaptive: true,
        limit,
        widened: Some(super::super::temporal_bound::temporal_widening_bound(limit)),
        query_occurred_range: None,
        effort_anchor: false,
    }
}

/// What that call returns to a reader with predicate `reads`: the rows its
/// cut keeps, best first, as the scope walk would take them.
fn reader_temporal_rows(
    vault: &Vault,
    config: &super::super::types::TemporalSearchConfig,
    now: u64,
    reads: &crate::pipeline::CandidateFilter<'_>,
) -> Result<Vec<ScoredEntity>> {
    use super::super::temporal_bound::{ReadableRows, execute_temporal_for_reader};

    let rtxn = vault.store.env.read_txn()?;
    let reader = ReadableRows::new(reads, None);
    let (rows, cut) = execute_temporal_for_reader(
        &vault.store.read(),
        &rtxn,
        config,
        now,
        &mut super::super::types::EntityMetadataCache::default(),
        None,
        &reader,
    )?;
    let mut kept = Vec::new();
    for hit in rows {
        if cut.keeps(&vault.store.read(), &rtxn, &hit.id)? {
            kept.push(hit);
        }
    }
    Ok(kept)
}

/// The spanner buffer of a channel with a large cap keeps exactly the rows
/// a full sort keeps, and trims an amortized constant number of times per
/// spanner (Astra's #1409 trigger: a trim threshold equal to the cap sorted
/// the whole buffer for every spanner past it).
#[test]
fn a_bounded_temporal_channel_trims_its_spanners_in_amortized_time() -> Result<()> {
    use super::super::channels::{SPANNER_TRIMS, execute_temporal};
    use super::super::temporal_bound::temporal_widening_bound;
    use super::super::types::{EntityMetadataCache, PER_SCAN_CAP_FACTOR, TemporalSearchConfig};

    // 50,000 rows outgrow the canonical 16 MiB map.
    let mut vault_config = crate::test_util::embedding_test_config();
    vault_config.map_size = 256 * 1024 * 1024;
    let (_dir, vault) = crate::test_util::open_test_vault_with(vault_config);
    let anchor = crate::unix_seconds_now() - 30 * 86_400;
    let row = |n: usize| {
        let mut bytes = [0x5c; 16];
        bytes[12..].copy_from_slice(&u32::try_from(n).expect("n").to_be_bytes());
        EntityId::from_bytes(bytes).expect("row id")
    };
    // 50,000 intervals from a month before the anchor to a month after it,
    // so every one spans each window and none ends inside it. Row `n` was
    // learned a minute before row `n - 1`: the newer, the better it ranks.
    let spanners = 50_000;
    let mut batch = vault.batch();
    for n in 0..spanners {
        let span = TimeRange {
            start: anchor - 30 * 86_400,
            end: anchor + 30 * 86_400,
        };
        batch = batch.put(&row(n), 1, span, anchor - 60 * n as u64, b"payload");
    }
    batch.commit()?;

    let widened = temporal_widening_bound(1);
    let config = TemporalSearchConfig {
        anchor_start: anchor,
        anchor_end: anchor,
        learned_start: None,
        learned_end: None,
        sigma_secs: 86_400,
        anchor_mode: TemporalAnchorMode::Occurred,
        adaptive: true,
        limit: 1,
        widened: Some(widened),
        query_occurred_range: None,
        effort_anchor: false,
    };
    let rtxn = vault.store.env.read_txn()?;
    let before = SPANNER_TRIMS.with(std::cell::Cell::get);
    let kept = execute_temporal(
        &vault.store.read(),
        &rtxn,
        &config,
        anchor,
        &mut EntityMetadataCache::default(),
        None,
    )?;
    let trims = SPANNER_TRIMS.with(std::cell::Cell::get) - before;
    // A full sort keeps the `widened` newest rows, newest first.
    assert_eq!(
        kept.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        (0..widened).map(row).collect::<Vec<_>>()
    );
    let cap = widened * PER_SCAN_CAP_FACTOR;
    assert!(
        trims <= spanners / cap + 1,
        "{trims} trims for {spanners} spanners at a cap of {cap}"
    );
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
            &vault.store.read(),
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
