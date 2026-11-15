//! A vector search inside an off-record room scores the vectors the room
//! staged beside base's walk (FIX 197). Each staged row was read for
//! liveness and admission (an entity read, its archive and deletion state,
//! staleness, the note check) before the page was cut to its limit, so a
//! page of ten cost reads for every row the room staged. The reads now run
//! only for the rows the page reaches.
//!
//! The test stages `STAGED` ASSET rows with 4-dimension vectors in a
//! roomless off-record stretch, each at a distinct angle from the query so
//! the ranking has no ties, plus a vector with no row at the top score, and
//! searches the stretch for `LIMIT` rows. The page must be the `LIMIT`
//! nearest rows in order, the rowless vector left out. It prints the fastest
//! of three searches: the measurement main and the fix are compared by.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test room_staged_vector_search`
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, Instant};

use oneiron::off_record::OffRecordBackendClass;
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::test_doors::untangle_regressions::{embedding_test_config, open_test_vault_with};
use oneiron::{EdgeActorClass, EntityId, RawEntityPut, TimeRange};

const STAGED: usize = 4_000;
const LIMIT: usize = 10;

/// Row `index`'s vector: unit length, at an angle from the query that grows
/// with `index` over 0.3..1.5 rad, so its score falls by at least ~1e-4 a row.
fn vector_of(index: usize) -> Vec<f32> {
    let step = 1.2 / f32::from(u16::try_from(STAGED).expect("row count"));
    let angle = 0.3 + step * f32::from(u16::try_from(index).expect("row index"));
    vec![angle.cos(), angle.sin(), 0.0, 0.0]
}

#[test]
fn a_room_search_pages_its_nearest_staged_rows() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    let session = vault
        .off_record_session_vault()
        .enter("fix197-staged-vectors", OffRecordBackendClass::Local)
        .expect("an off-record stretch");
    let memory = vault
        .memory(owner, EdgeActorClass::Human)
        .in_off_record_session(session.session_ref());

    let ids: Vec<EntityId> = (0..STAGED).map(|_| EntityId::now()).collect();
    let body = b"staged vector fixture";
    let puts: Vec<RawEntityPut<'_>> = ids
        .iter()
        .map(|id| RawEntityPut {
            id: *id,
            entity_type: ENTITY_TYPE_ASSET,
            occurred: TimeRange { start: 10, end: 10 },
            learned_at: 10,
            data: body,
        })
        .collect();
    let staging = Instant::now();
    memory
        .raw_put_entities(&puts)
        .expect("the rows stage in the room");
    for (index, id) in ids.iter().enumerate() {
        memory
            .raw_put_vector(id, &vector_of(index))
            .expect("the vector stages in the room");
    }
    // A vector at the query itself whose row the room never put: no page
    // holds it, as no base walk would.
    let rowless = EntityId::now();
    let rowless_staged = memory.raw_put_vector(&rowless, &[1.0, 0.0, 0.0, 0.0]);
    let staged_ms = staging.elapsed().as_secs_f64() * 1000.0;
    println!(
        "FIX197-ROWLESS staged={}",
        rowless_staged
            .as_ref()
            .map_or_else(|error| format!("refused: {error:?}"), |_| "yes".to_owned())
    );

    let query = [1.0, 0.0, 0.0, 0.0];
    let mut fastest = Duration::MAX;
    let mut page = Vec::new();
    for _ in 0..3 {
        let started = Instant::now();
        page = memory
            .raw_search_vector(&query, LIMIT)
            .expect("the room's vector search");
        fastest = fastest.min(started.elapsed());
    }
    let found: Vec<EntityId> = page.iter().map(|hit| hit.id).collect();
    assert_eq!(
        found,
        ids[..LIMIT],
        "the page is the nearest staged rows, best first"
    );
    assert!(
        !found.contains(&rowless),
        "a vector with no row takes no place"
    );
    println!(
        "FIX197-SEARCH staged={STAGED} limit={LIMIT} stage_ms={staged_ms:.0} search_ms={:.2}",
        fastest.as_secs_f64() * 1000.0
    );
}
