//! FIX MEMORIES-SLOT-BUDGET-CUT-UNCOUNTED: the MEMORIES projection drops
//! every optional row past its slot's cap or the shared cap. A companion
//! reading the board, and the receipt's board state ref, now carry how many
//! rows each slot lost, as the section's `cut` field. A section that cut
//! nothing serializes as before, with no `cut` key, so the state ref of
//! such a board does not move.
//!
//! The tests read the section as its JSON wire form, the form the HTTP board
//! serves, so they compile on a base without the field and fail there.
//!
//! Public crate surface only: `Vault::batch`, `Vault::context_pack` and
//! `context_board::project_memories_section`.
//! `cargo test --locked -p oneiron --all-features --test
//! memories_projection_cut_count`.

use oneiron::context_board::project_memories_section;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::{
    EntityId, HnswConfig, MemoriesBudget, MemoriesSection, TimeRange, Vault, VaultConfig,
};

const QUERY: &str = "matcha";
const TURNS: u8 = 5;

/// A vault holding `TURNS` TURNs whose text each names the query.
fn vault_with_turns() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    for seed in 1..=TURNS {
        let id = EntityId::now();
        let text = format!("{QUERY} ritual number {seed}");
        let vector = [f32::from(seed) / 255.0, 0.5, 0.25, 0.125];
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                u64::from(seed),
                text.as_bytes(),
            )
            .text(&id, &[("body", text.as_str())])
            .vector(&id, &vector)
            .commit()
            .expect("put a turn");
    }
    (dir, vault)
}

/// The MEMORIES section of one text query under `budget`, and its wire form.
fn board(vault: &Vault, budget: MemoriesBudget) -> (MemoriesSection, serde_json::Value) {
    let pack = vault
        .context_pack()
        .search_text(QUERY, 16)
        .run()
        .expect("the text query runs");
    let section = project_memories_section(&pack, budget, None, None);
    let wire = serde_json::to_value(&section).expect("the section serializes");
    (section, wire)
}

/// The rows of `section` in the turns slot.
fn turn_rows(section: &MemoriesSection) -> usize {
    section
        .rows
        .iter()
        .filter(|row| row.entity_type == ENTITY_TYPE_TURN)
        .count()
}

#[test]
fn rows_past_a_slot_cap_are_counted_as_cut() {
    let (_dir, vault) = vault_with_turns();
    let (whole, _) = board(&vault, MemoriesBudget::new(8, 8, 8, 8, 8));
    assert_eq!(
        turn_rows(&whole),
        usize::from(TURNS),
        "the query finds every turn"
    );

    let (section, wire) = board(&vault, MemoriesBudget::new(8, 2, 8, 8, 8));
    assert_eq!(turn_rows(&section), 2, "the turns cap keeps two rows");
    assert_eq!(
        wire.pointer("/cut/turns")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(TURNS) - 2),
        "the section counts the turns the cap cut: {wire}"
    );
    for slot in ["claims", "summaries", "facets", "other"] {
        assert_eq!(
            wire.pointer(&format!("/cut/{slot}"))
                .and_then(serde_json::Value::as_u64),
            Some(0),
            "no {slot} row was cut: {wire}"
        );
    }
}

#[test]
fn rows_past_the_shared_cap_are_counted_as_cut() {
    let (_dir, vault) = vault_with_turns();
    let (section, wire) = board(
        &vault,
        MemoriesBudget::new(8, 8, 8, 8, 8).with_shared_total(1),
    );
    assert_eq!(section.rows.len(), 1, "the shared cap keeps one row");
    assert_eq!(
        wire.pointer("/cut/turns")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(TURNS) - 1),
        "the section counts the turns the shared cap cut: {wire}"
    );
}

#[test]
fn a_section_that_cut_nothing_serializes_without_a_cut_key() {
    let (_dir, vault) = vault_with_turns();
    let (section, wire) = board(&vault, MemoriesBudget::new(8, 8, 8, 8, 8));
    assert_eq!(turn_rows(&section), usize::from(TURNS));
    assert!(
        wire.get("cut").is_none(),
        "an uncut section keeps its wire form and state ref: {wire}"
    );
}
