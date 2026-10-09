// A recalled TURN names the text revision of the words it served
// (`entity_revision::turn_text`): every door that reads a reference reads
// those words back at it.

/// Recall's TURN item for `query`, found by `meaning` and its words.
fn recalled_turn(
    facade: &Memory<'_>,
    query: &str,
    meaning: &[f32],
) -> crate::memory::MemoryItem {
    facade
        .recall_with_execution(
            query,
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
            &crate::retrieval_depth::RecallExecution {
                embedding: Some(meaning),
                ..Default::default()
            },
        )
        .expect("recall")
        .items
        .into_iter()
        .find(|item| item.kind == "TURN")
        .expect("the turn")
}

/// The `txt` a context pack pinned at `item`'s revision gives `turn`, found
/// by `meaning`, after the read lane's final filter.
fn pinned_pack_text(
    vault: &crate::Vault,
    lane: &crate::claim::ScopedRead<'_>,
    turn: &EntityId,
    meaning: &[f32],
    item: &crate::memory::MemoryItem,
) -> Option<String> {
    let revision = crate::vault::RevisionRef::from_hex(
        item.source_revision_ref.as_deref().expect("a pinned item"),
    )
    .expect("revision");
    let mut pack = vault
        .context_pack()
        .search_vector(meaning, 10)
        .hydrate(true)
        .read_mode(crate::vault::ReadMode::Pinned(revision))
        .run_unfinalized_with_telemetry()
        .expect("assemble")
        .value;
    lane.filter_context_pack(&mut pack).expect("filter the pack");
    pack.results
        .iter()
        .find(|entity| entity.id == *turn)
        .and_then(|entity| entity.fields.as_ref()?.get("txt")?.as_str().map(str::to_owned))
}

/// Astra 1333 re-check R3 (P2): a context pack pinned at the revision recall
/// served a turn under finds that turn, with its words. Bug repro: a pinned
/// pack admitted only revisions the turn's row owns, and a text revision is
/// none of them, so it dropped the turn.
#[test]
fn a_pack_pinned_at_a_recalled_turn_revision_keeps_the_turn() {
    const MEANING: [f32; 4] = [0.0, 1.0, 0.0, 0.0];
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let turn = witness_turn(&facade, 0xD5, &["the kettle whistles twice"], 1_900);
    fill_turn(&vault, &turn, &MEANING);
    let item = recalled_turn(&facade, "kettle", &MEANING);
    let lane = facade
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("owner read lane");
    assert_eq!(
        pinned_pack_text(&vault, &lane, &turn, &MEANING, &item).as_deref(),
        Some("the kettle whistles twice"),
        "{}",
        item.reference()
    );
}
