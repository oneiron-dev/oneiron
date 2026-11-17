//! A context pack and a graph walk bound to a room read its overlay ∪ base,
//! and never write what they read there into base (ARCH-0052 §2, D3).

use super::*;

/// Witnesses one turn into the room; returns the turn's id and its receipt.
fn room_turn(
    facade: &Memory<'_>,
    session: &crate::off_record::OffRecordSession<'_>,
    words: &str,
) -> (EntityId, WitnessReceipt) {
    let receipt = facade
        .witness_into_session(
            session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, words)],
                occurred_at: 900,
            },
            None,
        )
        .expect("session witness");
    let turn = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("receipt ref names the turn"),
    )
    .expect("turn id");
    (turn, receipt)
}

/// A vault that keeps its retrieval runs, so a run that reaches base shows.
fn telemetry_vault() -> (tempfile::TempDir, crate::Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = VaultConfig {
        retrieval_telemetry_capture: true,
        ..VaultConfig::default()
    };
    let vault = crate::Vault::open(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn base_runs(vault: &crate::Vault) -> usize {
    vault.retrieval_runs(64).expect("base runs").len()
}

fn ppr_cache_rows(vault: &crate::Vault) -> u64 {
    let txn = vault.store.env.read_txn().expect("read txn");
    vault.store.ppr_cache.len(&txn).expect("ppr cache rows")
}

/// A pack bound to the room retrieves, hydrates and walks the edges of a
/// message only the room holds. The same pack without the room's view
/// returns nothing of it.
#[test]
fn a_context_pack_bound_to_the_room_returns_the_message_only_the_room_holds() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-union-pack", 0x62);
    let facade = facade_for(&vault, actor);
    let words = "the room says copperwillowroom";
    let (_turn, receipt) = room_turn(&facade, &session, words);
    let message_short_id = short_id_part(&receipt.message_short_ids[0]);

    let outside = vault
        .context_pack()
        .search_text("copperwillowroom", 10)
        .run()
        .expect("pack outside the room");
    assert!(
        outside
            .results
            .iter()
            .all(|entity| entity.short_id != message_short_id),
        "outside the room, a pack cannot see the room's message"
    );

    let route = session.write_route().expect("route");
    let door = session.retrieval_telemetry(&route).expect("door");
    let view = session.read_view().expect("read view");
    let pack = vault
        .context_pack()
        .search_text("copperwillowroom", 10)
        .include_edges(true)
        .edge_hop(1)
        .in_session(&door)
        .reading(view.read())
        .run()
        .expect("pack in the room");
    let message = pack
        .results
        .iter()
        .find(|entity| entity.short_id == message_short_id)
        .unwrap_or_else(|| panic!("the room's pack returns its message, got {pack:?}"));
    assert_eq!(
        vault.get_raw(&message.id).expect("base get"),
        None,
        "the message is the room's alone"
    );
    let fields = serde_json::to_string(&message.fields).expect("fields json");
    assert!(
        fields.contains("copperwillowroom"),
        "the message is hydrated with its words, got {fields}"
    );
    assert!(
        message
            .edges
            .as_ref()
            .is_some_and(|edges| edges.iter().any(|edge| edge.kind == EdgeKind::PartOf)),
        "its edges, staged in the room, come with it"
    );
    drop(view);
    drop(door);

    session.close().expect("close session");
}

/// The walk's cache is keyed by base graph versions, which a room's writes
/// never bump. A walk in the room computes over overlay ∪ base past a warm
/// base row for the same seeds, and writes no row of its own into base, not
/// even once the room is on record: no cache row, and no run row naming the
/// room's rows (the taint guard covers references).
#[test]
fn a_walk_in_the_room_reaches_its_rows_past_a_warm_base_cache_and_caches_nothing() {
    let (_dir, vault) = telemetry_vault();
    let proof = crate::test_util::embedded_owner_proof(&vault);
    let (session, actor) = session_witness_fixture(&vault, "sess-union-ppr", 0x63);
    let facade = facade_for(&vault, actor);
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x64; 16])
                .expect("conversation id")
                .to_hex(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "said in base")],
            occurred_at: 800,
        })
        .expect("base witness");
    let warmed = vault
        .query()
        .search_ppr(&[actor], 2)
        .run_with_pending_vectors()
        .expect("base walk");
    assert!(
        !warmed.value.is_empty(),
        "the base walk reaches the base turn"
    );
    let warm_rows = ppr_cache_rows(&vault);
    assert!(warm_rows > 0, "the base walk cached its row");
    let runs = base_runs(&vault);
    assert!(runs > 0, "the base walk kept its run");

    room_turn(&facade, &session, "the room says pewterfinchroom");
    let reaches_the_room = |hits: &[crate::pipeline::ScoredEntity]| {
        hits.iter()
            .any(|hit| vault.get_raw(&hit.id).expect("base get").is_none())
    };

    {
        let route = session.write_route().expect("route");
        let door = session.retrieval_telemetry(&route).expect("door");
        let view = session.read_view().expect("read view");
        let walked = vault
            .query()
            .search_ppr(&[actor], 2)
            .in_session(&door)
            .reading(view.read())
            .run_with_pending_vectors()
            .expect("walk in the room");
        assert!(
            reaches_the_room(&walked.value),
            "the walk in the room reaches the room's rows, past the warm base row"
        );
    }
    assert_eq!(ppr_cache_rows(&vault), warm_rows, "and caches nothing");
    assert_eq!(base_runs(&vault), runs, "its run stays in the room");

    session.flip_on_record_as(&proof).expect("flip on record");
    {
        let route = session.write_route().expect("route");
        let door = session.retrieval_telemetry(&route).expect("door");
        let view = session.read_view().expect("read view");
        let walked = vault
            .query()
            .search_ppr(&[actor], 2)
            .in_session(&door)
            .reading(view.read())
            .run_with_pending_vectors()
            .expect("walk in the room on record");
        assert!(
            reaches_the_room(&walked.value),
            "on record, the room still reads what it held off record"
        );
    }
    assert_eq!(
        ppr_cache_rows(&vault),
        warm_rows,
        "a walk over the room's rows never lands in the base cache, on record or off"
    );
    assert_eq!(
        base_runs(&vault),
        runs,
        "on record, a run that read the room's rows keeps none in base"
    );

    session.close().expect("close session");
}
