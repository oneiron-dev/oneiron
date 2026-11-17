//! A room's recall reads its overlay ∪ base (ARCH-0052 §2 #target).

use super::*;

/// The words the room says, and nothing in base says.
const ROOM_WORDS: &str = "lanternquartzroom";

/// ARCH-0052 §2: every reader in the room sees overlay ∪ base. A turn
/// witnessed into the room exists only in its overlay. Recall in the room
/// returns it, with its words, at Light (the bare pack) and at Medium
/// (seeds, edges, hydration); the same recall outside the room does not.
#[test]
fn an_in_room_recall_returns_the_turn_only_the_room_holds() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_owner_fixture(&vault, "sess-union-recall");
    let facade = facade_for(&vault, actor);
    let receipt = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(
                    0,
                    WitnessAuthor::User,
                    &format!("the room says {ROOM_WORDS}"),
                )],
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
    assert_eq!(
        vault.get_raw(&turn).expect("base get"),
        None,
        "the turn is the room's alone"
    );

    let outside = facade
        .recall(
            ROOM_WORDS,
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall outside the room");
    assert!(
        outside
            .items
            .iter()
            .all(|item| !item.value_text.contains(ROOM_WORDS)),
        "outside the room, recall cannot see the room's turn"
    );

    for effort in [Effort::Light, Effort::Medium] {
        let pack = facade
            .recall_in_session(
                &session,
                ROOM_WORDS,
                effort,
                &RecallScope::default(),
                10,
                None,
                None,
            )
            .expect("recall in the room");
        let item = pack
            .items
            .iter()
            .find(|item| item.value_text.contains(ROOM_WORDS))
            .unwrap_or_else(|| {
                panic!("{effort:?} recall in the room returns its turn, got {pack:?}")
            });
        assert_eq!(item.kind, "TURN", "the message comes back as its turn");
        assert_eq!(
            short_id_part(&item.short_id),
            short_id_part(&receipt.turn_short_id),
            "the item names the turn by the room's own short id"
        );
    }

    session.close().expect("close session");
}

/// ARCH-0052 mode flip: on record, the room still reads the turns it held
/// off record, and base holds no reference to a live room row. A recall
/// there returns the room's turn and keeps none of its runs in base, at
/// Light and at Medium (whose seeds come from the room's own search).
#[test]
fn on_record_a_recall_over_the_rooms_turn_keeps_no_run_in_base() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = VaultConfig {
        retrieval_telemetry_capture: true,
        ..VaultConfig::default()
    };
    let vault = crate::Vault::open(dir.path(), config).expect("open vault");
    let proof = crate::test_util::embedded_owner_proof(&vault);
    let (session, actor) = session_owner_fixture(&vault, "sess-union-recall-runs");
    let facade = facade_for(&vault, actor);
    facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(
                    0,
                    WitnessAuthor::User,
                    &format!("the room says {ROOM_WORDS}"),
                )],
                occurred_at: 900,
            },
            None,
        )
        .expect("session witness");
    session.flip_on_record_as(&proof).expect("flip on record");
    let base_runs = || vault.retrieval_runs(64).expect("base runs").len();
    let before = base_runs();

    for effort in [Effort::Light, Effort::Medium] {
        let pack = facade
            .recall_in_session(
                &session,
                ROOM_WORDS,
                effort,
                &RecallScope::default(),
                10,
                None,
                None,
            )
            .expect("recall in the room on record");
        assert!(
            pack.items
                .iter()
                .any(|item| item.value_text.contains(ROOM_WORDS)),
            "{effort:?}: on record, the room still reads its turn, got {pack:?}"
        );
    }
    assert_eq!(base_runs(), before, "none of its runs reach base");

    session.close().expect("close session");
}
