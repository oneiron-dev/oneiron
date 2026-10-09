// Recall returns a matched MESSAGE as its TURN (ARCH-0004): what the fold
// keeps, and what it must not cost the recall.

/// Witnesses one turn of the user's messages `said`; returns the turn.
fn witness_turn(
    facade: &Memory<'_>,
    conversation: u8,
    said: &[&str],
    occurred_at: u64,
) -> EntityId {
    let receipt = facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([conversation; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: (0_u32..)
                .zip(said)
                .map(|(order, text)| witness_message(order, WitnessAuthor::User, text))
                .collect(),
            occurred_at,
        })
        .expect("witness a turn");
    EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("witness ref"),
    )
    .expect("turn id")
}

/// Sol 9B #4: a scope that names TURN alone finds a turn by its messages'
/// words, as the default scope does. A witnessed turn holds no text of its
/// own: its messages' words are the only words that find it. Bug repro: the
/// scope's kinds refused every MESSAGE before the fold could return it as its
/// TURN, so a turn-only recall found nothing.
#[test]
fn a_turn_only_scope_finds_a_turn_by_its_messages_words() {
    const SAID: &str = "the solar panel replacement is booked";
    let (_dir, vault) = open_vault();
    let facade = facade_for(&vault, put_person(&vault, 0xE4));
    witness_turn(
        &facade,
        0xE5,
        &[SAID],
        crate::unix_seconds_now() - 30 * 86_400,
    );

    for kinds in [None, Some(vec!["TURN".to_owned()])] {
        let pack = facade
            .recall(
                "solar panel",
                Effort::Light,
                &RecallScope {
                    kinds: kinds.clone(),
                    ..RecallScope::default()
                },
                10,
                None,
                None,
            )
            .expect("recall");
        let found: Vec<_> = pack
            .items
            .iter()
            .map(|item| (item.kind.as_str(), item.value_text.as_str()))
            .collect();
        assert!(found.contains(&("TURN", SAID)), "{kinds:?}: {found:?}");
        assert!(
            found.iter().all(|(kind, _)| *kind == "TURN"),
            "{kinds:?}: {found:?}"
        );
    }
}
