// Recall returns a matched MESSAGE as its TURN (ARCH-0004): what the fold
// keeps, and what it must not cost the recall.

/// A vault whose turns embed, with no embedder running: a test fills each
/// turn as the worker would ([`fill_turn`]).
fn open_embedding_vault() -> (tempfile::TempDir, crate::Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(
        dir.path(),
        crate::config::VaultConfig {
            embedding_model: Some("test/model@v1".to_owned()),
            dimensions: 4,
            ..crate::config::VaultConfig::default()
        },
    )
    .expect("open vault");
    (dir, vault)
}

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

/// The embedding worker's fill: `vector` for `turn` under its pending mark.
fn fill_turn(vault: &crate::Vault, turn: &EntityId, vector: &[f32]) {
    let leased = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault
            .store
            .pending_embedding_token(&rtxn, turn)
            .expect("pending marker")
            .expect("the witness marks the turn")
    };
    vault
        .batch()
        .vector_for_pending_embedding(turn, vector, &leased)
        .commit()
        .expect("fill the turn");
}

/// Sol 9B #1: RET-01 withholds a recall with a text and a vector query when
/// no keyword matched and every vector score is under the space's floor. A
/// turn found by the exact word of one of its messages is a keyword hit, even
/// when its own vector scores under the floor. Bug repro: the fold moved the
/// message's row onto its turn but left the keyword evidence on the message,
/// so recall saw only the weak vector and returned nothing.
#[test]
fn a_turn_found_by_its_message_word_keeps_that_keyword_evidence() {
    let query = [1.0_f32, 0.0, 0.0, 0.0];
    let (_dir, vault) = open_embedding_vault();
    let facade = facade_for(&vault, put_person(&vault, 0xE1));
    let turn = witness_turn(
        &facade,
        0xE2,
        &[
            "the inverter warranty runs out in march",
            "keep the receipt in the blue folder",
        ],
        1_800,
    );
    // Cosine 0.2 to the query, under the default floor of 0.3.
    fill_turn(&vault, &turn, &[0.2, 0.96_f32.sqrt(), 0.0, 0.0]);

    let pack = facade
        .recall_with_execution(
            "inverter",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
            &crate::retrieval_depth::RecallExecution {
                embedding: Some(query.as_slice()),
                ..Default::default()
            },
        )
        .expect("recall");
    assert!(
        pack.items
            .iter()
            .any(|item| item.kind == "TURN" && item.value_text.contains("inverter warranty")),
        "the keyword finds its turn: {:?}",
        pack.items
    );
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
