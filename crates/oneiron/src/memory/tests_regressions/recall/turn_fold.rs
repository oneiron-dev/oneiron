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

/// Sol 9B #6: recall's limit counts the turns it returns, not the messages
/// that found them. Bug repro: the text channel fetched `limit` messages,
/// three of one turn filled it and folded into one item, and the other
/// conversation's turn never became a candidate.
#[test]
fn several_messages_of_one_turn_leave_room_for_the_next_turn() {
    let (_dir, vault) = open_vault();
    let facade = facade_for(&vault, put_person(&vault, 0xE7));
    witness_turn(
        &facade,
        0xE8,
        &["solar", "solar panels", "solar roof"],
        1_900,
    );
    witness_turn(
        &facade,
        0xE9,
        &["we spent the whole afternoon talking about the solar array on the barn roof"],
        1_900,
    );

    let pack = facade
        .recall(
            "solar",
            Effort::Light,
            &RecallScope::default(),
            3,
            None,
            None,
        )
        .expect("recall");
    let turns = pack.items.iter().filter(|item| item.kind == "TURN").count();
    assert_eq!(turns, 2, "both conversations' turns: {:?}", pack.items);
}

/// Witnesses one turn of three short `solar` messages, which rank first, and
/// one of a long one, which ranks after them; returns the two turns.
fn crowded_and_next_turn(facade: &Memory<'_>) -> [EntityId; 2] {
    [
        witness_turn(facade, 0xEB, &["solar", "solar panels", "solar roof"], 1_900),
        witness_turn(
            facade,
            0xEC,
            &["we spent the whole afternoon talking about the solar array on the barn roof"],
            1_900,
        ),
    ]
}

/// CodeRabbit 1333: a strict scope widens the text read past its bound and
/// then keeps what the scope admits. On a run that folds messages, that cut
/// counts turns, as the unwidened bound does. Bug repro: it kept `limit`
/// rows, so two messages of one turn filled it and the other conversation's
/// turn never became a candidate.
#[test]
fn several_messages_of_one_turn_leave_room_for_the_next_turn_on_a_widened_read() {
    let (_dir, vault) = open_vault();
    let facade = facade_for(&vault, put_person(&vault, 0xEA));
    let turns = crowded_and_next_turn(&facade);

    let hits = vault
        .query()
        .search_text("solar", 2)
        .filter_types(&[
            crate::registry::ENTITY_TYPE_MESSAGE,
            crate::registry::ENTITY_TYPE_TURN,
        ])
        .fold_messages_into_turns(crate::pipeline::TurnFold::Fold)
        .run()
        .expect("widened read");
    let found: Vec<_> = hits.iter().map(|hit| hit.id).collect();
    assert!(
        turns.iter().all(|turn| found.contains(turn)),
        "both conversations' turns {turns:?} in {found:?}"
    );
}

/// The same cut on a HyDE retry's extra text query, which widens on its own.
/// Bug repro: the retry query kept `limit` rows, all of one turn.
#[test]
fn a_widened_retry_query_leaves_room_for_the_next_turn() {
    use crate::query_expansion::{
        CompletionRequest, EvidenceVerdict, GroundingContext, HydeExpander, HydeExpansion,
        HydeOptions, HydeRequest,
    };
    /// Finds nothing with the query itself, then retries once with `solar`.
    struct RetryWithSolar(std::sync::atomic::AtomicBool);
    impl HydeExpander for RetryWithSolar {
        fn id(&self) -> &str {
            "test/retry-with-solar"
        }
        fn expand(&self, request: &HydeRequest) -> crate::Result<HydeExpansion> {
            Ok(HydeExpansion {
                grounded_query: request.query.clone(),
                hypothetical_answer: String::new(),
                embedding: vec![0.0, 0.0, 0.0, 1.0],
                subqueries: vec!["solar".to_owned()],
            })
        }
        fn assess_evidence(&self, _: &CompletionRequest) -> crate::Result<EvidenceVerdict> {
            Ok(
                if self.0.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    EvidenceVerdict::Sufficient
                } else {
                    EvidenceVerdict::Insufficient {
                        gaps: vec!["solar".to_owned()],
                    }
                },
            )
        }
    }
    let (_dir, vault) = open_embedding_vault();
    let facade = facade_for(&vault, put_person(&vault, 0xED));
    let turns = crowded_and_next_turn(&facade);
    let host = RetryWithSolar(std::sync::atomic::AtomicBool::new(false));

    let hits = vault
        .query()
        .search_text("harbor", 2)
        .filter_types(&[
            crate::registry::ENTITY_TYPE_MESSAGE,
            crate::registry::ENTITY_TYPE_TURN,
        ])
        .fold_messages_into_turns(crate::pipeline::TurnFold::Fold)
        .hyde(
            &host,
            GroundingContext::default(),
            HydeOptions {
                channel_limit: 2,
                retry_once: true,
            },
        )
        .run()
        .expect("retried read");
    assert!(host.0.load(std::sync::atomic::Ordering::SeqCst), "the run retried");
    let found: Vec<_> = hits.iter().map(|hit| hit.id).collect();
    assert!(
        turns.iter().all(|turn| found.contains(turn)),
        "both conversations' turns {turns:?} in {found:?}"
    );
}

/// Greptile 1333 (allowed turns get skipped): the text channel reads on
/// until its rows hold `limit` results as the fold leaves them. A message
/// whose turn the reader may not retrieve is no such result in a TURN-only
/// recall, which drops it. Bug repro: the bound counted that message's turn,
/// stopped reading at it, and the fold then dropped it, so a scoped reader's
/// TURN-only recall returned nothing while a later turn it may read matched.
#[test]
fn a_turn_the_reader_may_not_retrieve_leaves_room_for_one_it_may() {
    const ALLOWED: &str = "we walked along the harbor after the ferry and talked for hours";
    let (_dir, vault, owner, scoped) =
        recall_after_control_writes_fixture_in(true, crate::config::VaultConfig::default());
    let space = EntityId::from_bytes([0x68; 16]).unwrap();
    let in_space = |order, text| {
        let mut message = witness_message(order, WitnessAuthor::User, text);
        message.metadata = Some(serde_json::json!({"rel": space.to_hex()}));
        message
    };
    let occurred_at = crate::unix_seconds_now() - 28 * 86_400;
    let owner_facade = facade_for(&vault, owner);
    // The best match, in a turn whose other message the reader may not read.
    owner_facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0xF1; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![
                in_space(0, "harbor harbor"),
                witness_message(1, WitnessAuthor::User, "harbor locker code is 4471"),
            ],
            occurred_at,
        })
        .expect("witness the partly withheld turn");
    owner_facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0xF2; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![in_space(0, ALLOWED)],
            occurred_at,
        })
        .expect("witness the readable turn");

    let pack = facade_for(&vault, scoped)
        .recall(
            "harbor",
            Effort::Light,
            &RecallScope {
                kinds: Some(vec!["TURN".to_owned()]),
                ..RecallScope::default()
            },
            1,
            None,
            None,
        )
        .expect("scoped turn-only recall");
    let found: Vec<_> = pack
        .items
        .iter()
        .map(|item| (item.kind.as_str(), item.value_text.as_str()))
        .collect();
    assert_eq!(found, [("TURN", ALLOWED)], "{:?}", pack.items);
}
