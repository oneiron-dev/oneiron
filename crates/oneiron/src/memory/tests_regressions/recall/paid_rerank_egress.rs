// Recall at high, xhigh and max: what leaves for a host's reranker is the
// exact text the write door judged, of a row pinned to the words it holds
// (#1419's follow-ups W1-1 and W1-4; Sol R31 F2 and F3 on its code).

/// The public BIP39 test vector's two halves. Each passes the write door
/// alone; joined by a newline, as a TURN joins its messages, they are one
/// recovery phrase (`batch/secret_scan/shapes.rs`).
const PHRASE_HALVES: [&str; 2] = [
    "legal winner thank year wave sausage",
    "worth useful legal winner thank yellow",
];

/// A [`ScriptedReranker`] on a lease of its own.
fn scripted<'a>(
    score: &'a (dyn Fn(usize, &str) -> f32 + Sync),
    during: &'a (dyn Fn(usize) + Sync),
) -> ScriptedReranker<'a> {
    ScriptedReranker {
        lease: crate::BudgetGuard::new(
            "paid-rerank-egress-test",
            100_000,
            crate::BudgetExhaustionPolicy::Suspend,
        )
        .admit()
        .expect("a lease")
        .lease,
        calls: std::sync::atomic::AtomicUsize::new(0),
        seen: std::sync::Mutex::default(),
        score,
        during,
    }
}

/// A high recall of `query` through the engine's door on `host`, with the
/// query vector `[1, 0, 0, 0]`.
fn recall_high(
    facade: &Memory<'_>,
    host: &ScriptedReranker<'_>,
    query: &str,
) -> crate::memory::MemoryPack {
    crate::task_verb::sdk::recall_at_door(
        facade,
        crate::task_verb::sdk::RecallRequest {
            query: query.to_owned(),
            effort: Some(crate::memory::RecallEffort::High),
            scope: None,
            limit: Some(10),
            format: None,
            as_of: None,
            deadline_ms: None,
        },
        |_| Some(vec![1.0, 0.0, 0.0, 0.0]),
        &crate::task_verb::sdk::RecallDoor {
            arrived: std::time::Instant::now(),
            on_cut: None,
            rerank: crate::memory::RecallRerank::Host(host),
        },
    )
    .expect("recall")
}

/// Gives a witnessed `turn` the vector `[1, 0, 0, 0]`, as an embedder would,
/// so a recall finds the TURN itself, not only its messages.
fn embed_turn(vault: &crate::Vault, turn: &EntityId) {
    let token = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault
            .store
            .pending_embedding_token(&rtxn, turn)
            .expect("pending marker")
            .expect("the witness marks the turn")
    };
    vault
        .batch()
        .vector_for_pending_embedding(turn, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()
        .expect("the turn's vector");
}

/// Sol R31 F2: a TURN's messages were judged by the write door one by one,
/// but the reranker was sent their joined text, and two halves of a
/// recovery phrase that each pass alone left together. The joined text is
/// judged as it leaves: no text sent holds both halves.
#[test]
fn a_turn_whose_messages_refuse_together_is_not_sent_whole() {
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let phrase = witness_turn(&facade, 0xF1, &PHRASE_HALVES, 1_900);
    embed_turn(&vault, &phrase);
    let other = witness_turn(
        &facade,
        0xF2,
        &["the raffle winner takes the lantern"],
        1_900,
    );
    embed_turn(&vault, &other);
    let sent = std::sync::Mutex::new(Vec::new());
    let score = |_: usize, text: &str| {
        sent.lock().unwrap().push(text.to_owned());
        1.0
    };
    let host = scripted(&score, &|_: usize| {});

    let pack = recall_high(&facade, &host, "winner");

    assert!(host.seen.lock().unwrap().contains(&phrase), "{pack:?}");
    let sent = sent.lock().unwrap();
    assert!(
        sent.iter()
            .all(|text| !(text.contains("sausage") && text.contains("yellow"))),
        "{sent:?}"
    );
    assert!(matches!(
        pack.retrieval_meta.rerank,
        Some(crate::memory::RerankReport::Applied { .. })
    ));
}

/// #1419 Wonder W1-4: a block whose every text reads back empty, here a
/// TURN whose joined words the write door refuses, makes no call. It runs
/// unreranked and says it skipped: `skipped / no_candidates`.
#[test]
fn a_block_with_no_words_to_send_makes_no_call() {
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let phrase = witness_turn(&facade, 0xF3, &PHRASE_HALVES, 1_900);
    embed_turn(&vault, &phrase);
    let host = scripted(&|_: usize, _: &str| 1.0, &|_: usize| {});

    // No word matches: the TURN's vector alone finds it.
    let pack = recall_high(&facade, &host, "zqxv");

    assert!(
        pack.items.iter().any(|item| item.kind == "TURN"),
        "the turn is found: {pack:?}"
    );
    assert_eq!(host.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(
        matches!(
            pack.retrieval_meta.rerank,
            Some(crate::memory::RerankReport::Skipped {
                reason: crate::memory::RerankSkip::NoCandidates
            })
        ),
        "{:?}",
        pack.retrieval_meta.rerank
    );
}

/// Sol R31 F3: a TURN whose messages show no words has no revision to pin
/// its words by, yet the first pass kept it in the block, and the paid door
/// read its words for the reranker at the mutable indexed frontier, whatever
/// they had become since. It is set aside: the reranker is sent nothing of
/// it, and it follows the reranked rows.
#[test]
fn a_turn_with_no_words_to_pin_is_sent_nothing() {
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let body = |content: &str| {
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![("content".into(), content.into())]),
        )
        .unwrap();
        body
    };
    let (empty_turn, asset) = (
        crate::test_util::entity(0x53),
        crate::test_util::entity(0x54),
    );
    for (id, kind, words) in [
        (
            empty_turn,
            crate::registry::ENTITY_TYPE_TURN,
            "the lantern stand",
        ),
        (
            asset,
            crate::registry::ENTITY_TYPE_ASSET,
            "a brass lantern hook",
        ),
    ] {
        vault
            .batch()
            .put(
                &id,
                kind,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                &body(words),
            )
            .text(&id, &[("body", words)])
            .commit()
            .expect("store the row");
    }
    let host = scripted(&|_: usize, _: &str| 1.0, &|_: usize| {});

    let pack = recall_high(&facade, &host, "lantern");

    let seen = host.seen.lock().unwrap();
    assert!(seen.contains(&asset), "{seen:?}");
    assert!(
        !seen.contains(&empty_turn),
        "the reranker was sent an unpinned turn"
    );
    assert!(matches!(
        pack.retrieval_meta.rerank,
        Some(crate::memory::RerankReport::Applied { .. })
    ));
}
