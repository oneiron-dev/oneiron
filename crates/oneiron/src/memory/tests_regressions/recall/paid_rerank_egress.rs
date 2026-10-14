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
    host: &dyn crate::memory::RecallRerankHost,
    query: &str,
) -> crate::memory::MemoryPack {
    recall_high_in(facade, host, query, None)
}

fn recall_high_in(
    facade: &Memory<'_>,
    host: &dyn crate::memory::RecallRerankHost,
    query: &str,
    scope: Option<crate::memory::RecallScope>,
) -> crate::memory::MemoryPack {
    crate::task_verb::sdk::recall_at_door(
        facade,
        crate::task_verb::sdk::RecallRequest {
            query: query.to_owned(),
            effort: Some(crate::memory::RecallEffort::High),
            scope,
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

/// A [`ScriptedReranker`] that says where its model runs.
struct Placed<'a> {
    host: &'a ScriptedReranker<'a>,
    on_device: bool,
}

impl crate::memory::RecallRerankHost for Placed<'_> {
    fn lease(&self) -> &crate::llm::BudgetLease {
        crate::memory::RecallRerankHost::lease(self.host)
    }

    fn score(
        &self,
        query: &str,
        documents: &[crate::memory::RerankDocument<'_>],
        egress: &crate::memory::RerankEgress<'_>,
        answer_at: Option<std::time::Instant>,
    ) -> MemoryResult<crate::memory::RerankScores> {
        crate::memory::RecallRerankHost::score(self.host, query, documents, egress, answer_at)
    }

    fn runs_on_device(&self) -> bool {
        self.on_device
    }
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

/// #1419 Wonder W1-4: a block whose every text reads back empty makes no
/// call. It runs unreranked and says it skipped: `skipped / no_candidates`.
/// Here the one row is a claim a device-only world keeps, read for a host
/// whose model runs elsewhere, so the block reads back empty through item 9
/// (on main its words were sent, and this fails for that). Before item 9 a
/// block read back empty only when its rows stopped being readable between
/// capture and egress, a race; with only the all-empty skip removed, this
/// makes the call W1-4 names.
#[test]
fn a_block_with_no_words_to_send_makes_no_call() {
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let (world, _) = kept_world(&vault, owner);
    let host = scripted(&|_: usize, _: &str| 1.0, &|_: usize| {});

    let pack = recall_high_in(
        &facade,
        &host,
        "lantern",
        Some(crate::memory::RecallScope {
            world_ref: Some(world.to_hex()),
            kinds: Some(vec!["CLAIM".to_owned()]),
            ..Default::default()
        }),
    );

    assert!(
        pack.items
            .iter()
            .any(|item| item.value_text.contains("under the mat")),
        "the kept claim is found and served here: {pack:?}"
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

/// A claim about `owner` in `world` (base reality for `None`), indexed by
/// its words.
fn remember_claim(
    vault: &crate::Vault,
    owner: EntityId,
    id: EntityId,
    world: Option<EntityId>,
    text: &str,
) {
    let mut claim = crate::claim::ClaimBody::new(
        "profile.note",
        crate::claim::ClaimSubject::Entity(owner),
        rmpv::Value::from(text),
        1.0,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    )
    .expect("a claim");
    claim.source = Some(crate::claim::ClaimSource::UserStated);
    claim.world = world;
    vault
        .put_claim(
            &id,
            &claim,
            crate::temporal::TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("store the claim");
    vault
        .batch()
        .text(&id, &[("body", text)])
        .commit()
        .expect("index the claim");
}

/// A WORLD flagged device-only on this device and a claim about lanterns
/// it keeps: the world and the kept claim.
fn kept_world(vault: &crate::Vault, owner: EntityId) -> (EntityId, EntityId) {
    let world = crate::test_util::entity(0x61);
    vault
        .put_entity(
            &world,
            crate::registry::ENTITY_TYPE_WORLD,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .expect("the world");
    let kept = crate::test_util::entity(0x62);
    remember_claim(
        vault,
        owner,
        kept,
        Some(world),
        "the lantern key is under the mat",
    );
    vault
        .keep_world_on_this_machine_for_test(world, true)
        .expect("flag the world");
    (world, kept)
}

/// [`kept_world`] and a portable claim about lanterns in base reality: the
/// world, the kept claim and the portable one.
fn device_only_world(vault: &crate::Vault, owner: EntityId) -> (EntityId, EntityId, EntityId) {
    let (world, kept) = kept_world(vault, owner);
    let portable = crate::test_util::entity(0x63);
    remember_claim(vault, owner, portable, None, "a brass lantern hook");
    (world, kept, portable)
}

/// Packet item 9 (the device-egress lane's question): #1419 made a remote
/// reranker live, and a recall sent it the words of a row a device-only world
/// keeps, which never leave this device. Judged on the vault's own flag, such
/// a row goes empty to a host whose model runs elsewhere, and scores last. A
/// host whose model runs on this device is sent its words.
#[test]
fn a_device_only_row_reaches_only_a_reranker_on_this_device() {
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let (world, kept, _) = device_only_world(&vault, owner);

    for on_device in [false, true] {
        let sent = std::sync::Mutex::new(Vec::new());
        let score = |_: usize, text: &str| {
            sent.lock().unwrap().push(text.to_owned());
            1.0
        };
        let host = scripted(&score, &|_: usize| {});
        let pack = recall_high_in(
            &facade,
            &Placed {
                host: &host,
                on_device,
            },
            "lantern",
            Some(crate::memory::RecallScope {
                world_ref: Some(world.to_hex()),
                ..Default::default()
            }),
        );

        assert!(
            host.seen.lock().unwrap().contains(&kept),
            "on device {on_device}: {pack:?}"
        );
        let sent = sent.lock().unwrap();
        assert_eq!(
            sent.iter().any(|text| text.contains("under the mat")),
            on_device,
            "{sent:?}"
        );
        assert!(
            sent.iter().any(|text| text.contains("brass lantern hook")),
            "{sent:?}"
        );
    }
}

/// A row sent empty was sent nothing to judge, so it scores last, whatever
/// the model makes of no words. Before, the model's score for an empty text
/// stood: here one that prefers no words would have put the claim it was
/// sent nothing of first.
#[test]
fn a_row_sent_empty_scores_last() {
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let (world, _, _) = device_only_world(&vault, owner);
    let host = scripted(
        &|_: usize, text: &str| if text.is_empty() { 100.0 } else { 1.0 },
        &|_: usize| {},
    );

    let pack = recall_high_in(
        &facade,
        &host,
        "lantern",
        Some(crate::memory::RecallScope {
            world_ref: Some(world.to_hex()),
            kinds: Some(vec!["CLAIM".to_owned()]),
            ..Default::default()
        }),
    );

    assert_eq!(host.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let order: Vec<&str> = pack
        .items
        .iter()
        .map(|item| item.value_text.as_str())
        .collect();
    assert_eq!(order.len(), 2, "{pack:?}");
    assert!(order[0].contains("brass lantern hook"), "{order:?}");
}
