// Recall at high, xhigh and max through a host's reranker
// (`memory/recall/paid.rs`): its scores apply only to the words they were
// given.

/// A host reranker that scores each document with `score(call, text)` and
/// runs `during(call)` first, as a write landing while a model scores would.
struct ScriptedReranker<'a> {
    lease: crate::llm::BudgetLease,
    calls: std::sync::atomic::AtomicUsize,
    score: &'a (dyn Fn(usize, &str) -> f32 + Sync),
    during: &'a (dyn Fn(usize) + Sync),
}

impl crate::memory::RecallRerankHost for ScriptedReranker<'_> {
    fn lease(&self) -> &crate::llm::BudgetLease {
        &self.lease
    }

    fn score(
        &self,
        _query: &str,
        documents: &[crate::memory::RerankDocument<'_>],
        _answer_at: Option<std::time::Instant>,
    ) -> MemoryResult<crate::memory::RerankScores> {
        let call = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        (self.during)(call);
        Ok(crate::memory::RerankScores {
            scores: documents
                .iter()
                .map(|document| (self.score)(call, document.text))
                .collect(),
            model: "test/reranker@v1".to_owned(),
            served_model: None,
        })
    }
}

/// Done-means (G1 check 4) at the engine's recall door: a turn whose message
/// is edited while its block is scored, past the words its item shows, takes
/// none of the first call's scores. The block is scored again, and the turn
/// is served at the words its second score is for. Sol round 2 (R2-3) asked
/// that the scores bind a row's words, not only its id, score and rank; the
/// edit here moves those too (it binds its actor with a claim that joins the
/// block), so the round-1 door refused the stale block as well.
#[cfg(feature = "sync")]
#[test]
fn a_turn_edited_while_it_is_scored_takes_none_of_the_stale_scores() {
    use crate::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
    // Longer than an item shows, so only the words past it change.
    let shown = "the lantern hangs in the attic. ".repeat(20);
    let first = format!("{shown}brass hook");
    let reordered = format!("{shown}hook brass");
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let edited = witness_turn(&facade, 0xE1, &[first.as_str()], 1_900);
    witness_turn(&facade, 0xE2, &["a lantern shop that sells wicks"], 1_900);
    let message = first_message(&vault, &edited);
    let actor = crate::write_envelope::WriteActor::new(owner, EdgeActorClass::Human);
    let authenticated = vault
        .authenticate_owner(
            owner,
            "principal:paid-rerank-test",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner");
    let authorization = DocAuthorization::Owner(&authenticated);
    vault
        .migrate_entity_text(
            &message,
            &TextField::MapField("content".into()),
            actor,
            &authorization,
        )
        .expect("move the message's text into its document");
    let during = |call: usize| {
        if call != 1 {
            return;
        }
        let end = vault.entity_text(&message).expect("text").chars().count();
        let whole = vault.entity_text_anchor(&message, 0, end).expect("anchor");
        vault
            .edit_entity_text(
                &message,
                &[AnchoredEdit {
                    actor: Some(actor),
                    verb: EditVerb::ReplaceQuotedSpan {
                        span: whole,
                        text: reordered.clone(),
                    },
                }],
                &authorization,
                2_000,
            )
            .expect("edit the message");
    };
    // The first call prefers every row but the edited turn; later calls the
    // edited turn.
    let score = |call: usize, text: &str| match (call, text.contains("hangs")) {
        (1, true) | (2.., false) => 0.0,
        (1, false) | (2.., true) => 10.0,
        (0, _) => unreachable!(),
    };
    let host = ScriptedReranker {
        lease: crate::BudgetGuard::new(
            "paid-rerank-test",
            100_000,
            crate::BudgetExhaustionPolicy::Suspend,
        )
        .admit()
        .expect("a lease")
        .lease,
        calls: std::sync::atomic::AtomicUsize::new(0),
        score: &score,
        during: &during,
    };
    let pack = crate::task_verb::sdk::recall_at_door(
        &facade,
        crate::task_verb::sdk::RecallRequest {
            query: "lantern".to_owned(),
            effort: Some(crate::memory::RecallEffort::High),
            scope: None,
            limit: Some(10),
            format: None,
            as_of: None,
            deadline_ms: None,
        },
        |_| None,
        &crate::task_verb::sdk::RecallDoor {
            arrived: std::time::Instant::now(),
            on_cut: None,
            rerank: crate::memory::RecallRerank::Host(&host),
        },
    )
    .expect("recall");
    let turns: Vec<&str> = pack
        .items
        .iter()
        .filter(|item| item.kind == "TURN")
        .map(|item| item.value_text.as_str())
        .collect();
    assert_eq!(turns.len(), 2, "{pack:?}");
    assert_eq!(
        host.calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the edited block is scored again: {turns:?}"
    );
    assert!(turns[0].starts_with("the lantern hangs"), "{turns:?}");
    assert!(matches!(
        pack.retrieval_meta.rerank,
        Some(crate::memory::RerankReport::Applied { calls: 2, .. })
    ));
}

/// Sol round 5 (R5-1): a NOTE's prose lives in its document, which its row
/// pin does not hold. A NOTE edited after the second pass takes its scores,
/// before the pack is hydrated, still renders the words the reranker scored:
/// before, the pack showed the edit, and a cut suffix passed the snapshot
/// check as a clipped prefix of the scored words.
#[test]
fn a_note_edited_after_its_scores_are_taken_renders_the_scored_words() {
    let scored = "the kettle whistles twice; the service account is retired.";
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let note = facade
        .author_take(crate::note::TakeTarget::Subject(owner), scored)
        .expect("a take")
        .id_hex;
    let host = ScriptedReranker {
        lease: crate::BudgetGuard::new(
            "paid-rerank-test",
            100_000,
            crate::BudgetExhaustionPolicy::Suspend,
        )
        .admit()
        .expect("a lease")
        .lease,
        calls: std::sync::atomic::AtomicUsize::new(0),
        score: &|_: usize, text: &str| text.len() as f32,
        during: &|_: usize| {},
    };
    let (taken, taken_rx) = std::sync::mpsc::channel();
    let (written_tx, written) = std::sync::mpsc::channel();
    crate::memory::recall::PREPARED_SCORES_TAKEN
        .with_borrow_mut(|hook| *hook = Some((taken, written)));
    let edited = std::sync::atomic::AtomicBool::new(false);
    let (writer, note, edited_flag) = (&vault, note.as_str(), &edited);
    let pack = std::thread::scope(|scope| {
        scope.spawn(move || {
            if taken_rx.recv().is_err() {
                return;
            }
            writer
                .memory(owner, EdgeActorClass::Human)
                .edit_note(
                    note,
                    &crate::note::NoteProgramEdit::WholeText {
                        text: "the kettle whistles twice".into(),
                        timeout_ms: 100,
                        base: None,
                    },
                )
                .expect("cut the take's suffix");
            edited_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = written_tx.send(());
        });
        let pack = crate::task_verb::sdk::recall_at_door(
            &facade,
            crate::task_verb::sdk::RecallRequest {
                query: "kettle".to_owned(),
                effort: Some(crate::memory::RecallEffort::High),
                scope: None,
                limit: Some(10),
                format: Some("json".to_owned()),
                as_of: None,
                deadline_ms: None,
            },
            |_| None,
            &crate::task_verb::sdk::RecallDoor {
                arrived: std::time::Instant::now(),
                on_cut: None,
                rerank: crate::memory::RecallRerank::Host(&host),
            },
        );
        // A recall that never took its scores releases the writer.
        crate::memory::recall::PREPARED_SCORES_TAKEN.with_borrow_mut(Option::take);
        pack
    })
    .expect("recall");
    assert!(edited.load(std::sync::atomic::Ordering::SeqCst), "{pack:?}");
    assert!(matches!(
        pack.retrieval_meta.rerank,
        Some(crate::memory::RerankReport::Applied { .. })
    ));
    let rendered = pack.rendered.as_deref().expect("a json pack");
    assert!(rendered.contains(scored), "{rendered}");
}

/// Done-means (the Engine lane's ruling on Sol round 6, R6-1): a streamed
/// MESSAGE holds its words in its entity document, which no row revision
/// pins, so no score can be bound to them. It is found but not reranked: it
/// comes back after the reranked rows, as its TURN, with no score the
/// reranker gave. Before, the reranker scored its row's empty words and its
/// TURN took that score (R6-1); then it was dropped from the recall.
#[cfg(feature = "sync")]
#[test]
fn a_streamed_message_comes_back_below_the_reranked_rows_unscored() {
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    witness_turn(&facade, 0xE3, &["a lantern shop that sells wicks"], 1_900);
    witness_turn(&facade, 0xE4, &["the lantern repair kit is on the shelf"], 1_900);
    // The best lexical match of the three.
    let streamed = "lantern lantern: the lantern wick is trimmed";
    let stream = facade
        .begin_message_stream(
            &WitnessTurn {
                conversation_ref: EntityId::from_bytes([0xE5; 16]).unwrap().to_hex(),
                turn_ref: Some(EntityId::now().to_hex()),
                occurred_at: 1_900,
                messages: vec![WitnessMessage {
                    id: Some(EntityId::now().to_hex()),
                    ..witness_message(0, WitnessAuthor::User, "")
                }],
            },
            Some(crate::memory::MessageWriteMode::Atomic),
        )
        .expect("open a stream");
    facade.append_to_stream(stream, streamed).expect("stream words");
    facade.finalize_stream(stream).expect("finalize the stream");
    // Empty words score highest, then the shop's.
    let scored = std::sync::Mutex::new(Vec::new());
    let score = |_: usize, text: &str| {
        scored.lock().unwrap().push(text.to_owned());
        match text {
            "" => 20.0,
            text if text.contains("shop") => 10.0,
            _ => 5.0,
        }
    };
    let host = ScriptedReranker {
        lease: crate::BudgetGuard::new(
            "paid-rerank-test",
            100_000,
            crate::BudgetExhaustionPolicy::Suspend,
        )
        .admit()
        .expect("a lease")
        .lease,
        calls: std::sync::atomic::AtomicUsize::new(0),
        score: &score,
        during: &|_: usize| {},
    };
    let pack = crate::task_verb::sdk::recall_at_door(
        &facade,
        crate::task_verb::sdk::RecallRequest {
            query: "lantern".to_owned(),
            effort: Some(crate::memory::RecallEffort::High),
            scope: None,
            limit: Some(10),
            format: None,
            as_of: None,
            deadline_ms: None,
        },
        |_| None,
        &crate::task_verb::sdk::RecallDoor {
            arrived: std::time::Instant::now(),
            on_cut: None,
            rerank: crate::memory::RecallRerank::Host(&host),
        },
    )
    .expect("recall");
    let turns: Vec<&str> = pack
        .items
        .iter()
        .filter(|item| item.kind == "TURN")
        .map(|item| item.value_text.as_str())
        .collect();
    assert_eq!(turns.len(), 3, "{turns:?}");
    assert!(turns[0].contains("shop"), "{turns:?}");
    assert!(turns[2].contains("wick is trimmed"), "{turns:?}");
    let scored = scored.lock().unwrap();
    assert!(
        scored
            .iter()
            .all(|text| !text.is_empty() && !text.contains("wick is")),
        "{scored:?}"
    );
    assert!(matches!(
        pack.retrieval_meta.rerank,
        Some(crate::memory::RerankReport::Applied { .. })
    ));
}

/// Sol round 7 (R7-1): a build without `sync` reads no entity document, but a
/// `sync` process sharing the vault may move a message's words into one. The
/// message's retained row still holds its old words, so the reranker scored
/// those, and its TURN, which shows none of them here, took that score.
/// Such a message is not reranked in this build either: it follows the
/// reranked rows.
#[cfg(not(feature = "sync"))]
#[test]
fn a_message_moved_to_its_document_by_a_sync_process_is_not_reranked() {
    use crate::side_table::{self, HexId, Named, SideTable};
    const DOCUMENT_HEADS: SideTable<HexId, rmpv::Value, Named> =
        SideTable::new(&side_table::ENTITY_DOC_HEAD);
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    witness_turn(&facade, 0xE6, &["a kettle shop that sells handles"], 1_900);
    let moved = witness_turn(
        &facade,
        0xE7,
        &["the kettle has a brass handle", "keep it quiet"],
        1_900,
    );
    let message = first_message(&vault, &moved);
    vault
        .pinned_short_ref(&message)
        .expect("pin the message's row");
    let raw = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &rtxn, &message)
            .expect("read the message row")
            .expect("the message row")
            .to_vec()
    };
    let (header, body) = raw.split_at(crate::batch::ENTITY_METADATA_HEADER_LEN);
    let rmpv::Value::Map(mut fields) =
        rmpv::decode::read_value(&mut std::io::Cursor::new(body)).expect("message body")
    else {
        panic!("a message body is a map");
    };
    fields.retain(|(key, _)| key.as_str() != Some("content"));
    fields.push((
        rmpv::Value::from("entity_doc_ref"),
        rmpv::Value::from(message.to_hex()),
    ));
    let mut pointer = header.to_vec();
    rmpv::encode::write_value(&mut pointer, &rmpv::Value::Map(fields)).expect("encode");
    vault
        .with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, message.as_bytes(), &pointer)?;
            DOCUMENT_HEADS.put(&vault.store, wtxn, &HexId(message), &rmpv::Value::Nil)
        })
        .expect("move the message's text out of its row, as a sync process does");
    // The moved words score highest, then the shop's.
    let scored = std::sync::Mutex::new(Vec::new());
    let score = |_: usize, text: &str| {
        scored.lock().unwrap().push(text.to_owned());
        if text.contains("brass") {
            20.0
        } else if text.contains("shop") {
            10.0
        } else {
            5.0
        }
    };
    let host = ScriptedReranker {
        lease: crate::BudgetGuard::new(
            "paid-rerank-test",
            100_000,
            crate::BudgetExhaustionPolicy::Suspend,
        )
        .admit()
        .expect("a lease")
        .lease,
        calls: std::sync::atomic::AtomicUsize::new(0),
        score: &score,
        during: &|_: usize| {},
    };
    let pack = crate::task_verb::sdk::recall_at_door(
        &facade,
        crate::task_verb::sdk::RecallRequest {
            query: "kettle".to_owned(),
            effort: Some(crate::memory::RecallEffort::High),
            scope: None,
            limit: Some(10),
            format: None,
            as_of: None,
            deadline_ms: None,
        },
        |_| None,
        &crate::task_verb::sdk::RecallDoor {
            arrived: std::time::Instant::now(),
            on_cut: None,
            rerank: crate::memory::RecallRerank::Host(&host),
        },
    )
    .expect("recall");
    let turns: Vec<&str> = pack
        .items
        .iter()
        .filter(|item| item.kind == "TURN")
        .map(|item| item.value_text.as_str())
        .collect();
    assert_eq!(
        turns.first(),
        Some(&"a kettle shop that sells handles"),
        "{turns:?}"
    );
    let scored = scored.lock().unwrap();
    assert!(
        scored.iter().all(|text| !text.contains("brass")),
        "{scored:?}"
    );
}
