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

/// The first message of `turn`, in message order.
#[cfg(feature = "sync")]
fn first_message(vault: &crate::Vault, turn: &EntityId) -> EntityId {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let messages = crate::tagging::turn_messages_in_txn(vault, &rtxn, turn)
        .expect("turn messages")
        .expect("a live turn");
    EntityId::from_hex(&messages[0].id).expect("message id")
}

/// The words a document chat named `item`'s reference reads for `turn`,
/// once the reference hydrates to that turn.
#[cfg(feature = "sync")]
fn read_back(facade: &Memory<'_>, turn: &EntityId, item: &crate::memory::MemoryItem) -> String {
    let reference = item.reference();
    let views = facade
        .hydrate(std::slice::from_ref(&reference))
        .expect("the reference hydrates");
    assert_eq!(views[0].id_hex, turn.to_hex());
    let crate::memory::ChatResponse::Answered { retrieval, .. } = facade
        .chat(
            "what was said",
            crate::memory::ChatDepth::Light,
            crate::memory::ChatOptions {
                scope: crate::memory::ChatScope::Documents {
                    source_short_ids: vec![reference],
                },
                limit: 10,
                format: None,
                lease: None,
                composer: None,
            },
        )
        .expect("chat")
    else {
        panic!("the named turn answers");
    };
    retrieval.items[0].value_text.clone()
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

/// Astra 1333 re-check F4 (P2): a context pack pinned at one turn's text
/// revision refuses each other turn it finds without searching that turn's
/// history. Bug repro: every other turn the pack found ran the search over
/// its messages' retained states and its row's retained revisions before it
/// was refused, so one pinned pack cost a search per unrelated turn.
#[test]
fn a_pack_pinned_at_one_turn_never_searches_another_turns_history() {
    const MEANING: [f32; 4] = [0.8, 0.0, 0.0, 0.6];
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let turn = witness_turn(&facade, 0xDB, &["the lantern swings at dusk"], 1_900);
    fill_turn(&vault, &turn, &MEANING);
    for (conversation, said) in [
        (0xDC, "the gate creaks in the wind"),
        (0xDD, "the rain drums on the roof"),
        (0xDE, "the clock ticks in the hall"),
    ] {
        let other = witness_turn(&facade, conversation, &[said], 1_900);
        fill_turn(&vault, &other, &MEANING);
    }
    let item = recalled_turn(&facade, "lantern", &MEANING);
    assert_eq!(item.value_text, "the lantern swings at dusk");
    let lane = facade
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("owner read lane");

    let searches = &crate::vault::entity_revision::HISTORY_SEARCHES;
    searches.with(|count| count.set(0));
    assert_eq!(
        pinned_pack_text(&vault, &lane, &turn, &MEANING, &item).as_deref(),
        Some("the lantern swings at dusk")
    );
    assert_eq!(searches.with(std::cell::Cell::get), 0);
}

/// Astra 1333 re-check R1 (P2): a turn's reference reads the words it was
/// served with after one of its messages is edited, through a document chat
/// and through a context pack pinned at it. The message's text already lives
/// in its entity document, which retains the earlier words. Bug repro: the
/// text revision could be checked only against its sources as they stand, so
/// the edit left the earlier reference resolving to nothing.
#[cfg(feature = "sync")]
#[test]
fn a_turn_reference_reads_back_the_words_it_was_served_with() {
    use crate::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
    const MEANING: [f32; 4] = [0.0, 0.0, 1.0, 0.0];
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let turn = witness_turn(
        &facade,
        0xD6,
        &["the appointment is on Monday", "see you there"],
        1_900,
    );
    fill_turn(&vault, &turn, &MEANING);
    let message = first_message(&vault, &turn);
    let actor = crate::write_envelope::WriteActor::new(owner, EdgeActorClass::Human);
    let authenticated = vault
        .authenticate_owner(
            owner,
            "principal:turn-text-test",
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

    let before = recalled_turn(&facade, "appointment", &MEANING);
    assert_eq!(before.value_text, "the appointment is on Monday\nsee you there");
    let end = vault.entity_text(&message).expect("text").chars().count();
    let whole = vault.entity_text_anchor(&message, 0, end).expect("anchor");
    vault
        .edit_entity_text(
            &message,
            &[AnchoredEdit {
                actor: Some(actor),
                verb: EditVerb::ReplaceQuotedSpan {
                    span: whole,
                    text: "the appointment is on Tuesday".into(),
                },
            }],
            &authorization,
            2_000,
        )
        .expect("edit the message");
    let after = recalled_turn(&facade, "appointment", &MEANING);
    assert_eq!(after.value_text, "the appointment is on Tuesday\nsee you there");
    assert_ne!(after.source_revision_ref, before.source_revision_ref);

    let lane = facade
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("owner read lane");
    for item in [&before, &after] {
        assert_eq!(
            read_back(&facade, &turn, item),
            item.value_text,
            "{}",
            item.reference()
        );
        assert_eq!(
            pinned_pack_text(&vault, &lane, &turn, &MEANING, item).as_deref(),
            Some(item.value_text.as_str()),
            "{}",
            item.reference()
        );
    }
}

/// Astra 1333 re-check R2 (P2): a turn's reference still hydrates after its
/// row takes new metadata of its own, which moves the content hash its short
/// name is filed under, while its messages stand. Bug repro: a text revision
/// found its turn by the name and the hash the reference carries, which the
/// row no longer has, so the lookup failed before the retained row it names
/// was ever read.
#[test]
fn a_turn_reference_hydrates_after_its_row_takes_new_metadata() {
    const MEANING: [f32; 4] = [0.0, 0.0, 0.0, 1.0];
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let turn = witness_turn(&facade, 0xA7, &["the boiler hums at night"], 1_900);
    fill_turn(&vault, &turn, &MEANING);
    let item = recalled_turn(&facade, "boiler", &MEANING);
    let reference = item.reference();
    let (_, hash) = crate::entity_id::parse_short_ref_syntax(&item.short_id).expect("short ref");

    let record = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        crate::ports::EntityStoreRead::port_entity_record(&vault.store, &rtxn, &turn)
            .expect("read the turn row")
            .expect("the turn row")
    };
    let titled = |title: &str| {
        let rmpv::Value::Map(mut fields) =
            rmpv::decode::read_value(&mut std::io::Cursor::new(&record.body)).expect("turn body")
        else {
            panic!("a turn body is a map");
        };
        fields.push((rmpv::Value::from("title"), rmpv::Value::from(title)));
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &rmpv::Value::Map(fields)).expect("encode");
        body
    };
    let body = (0..)
        .map(|n| titled(&format!("night noises {n}")))
        .find(|body| (xxhash_rust::xxh32::xxh32(body, 0) % 256) as u8 != hash)
        .expect("a title that moves the hash");
    vault
        .put_entity(
            &turn,
            crate::registry::ENTITY_TYPE_TURN,
            record.occurred,
            record.learned_at,
            &body,
        )
        .expect("give the turn row a title");

    let views = facade
        .hydrate(std::slice::from_ref(&reference))
        .expect("the reference hydrates");
    assert_eq!(views[0].id_hex, turn.to_hex());
}

/// Astra 1333 re-check F1 (P1): a turn's reference never reads back words
/// the owner purged from its message's document history. The message's
/// original row stays in the revision ledger (its pinned short ref was taken
/// before its text moved into the document), which the purge does not
/// reach. Bug repro: the search took that retained row as a state of the
/// message and served the purged words.
#[cfg(feature = "sync")]
#[test]
fn a_turn_reference_never_reads_back_purged_words() {
    use crate::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
    const MEANING: [f32; 4] = [0.6, 0.8, 0.0, 0.0];
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let turn = witness_turn(
        &facade,
        0xDF,
        &["the safe code is 4417", "keep it quiet"],
        1_900,
    );
    fill_turn(&vault, &turn, &MEANING);
    let message = first_message(&vault, &turn);
    vault
        .pinned_short_ref(&message)
        .expect("pin the message's row");
    let before = recalled_turn(&facade, "safe", &MEANING);
    assert_eq!(before.value_text, "the safe code is 4417\nkeep it quiet");

    let actor = crate::write_envelope::WriteActor::new(owner, EdgeActorClass::Human);
    let authenticated = vault
        .authenticate_owner(
            owner,
            "principal:turn-text-test",
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
    let end = vault.entity_text(&message).expect("text").chars().count();
    vault
        .edit_entity_text(
            &message,
            &[AnchoredEdit {
                actor: Some(actor),
                verb: EditVerb::ReplaceQuotedSpan {
                    span: vault.entity_text_anchor(&message, 0, end).expect("anchor"),
                    text: "the safe code was changed".into(),
                },
            }],
            &authorization,
            2_000,
        )
        .expect("edit the message");
    let head = vault.entity_text_frontier(&message).expect("frontier");
    vault
        .purge_entity_text_history(&message, &head, &authorization, 2_100)
        .expect("purge the document's history");

    assert!(
        facade
            .hydrate(std::slice::from_ref(&before.reference()))
            .is_err(),
        "a purged quotation still resolves: {}",
        before.reference()
    );
    let lane = facade
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("owner read lane");
    assert!(
        pinned_pack_text(&vault, &lane, &turn, &MEANING, &before).is_none(),
        "a pinned pack serves purged words"
    );
}

/// Astra 1333 re-check F2 (P2): a turn served while its message's document
/// stood at two merged heads reads those words back after a later edit. Bug
/// repro: the search offered only the state each change left, never the
/// merged state a later change was made on.
#[cfg(feature = "sync")]
#[test]
fn a_turn_reference_reads_back_words_served_at_a_merged_document_state() {
    use crate::entity_doc::{
        AnchoredEdit, DocAuthorization, EditVerb, TextField, TextUpdateOutcome, TextUpdateRequest,
    };
    const MEANING: [f32; 4] = [0.0, 0.6, 0.8, 0.0];
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let turn = witness_turn(&facade, 0xD8, &["the boat leaves at nine"], 1_900);
    fill_turn(&vault, &turn, &MEANING);
    let message = first_message(&vault, &turn);
    let actor = crate::write_envelope::WriteActor::new(owner, EdgeActorClass::Human);
    let authenticated = vault
        .authenticate_owner(
            owner,
            "principal:turn-text-test",
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
    let append = |text: &str, at: u64| {
        let end = vault.entity_text(&message).expect("text").chars().count();
        vault
            .edit_entity_text(
                &message,
                &[AnchoredEdit {
                    actor: Some(actor),
                    verb: EditVerb::AppendToSection {
                        section: vault.entity_text_anchor(&message, end, end).expect("anchor"),
                        text: text.into(),
                    },
                }],
                &authorization,
                at,
            )
            .expect("append to the message");
    };

    let base = vault.entity_text_frontier(&message).expect("frontier");
    append(" sharp", 2_000);
    let outcome = vault
        .update_entity_text(
            &TextUpdateRequest {
                entity: message,
                proposal: EntityId::from_bytes([0xD9; 16]).unwrap(),
                base,
                text: "the ferry leaves at nine".into(),
                actor,
                timeout_ms: 5_000,
                at: 2_010,
            },
            &authorization,
        )
        .expect("merge an edit made on the earlier text");
    assert!(
        matches!(outcome, TextUpdateOutcome::Merged { .. }),
        "{outcome:?}"
    );
    let merged = recalled_turn(&facade, "leaves", &MEANING);
    assert_eq!(
        merged.value_text,
        vault.entity_text(&message).expect("text")
    );
    append(" today", 2_020);

    assert_eq!(read_back(&facade, &turn, &merged), merged.value_text);
}

/// Astra 1333 re-check F3 (P2): a turn served while one of its messages
/// showed no text reads back the words it was served with after that
/// message is written again. Bug repro: the search let a message be absent
/// only when it shows no text now, so the set the turn was served with,
/// which left that message out, could not be made again.
#[cfg(feature = "sync")]
#[test]
fn a_turn_reference_reads_back_words_served_while_a_message_was_empty() {
    use crate::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
    const MEANING: [f32; 4] = [0.0, 0.0, 0.6, 0.8];
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let turn = witness_turn(
        &facade,
        0xDA,
        &["a first draft", "meet me by the harbour"],
        1_900,
    );
    fill_turn(&vault, &turn, &MEANING);
    let message = first_message(&vault, &turn);
    let actor = crate::write_envelope::WriteActor::new(owner, EdgeActorClass::Human);
    let authenticated = vault
        .authenticate_owner(
            owner,
            "principal:turn-text-test",
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
    let end = vault.entity_text(&message).expect("text").chars().count();
    vault
        .edit_entity_text(
            &message,
            &[AnchoredEdit {
                actor: Some(actor),
                verb: EditVerb::ReplaceQuotedSpan {
                    span: vault.entity_text_anchor(&message, 0, end).expect("anchor"),
                    text: String::new(),
                },
            }],
            &authorization,
            2_000,
        )
        .expect("empty the message");
    let served = recalled_turn(&facade, "harbour", &MEANING);
    assert_eq!(served.value_text, "meet me by the harbour");
    vault
        .edit_entity_text(
            &message,
            &[AnchoredEdit {
                actor: Some(actor),
                verb: EditVerb::AppendToSection {
                    section: vault.entity_text_anchor(&message, 0, 0).expect("anchor"),
                    text: "a second draft".into(),
                },
            }],
            &authorization,
            2_010,
        )
        .expect("write the message again");

    assert_eq!(read_back(&facade, &turn, &served), served.value_text);
}
