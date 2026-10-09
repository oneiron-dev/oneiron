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
    let message = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let messages = crate::tagging::turn_messages_in_txn(&vault, &rtxn, &turn)
            .expect("turn messages")
            .expect("a live turn");
        EntityId::from_hex(&messages[0].id).expect("message id")
    };
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

    let chat = |item: &crate::memory::MemoryItem| {
        let reference = item.reference();
        let views = facade
            .hydrate(std::slice::from_ref(&reference))
            .expect("the reference hydrates");
        assert_eq!(views[0].id_hex, turn.to_hex());
        let crate::memory::ChatResponse::Answered { retrieval, .. } = facade
            .chat(
                "when is the appointment",
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
    };
    let lane = facade
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("owner read lane");
    for item in [&before, &after] {
        assert_eq!(chat(item), item.value_text, "{}", item.reference());
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
