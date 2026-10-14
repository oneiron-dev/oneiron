// A TURN's words are its MESSAGEs' without the rest of their bodies: each
// door that joins them withholds a message whose stored body the write door
// refuses, as a lossy door withholds a refused body whole, and words the
// write door's text rules refuse.

const CUSTODY_PHRASE: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// Wonder R1 on the chat document pack, ruled for every door that joins a
/// turn's words (Engine, 2026-10-14): recall's TURN item, the scoped context
/// pack's `txt` (live, and pinned at the recalled revision), and a document
/// chat that names the turn, its answer and its items. Bug repro: each
/// joined the words of a message the write door refuses into the turn's.
#[test]
fn a_turn_gives_no_words_of_a_message_the_write_door_refuses() {
    const MEANING: [f32; 4] = [0.0, 0.0, 1.0, 0.0];
    let (_dir, vault, owner) = scan_off_embedding_vault();
    let facade = facade_for(&vault, owner);
    let kept = "the kettle whistles twice";
    let turn = witness_turn(&facade, 0xD9, &[CUSTODY_PHRASE, kept], 1_900);
    fill_turn(&vault, &turn, &MEANING);
    assert_eq!(refused_message_bodies(&vault, &turn), [true, false]);
    let item = recalled_turn(&facade, "kettle", &MEANING);
    turn_doors_serve(&vault, &facade, &turn, &item, &MEANING, kept, "sausage");
}

/// The words leg alone (Wonder R2): a reference pinned while a message held
/// the phrase, which a later write of its row made clean. Its stored body
/// now passes, and the words the pin serves, its earlier row's, are read as
/// they are served.
#[test]
fn a_turn_pinned_before_its_message_was_made_clean_gives_none_of_its_words() {
    const MEANING: [f32; 4] = [0.0, 1.0, 1.0, 0.0];
    let (_dir, vault, owner) = scan_off_embedding_vault();
    let facade = facade_for(&vault, owner);
    let kept = "the clock chimes at noon";
    let turn = witness_turn(&facade, 0xDA, &[CUSTODY_PHRASE, kept], 1_900);
    fill_turn(&vault, &turn, &MEANING);
    let pinned = recalled_turn(&facade, "clock", &MEANING);
    rewrite_first_message(&vault, &turn, |fields| {
        for (key, value) in fields.iter_mut() {
            if key.as_str() == Some("content") {
                *value = "the stove ticks softly".into();
            }
        }
    });
    assert_eq!(refused_message_bodies(&vault, &turn), [false, false]);
    turn_doors_serve(&vault, &facade, &turn, &pinned, &MEANING, kept, "sausage");
}

/// The body leg alone: a message whose row holds a credential beside words
/// the write door accepts gives none of them.
#[test]
fn a_turn_gives_no_words_of_a_message_whose_body_holds_a_secret() {
    const MEANING: [f32; 4] = [1.0, 0.0, 1.0, 0.0];
    let (_dir, vault, owner) = scan_off_embedding_vault();
    let facade = facade_for(&vault, owner);
    let kept = "the porch light flickers";
    let turn = witness_turn(&facade, 0xDC, &["the stove ticks softly", kept], 1_900);
    fill_turn(&vault, &turn, &MEANING);
    rewrite_first_message(&vault, &turn, |fields| {
        fields.push((
            rmpv::Value::from("password"),
            rmpv::Value::from("t7Rk2pLq9WzX"),
        ));
    });
    assert_eq!(refused_message_bodies(&vault, &turn), [true, false]);
    let item = recalled_turn(&facade, "porch", &MEANING);
    turn_doors_serve(&vault, &facade, &turn, &item, &MEANING, kept, "stove");
}

/// Rewrites the stored body of `turn`'s first message with `edit`, as a
/// write the owner's scan does not read may (a replica's): its earlier row
/// stays among its retained revisions.
fn rewrite_first_message(
    vault: &crate::Vault,
    turn: &EntityId,
    edit: impl FnOnce(&mut Vec<(rmpv::Value, rmpv::Value)>),
) {
    let message = first_message(vault, turn);
    let raw = vault.get_raw(&message).expect("raw read").expect("stored");
    let (header, body) = raw.split_at(crate::batch::ENTITY_METADATA_HEADER_LEN);
    let rmpv::Value::Map(mut fields) =
        rmpv::decode::read_value(&mut std::io::Cursor::new(body)).expect("message body")
    else {
        panic!("a message body is a map");
    };
    edit(&mut fields);
    let mut row = header.to_vec();
    rmpv::encode::write_value(&mut row, &rmpv::Value::Map(fields)).expect("encode");
    vault
        .with_write_txn(|wtxn| {
            crate::vault::entity_revision::capture_entity_revision(
                &vault.store,
                wtxn,
                &message,
                &row,
            )?;
            vault.store.entities.put(wtxn, message.as_bytes(), &row)
        })
        .expect("rewrite the message's row");
}

/// A vault whose turns embed, with the owner's write scan off.
fn scan_off_embedding_vault() -> (tempfile::TempDir, crate::Vault, EntityId) {
    let (dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let authenticated = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner session");
    vault
        .set_secret_scan_mode(
            &authenticated,
            crate::batch::secret_scan::SecretScanMode::Off,
            10,
        )
        .expect("scan off");
    (dir, vault, owner)
}

/// Whether the write door refuses each of `turn`'s message bodies, in order.
fn refused_message_bodies(vault: &crate::Vault, turn: &EntityId) -> Vec<bool> {
    let messages = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        crate::tagging::turn_messages_in_txn(vault, &rtxn, turn)
            .expect("turn messages")
            .expect("a live turn")
    };
    messages
        .iter()
        .map(|message| {
            let id = EntityId::from_hex(&message.id).expect("message id");
            let raw = vault.get_raw(&id).expect("raw read").expect("stored");
            crate::batch::export::write_door_refuses_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
        })
        .collect()
}

/// Asserts that each door that joins `turn`'s words serves `kept` and no
/// `withheld`: recall's `item`, the scoped context pack's `txt` live and
/// pinned at that item, and a document chat naming it, its items and its
/// answer, with no format, Markdown and plain text. A rendered answer need
/// not quote the words, so it is held only to `withheld`.
fn turn_doors_serve(
    vault: &crate::Vault,
    facade: &Memory<'_>,
    turn: &EntityId,
    item: &crate::memory::MemoryItem,
    meaning: &[f32],
    kept: &str,
    withheld: &str,
) {
    let lane = facade
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("owner read lane");
    let mut pack = vault
        .context_pack()
        .search_vector(meaning, 10)
        .hydrate(true)
        .run_unfinalized_with_telemetry()
        .expect("assemble")
        .value;
    lane.filter_context_pack(&mut pack)
        .expect("filter the pack");
    let live = pack
        .results
        .iter()
        .find(|entity| entity.id == *turn)
        .and_then(|entity| {
            entity
                .fields
                .as_ref()?
                .get("txt")?
                .as_str()
                .map(str::to_owned)
        });
    let mut served = vec![
        ("recall".to_owned(), item.value_text.clone()),
        ("pack live".to_owned(), live.unwrap_or_default()),
        (
            "pack pinned".to_owned(),
            pinned_pack_text(vault, &lane, turn, meaning, item).unwrap_or_default(),
        ),
    ];
    for format in [None, Some("md"), Some("txt")] {
        let crate::memory::ChatResponse::Answered {
            answer, retrieval, ..
        } = facade
            .chat(
                "what was said",
                crate::memory::ChatDepth::Light,
                crate::memory::ChatOptions {
                    scope: crate::memory::ChatScope::Documents {
                        source_short_ids: vec![item.reference()],
                    },
                    limit: 10,
                    format,
                    lease: None,
                    composer: None,
                },
            )
            .expect("chat")
        else {
            panic!("{format:?}: the named turn answers");
        };
        served.push((
            format!("chat {format:?} items"),
            format!("{:?}", retrieval.items),
        ));
        if format.is_none() {
            served.push(("chat answer".to_owned(), answer));
        } else {
            assert!(
                !answer.contains(withheld),
                "chat {format:?} answer: {answer}"
            );
        }
    }
    for (door, text) in served {
        assert!(
            text.contains(kept) && !text.contains(withheld),
            "{door}: {text}"
        );
    }
}
