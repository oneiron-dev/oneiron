// A TURN's words are its MESSAGEs' without the rest of their bodies: each
// door that joins them withholds a message whose stored body the write door
// refuses, as a lossy door withholds a refused body whole.

/// Wonder R1 on the chat document pack, ruled for every door that joins a
/// turn's words (Engine, 2026-10-14): recall's TURN item, the scoped context
/// pack's `txt` (live, and pinned at the recalled revision), and a document
/// chat that names the turn, its answer and its items. Bug repro: each
/// joined the words of a message the write door refuses into the turn's.
#[test]
fn a_turn_gives_no_words_of_a_message_the_write_door_refuses() {
    const MEANING: [f32; 4] = [0.0, 0.0, 1.0, 0.0];
    const PHRASE: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const KEPT: &str = "the kettle whistles twice";
    let (_dir, vault) = open_embedding_vault();
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
    let facade = facade_for(&vault, owner);
    let turn = witness_turn(&facade, 0xD9, &[PHRASE, KEPT], 1_900);
    fill_turn(&vault, &turn, &MEANING);
    let messages = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        crate::tagging::turn_messages_in_txn(&vault, &rtxn, &turn)
            .expect("turn messages")
            .expect("a live turn")
    };
    let refused: Vec<bool> = messages
        .iter()
        .map(|message| {
            let id = EntityId::from_hex(&message.id).expect("message id");
            let raw = vault.get_raw(&id).expect("raw read").expect("stored");
            crate::batch::export::write_door_refuses_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
        })
        .collect();
    assert_eq!(refused, [true, false]);
    let served = |text: &str| text.contains(KEPT) && !text.contains("sausage");

    let item = recalled_turn(&facade, "kettle", &MEANING);
    assert!(served(&item.value_text), "recall: {}", item.value_text);

    let lane = facade
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("owner read lane");
    let mut pack = vault
        .context_pack()
        .search_vector(&MEANING, 10)
        .hydrate(true)
        .run_unfinalized_with_telemetry()
        .expect("assemble")
        .value;
    lane.filter_context_pack(&mut pack)
        .expect("filter the pack");
    let live = pack
        .results
        .iter()
        .find(|entity| entity.id == turn)
        .and_then(|entity| {
            entity
                .fields
                .as_ref()?
                .get("txt")?
                .as_str()
                .map(str::to_owned)
        });
    let pinned = pinned_pack_text(&vault, &lane, &turn, &MEANING, &item);
    for (read, text) in [("live", live), ("pinned", pinned)] {
        let text = text.unwrap_or_default();
        assert!(served(&text), "context pack {read}: {text}");
    }

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
        let items = format!("{:?}", retrieval.items);
        assert!(!answer.contains("sausage"), "{format:?}: {answer}");
        assert!(served(&items), "{format:?}: {items}");
    }
}
