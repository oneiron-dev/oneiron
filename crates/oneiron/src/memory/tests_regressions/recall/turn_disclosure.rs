// A disclosure clamp sees a TURN through its messages: the turn carries each
// message's words and meaning, so it reaches an assembly only when the clamp
// admits every one of them.

/// Astra 1333 #1 (P1): with the owner present beside a known third party,
/// the clamp is supervised and withholds Tier-A records. A turn holding an
/// owner-marked private message stays out of the pack: its vector does not
/// find it by the private message's meaning, and no `txt` carries its words.
/// A mark set after assembly takes the turn out at the final filter, which
/// joins the text in its own read. Bug repro: the clamp checked the turn's
/// own mark alone, so the third party received the turn and the filter then
/// joined the private words into its `txt`.
#[test]
fn a_disclosure_clamp_keeps_out_a_turn_holding_a_withheld_message() {
    const PRIVATE: &str = "the gate code is 7731";
    const PRIVATE_MEANING: [f32; 4] = [0.0, 1.0, 0.0, 0.0];
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let turn = witness_turn(&facade, 0xD1, &[PRIVATE, "see you at the gate"], 1_800);
    fill_turn(&vault, &turn, &PRIVATE_MEANING);
    let private = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let messages = crate::tagging::turn_messages_in_txn(&vault, &rtxn, &turn)
            .expect("turn messages")
            .expect("a live turn");
        let message = messages
            .iter()
            .find(|message| message.text == PRIVATE)
            .expect("the private message");
        EntityId::from_hex(&message.id).expect("message id")
    };

    let contact = EntityId::from_bytes([0xD2; 16]).unwrap();
    let record = crate::counterparty_contact::CounterpartyContactRecord::user_introduction(
        EntityId::from_bytes([0xD3; 16]).unwrap(),
        "kenji@example.com",
        10,
    )
    .expect("contact record");
    vault
        .create_counterparty_contact(&contact, &record)
        .expect("create contact");
    let supervised = || {
        crate::disclosure::DisclosureContext::resolve(
            &vault,
            crate::interlocutor::InterlocutorSet::with_session_owner(vec![
                crate::interlocutor::Interlocutor::known_contact(
                    contact,
                    "kenji@example.com",
                    crate::counterparty_contact::CounterpartyFirstTouch::UserIntroduction,
                ),
            ]),
        )
        .expect("resolve the clamp")
    };
    assert_eq!(
        supervised().mode(),
        crate::disclosure::DisclosureMode::Supervised
    );
    let assemble = || {
        vault
            .context_pack()
            .search_vector(&PRIVATE_MEANING, 10)
            .hydrate(true)
            .disclosure_context(supervised())
            .run_unfinalized_with_telemetry()
            .expect("assemble")
    };
    let lane = facade
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("owner read lane");
    let turn_text = |pack: &crate::context_pack::ContextPack| {
        pack.results
            .iter()
            .find(|entity| entity.id == turn)
            .map(|entity| {
                entity
                    .fields
                    .as_ref()
                    .and_then(|fields| fields.get("txt"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            })
    };

    // Unmarked, the supervised pack carries the turn and its words.
    let mut before = assemble();
    lane.filter_context_pack(&mut before.value)
        .expect("filter the pack");
    assert!(
        turn_text(&before.value).is_some_and(|text| text.contains("7731")),
        "an unmarked turn is Tier B: {:?}",
        before.value.results
    );

    // Assembled, then marked: the final filter reads the mark.
    let mut raced = assemble();
    assert!(raced.value.results.iter().any(|entity| entity.id == turn));
    vault
        .set_disclosure_tier_a(&private, 100)
        .expect("owner marks the private message");
    lane.filter_context_pack_under(&mut raced.value, Some(&supervised()))
        .expect("filter the raced pack");
    assert_eq!(
        turn_text(&raced.value),
        None,
        "a turn kept its withheld message past the final filter"
    );

    // Marked before assembly: the vector hit never reaches the pack.
    let mut after = assemble();
    assert!(
        after.value.results.iter().all(|entity| entity.id != turn),
        "the private message's meaning found its turn: {:?}",
        after.value.results
    );
    lane.filter_context_pack(&mut after.value)
        .expect("filter the pack");
    for entity in after
        .value
        .results
        .iter()
        .chain(after.value.neighbors.iter())
    {
        assert_ne!(entity.id, turn);
        let fields = serde_json::to_string(&entity.fields).expect("fields");
        assert!(!fields.contains("7731"), "{fields}");
    }
}
