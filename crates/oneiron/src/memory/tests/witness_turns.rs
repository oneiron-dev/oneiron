//! Witness turn create/get/append/interleave, speaker atomicity, and meso enqueue on close.

use super::*;

#[test]
fn actor_key_grammar_parses_and_fails_closed() {
    let (_dir, vault) = open_vault();
    let person = put_person(&vault, 0x11);

    let (actor, class) =
        parse_actor_key(&vault, &format!("human:{}", person.to_hex())).expect("parse actor key");
    assert_eq!(actor, person);
    assert_eq!(class, EdgeActorClass::Human);

    let (_, agent_class) =
        parse_actor_key(&vault, &format!("agent:{}", person.to_hex())).expect("agent key");
    assert_eq!(agent_class, EdgeActorClass::Agent);

    for malformed in [
        "human",
        "wizard:0011001100110011001100110011aabb",
        "human:not-a-ref",
        "",
    ] {
        let err = parse_actor_key(&vault, malformed).expect_err("malformed key must fail");
        assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST, "key {malformed:?}");
        assert!(!err.suggestions.is_empty());
    }
}

#[test]
fn witness_writes_turn_messages_edges_and_text() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x21);
    let facade = facade_for(&vault, actor);

    let conversation_hex = EntityId::from_bytes([0x22; 16]).expect("conv id").to_hex();
    let receipt = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            // ONE-1767: one call = ONE non-system speaker. Mixed-author turns
            // are witnessed as consecutive single-speaker turns, so this row
            // set is all `User` (a `Companion` row here is a bad request).
            messages: vec![
                witness_message(0, WitnessAuthor::User, "quantum banana ledger"),
                witness_message(1, WitnessAuthor::User, "second owner row"),
                witness_message(2, WitnessAuthor::User, "closing note"),
            ],
            occurred_at: 500,
        })
        .expect("witness turn");

    assert_eq!(receipt.message_short_ids.len(), 3);
    assert!(receipt.receipt_ref.starts_with("witness:"));

    // One TURN + three MESSAGE entities + the CONVERSATION exist with the
    // right kinds.
    let turn = facade
        .get_entity(&receipt.turn_short_id)
        .expect("get turn")
        .expect("turn exists");
    assert_eq!(turn.kind, "TURN");
    let conversation = facade
        .get_entity(&conversation_hex)
        .expect("get conversation")
        .expect("conversation exists");
    assert_eq!(conversation.kind, "CONVERSATION");

    // The grouping speaker and structural conversation binding survive
    // readback; additive body fields remain legal.
    let turn_body = turn.body.clone().expect("turn body decodes");
    assert_eq!(turn_body["speaker"], serde_json::json!("user"));
    let turn_id = EntityId::from_hex(&turn.id_hex).expect("turn hex id");
    let conversation_id = EntityId::from_hex(&conversation_hex).expect("conversation hex id");
    let has_child_of_conversation = vault
        .edges_out(&turn_id)
        .expect("turn edges out")
        .into_iter()
        .any(|edge| edge.kind == EdgeKind::ChildOf && edge.target == conversation_id);
    assert!(
        has_child_of_conversation,
        "TURN is minted with its ChildOf(conversation) edge"
    );

    // Edges + typed read-back envelope per message.
    for (index, short_id) in receipt.message_short_ids.iter().enumerate() {
        let view = facade
            .get_entity(short_id)
            .expect("get message")
            .expect("message exists");
        assert_eq!(view.kind, "MESSAGE");
        assert_eq!(view.occurred_start, 500);
        assert_eq!(view.learned_at, 500);
        let body = view.body.expect("message body decodes");
        assert_eq!(body["order"], serde_json::json!(index as u64));
        assert_eq!(body["is_visible"], serde_json::json!(true));
        assert_eq!(body["type"], serde_json::json!("dialogue"));
        // ONE-1767: the MESSAGE body's `author` string encoding is untouched
        // (facade vocabulary `user`, NOT the canonical Dreamer role — that
        // lives only on the TURN's `speaker`).
        assert_eq!(body["author"], serde_json::json!("user"));

        let id = EntityId::from_hex(&view.id_hex).expect("hex id");
        let edges = vault.edges_out(&id).expect("edges out");
        let kinds: Vec<EdgeKind> = edges.iter().map(|edge| edge.kind).collect();
        assert!(
            kinds.contains(&EdgeKind::PartOf),
            "PartOf edge on {short_id}"
        );
        assert!(
            kinds.contains(&EdgeKind::BelongsTo),
            "BelongsTo edge on {short_id}"
        );
        assert!(
            kinds.contains(&EdgeKind::AuthoredBy),
            "AuthoredBy edge on {short_id}"
        );
    }

    // BM25 finds the content.
    let hits = vault.search_text("banana", 10).expect("search");
    let first_message = facade
        .get_entity(&receipt.message_short_ids[0])
        .unwrap()
        .unwrap();
    assert!(
        hits.iter()
            .any(|hit| hit.id.to_hex() == first_message.id_hex),
        "witnessed content must be BM25-findable"
    );
}

#[test]
fn witness_create_or_get_reuses_containers_and_skips_system_author_edge() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x31);
    let facade = facade_for(&vault, actor);

    let conversation_hex = EntityId::from_bytes([0x32; 16]).expect("conv").to_hex();
    let turn_hex = EntityId::from_bytes([0x33; 16]).expect("turn").to_hex();

    let first = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: Some(turn_hex.clone()),
            messages: vec![witness_message(0, WitnessAuthor::User, "first half")],
            occurred_at: 600,
        })
        .expect("first witness");
    let turn_id = EntityId::from_hex(&turn_hex).unwrap();
    let conversation_id = EntityId::from_hex(&conversation_hex).unwrap();
    let turn_raw_before = vault.get_raw(&turn_id).unwrap().expect("turn raw");
    let conversation_raw_before = vault
        .get_raw(&conversation_id)
        .unwrap()
        .expect("conversation raw");
    // Second call APPENDS permitted System interleave to the same TURN (a
    // System-only call carries no grouping speaker, so it must match the
    // stored speaker vacuously and succeed). ONE-1686: the interleave rides a
    // MACHINE actor with an explicit actor-bound `auto` ceiling, because an
    // unattributed `system` row is the engine's own voice.
    let system_facade = authorized_system_facade_for(&vault, put_machine(&vault, 0x34));
    let second = system_facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: Some(turn_hex.clone()),
            messages: vec![witness_message(1, WitnessAuthor::System, "system row")],
            occurred_at: 601,
        })
        .expect("second witness");
    assert_eq!(first.turn_short_id, second.turn_short_id);

    let turns = vault.entities_by_type(ENTITY_TYPE_TURN).expect("turns");
    assert_eq!(turns.len(), 1, "turn must not be duplicated");
    let conversations = vault
        .entities_by_type(ENTITY_TYPE_CONVERSATION)
        .expect("conversations");
    assert_eq!(
        conversations.len(),
        1,
        "conversation must not be duplicated"
    );

    // ONE-1767: the TURN row no longer survives an append byte-identically —
    // it is RE-PUT with the same body and occurred interval but a strictly
    // newer `learned_at` so a post-watermark append re-dirties the turn for
    // consolidation. The CONVERSATION row stays byte-identical
    // (idempotency-critical for the §3.5 hash checks).
    let turn_raw_after = vault.get_raw(&turn_id).unwrap().expect("turn raw after");
    let header_before = EntityMetadataHeader::parse(&turn_raw_before).expect("turn header before");
    let header_after = EntityMetadataHeader::parse(&turn_raw_after).expect("turn header after");
    assert_eq!(
        &turn_raw_after[ENTITY_METADATA_HEADER_LEN..],
        &turn_raw_before[ENTITY_METADATA_HEADER_LEN..],
        "reused TURN body must stay byte-identical"
    );
    assert_eq!(
        (header_after.occurred_start, header_after.occurred_end),
        (header_before.occurred_start, header_before.occurred_end),
        "reused TURN keeps its original occurred interval"
    );
    assert!(
        header_after.learned_at > header_before.learned_at,
        "append re-dirties the TURN: learned_at must strictly advance"
    );
    assert_eq!(
        vault
            .get_raw(&conversation_id)
            .unwrap()
            .expect("conversation raw after"),
        conversation_raw_before,
        "reused CONVERSATION must be byte-identical"
    );

    // System-authored rows get no AuthoredBy edge (design §2.1).
    let system_view = facade
        .get_entity(&second.message_short_ids[0])
        .unwrap()
        .expect("system message");
    let system_id = EntityId::from_hex(&system_view.id_hex).unwrap();
    let kinds: Vec<EdgeKind> = vault
        .edges_out(&system_id)
        .expect("edges")
        .iter()
        .map(|edge| edge.kind)
        .collect();
    assert!(!kinds.contains(&EdgeKind::AuthoredBy));
    assert!(kinds.contains(&EdgeKind::PartOf));

    // Type mismatch on a container ref fails closed.
    let err = facade
        .witness(&WitnessTurn {
            conversation_ref: turn_hex,
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "x")],
            occurred_at: 602,
        })
        .expect_err("turn id passed as conversation must fail");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
}

/// The mandatory facade-shaped acceptance: a CONVERSATION and a
/// Companion-authored TURN minted ONLY through `Memory::witness` (body
/// and `ChildOf` edge included) feed the production SessionEnd close shape —
/// without the stamped `speaker` the scanner's role gate drops the turn, and
/// without the edge `plan_partitions` cannot group it.
#[test]
fn witness_facade_turn_enqueues_meso_on_session_close() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x61);
    let facade = facade_for(&vault, actor);
    let session = mint_open_session(&vault, 400);

    let conversation_hex = EntityId::from_bytes([0x62; 16]).expect("conv id").to_hex();
    let receipt = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::Companion,
                "companion turn headed for the close",
            )],
            occurred_at: 500,
        })
        .expect("witness turn");

    // The grouping fact is the canonical Dreamer ROLE string, not the facade
    // vocabulary: Companion stamps `assistant` (what `dreamer_turn_role`
    // admits), never `companion`.
    let turn = facade
        .get_entity(&receipt.turn_short_id)
        .expect("get turn")
        .expect("turn exists");
    assert_eq!(
        turn.body.expect("turn body")["speaker"],
        serde_json::json!("assistant"),
        "TURN carries the canonical grouping speaker"
    );
    let turn_id = EntityId::from_hex(&turn.id_hex).expect("turn id");
    let conversation_id = EntityId::from_hex(&conversation_hex).expect("conversation id");
    assert!(
        vault
            .edges_out(&turn_id)
            .expect("turn edges")
            .iter()
            .any(|edge| edge.kind == EdgeKind::ChildOf && edge.target == conversation_id),
        "the witness mint carries the TURN -> CONVERSATION ChildOf edge"
    );

    assert_eq!(
        meso_partition_attempt_count(&vault),
        0,
        "no consolidation attempt exists before the close"
    );

    // The PRODUCTION close shape: read watermark -> scan dirty turns ->
    // plan partitions -> end the session with that wake.
    let wake = production_close_wake(&vault);
    assert_eq!(
        wake.plans.len(),
        1,
        "one facade-minted dirty conversation, one partition plan"
    );
    assert_eq!(wake.planned_turn_ids, vec![turn_id]);
    assert_eq!(wake.plans[0].key.conversation_ref, conversation_id);
    let ended = vault
        .end_session_with_wake(&session, crate::SessionClosePredicate::Explicit, 900, &wake)
        .expect("end session")
        .expect("session ended");
    assert_eq!(ended.session, session);
    assert_eq!(
        meso_partition_attempt_count(&vault),
        1,
        "the facade-minted turn enqueued the Meso ATTEMPT at session close"
    );
}

/// One call carries ONE non-system speaker. Both bad shapes — the User +
/// Companion mint and the cross-speaker append — fail with the facade
/// bad-request code, and the refusal is ATOMIC: no rows, no edges, no text
/// postings, no turn rewrite, no session-activity bump survive either arm.
#[test]
fn witness_rejects_mixed_non_system_speakers_atomically() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x63);
    let facade = facade_for(&vault, actor);
    mint_open_session(&vault, 400);

    // Arm one: the User + Companion MINT.
    let conversation_hex = EntityId::from_bytes([0x64; 16]).expect("conv id").to_hex();
    let err = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            messages: vec![
                witness_message(0, WitnessAuthor::User, "owner row in the ledger"),
                witness_message(
                    1,
                    WitnessAuthor::Companion,
                    "companion row in the same call",
                ),
            ],
            occurred_at: 500,
        })
        .expect_err("a mixed non-system mint is a bad request");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_TURN)
            .expect("turns")
            .is_empty(),
        "the refused mint left no TURN"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .is_empty(),
        "the refused mint left no MESSAGE rows"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_CONVERSATION)
            .expect("conversations")
            .is_empty(),
        "the refused mint left no CONVERSATION"
    );
    assert!(
        vault.search_text("ledger", 10).expect("search").is_empty(),
        "the refused mint left no text postings"
    );
    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session open");
    assert_eq!(
        open.last_activity, 400,
        "the refused mint never bumped session activity"
    );

    // Arm two: a Companion APPEND to a User turn.
    let conversation_id = EntityId::from_hex(&conversation_hex).expect("conversation id");
    let receipt = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "owner holds the turn alone",
            )],
            occurred_at: 500,
        })
        .expect("mint a user turn");
    let turn = facade
        .get_entity(&receipt.turn_short_id)
        .expect("get turn")
        .expect("turn exists");
    let turn_id = EntityId::from_hex(&turn.id_hex).expect("turn id");
    let turn_raw_before = vault.get_raw(&turn_id).expect("turn raw").expect("turn");
    let conversation_raw_before = vault
        .get_raw(&conversation_id)
        .expect("conversation raw")
        .expect("conversation");
    let turn_edges_before = vault.edges_out(&turn_id).expect("turn edges").len();

    let err = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: Some(turn.id_hex),
            messages: vec![witness_message(
                1,
                WitnessAuthor::Companion,
                "companion usurps the owner turn",
            )],
            occurred_at: 600,
        })
        .expect_err("a cross-speaker append is a bad request");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(
        vault
            .get_raw(&turn_id)
            .expect("turn raw after")
            .expect("turn"),
        turn_raw_before,
        "the refused append never re-put the TURN (not even a learned_at move)"
    );
    assert_eq!(
        vault
            .get_raw(&conversation_id)
            .expect("conversation raw after")
            .expect("conversation"),
        conversation_raw_before,
        "the refused append left the CONVERSATION untouched"
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len(),
        1,
        "the refused append added no MESSAGE"
    );
    assert_eq!(
        vault.edges_out(&turn_id).expect("turn edges after").len(),
        turn_edges_before,
        "the refused append changed no edges"
    );
    assert!(
        vault.search_text("usurps", 10).expect("search").is_empty(),
        "the refused append left no text postings"
    );
    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session open");
    assert_eq!(
        open.last_activity, 500,
        "the refused append never bumped session activity past the mint"
    );
}

/// The pre-transaction "no such turn" answer is ADVISORY: when the same-id
/// TURN commits in the window before the write transaction opens, the
/// transaction-authoritative re-read takes the APPEND path — stored-speaker
/// validation included — instead of overwriting the committed row as a mint.
#[test]
fn witness_concurrent_same_type_turn_creation_routes_through_validation() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x65);
    let facade = facade_for(&vault, actor);

    // Arm one: the raced TURN belongs to the speaker the call carries. The
    // concurrent body is not the witness mint shape — it carries a byte
    // marker any overwrite-as-new would erase — but it DOES carry the mint's
    // full binding facts (ONE-1767 second cycle): the speaker stamp and the
    // `ChildOf` conversation edge, both of which the append door validates.
    let conversation_hex = EntityId::from_bytes([0x66; 16]).expect("conv id").to_hex();
    let conversation_id = EntityId::from_hex(&conversation_hex).expect("conversation id");
    let turn_id = EntityId::from_bytes([0x67; 16]).expect("turn id");
    let concurrent_body = encode_rmpv(&Value::Map(vec![
        (Value::from("concurrent"), Value::from("marker")),
        (Value::from("speaker"), Value::from("assistant")),
    ]))
    .expect("concurrent body");
    let receipt = facade
        .witness_with_pre_txn_hook(
            &WitnessTurn {
                conversation_ref: conversation_hex,
                turn_ref: Some(turn_id.to_hex()),
                messages: vec![witness_message(0, WitnessAuthor::Companion, "late joiner")],
                occurred_at: 750,
            },
            || {
                let empty_body = encode_rmpv(&Value::Map(Vec::new())).expect("container body");
                vault
                    .batch()
                    .put(
                        &conversation_id,
                        ENTITY_TYPE_CONVERSATION,
                        test_time(700),
                        700,
                        &empty_body,
                    )
                    .put(
                        &turn_id,
                        ENTITY_TYPE_TURN,
                        test_time(700),
                        700,
                        &concurrent_body,
                    )
                    .edge(&turn_id, EdgeKind::ChildOf, &conversation_id, 1.0)
                    .commit()
                    .expect("the concurrent TURN commits in the advisory window");
            },
        )
        .expect("the race takes the append path, speaker validation included");
    assert_eq!(
        receipt.message_short_ids.len(),
        1,
        "the call's message landed on the raced turn"
    );

    // The committed row was re-put for the re-dirty, never overwritten as a
    // fresh mint: the marker body and the occurred interval survive intact;
    // only learned_at moved (700 -> 750).
    let raw = vault.get_raw(&turn_id).expect("turn raw").expect("turn");
    let header = EntityMetadataHeader::parse(&raw).expect("turn header");
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        concurrent_body.as_slice(),
        "the raced row was never overwritten as a fresh mint"
    );
    assert_eq!(
        (header.occurred_start, header.occurred_end),
        (700, 700),
        "the append path preserved the raced row's occurred interval"
    );
    assert_eq!(
        header.learned_at, 750,
        "the append path re-dirtied the raced row"
    );
    let message = facade
        .get_entity(&receipt.message_short_ids[0])
        .expect("get message")
        .expect("message exists");
    let message_id = EntityId::from_hex(&message.id_hex).expect("message id");
    assert!(
        vault
            .edges_out(&message_id)
            .expect("message edges")
            .iter()
            .any(|edge| edge.kind == EdgeKind::PartOf && edge.target == turn_id),
        "the appended message is PartOf the raced turn"
    );

    // Arm two: the raced TURN belongs to SOMEONE ELSE. The seed is the same
    // full mint shape (speaker stamp + `ChildOf`), so it is the SPEAKER check
    // — not the conversation-binding check — that rejects the whole call; the
    // concurrent row survives byte-identically (body AND learned_at) and
    // nothing of the refused call persists.
    let conversation2_hex = EntityId::from_bytes([0x68; 16]).expect("conv 2").to_hex();
    let conversation2_id = EntityId::from_hex(&conversation2_hex).expect("conversation 2 id");
    let turn2_id = EntityId::from_bytes([0x69; 16]).expect("turn 2");
    let user_body = encode_rmpv(&Value::Map(vec![
        (Value::from("concurrent"), Value::from("marker")),
        (Value::from("speaker"), Value::from("user")),
    ]))
    .expect("user body");
    let container2_body = encode_rmpv(&Value::Map(Vec::new())).expect("container body");
    let err = facade
        .witness_with_pre_txn_hook(
            &WitnessTurn {
                conversation_ref: conversation2_hex,
                turn_ref: Some(turn2_id.to_hex()),
                messages: vec![witness_message(0, WitnessAuthor::Companion, "speaker grab")],
                occurred_at: 850,
            },
            || {
                vault
                    .batch()
                    .put(
                        &conversation2_id,
                        ENTITY_TYPE_CONVERSATION,
                        test_time(800),
                        800,
                        &container2_body,
                    )
                    .put(&turn2_id, ENTITY_TYPE_TURN, test_time(800), 800, &user_body)
                    .edge(&turn2_id, EdgeKind::ChildOf, &conversation2_id, 1.0)
                    .commit()
                    .expect("the concurrent TURN commits in the advisory window");
            },
        )
        .expect_err("the raced row's stored speaker is enforced");
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
    let raw2 = vault
        .get_raw(&turn2_id)
        .expect("turn 2 raw")
        .expect("turn 2");
    let header2 = EntityMetadataHeader::parse(&raw2).expect("turn 2 header");
    assert_eq!(
        &raw2[ENTITY_METADATA_HEADER_LEN..],
        user_body.as_slice(),
        "the refused call never overwrote the raced row"
    );
    assert_eq!(
        header2.learned_at, 800,
        "the refused call never even re-put the raced row"
    );
    let conversation2_raw = vault
        .get_raw(&conversation2_id)
        .expect("conversation 2 raw")
        .expect("the hook-seeded conversation persists");
    let conversation2_header =
        EntityMetadataHeader::parse(&conversation2_raw).expect("conversation 2 header");
    assert_eq!(
        conversation2_header.learned_at, 800,
        "the refused call never re-put the seeded CONVERSATION"
    );
    assert_eq!(
        &conversation2_raw[ENTITY_METADATA_HEADER_LEN..],
        container2_body.as_slice(),
        "the seeded CONVERSATION body is byte-identical"
    );
}

/// An append landing AFTER the watermark passed the turn RE-DIRTIES it: the
/// next dirty scan returns the SAME turn id with a strictly greater
/// `learned_at`, and the re-put leaves no stale temporal-learned key behind.
#[test]
fn witness_append_redirties_the_same_turn() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x6A);
    let facade = facade_for(&vault, actor);
    let conversation_hex = EntityId::from_bytes([0x6B; 16]).expect("conv id").to_hex();
    let turn_id = EntityId::from_bytes([0x6C; 16]).expect("turn id");
    let scope = DreamerConsolidationScope::Meso;

    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![witness_message(0, WitnessAuthor::User, "the original turn")],
            occurred_at: 1_000,
        })
        .expect("mint the turn");
    let minted_raw = vault.get_raw(&turn_id).expect("turn raw").expect("turn");

    // The watermark moves PAST the minted turn; a scan now finds nothing.
    crate::dreamer_consolidation::advance_watermark(&vault, scope, 1_000)
        .expect("advance watermark");
    let watermark = crate::read_watermark(&vault, scope).expect("watermark");
    assert!(
        crate::scan_dirty_turns(&vault, scope, &watermark, 10)
            .expect("scan")
            .is_empty(),
        "the minted turn is already consolidated"
    );

    // The same-speaker append (with permitted System interleave) is BACKDATED
    // before the minted stamp — exactly the case where rewriting an
    // equal/older learned_at would stay invisible to consolidation.
    //
    // ONE-1686: the call carries a `system` row, so it rides the MACHINE actor
    // that may author one. The user row it carries is attributed to that same
    // actor, which is what a single witness call has always meant.
    let system_facade = authorized_system_facade_for(&vault, put_machine(&vault, 0x6D));
    system_facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![
                witness_message(1, WitnessAuthor::User, "the turn continues"),
                witness_message(2, WitnessAuthor::System, "tool row in between"),
            ],
            occurred_at: 900,
        })
        .expect("backdated same-speaker append");

    // learned_at moved STRICTLY beyond the watermark (max(900, 1000 + 1))…
    let raw = vault
        .get_raw(&turn_id)
        .expect("turn raw after")
        .expect("turn");
    let header = EntityMetadataHeader::parse(&raw).expect("header after");
    let minted_header = EntityMetadataHeader::parse(&minted_raw).expect("header before");
    assert_eq!(
        header.learned_at, 1_001,
        "a backdated append still re-dirties: strictly newer learned_at"
    );
    assert_eq!(
        (header.occurred_start, header.occurred_end),
        (minted_header.occurred_start, minted_header.occurred_end),
        "the re-put preserved the original occurred interval"
    );
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        &minted_raw[ENTITY_METADATA_HEADER_LEN..],
        "the re-put preserved the body bytes"
    );

    // …and the next dirty scan returns THE SAME turn id above the watermark.
    let watermark = crate::read_watermark(&vault, scope).expect("watermark after");
    let dirty = crate::scan_dirty_turns(&vault, scope, &watermark, 10).expect("scan after");
    assert_eq!(dirty.len(), 1, "the append re-dirtied exactly one turn");
    assert_eq!(dirty[0].turn_id, turn_id, "it is the SAME turn");
    assert!(
        dirty[0].learned_at > watermark.last_learned_at,
        "strictly above the watermark: {} > {}",
        dirty[0].learned_at,
        watermark.last_learned_at
    );

    // The re-put removed the stale temporal-learned key: only the new stamp
    // indexes the turn (apply_put deletes the old key and inserts the new).
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut old_key = [0_u8; 24];
    old_key[..8].copy_from_slice(&1_000_u64.to_be_bytes());
    old_key[8..24].copy_from_slice(turn_id.as_bytes());
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &old_key[..])
            .expect("old key read")
            .is_none(),
        "no stale old learned key survives the re-put"
    );
    let mut new_key = [0_u8; 24];
    new_key[..8].copy_from_slice(&1_001_u64.to_be_bytes());
    new_key[8..24].copy_from_slice(turn_id.as_bytes());
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &new_key[..])
            .expect("new key read")
            .is_some(),
        "the new learned key indexes the re-dirtied turn"
    );
}

/// System/tooling rows are permitted INTERLEAVE on an established turn: the
/// stored speaker is untouched and the append re-dirties it. But a call with
/// no non-system speaker can never MINT a turn — there is no grouping fact
/// to stamp, and inventing one is refused.
#[test]
fn witness_system_interleave_appends_but_never_mints_a_turn() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x6D);
    let facade = facade_for(&vault, actor);
    let conversation_hex = EntityId::from_bytes([0x6E; 16]).expect("conv id").to_hex();
    let turn_id = EntityId::from_bytes([0x6F; 16]).expect("turn id");

    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![witness_message(
                0,
                WitnessAuthor::Companion,
                "the assistant turn",
            )],
            occurred_at: 600,
        })
        .expect("mint an assistant turn");

    // The System-only APPEND succeeds and re-dirties the turn. ONE-1686: it is
    // witnessed by a MACHINE actor carrying an explicit actor-bound auto
    // ceiling, the permit required for unattributed rows.
    let system_facade = authorized_system_facade_for(&vault, put_machine(&vault, 0x72));
    system_facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![witness_message(1, WitnessAuthor::System, "tool result row")],
            occurred_at: 601,
        })
        .expect("system interleave on an established turn is permitted");
    let raw = vault.get_raw(&turn_id).expect("turn raw").expect("turn");
    let header = EntityMetadataHeader::parse(&raw).expect("turn header");
    assert_eq!(
        header.learned_at, 601,
        "the system-only append re-dirtied the turn"
    );
    let body = facade
        .get_entity(&turn_id.to_hex())
        .expect("get turn")
        .expect("turn")
        .body
        .expect("turn body");
    assert_eq!(
        body["speaker"],
        serde_json::json!("assistant"),
        "the stored grouping speaker is untouched by interleave"
    );

    // The authorized System-only MINT fails closed, whether the caller names
    // a fresh turn id or lets the door mint one.
    for turn_ref in [
        None,
        Some(
            EntityId::from_bytes([0x70; 16])
                .expect("fresh turn")
                .to_hex(),
        ),
    ] {
        let err = system_facade
            .witness(&WitnessTurn {
                conversation_ref: EntityId::from_bytes([0x71; 16])
                    .expect("fresh conv")
                    .to_hex(),
                turn_ref,
                messages: vec![witness_message(
                    0,
                    WitnessAuthor::System,
                    "orphan system rows",
                )],
                occurred_at: 700,
            })
            .expect_err("a system-only mint has no grouping speaker");
        assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
    }
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_TURN)
            .expect("turns")
            .len(),
        1,
        "no system-only TURN was ever minted"
    );
}

#[test]
fn witness_bumps_open_session_activity_atomically() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x71);
    let facade = facade_for(&vault, actor);

    let session = match vault.mint_session(400).expect("mint session") {
        crate::session_lifecycle::SessionMintOutcome::Minted(id) => id,
        other => panic!("expected fresh mint, got {other:?}"),
    };

    let conversation_hex = EntityId::from_bytes([0x72; 16]).expect("conv id").to_hex();
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "hello again")],
            occurred_at: 500,
        })
        .expect("witness turn");

    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session still open");
    assert_eq!(open.session, session);
    assert_eq!(
        open.last_activity, 500,
        "turn-witness bumps last_activity to the turn's occurred_at"
    );

    // An OLDER turn (backfill) never rewinds the activity clock.
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "backfilled note")],
            occurred_at: 450,
        })
        .expect("witness backfill turn");
    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session still open");
    assert_eq!(open.last_activity, 500, "activity clock is monotonic");
}

#[test]
fn witness_without_an_open_session_stays_valid() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x73);
    let facade = facade_for(&vault, actor);

    // ARCH-0002 open-endedness: turns outside any session are valid; the
    // bump is a no-op, not an error, and no session is minted.
    let conversation_hex = EntityId::from_bytes([0x74; 16]).expect("conv id").to_hex();
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "sessionless turn")],
            occurred_at: 600,
        })
        .expect("witness sessionless turn");
    assert_eq!(vault.open_session().expect("open session read"), None);
}
