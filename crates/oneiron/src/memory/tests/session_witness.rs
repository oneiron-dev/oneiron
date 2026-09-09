//! Session overlay witness, room-shell claims, flip/replay races, and promoted turns.

use super::*;

/// The load-bearing property of the whole ticket: a session-witnessed turn is
/// READABLE IN THE ROOM and INVISIBLE FROM BASE.
///
/// Both halves matter. Invisible-only would be indistinguishable from having
/// dropped the write; readable-only would be an ordinary base write wearing a
/// session's name.
#[test]
fn session_witness_lands_in_the_overlay_and_never_in_base() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-overlay", 0x51);
    let facade = facade_for(&vault, actor);

    let base_entity_rows = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault.store.entities.len(&rtxn).expect("entity count")
    };

    let receipt = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "in-room utterance")],
                occurred_at: 900,
            },
            Some("the room's summary"),
        )
        .expect("session witness");

    // The room sees its own turn through the composed view.
    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let turn_id = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("receipt ref names the turn"),
    )
    .expect("turn id");
    assert!(
        view.entities
            .get(&rtxn, turn_id.as_bytes())
            .expect("session get")
            .is_some(),
        "the session handle reads the turn it just witnessed"
    );
    drop(rtxn);
    drop(view);

    // Base sees nothing: not the turn, not the messages, not the summary, not
    // the shell. The row COUNT is the honest assertion — a per-id probe could
    // miss a row written under an id the test does not know.
    assert_eq!(vault.get_raw(&turn_id).expect("base get"), None);
    assert_eq!(
        {
            let rtxn = vault.store.env.read_txn().expect("read txn");
            vault.store.entities.len(&rtxn).expect("entity count")
        },
        base_entity_rows,
        "a session witness adds ZERO base entity rows"
    );

    session.close().expect("close session");
}

/// The receipt's short ids are SESSION-LOCAL: they carry the `s` sigil, so an
/// in-room alias can neither collide with nor shadow a durable short id, and a
/// leaked alias fails to parse at a base door rather than silently resolving
/// to the wrong entity.
#[test]
fn session_witness_receipt_carries_session_local_short_ids() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-alias", 0x52);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "alias probe")],
                occurred_at: 910,
            },
            None,
        )
        .expect("session witness");

    for alias in std::iter::once(&receipt.turn_short_id).chain(&receipt.message_short_ids) {
        let (short_id, _hash) = alias.split_once(':').expect("alias is short_id:hash");
        assert!(
            short_id.starts_with('s') && short_id[1..].chars().all(|c| c.is_ascii_digit()),
            "session aliases use the `s<n>` namespace, got {alias:?}"
        );
        // A base alias is <two letters><digits>, so `s<n>` cannot be minted by
        // the base counter and cannot shadow a durable alias. The base door
        // therefore resolves it to NOTHING — never to some other entity, which
        // is the failure mode a shared namespace would have produced.
        let (_, hash) = alias.split_once(':').expect("alias is short_id:hash");
        let hash = u8::from_str_radix(hash, 16).expect("hash is hex");
        assert!(
            vault
                .hydrate_short_id(short_id, hash)
                .expect("base hydrate")
                .is_none(),
            "session alias {alias:?} must not resolve through the base door"
        );
    }

    session.close().expect("close session");
}

/// One room is ONE conversation. A second witness reuses the shell allocated
/// by the first instead of minting a fresh one, so an in-session reader sees a
/// conversation rather than a turn-per-conversation shred.
#[test]
fn repeat_session_witness_reuses_the_room_shell() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-shell", 0x53);
    let facade = facade_for(&vault, actor);

    let turn = |content: &str, at: u64| WitnessTurn {
        conversation_ref: String::new(),
        turn_ref: None,
        messages: vec![witness_message(0, WitnessAuthor::User, content)],
        occurred_at: at,
    };
    let first = facade
        .witness_into_session(&session, &turn("first", 920), None)
        .expect("first witness");
    let second = facade
        .witness_into_session(&session, &turn("second", 921), None)
        .expect("second witness");

    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let conversation_of = |receipt: &WitnessReceipt| {
        let turn_id = EntityId::from_hex(
            receipt
                .receipt_ref
                .strip_prefix("witness:")
                .expect("receipt ref names the turn"),
        )
        .expect("turn id");
        assert!(
            view.entities
                .get(&rtxn, turn_id.as_bytes())
                .expect("turn lookup")
                .is_some(),
            "the receipt identifies a turn visible in the room"
        );
        let prefix = crate::vault::edge_kind_prefix(&turn_id, EdgeKind::ChildOf);
        let mut targets = view
            .edges_out
            .prefix_iter(&rtxn, &prefix)
            .expect("edge scan")
            .map(|row| {
                let (key, _) = row.expect("edge row");
                let (_, _, target) =
                    crate::edge::parse_strict_edge_record_key(&key).expect("edge key");
                target
            });
        let conversation = targets.next().expect("turn has a conversation");
        assert!(targets.next().is_none(), "turn has only one conversation");
        let raw = view
            .entities
            .get(&rtxn, conversation.as_bytes())
            .expect("conversation lookup")
            .expect("the conversation exists in the room");
        let _ = raw;
        conversation
    };
    assert_eq!(
        conversation_of(&first),
        conversation_of(&second),
        "both receipt-identified turns resolve to the same existing conversation"
    );
    drop(rtxn);
    drop(view);

    session.close().expect("close session");
}

/// K10: after a flip to on-record, the SAME session witness lands in BASE —
/// under a fresh continuation shell, never the overlay conversation id.
///
/// Reusing the overlay shell would write a base row referencing an overlay
/// member (the taint K4 rejects) and would make the private room reachable
/// from base by following the edge. The two transcripts stay separate
/// conversations, which is what "pre-flip turns remain base-invisible" means
/// structurally rather than by convention.
#[test]
fn post_flip_session_witness_lands_in_base_under_a_fresh_shell() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-flip", 0x54);
    let facade = facade_for(&vault, actor);

    facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "off-record turn")],
                occurred_at: 930,
            },
            None,
        )
        .expect("pre-flip witness");
    let overlay_shell = session.overlay_conversation_shell().expect("room shell");

    session.flip_on_record().expect("flip on record");
    let receipt = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "on-record turn")],
                occurred_at: 931,
            },
            None,
        )
        .expect("post-flip witness");

    let post_flip_turn = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("receipt ref names the turn"),
    )
    .expect("turn id");
    assert!(
        vault.get_raw(&post_flip_turn).expect("base get").is_some(),
        "an on-record turn is an ordinary base write"
    );
    let continuation = session
        .on_record_continuation_shell()
        .expect("continuation");
    assert_ne!(
        continuation, overlay_shell,
        "the continuation shell is never the overlay conversation id"
    );
    assert!(
        vault.get_raw(&overlay_shell).expect("base get").is_none(),
        "the room's own shell stays invisible to base across the flip"
    );

    session.close().expect("close session");
}

/// A replay-owned base witness makes its existing-row decision under the
/// writer transaction. The inner call deterministically commits in the outer
/// call's pre-transaction window, reproducing two retries that both observed
/// absence before one won the writer.
#[test]
fn replay_owned_base_witness_race_is_an_exact_no_op() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-replay-witness-race", 0x57);
    let facade = facade_for(&vault, actor);
    session.flip_on_record().expect("flip on record");
    let route = session.write_route().expect("mint base route");
    let continuation = session
        .on_record_continuation_shell()
        .expect("continuation shell");
    let turn_id = crate::test_util::entity(0x58);
    let message_id = crate::test_util::entity(0x59);
    let mut message = witness_message(0, WitnessAuthor::Companion, "one replay bubble");
    message.id = Some(message_id.to_hex());
    let turn = WitnessTurn {
        conversation_ref: continuation.to_hex(),
        turn_ref: Some(turn_id.to_hex()),
        messages: vec![message],
        occurred_at: 970,
    };

    let winning = std::cell::RefCell::new(None);
    let losing = facade
        .witness_with_route_and_before_txn(&turn, Some(&route), || {
            let receipt = facade
                .witness_with_route_and_before_txn(&turn, Some(&route), || {})
                .expect("winning retry commits");
            winning.replace(Some(receipt));
        })
        .expect("racing retry converges");
    assert_eq!(
        winning.into_inner().expect("winning receipt"),
        losing,
        "both retries report the same stable materialization"
    );
    let turn_raw = vault
        .get_raw(&turn_id)
        .expect("turn lookup")
        .expect("turn exists");
    let header = crate::batch::EntityMetadataHeader::parse(&turn_raw).expect("turn header");
    assert_eq!(
        header.learned_at, 970,
        "the losing retry must not re-dirty the committed TURN"
    );
    assert!(
        vault
            .get_raw(&message_id)
            .expect("message lookup")
            .is_some()
    );

    let later = facade
        .witness_with_route_and_before_txn(&turn, Some(&route), || {})
        .expect("later retry is also a no-op");
    assert_eq!(later, losing);
    let turn_raw = vault
        .get_raw(&turn_id)
        .expect("turn lookup")
        .expect("turn exists");
    let header = crate::batch::EntityMetadataHeader::parse(&turn_raw).expect("turn header");
    assert_eq!(header.learned_at, 970);

    session.close().expect("close session");
}

/// K10, the durable half: a BASE-routed session witness whose route went stale
/// commits ZERO base rows.
///
/// The base arm publishes the room's substance durably, so it is the arm where
/// a missed flip actually leaks: a witness admitted while the room was on
/// record must not land turn + messages + continuation shell in base once the
/// room has flipped back off record. The route minted before the flip stands
/// in for the in-flight route of a witness the flip overtakes mid-call.
#[test]
fn a_stale_base_route_session_witness_commits_no_base_rows() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-stale-base", 0x56);
    let facade = facade_for(&vault, actor);

    session.flip_on_record().expect("flip on record");
    let route = session.write_route().expect("mint base route");
    let continuation = session
        .on_record_continuation_shell()
        .expect("continuation shell");
    session.flip_off_record().expect("flip back off record");

    let base_entity_rows = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault.store.entities.len(&rtxn).expect("entity count")
    };
    let refused = facade
        .witness_with_route(
            &WitnessTurn {
                conversation_ref: continuation.to_hex(),
                turn_ref: None,
                messages: vec![witness_message(
                    0,
                    WitnessAuthor::User,
                    "overtaken by the flip",
                )],
                occurred_at: 950,
            },
            Some(&route),
        )
        .expect_err("a stale base route refuses the witness");
    assert!(
        refused.message.contains("off-record overlay generation"),
        "the refusal is the stale-route family, got {refused:?}"
    );
    assert_eq!(
        {
            let rtxn = vault.store.env.read_txn().expect("read txn");
            vault.store.entities.len(&rtxn).expect("entity count")
        },
        base_entity_rows,
        "a refused base-routed witness adds ZERO base entity rows"
    );

    session.close().expect("close session");
}

/// A route minted before a mode flip is refused by `revalidate` before ANY
/// staging — so a flip landing mid-call cannot leave half a turn in a room the
/// caller no longer believes it is in.
#[test]
fn a_route_minted_before_a_flip_is_refused() {
    let (_dir, vault) = open_vault();
    let (session, _actor) = session_witness_fixture(&vault, "sess-stale-route", 0x55);

    let route = session.write_route().expect("mint route");
    route.revalidate().expect("a fresh route is valid");
    session.flip_on_record().expect("flip on record");

    let refused = route
        .revalidate()
        .expect_err("a route minted before the flip is stale");
    assert_eq!(refused.kind(), ErrorKind::OffRecordOverlayLeaseClosed);

    session.close().expect("close session");
}

/// R3 lock order: the base writer is taken BEFORE the overlay segment permit,
/// on EVERY session write path.
///
/// The overlay states the invariant itself (`acquire_segment_lease`: "Base
/// writers are acquired before this permit; there is no reverse-order path"),
/// and the witness obeys it. The session retrieval-telemetry arm did not — it
/// installed the segment, then opened the base txn — so a witness holding the
/// base writer and waiting for the permit met a telemetry run holding the
/// permit and waiting for the writer: ABBA, on one room, no timeout anywhere in
/// the stack.
///
/// The whole race runs in a DETACHED driver thread and the test body waits on a
/// channel. That is deliberate: a deadlock inside `thread::scope` would hang
/// the suite (the implicit join blocks even while unwinding), so the watchdog
/// has to sit outside the scope. A timeout here IS the deadlock.
#[test]
fn concurrent_room_witness_and_telemetry_never_invert_the_lock_order() {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    const ROUNDS: usize = 40;

    let (done_tx, done_rx) = std::sync::mpsc::channel::<(usize, usize, bool)>();
    std::thread::spawn(move || {
        let (_dir, vault) = open_vault();
        let (session, actor) = session_witness_fixture(&vault, "sess-lock-order", 0x57);
        let facade = facade_for(&vault, actor);
        let overlay_shell = session
            .overlay_conversation_shell()
            .expect("allocate the room shell up front");

        let witnessed = AtomicUsize::new(0);
        let searched = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for round in 0..ROUNDS {
                    // Refusals are legitimate: the flipper may have sealed the
                    // room under this route. Only a HANG is a failure.
                    if facade
                        .witness_into_session(
                            &session,
                            &WitnessTurn {
                                conversation_ref: String::new(),
                                turn_ref: None,
                                messages: vec![witness_message(
                                    0,
                                    WitnessAuthor::User,
                                    "lockorderneedle",
                                )],
                                occurred_at: 960 + round as u64,
                            },
                            None,
                        )
                        .is_ok()
                    {
                        witnessed.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
            });
            scope.spawn(|| {
                for _ in 0..ROUNDS {
                    if session.search_text("lockorderneedle", 4).is_ok() {
                        searched.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
            });
            scope.spawn(|| {
                for _ in 0..ROUNDS {
                    let _ = session.flip_on_record();
                    let _ = session.flip_off_record();
                }
            });
        });

        // Classification survived the race: the room's own conversation shell
        // never became a base row, whichever arm each call took.
        let shell_leaked = vault.get_raw(&overlay_shell).expect("base get").is_some();
        done_tx
            .send((
                witnessed.load(AtomicOrdering::Relaxed),
                searched.load(AtomicOrdering::Relaxed),
                shell_leaked,
            ))
            .ok();
    });

    let (witnessed, searched, shell_leaked) = match done_rx
        .recv_timeout(std::time::Duration::from_secs(90))
    {
        Ok(outcome) => outcome,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!(
                "concurrent room witness + telemetry deadlocked (segment permit taken before the base writer)"
            )
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the concurrency driver thread panicked")
        }
    };
    assert!(
        witnessed > 0 && searched > 0,
        "both writers must make real progress, not merely fail fast \
         (witnessed {witnessed}, searched {searched})"
    );
    assert!(
        !shell_leaked,
        "the room's overlay conversation shell must never become a base row"
    );
}

/// R4: a FAILED session witness must not burn the room's one-shot shell claim.
///
/// The claim was consumed before the caller-controlled fallible work (message
/// id parsing, body encoding) and before the write transaction, with no
/// rollback. A first witness carrying a malformed message id therefore returned
/// `Err` having staged nothing — yet the room was marked shell-staged, so the
/// NEXT witness hung its `PartOf`/`BelongsTo` edges off a conversation id with
/// no entity row: a dangling journal that promote (ONE-1730) would replay.
#[test]
fn a_failed_session_witness_does_not_burn_the_room_shell_claim() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-shell-claim", 0x58);
    let facade = facade_for(&vault, actor);

    let mut malformed = witness_message(0, WitnessAuthor::User, "never lands");
    malformed.id = Some("zz".to_owned());
    let refused = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![malformed],
                occurred_at: 970,
            },
            None,
        )
        .expect_err("a malformed message id refuses the witness");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);

    facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "lands for real")],
                occurred_at: 971,
            },
            None,
        )
        .expect("the next witness succeeds");

    let shell = session.overlay_conversation_shell().expect("room shell");
    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert!(
        view.entities
            .get(&rtxn, shell.as_bytes())
            .expect("shell lookup")
            .is_some(),
        "the room's conversation shell row exists, so no edge dangles"
    );
    assert_eq!(
        view.type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CONVERSATION])
            .expect("type scan")
            .count(),
        1,
        "the claim stays one-shot: exactly ONE shell row per room"
    );
    drop(rtxn);
    drop(view);

    session.close().expect("close session");
}

/// R4, the other half: a witness that fails INSIDE the write transaction
/// RELEASES the shell claim.
///
/// Deferring the claim past the caller-controlled parsing is not enough — the
/// transaction itself is fallible (actor binding, overlay budget). This room's
/// byte budget admits a small turn and refuses an oversized one, so the first
/// witness dies after the claim is taken and after the shell `Put` is staged,
/// with the segment discarded. Only a released claim lets the next witness
/// stage the shell row the room's edges point at.
#[test]
fn an_in_transaction_failure_releases_the_room_shell_claim() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x59);
    let facade = facade_for(&vault, actor);
    let session = vault
        .off_record_session_vault()
        .enter_with_budget(
            "sess-witness-shell-rollback",
            crate::off_record::OffRecordBackendClass::Local,
            64 * 1024,
        )
        .expect("enter session");

    let turn = |content: String, at: u64| WitnessTurn {
        conversation_ref: String::new(),
        turn_ref: None,
        messages: vec![witness_message(0, WitnessAuthor::User, &content)],
        occurred_at: at,
    };
    let refused = facade
        .witness_into_session(&session, &turn("x".repeat(256 * 1024), 980), None)
        .expect_err("a turn larger than the whole room budget is refused");
    assert!(
        refused.message.contains("off-record overlay is full"),
        "the refusal is the overlay-budget family, got {refused:?}"
    );

    facade
        .witness_into_session(&session, &turn("small enough".to_owned(), 981), None)
        .expect("the next witness succeeds");

    let shell = session.overlay_conversation_shell().expect("room shell");
    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert!(
        view.entities
            .get(&rtxn, shell.as_bytes())
            .expect("shell lookup")
            .is_some(),
        "the released claim let the next witness stage the shell row"
    );
    assert_eq!(
        view.type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CONVERSATION])
            .expect("type scan")
            .count(),
        1,
        "still one-shot: exactly ONE shell row per room"
    );
    drop(rtxn);
    drop(view);

    session.close().expect("close session");
}

/// Every overlay witness mints a FRESH TURN, so the base door's mint contract
/// binds this door too: mixed non-system and all-system calls are the same
/// bad request, the staged TURN body carries the canonical speaker, and the
/// TURN -> room-shell `ChildOf` edge is journaled with it — the two facts a
/// promote must replay for consolidation to group and role the turn.
#[test]
fn session_witness_turn_carries_the_mint_contract() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-mint-contract", 0x5D);
    let facade = facade_for(&vault, actor);

    let mixed = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![
                    witness_message(0, WitnessAuthor::User, "owner row"),
                    witness_message(1, WitnessAuthor::Companion, "companion row"),
                ],
                occurred_at: 940,
            },
            None,
        )
        .expect_err("a mixed non-system overlay witness is a bad request");
    assert_eq!(mixed.code, MEMORY_CODE_BAD_REQUEST);

    let system_only = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::System, "tooling row")],
                occurred_at: 941,
            },
            None,
        )
        .expect_err("an all-system overlay witness is a bad request");
    assert_eq!(system_only.code, MEMORY_CODE_BAD_REQUEST);

    // The refusals staged nothing and burned no claim: the real witness mints
    // the room's ONE shell and its ONE TURN. ONE-1686: the call carries a
    // `system` row, so it rides the MACHINE actor with an explicit actor-bound
    // auto ceiling — the room runs the base door's ceiling contract, not a
    // looser one.
    let system_facade = authorized_system_facade_for(&vault, put_machine(&vault, 0x5E));
    let receipt = system_facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![
                    witness_message(0, WitnessAuthor::Companion, "the in-room answer"),
                    witness_message(1, WitnessAuthor::System, "permitted interleave"),
                ],
                occurred_at: 942,
            },
            None,
        )
        .expect("the room still witnesses after the refused calls");
    let turn_id = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("receipt ref names the turn"),
    )
    .expect("turn id");
    let shell = session.overlay_conversation_shell().expect("room shell");

    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let raw = view
        .entities
        .get(&rtxn, turn_id.as_bytes())
        .expect("session get")
        .expect("the staged TURN reads back in the room")
        .into_owned();
    let speaker = decode_witness_turn_speaker(&raw[ENTITY_METADATA_HEADER_LEN..])
        .expect("the staged TURN body carries its speaker entry");
    assert_eq!(
        speaker, "assistant",
        "Companion stamps the canonical Dreamer role, never `companion`"
    );
    let prefix = crate::vault::edge_kind_prefix(&turn_id, EdgeKind::ChildOf);
    let mut bound = None;
    for row in view
        .edges_out
        .prefix_iter(&rtxn, &prefix)
        .expect("edge scan")
    {
        let (key, _) = row.expect("edge row");
        let (_, _, target) = crate::edge::parse_strict_edge_record_key(&key).expect("edge key");
        bound = Some(target);
    }
    assert_eq!(
        bound,
        Some(shell),
        "the staged TURN is `ChildOf` the room shell"
    );
    assert_eq!(
        view.type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_TURN])
            .expect("turn scan")
            .count(),
        1,
        "only the admitted witness staged a TURN"
    );
    assert_eq!(
        view.type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CONVERSATION])
            .expect("conversation scan")
            .count(),
        1,
        "the refused calls staged no shell; the witness kept the claim one-shot"
    );
    drop(rtxn);
    drop(view);

    session.close().expect("close session");
}

/// The promote half of the same contract: a promoted overlay turn lands in
/// base WITH the stamped speaker and its `ChildOf` edge to the room shell, so
/// `conversation_of` answers the shell and `decode_turn_body` finds the role.
#[test]
fn promoted_session_turn_lands_with_speaker_and_conversation_binding() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-promote-stamp", 0x5E);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "publish this turn")],
                occurred_at: 950,
            },
            None,
        )
        .expect("overlay witness");
    let turn_id = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("receipt ref names the turn"),
    )
    .expect("turn id");
    let shell = session.overlay_conversation_shell().expect("room shell");

    let outcome = session.promote_turn(&turn_id).expect("promote the turn");
    assert_eq!(
        outcome.replayed.len(),
        3,
        "the closure replays shell + turn + message"
    );

    // Base now holds the turn with exactly the minted body —
    let turn = facade
        .get_entity(&turn_id.to_hex())
        .expect("get promoted turn")
        .expect("promoted turn is a base row");
    assert_eq!(
        turn.body.expect("turn body"),
        serde_json::json!({"speaker": "user"}),
        "the promoted TURN body carries the canonical speaker"
    );
    // — and the `ChildOf` binding `conversation_of` reads.
    let bound = vault
        .edges_out(&turn_id)
        .expect("promoted turn edges")
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::ChildOf)
        .map(|edge| edge.target);
    assert_eq!(
        bound,
        Some(shell),
        "the promoted turn's ChildOf resolves the room shell"
    );
    assert!(
        vault.get_raw(&shell).expect("shell read").is_some(),
        "the room shell promoted with the turn's closure"
    );

    session.close().expect("close session");
}
