//! Threshold fixtures of the room_thread scans for `no_engine_scan_refuses_for_its_row_count`
//! (FIX LIBTEST-SCAN-CHECK-TABLE-UNSEEDED-SCANS).

use super::*;

pub(super) fn seed(vault: &Vault, scan: EngineScan) -> Option<(usize, Read<'_>)> {
    match scan {
        EngineScan::RoomThreadChildRows => {
            // Trunk plus PAST thread roots under (room, anchor); the trunk's own
            // selection reads PAST child rows past ROW.
            let room = id(0x88, 0);
            let anchor = id(0x88, 1);
            vault
                .with_write_txn(|wtxn| {
                    rv_turns().put(
                        &vault.store,
                        wtxn,
                        &anchor,
                        &rv_room_turn(anchor, room, None, None, 1),
                    )?;
                    for (i, idx) in [2usize, 3, 4].iter().enumerate() {
                        let child = id(0x88, *idx);
                        let row = rv_room_turn(child, room, None, Some(anchor), 2 + i as u64);
                        rv_turns().put(&vault.store, wtxn, &child, &row)?;
                        rv_children().put(&vault.store, wtxn, &(room, anchor, child), &child)?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let sel = crate::workspace_roster::room_thread_turns_in_txn(
                        &vault, &txn, room, anchor,
                    )?
                    .expect("indexed");
                    Ok(sel.turns.len())
                }),
            ))
        }
        EngineScan::MessageOriginRows => {
            // PAST indexed projects with parentless, non-root authority are read
            // then hidden by the authority fold; no conversion proof is fabricated.
            let (message, turn, room) = (id(0x88, 10), id(0x88, 11), id(0x88, 12));
            let scope = vault.root_project().expect("root");
            let kind = vault.project_type_byte().expect("project kind");
            vault
                .with_write_txn(|wtxn| {
                    vis_plant(
                        vault,
                        wtxn,
                        message,
                        crate::registry::ENTITY_TYPE_MESSAGE,
                        b"message",
                    )?;
                    for (edge, target) in [(EdgeKind::PartOf, turn), (EdgeKind::BelongsTo, room)] {
                        let key = Store::encode_edge_key(&message, edge, &target);
                        vault.store.edges_out.put(wtxn, &key, &edge_value())?;
                    }
                    for index in 0..PAST {
                        let project = id(0x88, 13 + index);
                        let body = crate::workspace_roster::ProjectRecord::new(
                            project, None, scope, turn,
                        )?;
                        let bytes = rmp_serde::to_vec_named(&body).expect("project bytes");
                        vis_plant(vault, wtxn, project, kind, &bytes)?;
                        let key = [
                            b"project.origin_message.v1/".as_slice(),
                            message.as_bytes(),
                            project.as_bytes(),
                        ]
                        .concat();
                        vault.store.vault_meta.put(wtxn, &key, project.as_bytes())?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                0,
                Box::new(move || Ok(vault.message_hangs(message, room)?.projects.len())),
            ))
        }
        EngineScan::ThreadTaskCensus => {
            // The census uses conversion policy, not set_scan_threshold. Narrow both
            // to ROW. An idempotent third binding counts 2+1, then 3+0, at one scope.
            let owner = vault.ensure_embedded_owner_actor().expect("owner");
            let root = vault.root_project().expect("root");
            let project = id(0xca, 1);
            let record =
                crate::workspace_roster::ProjectRecord::new(project, Some(root), root, owner)
                    .expect("project record");
            vault.put_project(project, &record, 1).expect("project");
            let room = EntityId::from_hex(&record.home_room).expect("room");
            let grant = rmpv::Value::Map(vec![
                ("actor_ref".into(), owner.to_hex().into()),
                ("effector".into(), "core:read".into()),
                (
                    "scope".into(),
                    crate::federation::scope_codec::encode_scope_value(
                        &crate::federation::scope_codec::read_preset(),
                    )
                    .expect("scope"),
                ),
                ("receipt_required".into(), false.into()),
            ]);
            let manifest = crate::gate::default_policy_manifest_with_scoped_grants(vec![grant])
                .expect("manifest");
            crate::test_util::put_policy_manifest_bytes(
                vault,
                crate::gate::default_policy_manifest_id().expect("manifest id"),
                &manifest,
            )
            .expect("grant");
            let mut entries = vis_default_manifest_entries();
            let (_, conversion) = entries
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("project_conversion"))
                .expect("conversion row");
            let rmpv::Value::Map(fields) = conversion else {
                panic!("conversion map")
            };
            fields
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("max_tasks"))
                .expect("max_tasks")
                .1 = ROW.into();
            let mut data = Vec::new();
            rmpv::encode::write_value(&mut data, &rmpv::Value::Map(entries)).expect("encode");
            crate::test_util::put_policy_manifest_bytes(vault, id(0xca, 2), &data)
                .expect("conversion policy");
            let (trunk, thread) = (id(0xca, 10), id(0xca, 11));
            let speak = |turn: EntityId, message: EntityId, parent: Option<EntityId>| {
                crate::memory::WitnessTurn {
                    conversation_ref: room.to_hex(),
                    turn_ref: Some(turn.to_hex()),
                    thread_audience: None,
                    project: None,
                    messages: vec![crate::memory::WitnessMessage {
                        id: Some(message.to_hex()),
                        author: crate::memory::WitnessAuthor::User,
                        message_type: "text".into(),
                        content: "thread census".into(),
                        parts: None,
                        is_visible: true,
                        order: 0,
                        quote: None,
                        metadata: Some(parent.map_or(
                            serde_json::json!({}),
                            |anchor| serde_json::json!({"room_thread_of": anchor.to_hex()}),
                        )),
                    }],
                    occurred_at: 2,
                    assertions: Default::default(),
                }
            };
            let user = vault.memory(owner, crate::edge::EdgeActorClass::Human);
            user.rooms_speak(&speak(trunk, id(0xca, 12), None))
                .expect("trunk");
            user.rooms_speak(&speak(thread, id(0xca, 13), Some(trunk)))
                .expect("thread");
            let post_one = |index: usize| {
                let post: crate::task_verb::TaskPost = serde_json::from_value(serde_json::json!({
            "intent_key": format!("thread-census-{index}"), "assignee": "dreamer",
            "brief": {
                "schema": 1,
                "type_ref": {"node_id": id(0xca, 30 + index).to_hex(), "tree_version": 1},
                "objective": "Tidy the tide log",
                "intent": {"need": "Tidy the tide log", "care": "light"},
                "success": {
                    "question": "Is the tide log tidy?",
                    "criteria": {"yes_if_all": [{"text": "The duplicate dawn readings are merged."}]}
                },
                "escalation": {
                    "to": {"people": [owner.to_hex()]}, "triggers": [], "default": "proceed",
                    "reversibility": "reversible_read"
                }
            }
        })).expect("post");
                let receipt = user.tasks_post(post).expect("TASK post");
                match receipt.handle {
                    crate::task_verb::TaskHandle::Task { task_ref } => task_ref,
                    _ => panic!("an embedded-owner Dreamer post creates a TASK"),
                }
            };
            let tasks = [post_one(0), post_one(1), post_one(2)];
            vault
                .bind_room_thread_task(owner, room, thread, tasks[0])
                .expect("first");
            vault
                .bind_room_thread_task(owner, room, thread, tasks[1])
                .expect("second");
            let third = tasks[2];
            Some((
                PAST,
                Box::new(move || {
                    vault.bind_room_thread_task(owner, room, thread, third)?;
                    let txn = vault.store.env.read_txn()?;
                    Ok(rv_turns()
                        .get(&vault.store, &txn, &thread)?
                        .expect("thread")
                        .task_ids
                        .len())
                }),
            ))
        }
        EngineScan::ReplyStripRequestedRows => {
            // Project room plus a trunk TURN ChildOf it with no replies; the read
            // asks PAST strips past ROW and serves none.
            let (owner, room) = rv_project_room(vault, 30, 31);
            let trunk = id(0x88, 32);
            vault
                .put_entity(
                    &trunk,
                    crate::registry::ENTITY_TYPE_TURN,
                    crate::temporal::TimeRange { start: 1, end: 1 },
                    1,
                    b"trunk",
                )
                .expect("trunk");
            vault
                .with_write_txn(|wtxn| {
                    let out = Store::encode_edge_key(&trunk, EdgeKind::ChildOf, &room);
                    let back = Store::encode_edge_key(&room, EdgeKind::ChildOf, &trunk);
                    vault.store.edges_out.put(wtxn, &out, &edge_value())?;
                    vault.store.edges_in.put(wtxn, &back, &edge_value())?;
                    Ok(())
                })
                .expect("edge");
            let memory = vault.memory(owner, crate::edge::EdgeActorClass::Human);
            let req = crate::conversation_dag::ReplyStripsRequest {
                room_ref: room.to_hex(),
                thread_ref: trunk.to_hex(),
                after: None,
                limit: Some(PAST),
            };
            Some((
                0,
                Box::new(move || {
                    let page = memory
                        .rooms_reply_strips(&req)
                        .map_err(|e| crate::Error::InvalidConfig(e.message))?;
                    Ok(page.groups.len())
                }),
            ))
        }
        EngineScan::RoomRequestedPageRows => {
            // Project room with an empty history; the page asks PAST rows past
            // ROW and serves none.
            let (owner, room) = rv_project_room(vault, 40, 41);
            let memory = vault.memory(owner, crate::edge::EdgeActorClass::Human);
            Some((
                0,
                Box::new(move || {
                    let page = memory
                        .rooms_messages_page(room, None, PAST)
                        .map_err(|e| crate::Error::InvalidConfig(e.message))?;
                    Ok(page.rows.len())
                }),
            ))
        }
        EngineScan::RoomThreadListRows
        | EngineScan::RoomThreadPolicyRows
        | EngineScan::RoomThreadTokens
        | EngineScan::RoomThreadWaitRows => {
            // Project room with an empty history; the list asks PAST rows past
            // ROW and renders none. Keep the default token budget for the headings
            // and the quiet lane's find/get footer, even on an empty list.
            let (owner, room) = rv_project_room(vault, 50, 51);
            let memory = vault.memory(owner, crate::edge::EdgeActorClass::Human);
            let policy = crate::workspace_roster::RoomThreadPolicy {
                rows_per_list: PAST,
                waits_per_thread: PAST,
                ..Default::default()
            };
            Some((
                0,
                Box::new(move || {
                    let threads = memory
                        .rooms_threads(room, policy)
                        .map_err(|e| crate::Error::InvalidConfig(e.message))?;
                    Ok(threads.active.rows.len()
                        + threads.waiting.rows.len()
                        + threads.quiet.rows.len())
                }),
            ))
        }
        EngineScan::RoomLinkWalkRows => {
            // Four TURNs tip->m2->m1->root->anchor; the source walk reads PAST
            // links past ROW to its root.
            let room = id(0x88, 60);
            let anchor = id(0x88, 61);
            let root = id(0x88, 62);
            let m1 = id(0x88, 63);
            let m2 = id(0x88, 64);
            let tip = id(0x88, 65);
            for tid in [root, m1, m2, tip] {
                vault
                    .put_entity(
                        &tid,
                        crate::registry::ENTITY_TYPE_TURN,
                        crate::temporal::TimeRange { start: 1, end: 1 },
                        1,
                        b"turn",
                    )
                    .expect("turn");
            }
            vault
                .with_write_txn(|wtxn| {
                    rv_turns().put(
                        &vault.store,
                        wtxn,
                        &root,
                        &rv_room_turn(root, room, Some(anchor), Some(anchor), 1),
                    )?;
                    rv_turns().put(
                        &vault.store,
                        wtxn,
                        &m1,
                        &rv_room_turn(m1, room, Some(root), Some(anchor), 2),
                    )?;
                    rv_turns().put(
                        &vault.store,
                        wtxn,
                        &m2,
                        &rv_room_turn(m2, room, Some(m1), Some(anchor), 3),
                    )?;
                    rv_turns().put(
                        &vault.store,
                        wtxn,
                        &tip,
                        &rv_room_turn(tip, room, Some(m2), Some(anchor), 4),
                    )?;
                    Ok(())
                })
                .expect("seed");
            Some((
                1,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let found = crate::workspace_roster::room_thread_source_in(&vault, &txn, tip)?;
                    Ok(usize::from(found.is_some()))
                }),
            ))
        }
        EngineScan::RoomRetryLineageRows => {
            // Three live MESSAGEs regenerate back to the response slot. The existing
            // crate-visible prover walks all three and returns the source's one message.
            let owner = id(0xcb, 0);
            vault
                .put_entity(
                    &owner,
                    crate::registry::ENTITY_TYPE_PERSON,
                    crate::temporal::TimeRange { start: 1, end: 1 },
                    1,
                    b"owner",
                )
                .expect("owner");
            let root = vault.root_project().expect("root");
            let project = id(0xcb, 1);
            let record =
                crate::workspace_roster::ProjectRecord::new(project, Some(root), root, owner)
                    .expect("project record");
            vault.put_project(project, &record, 1).expect("project");
            let room = EntityId::from_hex(&record.home_room).expect("room");
            crate::test_util::authorize_readers(vault, &[&owner.to_hex()]);
            let (parent, slot, mid, source) =
                (id(0xcb, 10), id(0xcb, 11), id(0xcb, 12), id(0xcb, 13));
            let (m0, m1, m2) = (id(0xcb, 20), id(0xcb, 21), id(0xcb, 22));
            vault
                .put_entity(
                    &parent,
                    crate::registry::ENTITY_TYPE_TURN,
                    crate::temporal::TimeRange { start: 1, end: 1 },
                    1,
                    b"turn",
                )
                .expect("turn");
            for (turn, message) in [(slot, m0), (mid, m1), (source, m2)] {
                vault
                    .memory(owner, crate::edge::EdgeActorClass::Human)
                    .witness(&crate::memory::WitnessTurn {
                        conversation_ref: room.to_hex(),
                        turn_ref: Some(turn.to_hex()),
                        thread_audience: None,
                        project: None,
                        messages: vec![crate::memory::WitnessMessage {
                            id: Some(message.to_hex()),
                            author: crate::memory::WitnessAuthor::User,
                            message_type: "text".into(),
                            content: "retry lineage".into(),
                            parts: None,
                            metadata: None,
                            is_visible: true,
                            order: 0,
                            quote: None,
                        }],
                        occurred_at: 1,
                        assertions: Default::default(),
                    })
                    .expect("message");
            }
            vault
                .with_write_txn(|txn| {
                    rv_turns().put(
                        &vault.store,
                        txn,
                        &parent,
                        &rv_room_turn(parent, room, None, None, 1),
                    )?;
                    for (turn, at, message) in [(slot, 2, m0), (mid, 3, m1), (source, 4, m2)] {
                        let mut row = rv_room_turn(turn, room, Some(parent), None, at);
                        // rv_room_turn defaults actor to turn id; this proof checks it.
                        row.actor = owner.to_hex();
                        row.message_ids = vec![message.to_hex()];
                        rv_turns().put(&vault.store, txn, &turn, &row)?;
                    }
                    rr_claims().put(
                        &vault.store,
                        txn,
                        &parent,
                        &crate::workspace_roster::RoomClaimReceipt {
                            room_id: room.to_hex(),
                            turn_id: parent.to_hex(),
                            actor: owner.to_hex(),
                            receipt_ref: "rooms.claim:retry-scan".to_owned(),
                            at: 2,
                        },
                    )?;
                    rr_response().put(&vault.store, txn, &parent, &slot)?;
                    for (message, turn) in [(m0, slot), (m1, mid), (m2, source)] {
                        for (kind, target) in [
                            (EdgeKind::AuthoredBy, owner),
                            (EdgeKind::BelongsTo, room),
                            (EdgeKind::PartOf, turn),
                        ] {
                            let key = Store::encode_edge_key(&message, kind, &target);
                            vault.store.edges_out.put(txn, &key, &edge_value())?;
                        }
                    }
                    for (newer, older) in [(m2, m1), (m1, m0)] {
                        let key = Store::encode_edge_key(&newer, EdgeKind::Regenerates, &older);
                        vault.store.edges_out.put(txn, &key, &edge_value())?;
                    }
                    Ok(())
                })
                .expect("lineage");
            let action = crate::conversation::TurnActionAttempt {
                action: crate::conversation::TurnAction::Retry,
                conversation: room,
                user_turn: parent,
                assistant_turn: source,
                message: m2,
                actor: owner,
                actor_class: crate::edge::EdgeActorClass::Human as u8,
                authority: crate::conversation::TurnActionAuthority::Native,
                off_device: false,
                rebound_from: Vec::new(),
            };
            Some((
                1,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let permit = crate::workspace_roster::RoomRegenerationPermit::prove_in(
                        vault, &txn, &action, owner,
                    )?;
                    Ok(permit.source.message_ids.len())
                }),
            ))
        }
        EngineScan::RoomMentions => {
            // Three valid handles, three distinct seated people. The witness validates
            // all handles past ROW and keeps all three addresses on the room turn.
            let owner = id(0xcc, 0);
            let people: Vec<_> = (1..=PAST).map(|index| id(0xcc, index)).collect();
            for person in std::iter::once(&owner).chain(people.iter()) {
                vault
                    .put_entity(
                        person,
                        crate::registry::ENTITY_TYPE_PERSON,
                        crate::temporal::TimeRange { start: 1, end: 1 },
                        1,
                        b"room participant",
                    )
                    .expect("person");
            }
            let root = vault.root_project().expect("root");
            let project = id(0xcc, 4);
            let mut record =
                crate::workspace_roster::ProjectRecord::new(project, Some(root), root, owner)
                    .expect("project record");
            record.roster.extend(people.iter().map(EntityId::to_hex));
            vault.put_project(project, &record, 1).expect("project");
            let room = EntityId::from_hex(&record.home_room).expect("room");
            let handles: Vec<_> = (0..PAST).map(|i| format!("@mention-{i}")).collect();
            for (person, handle) in people.iter().zip(&handles) {
                vault
                    .bind_room_handle(room, handle, *person)
                    .expect("handle");
            }
            let grant = rmpv::Value::Map(vec![
                ("actor_ref".into(), owner.to_hex().into()),
                ("effector".into(), "core:read".into()),
                (
                    "scope".into(),
                    crate::federation::scope_codec::encode_scope_value(
                        &crate::federation::scope_codec::read_preset(),
                    )
                    .expect("scope"),
                ),
                ("receipt_required".into(), false.into()),
            ]);
            let manifest = crate::gate::default_policy_manifest_with_scoped_grants(vec![grant])
                .expect("manifest");
            crate::test_util::put_policy_manifest_bytes(
                vault,
                crate::gate::default_policy_manifest_id().expect("manifest id"),
                &manifest,
            )
            .expect("grant");
            let turn_id = id(0xcc, 5);
            let turn = crate::memory::WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(turn_id.to_hex()),
                thread_audience: None,
                project: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: Some(id(0xcc, 6).to_hex()),
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "text".to_owned(),
                    content: "all three handles remain addressed".to_owned(),
                    parts: None,
                    metadata: Some(serde_json::json!({"room_mentions": handles})),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: 2,
                assertions: Default::default(),
            };
            Some((
                PAST,
                Box::new(move || {
                    vault
                        .memory(owner, crate::edge::EdgeActorClass::Human)
                        .rooms_speak(&turn)
                        .map_err(|error| crate::Error::InvalidConfig(format!("{error:?}")))?;
                    let txn = vault.store.env.read_txn()?;
                    let stored = rv_turns().get(&vault.store, &txn, &turn_id)?.expect("turn");
                    assert_eq!(
                        stored.addressed_agents,
                        people
                            .iter()
                            .map(EntityId::to_hex)
                            .collect::<std::collections::BTreeSet<_>>(),
                    );
                    Ok(stored.addressed_agents.len())
                }),
            ))
        }
        EngineScan::RoomRosterMembers => {
            // A replicated body keeps all PAST members even when their PERSON
            // rows arrive later; use the same validator the replication write uses.
            let room = id(0x89, PAST);
            let body = crate::conversation::ConversationBody {
                member_ids: (0..PAST).map(|index| id(0x89, index)).collect(),
                ..Default::default()
            };
            let bytes = body.to_bytes().expect("body bytes");
            vault
                .with_write_txn(|wtxn| {
                    vis_plant(
                        vault,
                        wtxn,
                        room,
                        crate::registry::ENTITY_TYPE_CONVERSATION,
                        &bytes,
                    )
                })
                .expect("seed replicated room");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    crate::conversation::validate_put_in_txn(
                        &vault.store,
                        &txn,
                        room,
                        &bytes,
                        true,
                    )?;
                    Ok(PAST)
                }),
            ))
        }
        EngineScan::AudienceEdgeRows => {
            // PAST structural edges out of one record: the counted neighborhood read.
            let src = id(0x89, 10);
            vault
                .with_write_txn(|wtxn| {
                    for index in 11..11 + PAST {
                        let key =
                            Store::encode_edge_key(&src, EdgeKind::BelongsTo, &id(0x89, index));
                        vault.store.edges_out.put(wtxn, &key, &edge_value())?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    Ok(crate::conversation_dag::counted_edge_ids(
                        &vault.store,
                        &txn,
                        &src,
                        EdgeKind::BelongsTo,
                        false,
                    )?
                    .len())
                }),
            ))
        }
        EngineScan::RoomAncestryRecords => {
            // A 3-record ChildOf chain ending in a room: the walk counts every ancestor.
            let leaf = vis_ancestry_chain(vault, 20).0;
            Some((
                1,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    Ok(crate::conversation::room_for_record_in(&vault, &txn, leaf)?
                        .map_or(0, |_| 1))
                }),
            ))
        }
        EngineScan::PrivateThreadAncestryRecords => {
            // The same 3-record chain with no thread bindings: the walk still
            // counts every record it reaches.
            let (leaf, _, _) = vis_ancestry_chain(vault, 30);
            let raw = vis_record(crate::registry::ENTITY_TYPE_PERSON, b"leaf");
            Some((
                0,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    Ok(
                        crate::conversation::private_thread_word_turns_in(
                            &vault, &txn, leaf, &raw,
                        )?
                        .map_or(0, |turns| turns.len()),
                    )
                }),
            ))
        }
        EngineScan::WordSourceRecords => {
            // A word-source chain of three conversation.summary claims over one
            // MESSAGE: the room rule judges all four rows (the MESSAGE has no
            // stamp, so the revision is withheld after every row was judged).
            let subject = id(0x89, 80);
            let chain = [id(0x89, 81), id(0x89, 82), id(0x89, 83)];
            let msg = id(0x89, 84);
            vault
                .with_write_txn(|wtxn| {
                    vis_plant(
                        vault,
                        wtxn,
                        subject,
                        crate::registry::ENTITY_TYPE_PERSON,
                        b"reader",
                    )?;
                    for (claim, covered) in
                        [(chain[0], chain[1]), (chain[1], chain[2]), (chain[2], msg)]
                    {
                        vis_plant(
                            vault,
                            wtxn,
                            claim,
                            crate::registry::ENTITY_TYPE_CLAIM,
                            &vis_cover_claim(subject, &[covered]),
                        )?;
                    }
                    vis_plant(
                        vault,
                        wtxn,
                        msg,
                        crate::registry::ENTITY_TYPE_MESSAGE,
                        b"hi",
                    )?;
                    Ok(())
                })
                .expect("seed");
            let raw = vis_record(
                crate::registry::ENTITY_TYPE_CLAIM,
                &vis_cover_claim(subject, &[chain[1]]),
            );
            let scope = crate::federation::Scope::top();
            Some((
                0,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    Ok(usize::from(crate::disclosure::discloses_raw(
                        &vault, &txn, &scope, chain[0], &raw,
                    )?))
                }),
            ))
        }
        EngineScan::RoomPolicyRows => {
            // One trusted manifest holding PAST room-policy rows: the fold counts them.
            let mut entries = vis_default_manifest_entries();
            let rows = entries
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("room_policy_rows"))
                .expect("shipped room-policy rows");
            rows.1 = rmpv::Value::Array(["owner", "admin", "member"].map(vis_policy_row).to_vec());
            let mut data = Vec::new();
            rmpv::encode::write_value(&mut data, &rmpv::Value::Map(entries)).expect("encode");
            crate::test_util::put_policy_manifest_bytes(
                vault,
                crate::gate::default_policy_manifest_id().expect("manifest id"),
                &data,
            )
            .expect("manifest");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    Ok(crate::gate::resolve_policy_manifest(&vault.store, &txn)?
                        .room_policy_rows
                        .len())
                }),
            ))
        }
        EngineScan::RoomThreadHolderRows => {
            // One trusted manifest holding PAST room-thread holder rows.
            let mut entries = vis_default_manifest_entries();
            let room_thread = entries
                .iter_mut()
                .find(|(key, _)| key.as_str() == Some("room_thread"))
                .expect("default room_thread row");
            match &mut room_thread.1 {
                rmpv::Value::Map(fields) => {
                    let holders = fields
                        .iter_mut()
                        .find(|(name, _)| name.as_str() == Some("holder_rows"))
                        .expect("holder_rows");
                    holders.1 = rmpv::Value::Array(
                        (0..PAST)
                            .map(|index| vis_holder_row(id(0x89, 60 + index)))
                            .collect(),
                    );
                }
                _ => panic!("room_thread shape"),
            }
            let mut data = Vec::new();
            rmpv::encode::write_value(&mut data, &rmpv::Value::Map(entries)).expect("encode");
            crate::test_util::put_policy_manifest_bytes(vault, id(0x89, 51), &data)
                .expect("manifest");
            Some((
                PAST,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    Ok(crate::gate::resolve_policy_manifest(&vault.store, &txn)?
                        .room_thread
                        .map_or(0, |manifest| manifest.holder_rows()))
                }),
            ))
        }
        EngineScan::AudienceCoverDepth => {
            // A conversation.summary cover chain three deep over plain records:
            // every cover reads, so the walk reaches depth PAST.
            let subject = id(0x89, 70);
            let chain = [id(0x89, 71), id(0x89, 72), id(0x89, 73)];
            vault
                .with_write_txn(|wtxn| {
                    vis_plant(
                        vault,
                        wtxn,
                        subject,
                        crate::registry::ENTITY_TYPE_PERSON,
                        b"reader",
                    )?;
                    for (claim, covered) in [
                        (chain[0], chain[1]),
                        (chain[1], chain[2]),
                        (chain[2], subject),
                    ] {
                        vis_plant(
                            vault,
                            wtxn,
                            claim,
                            crate::registry::ENTITY_TYPE_CLAIM,
                            &vis_cover_claim(subject, &[covered]),
                        )?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                1,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let mut cache = crate::conversation::AudienceCache::default();
                    Ok(usize::from(cache.readable(&vault, &txn, chain[0], &[])?))
                }),
            ))
        }
        EngineScan::AskSoftConfirmDeliveryRows => {
            // PAST settled (`Closed`) delivery rows: the sweep's page reads
            // every row past ROW and serves none pending, twice (the second
            // read wraps past the cursor onto the same rows).
            let group = id(0x8a, 0);
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        ASK_DELIVERIES.put(
                            &vault.store,
                            wtxn,
                            &(group, id(0x8a, 1 + index)),
                            &crate::task_verb::TaskAskSoftConfirmDelivery::Closed,
                        )?;
                    }
                    Ok(())
                })
                .expect("seed");
            Some((
                0,
                Box::new(move || vault.retry_pending_ask_soft_confirms(PAST)),
            ))
        }
        EngineScan::OpenAskTaskRows => {
            // PAST TASK index rows with no bodies: the open-ask walk reads
            // every TASK row past ROW; each is unreadable, none is an ask.
            let actor = id(0x8a, 13);
            vault
                .put_entity(
                    &actor,
                    crate::registry::ENTITY_TYPE_PERSON,
                    crate::temporal::TimeRange { start: 1, end: 1 },
                    1,
                    b"actor",
                )
                .expect("seed");
            vault
                .with_write_txn(|wtxn| {
                    for index in 0..PAST {
                        let key = Store::encode_type_key(
                            crate::registry::ENTITY_TYPE_TASK,
                            &id(0x8a, 10 + index),
                        );
                        vault.store.type_index.put(wtxn, &key, &[])?;
                    }
                    Ok(())
                })
                .expect("seed");
            let person = id(0x8a, 14);
            Some((
                0,
                Box::new(move || {
                    let memory = vault.memory(actor, crate::edge::EdgeActorClass::Agent);
                    crate::human_task::open_asks_for(&memory, person)
                        .map(|asks| asks.asks.len())
                        .map_err(mem_err)
                }),
            ))
        }
        EngineScan::GuestDisclosureRefs => {
            // One guest ask disclosing PAST refs under a class whose guest
            // fact limit is ROW: admission observes every ref past that row,
            // and one member TASK answers, twice (replay).
            let (owner, spec) = guest_spec(vault, Some(u16::try_from(ROW).expect("class row")));
            vault
                .memory(owner, crate::edge::EdgeActorClass::Human)
                .tasks_ask(&spec)
                .map_err(mem_err)
                .expect("seed");
            Some((
                1,
                Box::new(move || {
                    vault
                        .memory(owner, crate::edge::EdgeActorClass::Human)
                        .tasks_ask(&spec)
                        .map(|receipt| receipt.task_refs.len())
                        .map_err(mem_err)
                }),
            ))
        }
        EngineScan::GuestGrantDisclosedRefs => {
            // One guest ask disclosing PAST refs: minting its guest grant
            // reads every disclosed ref past ROW, and one member TASK
            // answers, twice (replay). The disclosure count stays under its
            // default limit, so no second check parks.
            let (owner, spec) = guest_spec(vault, None);
            vault
                .memory(owner, crate::edge::EdgeActorClass::Human)
                .tasks_ask(&spec)
                .map_err(mem_err)
                .expect("seed");
            Some((
                1,
                Box::new(move || {
                    vault
                        .memory(owner, crate::edge::EdgeActorClass::Human)
                        .tasks_ask(&spec)
                        .map(|receipt| receipt.task_refs.len())
                        .map_err(mem_err)
                }),
            ))
        }
        EngineScan::AttendeeIdentityCandidates | EngineScan::AttendeeIdentityKeyBytes => {
            // One first entry offers PAST candidates on 3-byte session/speaker
            // keys: both dimensions cross ROW, and its identity ask stays pending.
            let event = attendee_event();
            vault
                .with_write_txn(|wtxn| {
                    crate::task_verb::admit_attendee_entry_in_txn(
                        vault,
                        wtxn,
                        id(0x8a, 33),
                        &event,
                    )?;
                    Ok(())
                })
                .expect("seed");
            Some((
                1,
                Box::new(move || {
                    vault.with_write_txn(|wtxn| {
                        let admission = crate::task_verb::admit_attendee_entry_in_txn(
                            vault,
                            wtxn,
                            id(0x8a, 33),
                            &event,
                        )?;
                        Ok(usize::from(admission.ask_pending))
                    })
                }),
            ))
        }
        EngineScan::TaskPostIntentKeyBytes => {
            // One TASK post under a 3-byte caller intent key: the post
            // observes the key's bytes past ROW; replays answer idempotent.
            let owner = vault
                .ensure_embedded_owner_actor()
                .map_err(mem_err)
                .expect("owner");
            let post: crate::task_verb::TaskPost = serde_json::from_value(serde_json::json!({
                "intent_key": "key",
                "assignee": "dreamer",
                "brief": {
                    "schema": 1,
                    "type_ref": {"node_id": EntityId::now().to_hex(), "tree_version": 1},
                    "objective": "Tidy the tide log",
                    "intent": {"need": "Tidy the tide log", "care": "light"},
                    "success": {
                        "question": "Is the tide log tidy?",
                        "criteria": {"yes_if_all": [{"text": "The duplicate dawn readings are merged."}]},
                    },
                    "escalation": {
                        "to": {"people": [owner.to_hex()]},
                        "triggers": [],
                        "default": "proceed",
                        "reversibility": "reversible_read",
                    },
                },
            }))
            .expect("post");
            vault
                .memory(owner, crate::edge::EdgeActorClass::Human)
                .tasks_post(post.clone())
                .map_err(mem_err)
                .expect("seed");
            Some((
                1,
                Box::new(move || {
                    vault
                        .memory(owner, crate::edge::EdgeActorClass::Human)
                        .tasks_post(post.clone())
                        .map(|receipt| usize::from(receipt.idempotent_replay))
                        .map_err(mem_err)
                }),
            ))
        }
        EngineScan::CommWidenAncestorRows => {
            // Four agent dispatches in one parent chain: the child's reach
            // walk reads its PAST ancestors past ROW; all keep Parent reach.
            let input = comm_input();
            let encoded =
                crate::agent_dispatch::encode_agent_dispatch_input(&input).expect("input");
            let queue = crate::attempt_queue::AttemptQueue::new(vault);
            let mut parent = None;
            let mut child = None;
            for _ in 0..=PAST {
                let payload = crate::store::dreamer_attempt_payload::DreamerAttemptPayload {
                    attempt_type: crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
                    input: encoded.clone(),
                    parent_attempt: parent,
                };
                let bytes = crate::dreamer_runner::encode_dreamer_attempt_payload(&payload)
                    .expect("payload");
                let outcome = queue
                    .enqueue(crate::attempt_queue::EnqueueAttempt {
                        kind: crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
                        payload: bytes,
                        dedupe_key: None,
                        run_id: None,
                        now: LEARNED_AT,
                    })
                    .expect("enqueue");
                let crate::attempt_queue::EnqueueOutcome::Enqueued(record) = outcome else {
                    panic!("a keyless enqueue never dedupes");
                };
                parent = Some(record.id);
                child = Some(record.id);
            }
            let child = child.expect("four attempts");
            Some((
                0,
                Box::new(move || {
                    let txn = vault.store.env.read_txn()?;
                    let reach =
                        crate::agent_dispatch::effective_comm_in_txn(vault, &txn, child, &input)?;
                    Ok(reach as usize)
                }),
            ))
        }
        other => unreachable!("{} is seeded in another module", other.code()),
    }
}

/// This file's view of the room-turn table (rooms keeps its own private).
fn rv_turns() -> crate::side_table::SideTable<
    crate::EntityId,
    crate::workspace_roster::RoomTurn,
    crate::side_table::LegacyJson,
> {
    crate::side_table::SideTable::new(&crate::side_table::ROOMS_TURN)
}

/// This file's view of the parent-to-child thread index.
fn rv_children() -> crate::side_table::SideTable<
    (crate::EntityId, crate::EntityId, crate::EntityId),
    crate::EntityId,
    crate::side_table::Raw,
> {
    crate::side_table::SideTable::new(&crate::side_table::ROOMS_THREAD_CHILDREN)
}

fn rr_claims() -> crate::side_table::SideTable<
    EntityId,
    crate::workspace_roster::RoomClaimReceipt,
    crate::side_table::LegacyJson,
> {
    crate::side_table::SideTable::new(&crate::side_table::ROOMS_CLAIM)
}

fn rr_response() -> crate::side_table::SideTable<EntityId, EntityId, crate::side_table::Raw> {
    crate::side_table::SideTable::new(&crate::side_table::ROOMS_RESPONSE)
}

/// One room-turn row; the actor is the turn itself, which these reads never check.
fn rv_room_turn(
    id: crate::EntityId,
    room: crate::EntityId,
    reply_to: Option<crate::EntityId>,
    thread_of: Option<crate::EntityId>,
    at: u64,
) -> crate::workspace_roster::RoomTurn {
    crate::workspace_roster::RoomTurn {
        turn_id: id.to_hex(),
        room_id: room.to_hex(),
        actor: id.to_hex(),
        addressed_agents: std::collections::BTreeSet::new(),
        message_ids: Vec::new(),
        reply_to: reply_to.map(|r| r.to_hex()),
        thread_of: thread_of.map(|t| t.to_hex()),
        at,
        task_ids: Vec::new(),
        converted_project: None,
        quotes: std::collections::BTreeMap::new(),
    }
}

/// A project room owned by a fresh PERSON with an unrestricted `core:read`
/// grant for that owner; returns `(owner, room)`.
fn rv_project_room(vault: &Vault, owner_idx: usize, proj_idx: usize) -> (EntityId, EntityId) {
    let owner = id(0x88, owner_idx);
    vault
        .put_entity(
            &owner,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .expect("owner");
    let root = vault.root_project().expect("root");
    let project = id(0x88, proj_idx);
    let record = crate::workspace_roster::ProjectRecord::new(project, Some(root), root, owner)
        .expect("record");
    vault.put_project(project, &record, 1).expect("project");
    let room = crate::EntityId::from_hex(&record.home_room).expect("room");
    let scope = crate::federation::scope_codec::read_preset();
    let grant = rmpv::Value::Map(vec![
        ("actor_ref".into(), owner.to_hex().into()),
        ("effector".into(), "core:read".into()),
        (
            "scope".into(),
            crate::federation::scope_codec::encode_scope_value(&scope).expect("scope"),
        ),
        ("receipt_required".into(), false.into()),
    ]);
    let manifest =
        crate::gate::default_policy_manifest_with_scoped_grants(vec![grant]).expect("manifest");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().expect("manifest id"),
        &manifest,
    )
    .expect("grant");
    (owner, room)
}

/// Raw stored-entity bytes: the test header (occurred 1..1, learned 1) plus `body`.
fn vis_record(entity_type: u8, body: &[u8]) -> Vec<u8> {
    crate::test_util::entity_record(
        entity_type,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        1,
        body,
    )
}

/// Plants one entity row in the caller's write transaction.
fn vis_plant(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<()> {
    vault
        .store
        .entities
        .put(wtxn, id.as_bytes(), &vis_record(entity_type, body))?;
    Ok(())
}

/// Plants a 3-record `ChildOf` chain `leaf -> mid -> room` (bodies
/// `leaf`/`mid`/`room`) and returns `(leaf, mid, room)`.
fn vis_ancestry_chain(vault: &Vault, base: usize) -> (EntityId, EntityId, EntityId) {
    let (leaf, mid, room) = (id(0x89, base), id(0x89, base + 1), id(0x89, base + 2));
    vault
        .with_write_txn(|wtxn| {
            vis_plant(
                vault,
                wtxn,
                leaf,
                crate::registry::ENTITY_TYPE_PERSON,
                b"leaf",
            )?;
            vis_plant(
                vault,
                wtxn,
                mid,
                crate::registry::ENTITY_TYPE_PERSON,
                b"mid",
            )?;
            vis_plant(
                vault,
                wtxn,
                room,
                crate::registry::ENTITY_TYPE_CONVERSATION,
                b"room",
            )?;
            for (child, parent) in [(leaf, mid), (mid, room)] {
                let key = Store::encode_edge_key(&child, EdgeKind::ChildOf, &parent);
                vault.store.edges_out.put(wtxn, &key, &edge_value())?;
            }
            Ok(())
        })
        .expect("ancestry chain");
    (leaf, mid, room)
}

/// A `conversation.summary` claim body about `subject` covering `covers`.
fn vis_cover_claim(subject: EntityId, covers: &[EntityId]) -> Vec<u8> {
    let body = crate::ClaimBody::new(
        "conversation.summary",
        crate::ClaimSubject::Entity(subject),
        rmpv::Value::Map(vec![(
            "covers".into(),
            rmpv::Value::Array(
                covers
                    .iter()
                    .map(|covered| rmpv::Value::Binary(covered.as_bytes().to_vec()))
                    .collect(),
            ),
        )]),
        1.0,
        crate::ClaimApprovalStatus::Auto,
        crate::ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    crate::claim::encode_claim_body(&body).expect("claim encode")
}

/// One room-policy `delegate` row allowing `role`.
fn vis_policy_row(role: &str) -> rmpv::Value {
    rmpv::Value::Map(vec![
        ("action".into(), "delegate".into()),
        ("roles".into(), rmpv::Value::Array(vec![role.into()])),
        ("allow".into(), true.into()),
        ("precedence".into(), "nested_narrowing".into()),
    ])
}

/// One room-thread holder row for `actor` with the shipped base settings.
fn vis_holder_row(actor: EntityId) -> rmpv::Value {
    rmpv::Value::Map(vec![
        ("actor_ref".into(), actor.to_hex().into()),
        (
            "settings".into(),
            rmpv::Value::Map(vec![
                ("fresh_for_secs".into(), (7 * 86_400u64).into()),
                ("rows_per_list".into(), 8u64.into()),
                ("tokens_per_list".into(), 512u64.into()),
                ("fill".into(), "stage".into()),
                ("waits_per_thread".into(), 8u64.into()),
            ]),
        ),
    ])
}

/// The shipped policy manifest as mutable map entries.
fn vis_default_manifest_entries() -> Vec<(rmpv::Value, rmpv::Value)> {
    let shipped = crate::gate::default_policy_manifest().expect("default manifest");
    match rmpv::decode::read_value(&mut shipped.as_slice()).expect("decode default") {
        rmpv::Value::Map(entries) => entries,
        _ => panic!("default policy manifest is not a map"),
    }
}

/// A facade error as the table test's error: reads return `Result<usize>`.
fn mem_err(error: crate::memory::MemoryError) -> crate::Error {
    crate::Error::InvalidConfig(error.to_string())
}

/// The soft-confirm delivery table, bound here as its owner module binds it.
const ASK_DELIVERIES: crate::side_table::SideTable<
    (EntityId, EntityId),
    crate::task_verb::TaskAskSoftConfirmDelivery,
    crate::side_table::Named,
> = crate::side_table::SideTable::new(&crate::side_table::TASK_ASK_SOFT_CONFIRM_DELIVERY);

/// One guest ask spec over `PAST` question refs (one reference plus two
/// context refs), with an owner-stamped disclosure grant covering all three.
/// `class_limit` becomes the spec class's `guest_fact_limit`, or no class.
fn guest_spec(
    vault: &Vault,
    class_limit: Option<u16>,
) -> (EntityId, crate::task_verb::TaskAskSpec) {
    use crate::task_verb::{
        ConsultPayloadRef, TaskAskClass, TaskAskDecide, TaskAskDefault, TaskAskElectorate,
        TaskAskGuest, TaskAskOption, TaskAskOptionId, TaskAskQuestion, TaskAskSpec, TaskAskTarget,
    };
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let person = id(0x8a, 20);
    let companion = id(0x8a, 21);
    for actor in [person, companion] {
        vault
            .put_entity(
                &actor,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .expect("person");
    }
    // Recorded disclosure does not grant either recipient its own record read.
    crate::test_util::authorize_readers(vault, &[&person.to_hex(), &companion.to_hex()]);
    let questions: Vec<EntityId> = (0..PAST).map(|index| id(0x8a, 22 + index)).collect();
    for question in &questions {
        let body =
            rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))
                .expect("question body");
        vault
            .put_entity(
                question,
                crate::registry::ENTITY_TYPE_TURN,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                &body,
            )
            .expect("question");
    }
    let auth = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("auth");
    let bound = crate::consent::GrantBound::disclosure(
        crate::consent::AudienceBound::new([owner.to_hex(), person.to_hex()]).expect("audience"),
        crate::consent::DisclosureClass::new("meeting").expect("class"),
        crate::consent::DisclosureEnvelope::new(questions.iter().map(|id| id.to_hex()))
            .expect("envelope"),
    )
    .expect("bound");
    let guest = TaskAskGuest {
        companion_ref: companion,
        disclosure_grant_ref: bound.digest().to_hex(),
        holder_key: None,
    };
    vault.create_standing_grant(&auth, bound).expect("grant");
    let yes = TaskAskOptionId::new("yes").expect("yes");
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(questions[0]));
    what.options = [
        (yes.clone(), TaskAskOption::new("same display text")),
        (
            TaskAskOptionId::new("no").expect("no"),
            TaskAskOption::new("same display text"),
        ),
    ]
    .into();
    what.context_refs = vec![
        ConsultPayloadRef::Turn(questions[1]),
        ConsultPayloadRef::Turn(questions[2]),
    ];
    what.class_key = Some("meeting".to_owned());
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::Guests([(person, guest)].into())),
        what,
        None,
        TaskAskDefault::Hold,
    );
    spec.decide = Some(TaskAskDecide::AtLeast {
        count: 1,
        of: TaskAskElectorate::Any,
        answer: yes,
    });
    if let Some(limit) = class_limit {
        spec.class = Some(TaskAskClass {
            key: "meeting".to_owned(),
            version: 7,
            governance: false,
            deadline_seconds: 100,
            allowed_recipients: [person].into(),
            required_people: [person].into(),
            minimum_responses: 1,
            required_sources: Default::default(),
            decision: None,
            disclosure: [(
                person,
                questions
                    .iter()
                    .copied()
                    .map(ConsultPayloadRef::Turn)
                    .collect(),
            )]
            .into(),
            fallback: [TaskAskDefault::Hold].into(),
            guest_fact_limit: Some(limit),
            soft_confirm_surface: None,
            remind: vec![20, 40],
        });
    }
    (owner, spec)
}

/// One unplaced speaker's first-entry event: `PAST` identity candidates and
/// 3-byte session/speaker keys.
fn attendee_event() -> crate::conversation::ContainerAttendeeEvent {
    crate::conversation::ContainerAttendeeEvent {
        container: id(0x8a, 34),
        attendee: crate::conversation::ContainerAttendee::Speaker {
            session_key: "ses".to_owned(),
            speaker_key: "spk".to_owned(),
        },
        roster_revision: 1,
        trigger_turn: None,
        candidates: (0..PAST).map(|index| id(0x8a, 30 + index)).collect(),
        until: LEARNED_AT,
        history: crate::conversation::HistoryChoice::Inherit,
    }
}

/// One frozen worker dispatch input, as the dispatch tests build it.
fn comm_input() -> crate::agent_dispatch::AgentDispatchInput {
    let definition = crate::agent_def::AgentDefinition::new(
        "oneiron.agent.custom",
        "Comm widen fixture",
        "1.0.0",
        Some("You are a comm fixture.".to_owned()),
        vec![crate::skill::SkillDependency::new("oneiron.skill.search")],
        vec!["web.search".to_owned()],
        Vec::new(),
        None,
        crate::agent_def::AgentScope::All,
        crate::agent_def::AgentCeiling::Proposed,
        None,
        crate::claim::ClaimApprovalStatus::Approved,
        crate::claim::ClaimLifecycleStatus::Active,
        crate::claim::ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("test"),
        )]),
        None,
        true,
        None,
    );
    crate::agent_dispatch::AgentDispatchInput::frozen(
        crate::agent_dispatch::AgentDispatchTarget::Custom(id(0x8a, 40)),
        definition,
    )
}
