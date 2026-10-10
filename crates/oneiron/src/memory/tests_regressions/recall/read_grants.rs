#[test]
fn actor_bound_recall_requires_its_read_grant_on_both_paths() {
    let (_dir, vault, _owner, scoped) = recall_after_control_writes_fixture(false);
    let facade = facade_for(&vault, scoped);
    let facet = EntityId::from_bytes([0x6c; 16]).unwrap();
    vault
        .put_entity(
            &facet,
            crate::registry::ENTITY_TYPE_FACET,
            crate::TimeRange {
                start: 1400,
                end: 1400,
            },
            1400,
            &rmp_serde::to_vec_named(&serde_json::json!({"name": "facet"})).unwrap(),
        )
        .unwrap();
    for scope in [
        RecallScope::default(),
        RecallScope {
            facet: Some(facet.to_hex()),
            ..Default::default()
        },
    ] {
        let recall = || {
            facade
                .recall("window seat", Effort::Light, &scope, 20, None, None)
                .unwrap()
        };
        assert!(
            !recall().items.iter().any(gives_control_message),
            "ungranted actor received the message"
        );
    }
    let grant_id = EntityId::from_bytes([0x6b; 16]).unwrap();
    let grant = vault.get_access_grant(&grant_id).unwrap().unwrap();
    vault
        .revoke_access_grant(&grant_id, crate::unix_seconds_now())
        .unwrap();
    vault
        .install_read_permit_for_test(crate::WriteActor::new(scoped, EdgeActorClass::Human))
        .unwrap();
    for scope in [
        RecallScope::default(),
        RecallScope {
            facet: Some(facet.to_hex()),
            ..Default::default()
        },
    ] {
        let pack = facade
            .recall("window seat", Effort::Light, &scope, 20, None, None)
            .unwrap();
        assert!(
            !pack.items.iter().any(gives_control_message),
            "policy permit alone admitted a message: {scope:?}"
        );
    }
    vault
        .create_access_grant(&EntityId::from_bytes([0x76; 16]).unwrap(), &grant)
        .unwrap();
    for scope in [
        RecallScope::default(),
        RecallScope {
            facet: Some(facet.to_hex()),
            ..Default::default()
        },
    ] {
        let pack = facade
            .recall("window seat", Effort::Light, &scope, 20, None, None)
            .unwrap();
        assert!(
            pack.items.iter().any(gives_control_message),
            "granted actor lost the message: {scope:?}"
        );
    }
}

#[test]
fn scoped_recall_hides_world_ids_without_claim_read_authority() {
    let (_dir, vault, owner, scoped) = recall_after_control_writes_fixture(false);
    let hidden = EntityId::from_bytes([0x7a; 16]).unwrap();
    let requested = EntityId::from_bytes([0x7b; 16]).unwrap();
    let mut input = claim_input(
        "profile.city",
        &owner,
        "user_stated",
        serde_json::json!("hidden world record"),
    );
    input.world_ref = Some(hidden.to_hex());
    facade_for(&vault, owner)
        .claim_upsert(&input)
        .expect("owner claim");
    let scope = RecallScope {
        world_ref: Some(requested.to_hex()),
        facet: None,
        kinds: None,
    };
    let owner_pack = facade_for(&vault, owner)
        .recall("hidden world record", Effort::Light, &scope, 10, None, None)
        .expect("owner recall");
    assert_eq!(
        owner_pack.scope_honesty.out_of_scope_worlds,
        vec![hidden.to_hex()]
    );
    let denied = facade_for(&vault, scoped)
        .recall("hidden world record", Effort::Light, &scope, 10, None, None)
        .expect("scoped recall");
    assert!(denied.items.is_empty());
    assert!(denied.scope_honesty.out_of_scope_worlds.is_empty());

    vault
        .install_read_permit_for_test(crate::WriteActor::new(scoped, EdgeActorClass::Human))
        .expect("scoped claim read permit");
    let admitted = facade_for(&vault, scoped)
        .recall("hidden world record", Effort::Light, &scope, 10, None, None)
        .expect("permitted recall");
    assert_eq!(
        admitted.scope_honesty.out_of_scope_worlds,
        vec![hidden.to_hex()]
    );
}

#[test]
fn scoped_recall_never_renders_an_unreadable_edge_neighbor() {
    let (_dir, vault) = open_vault();
    let writer = put_person(&vault, 0x72);
    let scoped = put_person(&vault, 0x73);
    let facade = facade_for(&vault, writer);
    let anchor = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".into(),
            body: serde_json::json!({"name": "anchorforprivateedge"}),
            text_fields: Some(vec![TextIndexField {
                field: "name".into(),
                value: "anchorforprivateedge".into(),
            }]),
            edges: None,
            occurred_at: 1,
            learned_at: None,
        })
        .unwrap();
    let mut message = witness_message(0, WitnessAuthor::User, "private edge neighbor payload");
    message.metadata = Some(serde_json::json!({
        "rel": EntityId::from_bytes([0x74; 16]).unwrap().to_hex()
    }));
    let hidden = facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x75; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![message],
            occurred_at: crate::unix_seconds_now(),
        })
        .unwrap();
    let hidden = EntityId::from_hex(
        &facade
            .get_entity(&hidden.message_short_ids[0])
            .unwrap()
            .value
            .unwrap()
            .id_hex,
    )
    .unwrap();
    vault
        .batch()
        .edge(
            &EntityId::from_hex(&anchor.id_hex).unwrap(),
            crate::EdgeKind::Mentions,
            &hidden,
            1.0,
        )
        .commit()
        .unwrap();
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"private edge recall").unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    vault
        .install_read_permit_for_test(crate::WriteActor::new(scoped, EdgeActorClass::Human))
        .unwrap();
    let pack = facade_for(&vault, scoped)
        .recall(
            "anchorforprivateedge",
            Effort::Medium,
            &RecallScope::default(),
            10,
            Some("json"),
            None,
        )
        .unwrap();
    assert!(
        pack.items
            .iter()
            .any(|item| item.value_text.contains("anchorforprivateedge"))
    );
    assert!(
        pack.items
            .iter()
            .all(|item| !item.value_text.contains("private edge neighbor payload"))
    );
    assert!(
        !pack
            .rendered
            .as_deref()
            .unwrap_or_default()
            .contains("private edge neighbor payload")
    );
}

#[test]
fn scoped_recall_provenance_does_not_name_a_denied_supersedes_target() {
    let (_dir, vault, owner, scoped) = recall_after_control_writes_fixture(true);
    let mut allowed = witness_message(0, WitnessAuthor::User, "scoped provenance anchor");
    allowed.metadata = Some(serde_json::json!({
        "rel": EntityId::from_bytes([0x68; 16]).unwrap().to_hex()
    }));
    let anchor = facade_for(&vault, owner)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x7e; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![allowed],
            occurred_at: crate::unix_seconds_now(),
        })
        .expect("allowed witness");
    let anchor_id = EntityId::from_hex(
        &facade_for(&vault, owner)
            .get_entity(&anchor.message_short_ids[0])
            .unwrap()
            .value
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let hidden_space = EntityId::from_bytes([0x7c; 16]).unwrap();
    let mut message = witness_message(0, WitnessAuthor::User, "denied provenance body");
    message.metadata = Some(serde_json::json!({"rel": hidden_space.to_hex()}));
    let receipt = facade_for(&vault, owner)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x7d; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![message],
            occurred_at: crate::unix_seconds_now(),
        })
        .expect("hidden witness");
    let target = EntityId::from_hex(
        &facade_for(&vault, owner)
            .get_entity(&receipt.message_short_ids[0])
            .unwrap()
            .value
            .unwrap()
            .id_hex,
    )
    .unwrap();
    vault
        .batch()
        .edge(&anchor_id, crate::EdgeKind::Supersedes, &target, 1.0)
        .commit()
        .expect("provenance edge");
    let facet = EntityId::from_bytes([0x7f; 16]).unwrap();
    vault
        .put_entity(
            &facet,
            crate::registry::ENTITY_TYPE_FACET,
            crate::TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({"name": "facet"})).unwrap(),
        )
        .unwrap();
    // The message's own item carries its provenance: a scope that names
    // MESSAGE keeps it from returning as its turn.
    let messages = Some(vec!["MESSAGE".to_owned()]);
    for scope in [
        RecallScope {
            kinds: messages.clone(),
            ..Default::default()
        },
        RecallScope {
            facet: Some(facet.to_hex()),
            kinds: messages,
            ..Default::default()
        },
    ] {
        let pack = facade_for(&vault, scoped)
            .recall(
                "scoped provenance anchor",
                Effort::Light,
                &scope,
                10,
                None,
                None,
            )
            .expect("scoped recall");
        let item = pack
            .items
            .iter()
            .find(|item| item.value_text.contains("scoped provenance anchor"))
            .unwrap_or_else(|| panic!("readable anchor in {scope:?}: {:?}", pack.items));
        assert_eq!(
            item.provenance.source_revision_ids,
            vec![anchor_id.to_hex()],
            "{scope:?}"
        );
        assert!(
            !item
                .provenance
                .source_revision_ids
                .contains(&target.to_hex()),
            "{scope:?}"
        );
    }
}

#[test]
fn scoped_recall_rechecks_a_grant_revoked_during_retrieval() {
    use std::sync::Arc;

    let (_dir, vault, _owner, scoped) = recall_after_control_writes_fixture(true);
    let vault = Arc::new(vault);
    let writer = Arc::clone(&vault);
    *vault.test_hooks().after_retrieval_text.lock().unwrap() = Some(Box::new(move || {
        let writer = Arc::clone(&writer);
        std::thread::spawn(move || {
            writer
                .revoke_access_grant(
                    &EntityId::from_bytes([0x6b; 16]).unwrap(),
                    crate::unix_seconds_now(),
                )
                .unwrap();
        })
        .join()
        .unwrap();
    }));
    let pack = facade_for(&vault, scoped)
        .recall(
            "window seat",
            Effort::Light,
            &RecallScope::default(),
            20,
            Some("json"),
            None,
        )
        .unwrap();
    assert!(!pack.items.iter().any(gives_control_message));
    assert!(
        !pack
            .rendered
            .as_deref()
            .unwrap_or_default()
            .contains("window seat control recall")
    );
}

/// Sol 9B #2 (P1): a TURN's text, and so its vector, is all its messages'.
/// A reader who may read the turn and one of its messages, but not the
/// other, never retrieves the turn: not by the withheld message's meaning
/// through the turn's vector, and not by the other message's words, which
/// come back as that message alone. The owner finds the turn both ways.
/// Bug repro: recall admitted the vector hit on the turn's own grants, so the
/// scoped reader's paraphrase of the withheld message found the turn.
#[test]
fn a_turn_reaches_a_scoped_reader_only_when_it_may_read_every_message() {
    const WITHHELD_MEANING: [f32; 4] = [0.0, 1.0, 0.0, 0.0];
    let (_dir, vault, owner, scoped) = recall_after_control_writes_fixture_in(
        true,
        crate::config::VaultConfig {
            embedding_model: Some("test/model@v1".to_owned()),
            dimensions: WITHHELD_MEANING.len(),
            ..crate::config::VaultConfig::default()
        },
    );
    let space = EntityId::from_bytes([0x68; 16]).unwrap();
    let mut granted = witness_message(0, WitnessAuthor::User, "harbor view table for two");
    granted.metadata = Some(serde_json::json!({"rel": space.to_hex()}));
    // No space: a message only its owner's grants admit.
    let withheld = witness_message(1, WitnessAuthor::User, "harbor locker code is 4471");
    let receipt = facade_for(&vault, owner)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x77; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![granted, withheld],
            occurred_at: crate::unix_seconds_now() - 28 * 86_400,
        })
        .expect("witness a turn of two messages");
    let turn = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("witness ref"),
    )
    .expect("turn id");
    fill_turn(&vault, &turn, &WITHHELD_MEANING);

    // A paraphrase of the withheld message, sharing no word with the turn.
    let by_meaning = |actor| {
        facade_for(&vault, actor)
            .recall_with_execution(
                "which digits open my storage box",
                Effort::Medium,
                &RecallScope::default(),
                20,
                None,
                None,
                &crate::retrieval_depth::RecallExecution {
                    embedding: Some(WITHHELD_MEANING.as_slice()),
                    ..Default::default()
                },
            )
            .expect("recall by meaning")
    };
    let owner_pack = by_meaning(owner);
    assert!(
        owner_pack
            .items
            .iter()
            .any(|item| item.kind == "TURN" && item.value_text.contains("4471")),
        "the owner finds the turn by its meaning: {:?}",
        owner_pack.items
    );
    let pack = by_meaning(scoped);
    assert!(
        pack.items.iter().all(|item| item.kind != "TURN"),
        "the withheld message's meaning finds its turn: {:?}",
        pack.items
    );

    let owner_pack = facade_for(&vault, owner)
        .recall(
            "harbor",
            Effort::Light,
            &RecallScope::default(),
            20,
            None,
            None,
        )
        .expect("owner recall");
    assert!(
        owner_pack
            .items
            .iter()
            .any(|item| item.kind == "TURN" && item.value_text.contains("4471")),
        "the owner reads the whole turn: {:?}",
        owner_pack.items
    );

    for effort in [Effort::Light, Effort::Medium] {
        for format in [Some("json"), Some("md")] {
            let pack = facade_for(&vault, scoped)
                .recall("harbor", effort, &RecallScope::default(), 20, format, None)
                .expect("scoped recall");
            assert!(
                pack.items
                    .iter()
                    .any(|item| item.kind == "MESSAGE"
                        && item.value_text == "harbor view table for two"),
                "{effort:?} returns the message it may read: {:?}",
                pack.items
            );
            for item in &pack.items {
                assert_ne!(item.kind, "TURN", "{effort:?}: {item:?}");
                assert!(!item.value_text.contains("4471"), "{effort:?}: {item:?}");
                assert!(
                    item.cited_messages
                        .iter()
                        .all(|message| !message.value_text.contains("4471")),
                    "{effort:?}: {item:?}"
                );
            }
            let rendered = pack.rendered.expect("rendered pack");
            // Light renders the minimal profile, which carries no content.
            if effort == Effort::Medium {
                assert!(rendered.contains("harbor view"), "{format:?}: {rendered}");
            }
            assert!(
                !rendered.contains("4471"),
                "{effort:?} {format:?}: {rendered}"
            );
        }
    }
}
