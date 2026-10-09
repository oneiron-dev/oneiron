#[test]
fn recall_returns_versioned_pack_with_provenance() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x1D);
    let facade = facade_for(&vault, actor);

    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x1E; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "aurora borealis sighting over the fjord",
            )],
            occurred_at: 1500,
        })
        .expect("witness");

    for effort in [Effort::Light, Effort::Medium] {
        let pack = facade
            .recall("aurora", effort, &RecallScope::default(), 10, None, None)
            .expect("recall");
        assert_eq!(pack.pack_version, 1);
        assert!(!pack.items.is_empty(), "{effort:?} finds the message");
        for item in &pack.items {
            assert!(!item.provenance.source.is_empty());
            assert!(!item.provenance.source_revision_ids.is_empty());
            assert!(!item.hedge_bucket.is_empty());
        }
        assert_eq!(pack.retrieval_meta.sparse, Some(true));
        assert!(pack.retrieval_meta.deep_pending.is_none());
        assert!(pack.retrieval_meta.total_candidates >= 1);
    }

    // MESSAGE items carry their TURN as structural evidence.
    let pack = facade
        .recall(
            "aurora",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    let message_item = pack
        .items
        .iter()
        .find(|item| item.kind == "MESSAGE")
        .expect("message item");
    assert!(!message_item.provenance.evidence_turn_ids.is_empty());
}

#[test]
fn recall_scope_honesty_lists_excluded_worlds() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x23);
    let facade = facade_for(&vault, actor);

    // The subject is MINTED through the structural door carrying its text
    // field, rather than pre-created and then overwritten: ONE-1889 made the
    // door create-only, and one create reaches the same state.
    let subject = EntityId::from_hex(
        &facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "atlantis explorer"}),
                text_fields: Some(vec![TextIndexField {
                    field: "name".to_owned(),
                    value: "atlantis explorer".to_owned(),
                }]),
                edges: None,
                occurred_at: 1600,
                learned_at: None,
            })
            .expect("subject text")
            .id_hex,
    )
    .expect("subject id");

    let world_one = EntityId::from_bytes([0x25; 16]).unwrap();
    let world_two = EntityId::from_bytes([0x26; 16]).unwrap();
    let mut input = claim_input(
        "profile.city",
        &subject,
        "user_stated",
        serde_json::json!("sunken city of gold"),
    );
    input.world_ref = Some(world_two.to_hex());
    let receipt = facade.claim_upsert(&input).expect("world claim");
    assert_eq!(receipt.approval, "auto");

    // Scoped to world ONE: world TWO is honestly reported as excluded and
    // its claim never appears in items (AC-4 narrowing).
    let pack = facade
        .recall(
            "atlantis",
            Effort::Medium,
            &RecallScope {
                world_ref: Some(world_one.to_hex()),
                facet: None,
            },
            10,
            None,
            None,
        )
        .expect("scoped recall");
    assert_eq!(
        pack.scope_honesty.out_of_scope_worlds,
        vec![world_two.to_hex()],
        "excluded world listed in scope honesty"
    );
    assert!(
        !pack
            .items
            .iter()
            .any(|item| item.world.as_deref() == Some(world_two.to_hex().as_str())),
        "out-of-world claim excluded from items"
    );

    // Unset scope reads base plus the actor's active world (ARCH-0022), never
    // every world. This actor holds no world grant, so world TWO stays out
    // and scope honesty names it.
    let floor = facade
        .recall(
            "atlantis",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("floor recall");
    assert_eq!(
        floor.scope_honesty.out_of_scope_worlds,
        vec![world_two.to_hex()]
    );
    assert!(
        !floor
            .items
            .iter()
            .any(|item| item.world.as_deref() == Some(world_two.to_hex().as_str()))
    );
}

/// ARCH-0022: outside a room, retrieval defaults to base plus the active
/// world. The active world is the actor's own DEFAULT-SUBSET inside its owner
/// grant; any world past it stays out of an unset recall.
#[test]
fn unset_recall_reads_base_plus_the_active_world() {
    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::pipeline::{
        PREDICATE_WORLD_ACCESS_ALLOWED_SET, PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
        WorldAuthoritySet, world_access_claim_body,
    };
    // Owner grants are critical writes; the legacy fixture lands them without
    // the confirm round trip this test is not about.
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let actor = put_person(&vault, 0x2A);
    let facade = facade_for(&vault, actor);
    let active = EntityId::from_bytes([0x2B; 16]).unwrap();
    let other = EntityId::from_bytes([0x2C; 16]).unwrap();
    for (world, text) in [
        (active, "harbor in the active story"),
        (other, "harbor elsewhere"),
    ] {
        let mut input = claim_input(
            "profile.city",
            &actor,
            "user_stated",
            serde_json::json!(text),
        );
        input.world_ref = Some(world.to_hex());
        facade.claim_upsert(&input).expect("world claim");
    }
    let home = claim_input(
        "note.topic",
        &actor,
        "user_stated",
        serde_json::json!("harbor at home"),
    );
    facade.claim_upsert(&home).expect("base claim");
    // A base claim beside them: base is listed as excluded only when the
    // actor's reading default drops it.
    let unset = || {
        facade
            .recall(
                "harbor",
                Effort::Light,
                &RecallScope::default(),
                10,
                None,
                None,
            )
            .expect("unset recall")
            .scope_honesty
            .out_of_scope_worlds
    };
    let mut both = vec![active.to_hex(), other.to_hex()];
    both.sort();
    assert_eq!(unset(), both, "no grant: base reality only");

    // A row about the actor that no owner granted governs nobody: the actor
    // still reads base reality, so the base claim is not listed as excluded.
    let stray = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        actor,
        &WorldAuthoritySet::new(false, [active]).unwrap(),
        ClaimSource::UserStated,
        ClaimApprovalStatus::Proposed,
        None,
        None,
    )
    .unwrap();
    vault
        .put_claim(
            &EntityId::from_bytes([0x2F; 16]).unwrap(),
            &stray,
            test_time(1),
            1,
        )
        .expect("proposed row");
    assert_eq!(unset(), both, "a proposed row leaves the actor ungoverned");

    let grant = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        actor,
        &WorldAuthoritySet::new(true, [active, other]).unwrap(),
        ClaimSource::UserStated,
        ClaimApprovalStatus::Approved,
        None,
        None,
    )
    .unwrap();
    vault
        .put_claim(
            &EntityId::from_bytes([0x2D; 16]).unwrap(),
            &grant,
            test_time(1),
            1,
        )
        .expect("owner grant");
    assert_eq!(unset(), both, "a grant without a default reads base");

    let mut default = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
        actor,
        &WorldAuthoritySet::new(true, [active]).unwrap(),
        ClaimSource::Inferred,
        ClaimApprovalStatus::Auto,
        None,
        None,
    )
    .unwrap();
    let envelope = crate::write_envelope::WriteEnvelope::new(
        crate::write_envelope::WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::Inferred,
        crate::write_envelope::WriteProvenance::new(rmpv::Value::from("active-world")).unwrap(),
        ClaimApprovalStatus::Auto,
    );
    default.evidence = Some(crate::write_envelope::write_envelope_evidence(
        &envelope, None,
    ));
    vault
        .put_claim(
            &EntityId::from_bytes([0x2E; 16]).unwrap(),
            &default,
            test_time(2),
            2,
        )
        .expect("actor default");
    assert_eq!(unset(), vec![other.to_hex()], "base plus the active world");
}

/// Greptile on #1312: a recall reads only the worlds it asked for in every
/// part of its pack, not only the ranked rows. At medium effort a base record
/// that mentions a claim in another world reaches that claim as a neighbour;
/// an unset recall, which reads base reality here, keeps it out of the pack
/// and its rendered text. Naming the world brings it back.
#[test]
fn recall_neighbours_stay_inside_the_asked_worlds() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x31);
    let facade = facade_for(&vault, actor);
    let elsewhere = EntityId::from_bytes([0x32; 16]).unwrap();
    let mut input = claim_input(
        "profile.city",
        &actor,
        "user_stated",
        serde_json::json!("sunken city of gold"),
    );
    input.world_ref = Some(elsewhere.to_hex());
    let claim = facade.claim_upsert(&input).expect("world claim");
    let claim_hex = facade
        .get_entity(&claim.claim_short_id)
        .expect("claim read")
        .value
        .expect("the actor reads its claim")
        .id_hex;
    facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "atlantis explorer"}),
            text_fields: Some(vec![TextIndexField {
                field: "name".to_owned(),
                value: "atlantis explorer".to_owned(),
            }]),
            edges: Some(vec![StructuralEdgeSpec {
                edge_kind: "mentions".to_owned(),
                target_ref: claim_hex,
                weight: Some(0.9),
            }]),
            occurred_at: 1700,
            learned_at: None,
        })
        .expect("base record");
    let rendered = |world_ref: Option<String>| {
        facade
            .recall(
                "atlantis",
                Effort::Medium,
                &RecallScope {
                    world_ref,
                    facet: None,
                },
                10,
                Some("md"),
                None,
            )
            .expect("recall")
            .rendered
            .expect("rendered pack")
    };
    let named = rendered(Some(elsewhere.to_hex()));
    assert!(named.contains("sunken city"), "{named}");
    let unset = rendered(None);
    assert!(unset.contains("atlantis"), "{unset}");
    assert!(!unset.contains("sunken city"), "{unset}");
}

#[test]
fn recall_deep_requires_lease_and_marks_pending() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x27);
    let facade = facade_for(&vault, actor);

    let err = facade
        .recall(
            "anything",
            Effort::High,
            &RecallScope::default(),
            5,
            None,
            None,
        )
        .expect_err("deep without lease");
    assert_eq!(err.code, MEMORY_CODE_LEASE_REQUIRED);

    let lease = crate::llm::BudgetLease::for_test("recall-spike");
    let error = facade
        .recall(
            "anything",
            Effort::High,
            &RecallScope::default(),
            5,
            None,
            Some(&lease),
        )
        .expect_err("paid tier without a prepared scorer must not execute a lower tier");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
}

#[test]
fn recall_and_query_verbs_respect_limits() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x28);
    let facade = facade_for(&vault, actor);

    // Seed limit + 3 matching docs (limit = 2).
    let messages = (0..5)
        .map(|i| witness_message(i, WitnessAuthor::User, &format!("pelican count {i}")))
        .collect();
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x29; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages,
            occurred_at: 1700,
        })
        .expect("witness");

    assert_eq!(facade.query_bm25("pelican", 2).expect("bm25").len(), 2);
    assert_eq!(
        facade
            .recall(
                "pelican",
                Effort::Light,
                &RecallScope::default(),
                2,
                None,
                None
            )
            .expect("recall")
            .items
            .len(),
        2
    );

    // Neighbors limit: an anchor with 5 outgoing edges returns exactly 2.
    let targets: Vec<String> = (0x30..0x35_u8)
        .map(|seed| put_person(&vault, seed).to_hex())
        .collect();
    let anchor = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({"name": "flock"}),
            text_fields: None,
            edges: Some(
                targets
                    .iter()
                    .map(|target| StructuralEdgeSpec {
                        edge_kind: "mentions".to_owned(),
                        target_ref: target.clone(),
                        weight: Some(0.7),
                    })
                    .collect(),
            ),
            occurred_at: 1701,
            learned_at: None,
        })
        .expect("anchor");
    assert_eq!(
        facade
            .neighbors(
                &anchor.id_hex,
                &NeighborOpts {
                    edge_kind: None,
                    min_weight: None,
                    limit: 2,
                },
            )
            .expect("neighbors")
            .len(),
        2
    );
}
