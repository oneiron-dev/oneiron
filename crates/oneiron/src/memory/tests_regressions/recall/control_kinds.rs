/// ARCH-0002: AUTHORITY_LOG is a maintenance record with no short-id prefix,
/// so it never appears in a prompt-facing pack. A pairing appends a SlipMint
/// seconds before the recall, inside the effort's default now anchor, where
/// the temporal channel reaches it. Naming the kind still reaches it.
#[test]
fn recall_leaves_a_fresh_slip_mint_out_unless_the_kind_is_named() {
    use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
    use ed25519_dalek::{Signer, SigningKey};

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x64);
    let facade = facade_for(&vault, actor);
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x65; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "I prefer a window seat when I fly.",
            )],
            occurred_at: crate::unix_seconds_now() - 28 * 86_400,
        })
        .expect("witness");

    let issuer = crate::authority::HostSlipIssuer::from_secret(b"recall pairing secret").unwrap();
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let holder = SigningKey::from_bytes(&[0x66; 32]);
    let public = holder.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(&issuer, crate::federation::Scope::top(), 3_600)
        .expect("pairing link");
    let transcript =
        crate::authority::pairing_binding_transcript(&link.code, &public, "recall-holder").unwrap();
    vault
        .redeem_pairing_link(
            &issuer,
            &link.code,
            "recall-holder",
            public,
            &holder.sign(&transcript).to_bytes(),
        )
        .expect("pair");

    // This control-kind check uses the trusted local owner. The witness actor
    // above is not owner-bound after the authority root is established.
    let owner = vault.ensure_embedded_owner_actor().expect("local owner");
    // Medium is the SDKs' default recall effort; no vector makes it sparse.
    let pack = facade_for(&vault, owner)
        .recall(
            "window seat",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    let kinds: Vec<&str> = pack.items.iter().map(|item| item.kind.as_str()).collect();
    assert_eq!(pack.retrieval_meta.sparse, Some(true));
    // The message comes back as its turn (ARCH-0004).
    assert!(kinds.contains(&"TURN"), "{kinds:?}");
    assert!(!kinds.contains(&"AUTHORITY_LOG"), "{kinds:?}");

    // The caller's own kind filter names it.
    let named = vault
        .context_pack()
        .search_text("window seat", 10)
        .limit(10)
        .retrieval_effort(Effort::Medium, &[])
        .filter_types(&[ENTITY_TYPE_AUTHORITY_LOG])
        .run()
        .expect("named pack");
    assert!(!named.results.is_empty());
    assert!(
        named
            .results
            .iter()
            .all(|entity| entity.entity_type == ENTITY_TYPE_AUTHORITY_LOG)
    );

    // So does an authority filter that lists it.
    let floor =
        crate::gate::resolve_policy_manifest(&vault.store, &vault.store.env.read_txn().unwrap())
            .unwrap()
            .retrieval_floor_for_actor(None);
    let filter = crate::gate::narrow_retrieval_filter(
        &floor,
        Some(&crate::gate::RetrievalFilter {
            entity_types: Some([ENTITY_TYPE_AUTHORITY_LOG].into()),
            ..Default::default()
        }),
    )
    .unwrap();
    let hits = vault
        .query()
        .search_text("window seat", 10)
        .limit(10)
        .retrieval_effort(Effort::Medium, &[])
        .authority_filter(filter)
        .run()
        .expect("named query");
    assert!(!hits.is_empty());
}

/// A fresh fixture per retrieval keeps all four control operations immediately
/// before that retrieval (the policy test door only accepts the stock manifest).
fn recall_after_control_writes_fixture(
    grant_read: bool,
) -> (tempfile::TempDir, crate::Vault, EntityId, EntityId) {
    use crate::access_grant::{
        AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let (dir, vault) = open_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner person");
    let scoped = put_person(&vault, 0x67);
    let space = EntityId::from_bytes([0x68; 16]).unwrap();
    let mut message = witness_message(0, WitnessAuthor::User, "window seat control recall");
    message.metadata = Some(serde_json::json!({"rel": space.to_hex()}));
    facade_for(&vault, owner)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x69; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![message],
            occurred_at: crate::unix_seconds_now() - 28 * 86_400,
        })
        .expect("witness message");

    let issuer = crate::authority::HostSlipIssuer::from_secret(b"control recall pairing secret")
        .expect("issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let holder = SigningKey::from_bytes(&[0x6a; 32]);
    let public = holder.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(&issuer, crate::federation::Scope::top(), 3_600)
        .expect("pairing link");
    let transcript =
        crate::authority::pairing_binding_transcript(&link.code, &public, "control-recall-holder")
            .expect("transcript");
    vault
        .redeem_pairing_link(
            &issuer,
            &link.code,
            "control-recall-holder",
            public,
            &holder.sign(&transcript).to_bytes(),
        )
        .expect("slip mint");
    vault.authority_fold().expect("authority log fold");
    if grant_read {
        vault
            .install_read_permit_for_test(crate::WriteActor::new(scoped, EdgeActorClass::Human))
            .expect("scoped read permit");
    }
    vault
        .create_access_grant(
            &EntityId::from_bytes([0x6b; 16]).unwrap(),
            &AccessGrant {
                authority_scope: crate::federation::scope_codec::read_preset(),
                principal_ref: scoped,
                scope: AccessGrantScope::Messages { space_ref: space },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: crate::unix_seconds_now(),
                revoked_at: None,
                expires_at: None,
            },
        )
        .expect("scoped message grant");
    (dir, vault, owner, scoped)
}

/// Whether a recall item hands its reader the control fixture's message: the
/// message itself, or a turn that holds or quotes its words.
fn gives_control_message(item: &crate::memory::MemoryItem) -> bool {
    const SAID: &str = "window seat control recall";
    item.kind == "MESSAGE"
        || item.value_text.contains(SAID)
        || item
            .cited_messages
            .iter()
            .any(|message| message.value_text.contains(SAID))
}

fn assert_recall_after_control_writes_has_only_context(pack: &crate::memory::MemoryPack) {
    let kinds: Vec<&str> = pack.items.iter().map(|item| item.kind.as_str()).collect();
    assert!(
        pack.items.iter().any(gives_control_message),
        "message remains readable: {kinds:?}"
    );
    for control in ["AUTHORITY_LOG", "POLICY_MANIFEST", "ACCESS_GRANT"] {
        assert!(
            !kinds.contains(&control),
            "{control} reached recall: {kinds:?}"
        );
    }
}

#[test]
fn owner_recall_after_control_writes_holds_no_control_kind() {
    for effort in [Effort::Medium, Effort::Light] {
        let (_dir, vault, owner, _scoped) = recall_after_control_writes_fixture(true);
        let pack = facade_for(&vault, owner)
            .recall(
                "window seat",
                effort,
                &RecallScope::default(),
                20,
                None,
                None,
            )
            .expect("owner recall");
        assert_recall_after_control_writes_has_only_context(&pack);
    }
}

#[test]
fn scoped_person_recall_after_control_writes_holds_no_control_kind() {
    for effort in [Effort::Medium, Effort::Light] {
        let (_dir, vault, _owner, scoped) = recall_after_control_writes_fixture(true);
        let pack = facade_for(&vault, scoped)
            .recall(
                "window seat",
                effort,
                &RecallScope::default(),
                20,
                None,
                None,
            )
            .expect("scoped recall");
        assert_recall_after_control_writes_has_only_context(&pack);
    }
}

#[test]
fn naming_a_control_kind_returns_it_to_a_caller_allowed_to_read_it() {
    use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_POLICY_MANIFEST};

    for effort in [Effort::Medium, Effort::Light] {
        for kind in [ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_ACCESS_GRANT] {
            let (_dir, vault, _owner, _scoped) = recall_after_control_writes_fixture(true);
            // The stock policy row retains its pinned timestamp 0 on rewrite;
            // explicit kind reach needs a candidate signal at that row's time.
            let anchor = if kind == ENTITY_TYPE_POLICY_MANIFEST {
                crate::gate::DEFAULT_POLICY_MANIFEST_TIMESTAMP
            } else {
                crate::unix_seconds_now()
            };
            let pack = vault
                .context_pack()
                .search_temporal(anchor, anchor, 20)
                .limit(20)
                .retrieval_effort(effort, &[])
                .filter_types(&[kind])
                .run()
                .expect("explicitly named control kind");
            assert!(!pack.results.is_empty(), "kind {kind} at {effort:?}");
            assert!(
                pack.results.iter().all(|row| row.entity_type == kind),
                "only the named kind may be returned: {kind} at {effort:?}"
            );
        }
    }
}

#[test]
fn unnamed_control_neighbor_stays_out_of_owner_and_scoped_recall() {
    use crate::access_grant::{
        AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    };

    let (_dir, vault) = open_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let scoped = put_person(&vault, 0x73);
    vault
        .install_read_permit_for_test(crate::WriteActor::new(scoped, EdgeActorClass::Human))
        .expect("scoped read permit");
    let anchor = facade_for(&vault, owner)
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({"name": "auditcontrolneighbor"}),
            text_fields: Some(vec![TextIndexField {
                field: "name".to_owned(),
                value: "auditcontrolneighbor".to_owned(),
            }]),
            edges: None,
            occurred_at: 1000,
            learned_at: None,
        })
        .expect("indexed event");
    let control = EntityId::from_bytes([0x71; 16]).unwrap();
    vault
        .create_access_grant(
            &control,
            &AccessGrant {
                authority_scope: crate::federation::Scope::top(),
                principal_ref: owner,
                scope: AccessGrantScope::Messages {
                    space_ref: EntityId::from_bytes([0x72; 16]).unwrap(),
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: 1000,
                revoked_at: None,
                expires_at: None,
            },
        )
        .expect("control row");
    let recall = |actor, effort| {
        facade_for(&vault, actor)
            .recall(
                "auditcontrolneighbor",
                effort,
                &RecallScope::default(),
                20,
                Some("json"),
                None,
            )
            .expect("ordinary recall")
    };
    let assert_no_control = |pack: crate::memory::MemoryPack| {
        assert!(pack.items.iter().any(|item| item.kind == "EVENT"));
        assert!(pack.items.iter().all(|item| item.kind != "ACCESS_GRANT"));
        let rendered: serde_json::Value =
            serde_json::from_str(pack.rendered.as_deref().expect("JSON rendering"))
                .expect("valid JSON");
        assert!(
            rendered.get("access_grants").is_none(),
            "unnamed grant reached rendered recall: {rendered}"
        );
    };
    assert_no_control(recall(owner, Effort::Medium)); // No edge: negative control.
    vault
        .batch()
        .edge(
            &EntityId::from_hex(&anchor.id_hex).unwrap(),
            EdgeKind::Mentions,
            &control,
            1.0,
        )
        .commit()
        .expect("context-to-control edge");
    assert_no_control(recall(owner, Effort::Light)); // No walk: negative control.
    assert_no_control(recall(owner, Effort::Medium));
    assert_no_control(recall(scoped, Effort::Medium));

    let pack = vault
        .context_pack()
        .search_text("auditcontrolneighbor", 20)
        .edge_hop(1)
        .run()
        .expect("ordinary context pack");
    assert!(
        pack.results
            .iter()
            .any(|entity| entity.entity_type == crate::registry::ENTITY_TYPE_EVENT)
    );
    assert!(pack.neighbors.iter().all(|entity| entity.id != control));
}
