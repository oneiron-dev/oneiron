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

    // Medium is the SDKs' default recall effort; no vector makes it sparse.
    let pack = facade
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
    assert!(kinds.contains(&"MESSAGE"), "{kinds:?}");
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
fn recall_after_control_writes_fixture() -> (tempfile::TempDir, crate::Vault, EntityId, EntityId) {
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
    vault
        .install_read_permit_for_test(crate::WriteActor::new(scoped, EdgeActorClass::Human))
        .expect("scoped read permit");
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

fn assert_recall_after_control_writes_has_only_context(pack: &crate::memory::MemoryPack) {
    let kinds: Vec<&str> = pack.items.iter().map(|item| item.kind.as_str()).collect();
    assert!(
        kinds.contains(&"MESSAGE"),
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
        let (_dir, vault, owner, _scoped) = recall_after_control_writes_fixture();
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
        let (_dir, vault, _owner, scoped) = recall_after_control_writes_fixture();
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
            let (_dir, vault, _owner, _scoped) = recall_after_control_writes_fixture();
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
