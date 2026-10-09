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
