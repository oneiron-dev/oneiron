//! Actor-authority and witness-pinning security regressions (review batch #471).

use super::*;

// ── security regressions (codex review of #471) ─────────────────────────

/// F5: the migrator pre-creates derived parents with the pinned
/// `{convex_id}` bodies via put_structural; witness create-or-get REUSES
/// them without any re-put, so the pinned bytes survive untouched.
#[test]
fn witness_reuses_migrator_pinned_parent_bodies_byte_identically() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x43);
    let facade = facade_for(&vault, actor);

    let conversation_hex = EntityId::from_bytes([0x44; 16]).unwrap().to_hex();
    let turn_hex = EntityId::from_bytes([0x45; 16]).unwrap().to_hex();
    facade
        .put_structural(&StructuralPutInput {
            id: Some(conversation_hex.clone()),
            kind: "CONVERSATION".to_owned(),
            body: serde_json::json!({"convex_id": "conv-11"}),
            text_fields: None,
            edges: None,
            occurred_at: 650,
            learned_at: None,
        })
        .expect("pinned conversation put");
    // ONE-1767: an append against an UNSTAMPED TURN is a bad request (no
    // legacy fallback), so the migrator-pinned body must already carry the
    // grouping speaker fact for witness to admit a same-speaker append — and
    // (second cycle) the append door also enforces the conversation binding,
    // so the pin carries the migrator's `child_of` parent edge alongside.
    facade
        .put_structural(&StructuralPutInput {
            id: Some(turn_hex.clone()),
            kind: "TURN".to_owned(),
            body: serde_json::json!({"convex_id": "turn-77", "speaker": "user"}),
            text_fields: None,
            edges: Some(vec![StructuralEdgeSpec {
                edge_kind: "child_of".to_owned(),
                target_ref: conversation_hex.clone(),
                weight: None,
            }]),
            occurred_at: 650,
            learned_at: None,
        })
        .expect("pinned turn put");
    let turn_id = EntityId::from_hex(&turn_hex).unwrap();
    let conversation_id = EntityId::from_hex(&conversation_hex).unwrap();
    let turn_raw = vault.get_raw(&turn_id).unwrap().expect("turn raw");
    let conversation_raw = vault
        .get_raw(&conversation_id)
        .unwrap()
        .expect("conversation raw");

    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: Some(turn_hex),
            messages: vec![witness_message(0, WitnessAuthor::User, "migrated row")],
            occurred_at: 651,
        })
        .expect("witness over pinned parents");

    // The pinned parent BODIES survive the append untouched; the TURN row is
    // re-put only to move `learned_at` forward (re-dirty), so its header
    // changes while its body bytes and occurred interval do not.
    let turn_after = vault.get_raw(&turn_id).unwrap().expect("turn after");
    let header_before = EntityMetadataHeader::parse(&turn_raw).expect("turn header before");
    let header_after = EntityMetadataHeader::parse(&turn_after).expect("turn header after");
    assert_eq!(
        &turn_after[ENTITY_METADATA_HEADER_LEN..],
        &turn_raw[ENTITY_METADATA_HEADER_LEN..],
        "pinned {{convex_id}} TURN body bytes must be identical after witness"
    );
    assert_eq!(
        (header_after.occurred_start, header_after.occurred_end),
        (header_before.occurred_start, header_before.occurred_end),
        "pinned TURN keeps its original occurred interval"
    );
    assert!(
        header_after.learned_at > header_before.learned_at,
        "the append re-dirties the pinned TURN: learned_at only moves forward"
    );
    assert_eq!(
        vault
            .get_raw(&conversation_id)
            .unwrap()
            .expect("conversation after"),
        conversation_raw,
        "pinned {{convex_id}} CONVERSATION body must be byte-identical after witness"
    );
}

/// F1: no non-owner actor can mint an actor-capable entity type. MACHINE
/// (the `system` class type) is never facade-writable; PERSON (rebindable
/// as human/agent) requires a verified human-class owner actor.
#[test]
fn put_structural_gates_actor_capable_kinds() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x46);
    let agent_person = put_person(&vault, 0x4E);
    let owner_facade = facade_for(&vault, owner);
    let agent_facade = vault.memory(agent_person, EdgeActorClass::Agent);

    let mint = |facade: &Memory<'_>, kind: &str| {
        facade.put_structural(&StructuralPutInput {
            id: None,
            kind: kind.to_owned(),
            body: serde_json::json!({"name": "candidate actor"}),
            text_fields: None,
            edges: None,
            occurred_at: 660,
            learned_at: None,
        })
    };

    // Every actor-capable kind is refused for an agent-bound actor.
    for kind in ["PERSON", "MACHINE"] {
        let err = mint(&agent_facade, kind)
            .expect_err("agent-bound actors must not mint actor-capable kinds");
        assert_eq!(err.code, MEMORY_CODE_FORBIDDEN, "kind {kind}");
        assert!(!err.suggestions.is_empty());
    }
    // MACHINE is refused even for the owner (engine-host provisioning).
    let err = mint(&owner_facade, "MACHINE").expect_err("MACHINE never facade-writable");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    // The verified owner may mint PERSON (design §2.3/§2.8 migrator door).
    mint(&owner_facade, "PERSON").expect("owner mints companion persona");
    // Non-actor kinds stay open to agents.
    mint(&agent_facade, "EVENT").expect("agents may write non-actor structural kinds");
}

/// F2: caller-asserted actor keys are resolved against the store before
/// any authority is granted — nonexistent ids and class/type mismatches
/// fail closed on every authority-bearing verb.
#[test]
fn asserted_actor_bindings_resolve_against_the_store() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x5A);
    let subject = put_person(&vault, 0x5B);
    let owner_facade = facade_for(&vault, owner);
    let claim = owner_facade
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("owner claim");
    let event = owner_facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({"name": "hanami"}),
            text_fields: None,
            edges: None,
            occurred_at: 670,
            learned_at: None,
        })
        .expect("event");

    // A nonexistent actor id gets NO authority from its asserted class.
    let ghost = EntityId::from_bytes([0x77; 16]).unwrap();
    let ghost_facade = facade_for(&vault, ghost);
    for err in [
        ghost_facade
            .claim_retract(&claim.claim_short_id)
            .expect_err("ghost retract"),
        ghost_facade
            .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
            .expect_err("ghost delete"),
        ghost_facade
            .witness(&WitnessTurn {
                conversation_ref: EntityId::from_bytes([0x78; 16]).unwrap().to_hex(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "x")],
                occurred_at: 671,
            })
            .expect_err("ghost witness"),
    ] {
        assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
        assert!(err.message.contains("does not exist"), "{}", err.message);
    }

    // An existing NON-PERSON entity asserted as human is a type mismatch.
    let event_id = EntityId::from_hex(&event.id_hex).unwrap();
    let mismatch_facade = facade_for(&vault, event_id);
    for err in [
        mismatch_facade
            .claim_retract(&claim.claim_short_id)
            .expect_err("mismatch retract"),
        mismatch_facade
            .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
            .expect_err("mismatch delete"),
    ] {
        assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
        assert!(
            err.message.contains("cannot act as class"),
            "{}",
            err.message
        );
    }

    // Bind-time verification: asActor keys hit the same store truth.
    let err =
        parse_actor_key(&vault, &format!("human:{}", ghost.to_hex())).expect_err("ghost bind");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    let err = parse_actor_key(&vault, &format!("system:{}", owner.to_hex()))
        .expect_err("PERSON cannot bind as system");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
}

/// F3: a commit is one transaction — a write that fails validation after
/// the gate leaves NO phantom decision behind.
#[test]
fn failed_commit_leaves_no_phantom_gate_decision() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x5C);
    let facade = facade_for(&vault, actor);

    let claim_id = EntityId::from_bytes([0x5D; 16]).unwrap();
    let missing_subject = EntityId::from_bytes([0x5E; 16]).unwrap();
    let mut input = claim_input(
        "profile.name",
        &missing_subject,
        "user_stated",
        serde_json::json!("Nobody"),
    );
    input.id = Some(claim_id.to_hex());
    let receipts = facade.commit(&[input]).expect("commit batch");
    assert_eq!(receipts[0].approval, "rejected");

    assert!(
        vault.get_claim(&claim_id).expect("read back").is_none(),
        "rejected element must not persist"
    );
    assert!(
        !facade
            .receipts(100)
            .expect("receipts")
            .iter()
            .any(|r| r.claim_ref.as_deref() == Some(claim_id.to_hex().as_str())),
        "no phantom gate decision for a write that never happened"
    );
}

/// F2: retraction authority — agents may retract only their own writes;
/// deletion is an owner (human-class) verb outright.
#[test]
fn retract_and_delete_enforce_actor_authority() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x47);
    let agent_person = put_person(&vault, 0x48);
    let subject = put_person(&vault, 0x49);
    let owner_facade = facade_for(&vault, owner);
    let agent_facade = vault.memory(agent_person, EdgeActorClass::Agent);

    // Owner writes a claim; a foreign agent may NOT retract it.
    let owner_claim = owner_facade
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("owner claim");
    let err = agent_facade
        .claim_retract(&owner_claim.claim_short_id)
        .expect_err("cross-actor retract must be denied");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    assert!(!err.suggestions.is_empty());

    // The agent CAN retract its own write. The writer here is the
    // first-party eiri agent (the one agent ref the default manifest
    // grants an auto ceiling) so its claim lands auto — a proposed claim
    // parks a pending consent, and the engine refuses body rewrites while
    // consent is parked (GateConsentStale), which is consent-queue
    // machinery, not retraction authority.
    let first_party_agent = EntityId::from_hex(&crate::gate::first_party_connector_actor_ref())
        .expect("first-party agent id");
    vault
        .put_entity(
            &first_party_agent,
            ENTITY_TYPE_PERSON,
            test_time(1),
            1,
            b"eiri agent",
        )
        .expect("put eiri agent");
    let eiri_facade = vault.memory(first_party_agent, EdgeActorClass::Agent);
    let mut agent_input = claim_input(
        "profile.mood",
        &subject,
        "observed",
        serde_json::json!("curious"),
    );
    agent_input.occurred_at = Some(120);
    agent_input.learned_at = Some(120);
    let agent_claim = eiri_facade.claim_upsert(&agent_input).expect("agent claim");
    assert_eq!(agent_claim.approval, "auto");
    let err = agent_facade
        .claim_retract(&agent_claim.claim_short_id)
        .expect_err("a DIFFERENT agent may not retract it");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    eiri_facade
        .claim_retract(&agent_claim.claim_short_id)
        .expect("agent retracts its own write");

    // The human owner can retract anything (here: nothing left active from
    // the agent, so retract the owner claim to prove the owner path).
    owner_facade
        .claim_retract(&owner_claim.claim_short_id)
        .expect("owner retracts");

    // Deletion is an owner verb: agents are denied regardless of target.
    let target = put_person(&vault, 0x4A);
    let err = agent_facade
        .safe_delete(&target.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("agent delete must be denied");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        vault.get_raw(&target).expect("read target").is_some(),
        "a denied deletion must not start a tombstone or scrub"
    );
    let receipt = owner_facade
        .safe_delete(&target.to_hex(), SafeDeleteReason::UserDelete)
        .expect("owner delete");
    assert!(receipt.existed);
}

/// F3: the replacement write and the supersession are one transaction — a
/// refused supersession (generated-origin claim over user-stated truth)
/// rolls the replacement back instead of leaving an orphan revision.
#[test]
fn refused_supersession_rolls_back_the_replacement() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x4B);
    let subject = put_person(&vault, 0x4C);
    let facade = facade_for(&vault, actor);

    let first = facade
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("user-stated truth");

    // A generated-origin revision may not supersede user-stated truth
    // (engine source-trust supersession rights): the whole composed write
    // must roll back.
    let replacement_id = EntityId::from_bytes([0x4D; 16]).unwrap();
    let mut generated = claim_input(
        "profile.name",
        &subject,
        "generated",
        serde_json::json!("Overwritten"),
    );
    generated.id = Some(replacement_id.to_hex());
    generated.occurred_at = Some(200);
    generated.learned_at = Some(200);
    let err = facade
        .claim_upsert(&generated)
        .expect_err("generated must not supersede user-stated");
    assert!(!err.suggestions.is_empty());

    assert!(
        vault
            .get_claim(&replacement_id)
            .expect("read back")
            .is_none(),
        "refused supersession must not leave the replacement persisted"
    );
    let survivors = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: Some("profile.name".to_owned()),
            lifecycle: Some("active".to_owned()),
            limit: 10,
        })
        .expect("list");
    assert_eq!(
        survivors.len(),
        1,
        "the prior truth stays the only active claim"
    );
    assert_eq!(
        short_id_part(&survivors[0].short_ref.clone().unwrap_or_default()),
        short_id_part(&first.claim_short_id),
        "prior claim untouched"
    );
}

/// D1: a hard-deleted id is permanent through the facade — recreation is
/// refused (same type AND retyped), killing the two-step retype
/// (hard-delete → recreate) and re-import resurrection. A soft
/// user_delete keeps engine semantics: the shell retains its type, so a
/// same-type re-put stays engine-legal and a retype re-put stays blocked
/// by EntityTypeImmutable.
#[test]
fn hard_deleted_ids_cannot_be_recreated_through_the_facade() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x62);
    let facade = facade_for(&vault, owner);

    let put_kind = |kind: &str, id_hex: &str, at: u64| {
        facade.put_structural(&StructuralPutInput {
            id: Some(id_hex.to_owned()),
            kind: kind.to_owned(),
            body: serde_json::json!({"name": "target"}),
            text_fields: None,
            edges: None,
            occurred_at: at,
            learned_at: None,
        })
    };

    // Hard delete → recreation refused, retyped or not.
    let victim = EntityId::from_bytes([0x63; 16]).unwrap();
    put_kind("EVENT", &victim.to_hex(), 700).expect("create victim");
    facade
        .safe_delete(&victim.to_hex(), SafeDeleteReason::UserHardDelete)
        .expect("hard delete");
    for kind in ["PERSON", "EVENT"] {
        let err = put_kind(kind, &victim.to_hex(), 701)
            .expect_err("recreation at a hard-deleted id must be refused");
        assert_eq!(err.code, MEMORY_CODE_FORBIDDEN, "kind {kind}");
        assert!(err.message.contains("hard-deleted"), "{}", err.message);
    }
    // The refusal covers the claim door too (resurrection, not just retype).
    let mut claim = claim_input(
        "profile.name",
        &owner,
        "user_stated",
        serde_json::json!("ghost"),
    );
    claim.id = Some(victim.to_hex());
    let err = facade.claim_upsert(&claim).expect_err("claim at purged id");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);

    // ... and the witness door (message ids) and the blob-artifact door.
    let mut ghost_message = witness_message(0, WitnessAuthor::User, "revenant");
    ghost_message.id = Some(victim.to_hex());
    let err = facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x66; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![ghost_message],
            occurred_at: 707,
        })
        .expect_err("witness message at purged id");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    let err = facade
        .put_blob_artifact(&BlobArtifactInput {
            id: Some(victim.to_hex()),
            name: "revenant.m4a".to_owned(),
            media_type: "audio/mp4".to_owned(),
            occurred_at: 708,
            learned_at: None,
        })
        .expect_err("blob artifact at purged id");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);

    // GDPR (hard reason) marks the id permanent the same way.
    let gdpr_victim = EntityId::from_bytes([0x64; 16]).unwrap();
    put_kind("EVENT", &gdpr_victim.to_hex(), 702).expect("create gdpr victim");
    facade
        .safe_delete(&gdpr_victim.to_hex(), SafeDeleteReason::GdprDelete)
        .expect("gdpr delete");
    let err = put_kind("EVENT", &gdpr_victim.to_hex(), 703)
        .expect_err("gdpr-erased id must not resurrect");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);

    // Soft user_delete: shell keeps its type; a facade RETYPE at the id
    // stays blocked by the engine (EntityTypeImmutable), and the id is
    // NOT marked hard-deleted.
    let soft_victim = EntityId::from_bytes([0x65; 16]).unwrap();
    put_kind("EVENT", &soft_victim.to_hex(), 704).expect("create soft victim");
    facade
        .safe_delete(&soft_victim.to_hex(), SafeDeleteReason::UserDelete)
        .expect("soft delete");
    let err = put_kind("PERSON", &soft_victim.to_hex(), 705)
        .expect_err("soft-deleted shell keeps its type");
    assert!(
        !err.message.contains("hard-deleted"),
        "soft delete must not use the hard marker: {}",
        err.message
    );
    // A3 was a positive case here (a SAME-TYPE re-put at a soft-deleted id
    // stayed legal), guarding against an over-broadened refusal. ONE-1889
    // supersedes it deliberately: the structural door is create-only, and a
    // soft-deleted shell is still a stored row whose state a re-put would
    // destroy — precisely what the tombstone keeps recoverable. What A3 was
    // really protecting still holds and is asserted here: the soft path stays
    // DISTINGUISHABLE from the hard path (no hard-delete marker, no
    // hard-delete message) and the shell survives the refusal intact.
    let shell_before = vault.get_raw(&soft_victim).expect("shell raw");
    let err = put_kind("EVENT", &soft_victim.to_hex(), 706)
        .expect_err("create-only refuses a same-type re-put at a stored shell");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        !err.message.contains("hard-deleted"),
        "soft delete must not borrow the hard marker's refusal: {}",
        err.message
    );
    assert!(
        err.message.contains("EVENT"),
        "refusal names the stored kind: {}",
        err.message
    );
    assert_eq!(
        vault.get_raw(&soft_victim).expect("shell after"),
        shell_before,
        "the soft-deleted shell is untouched by the refusal"
    );
}
