//! Security-regression suite from a cross-cutting review batch: tests span
//! witness, structural puts, actor authority, supersession, hard-delete,
//! query, recall, consolidation, seeding, and outbound scheduling in one
//! historical region. Kept whole (not split per concern) pending per-test
//! triage to the owning concern files.

use super::outbound::*;
use super::tests::{
    claim_input, facade_for, open_vault, put_person, short_id_part, test_time, witness_message,
};
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::outbound::OutboundDispatchError;
use crate::registry::ENTITY_TYPE_PERSON;

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
    let agent_facade = vault.memory_facade(agent_person, EdgeActorClass::Agent);

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
        assert_eq!(err.code, FACADE_CODE_FORBIDDEN, "kind {kind}");
        assert!(!err.suggestions.is_empty());
    }
    // MACHINE is refused even for the owner (engine-host provisioning).
    let err = mint(&owner_facade, "MACHINE").expect_err("MACHINE never facade-writable");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
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
        assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
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
        assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
        assert!(
            err.message.contains("cannot act as class"),
            "{}",
            err.message
        );
    }

    // Bind-time verification: asActor keys hit the same store truth.
    let err =
        parse_actor_key(&vault, &format!("human:{}", ghost.to_hex())).expect_err("ghost bind");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    let err = parse_actor_key(&vault, &format!("system:{}", owner.to_hex()))
        .expect_err("PERSON cannot bind as system");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
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
    let agent_facade = vault.memory_facade(agent_person, EdgeActorClass::Agent);

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
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(!err.suggestions.is_empty());

    // The agent CAN retract its own write. The writer here is the
    // first-party eiri agent (the one agent ref the default manifest
    // grants an auto ceiling) so its claim lands auto — a proposed claim
    // parks a pending consent, and the engine refuses body rewrites while
    // consent is parked (GateConsentStale), which is consent-queue
    // machinery, not retraction authority.
    let eiri_agent = EntityId::from_hex(&crate::gate::first_party_eiri_connector_actor_ref())
        .expect("first-party agent id");
    vault
        .put_entity(
            &eiri_agent,
            ENTITY_TYPE_PERSON,
            test_time(1),
            1,
            b"eiri agent",
        )
        .expect("put eiri agent");
    let eiri_facade = vault.memory_facade(eiri_agent, EdgeActorClass::Agent);
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
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
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
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
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
        assert_eq!(err.code, FACADE_CODE_FORBIDDEN, "kind {kind}");
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
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);

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
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    let err = facade
        .put_blob_artifact(&BlobArtifactInput {
            id: Some(victim.to_hex()),
            name: "revenant.m4a".to_owned(),
            media_type: "audio/mp4".to_owned(),
            occurred_at: 708,
            learned_at: None,
        })
        .expect_err("blob artifact at purged id");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);

    // GDPR (hard reason) marks the id permanent the same way.
    let gdpr_victim = EntityId::from_bytes([0x64; 16]).unwrap();
    put_kind("EVENT", &gdpr_victim.to_hex(), 702).expect("create gdpr victim");
    facade
        .safe_delete(&gdpr_victim.to_hex(), SafeDeleteReason::GdprDelete)
        .expect("gdpr delete");
    let err = put_kind("EVENT", &gdpr_victim.to_hex(), 703)
        .expect_err("gdpr-erased id must not resurrect");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);

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
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
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

// ═══ BRIDGE-02 (ONE-1455): query surface ═══════════════════════════════

#[test]
fn query_bm25_ranks_exact_match_above_partial() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x17);
    let facade = facade_for(&vault, actor);

    let conversation = EntityId::from_bytes([0x18; 16]).unwrap().to_hex();
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation,
            turn_ref: None,
            messages: vec![
                witness_message(0, WitnessAuthor::User, "solar panel maintenance guide"),
                witness_message(1, WitnessAuthor::User, "solar flare forecast"),
            ],
            occurred_at: 1300,
        })
        .expect("witness");

    let hits = facade.query_bm25("solar panel", 10).expect("bm25");
    assert!(hits.len() >= 2, "both docs match the shared term");
    assert!(
        hits[0]
            .snippet
            .as_deref()
            .is_some_and(|s| s.contains("panel")),
        "exact-term doc must rank first; got snippet {:?}",
        hits[0].snippet
    );
    for pair in hits.windows(2) {
        assert!(pair[0].score >= pair[1].score, "scores must be monotonic");
    }
    assert!(
        hits[0].score > hits[1].score,
        "exact match outranks partial"
    );
    assert_eq!(hits[0].kind, "MESSAGE");
}

#[test]
fn neighbors_filters_by_weight_and_kind() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x19);
    let facade = facade_for(&vault, actor);

    let strong = put_person(&vault, 0x1A);
    let weak = put_person(&vault, 0x1B);
    let attached = put_person(&vault, 0x1C);
    let anchor = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({"name": "hanami"}),
            text_fields: None,
            edges: Some(vec![
                StructuralEdgeSpec {
                    edge_kind: "mentions".to_owned(),
                    target_ref: strong.to_hex(),
                    weight: Some(0.9),
                },
                StructuralEdgeSpec {
                    edge_kind: "mentions".to_owned(),
                    target_ref: weak.to_hex(),
                    weight: Some(0.2),
                },
                StructuralEdgeSpec {
                    edge_kind: "attached".to_owned(),
                    target_ref: attached.to_hex(),
                    weight: Some(0.8),
                },
            ]),
            occurred_at: 1400,
            learned_at: None,
        })
        .expect("anchor");

    // Kind + weight filters, engine-side.
    let hits = facade
        .neighbors(
            &anchor.id_hex,
            &NeighborOpts {
                edge_kind: Some("mentions".to_owned()),
                min_weight: Some(0.5),
                limit: 10,
            },
        )
        .expect("neighbors");
    assert_eq!(hits.len(), 1, "weak mention and attached edge filtered out");
    let hydrated = facade
        .hydrate(std::slice::from_ref(&hits[0].short_id))
        .expect("hit hydrates");
    assert_eq!(hydrated[0].id_hex, strong.to_hex());
    assert!((hits[0].weight - 0.9).abs() < 1e-6, "weight equals stored");
    assert_eq!(hits[0].edge_kind, "mentions");
    assert_eq!(hits[0].direction, "out");

    // Inbound direction from the target's side.
    let inbound = facade
        .neighbors(
            &strong.to_hex(),
            &NeighborOpts {
                edge_kind: Some("mentions".to_owned()),
                min_weight: None,
                limit: 10,
            },
        )
        .expect("inbound neighbors");
    let inbound_hit = inbound
        .iter()
        .find(|hit| hit.direction == "in")
        .expect("anchor visible as inbound neighbor");
    let hydrated = facade
        .hydrate(std::slice::from_ref(&inbound_hit.short_id))
        .expect("inbound hit hydrates");
    assert_eq!(hydrated[0].id_hex, anchor.id_hex);

    // Unknown edge kind fails closed.
    let err = facade
        .neighbors(
            &anchor.id_hex,
            &NeighborOpts {
                edge_kind: Some("linked".to_owned()),
                min_weight: None,
                limit: 10,
            },
        )
        .expect_err("unknown edge kind");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
}

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

    for effort in [Effort::Minimal, Effort::Standard] {
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
            Effort::Standard,
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
            Effort::Standard,
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

    // Vault floor (unset scope) excludes nothing.
    let floor = facade
        .recall(
            "atlantis",
            Effort::Standard,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("floor recall");
    assert!(floor.scope_honesty.out_of_scope_worlds.is_empty());
}

#[test]
fn recall_deep_requires_lease_and_marks_pending() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x27);
    let facade = facade_for(&vault, actor);

    let err = facade
        .recall(
            "anything",
            Effort::Deep,
            &RecallScope::default(),
            5,
            None,
            None,
        )
        .expect_err("deep without lease");
    assert_eq!(err.code, FACADE_CODE_LEASE_REQUIRED);
    assert!(
        err.suggestions.iter().any(|s| s.contains("lease")),
        "suggestions mention the lease: {:?}",
        err.suggestions
    );

    let lease = crate::llm::BudgetLease::for_test("recall-spike");
    let pack = facade
        .recall(
            "anything",
            Effort::Deep,
            &RecallScope::default(),
            5,
            None,
            Some(&lease),
        )
        .expect("leased deep executes as standard");
    assert_eq!(pack.retrieval_meta.deep_pending, Some(true));
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
                Effort::Minimal,
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

#[test]
fn recall_confidence_is_absolute_across_candidate_sets() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x36);
    let facade = facade_for(&vault, actor);

    // Minted through the create-only door with its text field (ONE-1889),
    // rather than pre-created and overwritten.
    let subject = EntityId::from_hex(
        &facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "quokka researcher"}),
                text_fields: Some(vec![TextIndexField {
                    field: "name".to_owned(),
                    value: "quokka researcher".to_owned(),
                }]),
                edges: None,
                occurred_at: 1800,
                learned_at: None,
            })
            .expect("subject")
            .id_hex,
    )
    .expect("subject id");
    let mut input = claim_input(
        "profile.name",
        &subject,
        "user_stated",
        serde_json::json!("Quokka"),
    );
    input.confidence = 0.8;
    facade.claim_upsert(&input).expect("claim");

    let find_claim_confidence = |pack: &MemoryPack| {
        pack.items
            .iter()
            .find(|item| item.kind == "CLAIM")
            .map(|item| item.confidence)
    };

    let first = facade
        .recall(
            "quokka",
            Effort::Standard,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("first recall");
    let first_confidence = find_claim_confidence(&first);

    // Grow the candidate set, then recall again: the same claim must carry
    // the identical calibrated-absolute confidence (never set-relative).
    let extra = (0..4)
        .map(|i| witness_message(i, WitnessAuthor::User, &format!("quokka field note {i}")))
        .collect();
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x38; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: extra,
            occurred_at: 1801,
        })
        .expect("extra docs");
    let second = facade
        .recall(
            "quokka",
            Effort::Standard,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("second recall");
    let second_confidence = find_claim_confidence(&second);

    assert!(
        first_confidence.is_some() && second_confidence.is_some(),
        "claim surfaces in both packs (first: {first_confidence:?}, second: {second_confidence:?})"
    );
    assert_eq!(first_confidence, second_confidence);
    assert!(
        (first_confidence.unwrap() - 0.8).abs() < 1e-6,
        "absolute value from the body"
    );
}

#[test]
fn recall_short_ids_hydrate_and_formats_render() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x39);
    let facade = facade_for(&vault, actor);

    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x3A; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "ceramic kiln firing log",
            )],
            occurred_at: 1900,
        })
        .expect("witness");

    let pack = facade
        .recall(
            "ceramic",
            Effort::Standard,
            &RecallScope::default(),
            10,
            Some("md"),
            None,
        )
        .expect("recall");
    assert!(pack.rendered.as_deref().is_some_and(|r| !r.is_empty()));

    // Every shortId round-trips through hydrate (OF-096).
    let refs: Vec<String> = pack
        .items
        .iter()
        .map(|item| item.short_id.clone())
        .collect();
    assert!(!refs.is_empty());
    let views = facade.hydrate(&refs).expect("hydrate round-trip");
    assert_eq!(views.len(), refs.len());

    // BM25 hits hydrate too.
    let hits = facade.query_bm25("ceramic", 5).expect("bm25");
    let refs: Vec<String> = hits.iter().map(|hit| hit.short_id.clone()).collect();
    assert_eq!(facade.hydrate(&refs).expect("hydrate").len(), hits.len());

    // Unknown format fails closed.
    let err = facade
        .recall(
            "ceramic",
            Effort::Standard,
            &RecallScope::default(),
            10,
            Some("docx"),
            None,
        )
        .expect_err("unknown format");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(err.suggestions.iter().any(|s| s.contains("toon")));
}

/// Builds a distinct, non-reserved entity id from a counter for bulk index
/// seeding (avoids the crate-root test helper, which is module-private).
fn seeded_bulk_id(tag: u8, counter: usize) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&(counter as u64 + 1).to_le_bytes());
    bytes[15] = tag;
    EntityId::from_bytes(bytes).expect("seeded id is never reserved")
}

/// #482a regression: world-scoped recall enumerates out-of-scope worlds with
/// the bounded page primitive, so a CLAIM index larger than the
/// materialization ceiling does not hard-fail. The old
/// `entities_by_type().take(cap)` path errored with IndexOverflow before the
/// take could run.
#[test]
fn recall_scope_honesty_stays_bounded_on_a_large_claim_index() {
    use crate::registry::ENTITY_TYPE_CLAIM;
    use crate::store::Store;

    // One past MAX_TYPE_QUERY_RESULTS (module-private const, mirrored here).
    const OVER_MATERIALIZATION_CAP: usize = 100_000 + 1;

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x5C);
    let facade = facade_for(&vault, actor);

    vault
        .with_write_txn(|wtxn| {
            for i in 0..OVER_MATERIALIZATION_CAP {
                let id = seeded_bulk_id(0xC1, i);
                let key = Store::encode_type_key(ENTITY_TYPE_CLAIM, &id);
                vault.store.type_index.put(wtxn, &key, &[])?;
            }
            Ok(())
        })
        .expect("seed claim type index");

    let world = EntityId::from_bytes([0x5D; 16]).unwrap();
    let pack = facade
        .recall(
            "anything",
            Effort::Standard,
            &RecallScope {
                world_ref: Some(world.to_hex()),
                facet: None,
            },
            5,
            None,
            None,
        )
        .expect("world-scoped recall must not hard-fail on a large claim index");
    assert!(
        pack.scope_honesty.out_of_scope_worlds.is_empty(),
        "no surfaceable out-of-scope claims among the bounded scan window"
    );
}

/// #482b regression: neighbors bounds the edge scan by `limit`, so a node with
/// more edges than the full-materialization ceiling returns a bounded result
/// instead of IndexOverflow. The old `edges_out()`/`edges_in()` path
/// materialized every edge up front.
#[test]
fn neighbors_stays_bounded_on_a_high_degree_node() {
    use crate::store::Store;

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x5E);
    let center = put_person(&vault, 0x5F);
    let facade = facade_for(&vault, actor);

    // One past the edge materialization ceiling on a single source node.
    let edge_count = crate::vault::MAX_EDGE_QUERY_RESULTS + 1;
    let mut value = [0u8; 12];
    value[0..4].copy_from_slice(&0.9_f32.to_le_bytes());
    value[4..12].copy_from_slice(&1_u64.to_le_bytes());
    vault
        .with_write_txn(|wtxn| {
            for i in 0..edge_count {
                let target = seeded_bulk_id(0xE1, i);
                let key = Store::encode_edge_key(&center, EdgeKind::BelongsTo, &target);
                vault.store.edges_out.put(wtxn, &key, &value)?;
            }
            Ok(())
        })
        .expect("seed high-degree edges");

    let hits = facade
        .neighbors(
            &center.to_hex(),
            &NeighborOpts {
                edge_kind: None,
                min_weight: None,
                limit: 5,
            },
        )
        .expect("neighbors must not hard-fail on a high-degree node");
    assert_eq!(hits.len(), 5, "bounded by limit, not the full edge set");
    assert!(hits.iter().all(|hit| hit.direction == "out"));
}

// ═══ BRIDGE-03 (ONE-1456): Dreamer + seed + outbound wiring ═════════════

#[test]
fn consolidation_queue_round_trip_with_facade_writeback() {
    use crate::dreamer_runner::{
        AdmitDreamerAttempt, AdmitDreamerConsolidationAttempt, CompleteDreamerAttempt,
        CompleteDreamerAttemptOutcome, DreamerAdmissionOutcome, DreamerClaimAuthoringAdmission,
        DreamerClaimAuthoringBatchTier, DreamerConsolidationAdmissionOutcome,
        DreamerConsolidationScope, DreamerRunnerStore,
    };

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x51);
    let subject = put_person(&vault, 0x52);
    let facade = facade_for(&vault, actor);

    // Enqueue through the bridge verb; advisory dedupe coalesces re-enqueues.
    let attempt = facade
        .enqueue_consolidation(&ConsolidationAttemptInput {
            scope: "micro".to_owned(),
            input: serde_json::json!({"window": "w-1"}),
            run_id: Some("run-bridge-1".to_owned()),
            dedupe_key: Some("bridge-dedupe-1".to_owned()),
            now: Some(2000),
        })
        .expect("enqueue");
    assert_eq!(attempt.state, "queued");
    assert!(!attempt.existing);
    let again = facade
        .enqueue_consolidation(&ConsolidationAttemptInput {
            scope: "micro".to_owned(),
            input: serde_json::json!({"window": "w-1"}),
            run_id: Some("run-bridge-1".to_owned()),
            dedupe_key: Some("bridge-dedupe-1".to_owned()),
            now: Some(2001),
        })
        .expect("re-enqueue");
    assert!(again.existing, "advisory dedupe coalesces");
    assert_eq!(again.job_ref, attempt.job_ref);

    // Poll model: queued → (admit engine-side) → leased → completed.
    let status = facade
        .dreamer_attempt_status(&attempt.job_ref)
        .expect("status")
        .expect("attempt exists");
    assert_eq!(status.state, "queued");
    assert_eq!(status.run_id.as_deref(), Some("run-bridge-1"));

    let store = DreamerRunnerStore::new(&vault);
    let admitted = store
        .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 7,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "bridge-test-worker".to_owned(),
                now: 2002,
                budget_id: "wake:micro".to_owned(),
                budget_total_units: 10,
                reserve_units: 1,
                started_milestone: None,
            },
        })
        .expect("admit");
    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted_attempt,
    )) = admitted
    else {
        panic!("expected admitted consolidation attempt, got {admitted:?}");
    };
    let leased = facade
        .dreamer_attempt_status(&attempt.job_ref)
        .expect("status")
        .expect("attempt exists");
    assert_eq!(leased.state, "leased");
    assert_eq!(leased.lease_owner.as_deref(), Some("bridge-test-worker"));

    // AC-5 (W3 non-contention): an interactive witness during the running
    // consolidation succeeds without waiting on the attempt.
    facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x53; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "mid-consolidation note",
            )],
            occurred_at: 2003,
        })
        .expect("source write never queues behind derived work");

    // Writeback rides the SAME facade commit path: generated source lands
    // proposed (requires_explicit_auto_permit; no generated auto-permit
    // policy exists at base) with a per-write receipt.
    let writeback = facade
        .commit(&[{
            let mut input = claim_input(
                "eiri.summary.window",
                &subject,
                "generated",
                serde_json::json!({"summary": "moss gardens dominate the week"}),
            );
            input.occurred_at = Some(2004);
            input.learned_at = Some(2004);
            input
        }])
        .expect("writeback commit");
    assert_eq!(writeback.len(), 1);
    assert_eq!(
        writeback[0].approval, "proposed",
        "generated writeback never lands auto"
    );
    assert!(writeback[0].receipt_ref.starts_with("gate:"));
    let receipts = facade.receipts(50).expect("receipts");
    assert!(
        receipts
            .iter()
            .any(|r| r.receipt_ref == writeback[0].receipt_ref),
        "writeback receipt resolvable via receipts()"
    );
    assert!(
        !facade.pending_writes(50).expect("pending").is_empty(),
        "proposed writeback parks for consent"
    );

    // Writeback is retrievable through the ungated claim reads; the D19
    // admission keeps PROPOSED claims out of recall packs until consent
    // resolves (asserted as non-leakage).
    let listed = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: Some("eiri.summary.window".to_owned()),
            lifecycle: Some("active".to_owned()),
            limit: 10,
        })
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].source.as_deref(), Some("generated"));
    let pack = facade
        .recall(
            "moss gardens",
            Effort::Standard,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("recall");
    assert!(
        !pack.items.iter().any(|item| item.kind == "CLAIM"),
        "proposed writeback must NOT surface in packs before consent"
    );

    // Complete the lease; the bridge polls the terminal state.
    let completed = store
        .complete(CompleteDreamerAttempt {
            id: admitted_attempt.status.attempt.id,
            lease_owner: "bridge-test-worker".to_owned(),
            attempt_count: admitted_attempt.status.attempt.attempt_count,
            now: 2005,
        })
        .expect("complete");
    assert!(matches!(
        completed,
        CompleteDreamerAttemptOutcome::Completed(_)
    ));
    let done = facade
        .dreamer_attempt_status(&attempt.job_ref)
        .expect("status")
        .expect("attempt exists");
    assert_eq!(done.state, "completed");

    // Unknown scope fails closed.
    let err = facade
        .enqueue_consolidation(&ConsolidationAttemptInput {
            scope: "giga".to_owned(),
            input: serde_json::json!({}),
            run_id: None,
            dedupe_key: None,
            now: Some(2006),
        })
        .expect_err("unknown scope");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
}

/// G1: enqueue_consolidation is a side-effecting verb and runs the same
/// store-resolved actor check as every other write verb.
#[test]
fn enqueue_consolidation_requires_a_verified_actor() {
    let (_dir, vault) = open_vault();
    let enqueue = |facade: &Memory<'_>| {
        facade.enqueue_consolidation(&ConsolidationAttemptInput {
            scope: "micro".to_owned(),
            input: serde_json::json!({"window": "w-g1"}),
            run_id: None,
            dedupe_key: None,
            now: Some(2100),
        })
    };

    // Ghost actor: refused.
    let ghost = EntityId::from_bytes([0x60; 16]).unwrap();
    let err = enqueue(&facade_for(&vault, ghost)).expect_err("ghost enqueue");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(err.message.contains("does not exist"), "{}", err.message);

    // Type-mismatched actor (an EVENT bound as human): refused.
    let owner = put_person(&vault, 0x61);
    let owner_facade = facade_for(&vault, owner);
    let event = owner_facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({"name": "g1"}),
            text_fields: None,
            edges: None,
            occurred_at: 2101,
            learned_at: None,
        })
        .expect("event");
    let event_id = EntityId::from_hex(&event.id_hex).unwrap();
    let err = enqueue(&facade_for(&vault, event_id)).expect_err("mismatch enqueue");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        err.message.contains("cannot act as class"),
        "{}",
        err.message
    );

    // A verified actor enqueues normally.
    enqueue(&owner_facade).expect("verified enqueue");
}

#[test]
fn seed_claims_force_proposed_with_per_element_receipts() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x54);
    let subject = put_person(&vault, 0x55);
    let facade = facade_for(&vault, actor);

    // AC-3: a user_stated seed — auto-eligible through commit — is FORCED
    // proposed on the seed path, parks for consent, and emits a receipt.
    // eiri.* predicates carry the default manifest's critical criticality,
    // so the forced-proposed seed parks as a pending consent (profile.*
    // seeds land proposed with gate outcome allow and do not park).
    let receipts = facade
        .seed_claims(&[
            claim_input(
                "eiri.profile.name",
                &subject,
                "user_stated",
                serde_json::json!("Cold Start"),
            ),
            // Violating element: rejected while the others land (C3).
            claim_input(
                "BadPredicate",
                &subject,
                "user_stated",
                serde_json::json!("x"),
            ),
            claim_input(
                "eiri.onboarding.answer",
                &subject,
                "imported",
                serde_json::json!({"question_id": "q-1", "selected_option_id": "a"}),
            ),
        ])
        .expect("seed");
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].approval, "proposed", "seed forces proposed");
    assert!(receipts[0].receipt_ref.starts_with("gate:"));
    assert_eq!(receipts[1].approval, "rejected");
    assert_eq!(receipts[2].approval, "proposed");

    let pending = facade.pending_writes(50).expect("pending");
    assert_eq!(pending.len(), 2, "both landed seeds park for consent");
    let listed = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: None,
            lifecycle: Some("active".to_owned()),
            limit: 10,
        })
        .expect("list");
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|claim| claim.approval == "proposed"));
}

#[test]
fn schedule_outbound_holds_gate_checks_and_dedupes() {
    use crate::attempt_queue::AttemptQueue;

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x56);
    let facade = facade_for(&vault, actor);

    let draft = OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "kenji@example.com".to_owned(),
        on_behalf_of: Some("owner".to_owned()),
        content_ref: Some("content:invite".to_owned()),
        idempotency_key: Some("idem-invite-1".to_owned()),
        dedupe_key: Some("dedupe-invite-1".to_owned()),
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:send-now".to_owned(),
        job_ref: Some("brief:party".to_owned()),
        occurred_at: Some(3000),
    };
    let receipt = facade.schedule_outbound(&draft).expect("schedule");
    assert!(receipt.intent_ref.starts_with("intent:"));
    assert!(!receipt.deduped);
    // Schedule-only surface: the sink is never reached — under the default
    // manifest the external-effect gate pends (no policy grant) and the
    // Hold window keeps delivery with the delivery-window machinery.
    // Receipts, not admission, are the contract (GOV-compatible).
    assert!(
        matches!(receipt.outcome.as_str(), "held" | "suppressed" | "let_go"),
        "schedule-only dispatch must not deliver; got {}",
        receipt.outcome
    );
    let gate_ref = receipt
        .gate_decision_ref
        .clone()
        .expect("gate decision persisted");
    let receipts = facade.receipts(50).expect("receipts");
    assert!(
        receipts.iter().any(|r| r.receipt_ref == gate_ref),
        "intent's gate receipt queryable via receipts()"
    );

    // AC-4 idempotency: a second call with the same idempotency_key does
    // not double-enqueue and produces no second gate decision.
    let decisions_before = facade.receipts(100).expect("receipts").len();
    let replay = facade.schedule_outbound(&draft).expect("replay");
    assert!(replay.deduped);
    assert_eq!(replay.outcome, "already_scheduled");
    assert_eq!(replay.intent_ref, receipt.intent_ref);
    assert_eq!(
        facade.receipts(100).expect("receipts").len(),
        decisions_before,
        "no second gate decision on dedupe"
    );
    let queue = AttemptQueue::new(&vault);
    let scheduled = queue
        .list()
        .expect("list attempts")
        .into_iter()
        .filter(|attempt| attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND)
        .count();
    assert_eq!(scheduled, 1, "one durable schedule row");

    // Unknown trigger fails closed.
    let mut bad = draft;
    bad.idempotency_key = Some("idem-invite-2".to_owned());
    bad.trigger = "vibes".to_owned();
    let err = facade.schedule_outbound(&bad).expect_err("unknown trigger");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
}

#[test]
fn missing_bound_outbound_actor_maps_to_forbidden() {
    let err = facade_error_from_outbound_dispatch(OutboundDispatchError::InvalidBoundActor);

    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert_ne!(err.code, FACADE_CODE_NOT_FOUND);
}

/// #484a regression: an unsupported channel is rejected BEFORE the durable
/// enqueue, so it leaves no orphan attempt/dedupe entry and a retry (on a
/// supported channel, same idempotency key) is not wedged as an existing
/// dedupe hit.
#[test]
fn schedule_outbound_unsupported_channel_leaves_no_orphan_and_allows_retry() {
    use crate::attempt_queue::{AttemptQueue, AttemptState};

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x60);
    let facade = facade_for(&vault, actor);

    let mut draft = OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "carrier_pigeon".to_owned(),
        target: "roost@example.com".to_owned(),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some("idem-orphan-1".to_owned()),
        dedupe_key: Some("dedupe-orphan-1".to_owned()),
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:pigeon".to_owned(),
        job_ref: None,
        occurred_at: Some(4000),
    };

    let err = facade
        .schedule_outbound(&draft)
        .expect_err("unsupported channel fails closed");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);

    // No live (non-cancelled) schedule row orphaned by the failed dispatch.
    let queue = AttemptQueue::new(&vault);
    let live = queue
        .list()
        .expect("list attempts")
        .into_iter()
        .find(|attempt| {
            attempt.kind == BRIDGE_OUTBOUND_ATTEMPT_KIND && attempt.state != AttemptState::Cancelled
        });
    assert!(
        live.is_none(),
        "unsupported channel must not leave a live outbound attempt"
    );

    // A retry on a supported channel with the SAME idempotency key proceeds
    // (no lingering dedupe entry to coalesce onto).
    draft.channel = "email".to_owned();
    let receipt = facade.schedule_outbound(&draft).expect("retry proceeds");
    assert!(
        !receipt.deduped,
        "retry re-enqueues instead of deduping onto an orphan"
    );
    assert!(receipt.intent_ref.starts_with("intent:"));
}

/// #484b regression: an idempotent retry recovers the ORIGINAL gate decision
/// ref instead of an empty gate result. The first schedule persists its gate
/// surface keyed by attempt id; the dedupe branch reads it back.
#[test]
fn schedule_outbound_dedupe_recovers_original_gate_decision_ref() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x61);
    let facade = facade_for(&vault, actor);

    let draft = OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "kenji@example.com".to_owned(),
        on_behalf_of: None,
        content_ref: None,
        idempotency_key: Some("idem-recover-1".to_owned()),
        dedupe_key: Some("dedupe-recover-1".to_owned()),
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:recover".to_owned(),
        job_ref: None,
        occurred_at: Some(5000),
    };

    let first = facade.schedule_outbound(&draft).expect("first schedule");
    assert!(!first.deduped);
    let gate_ref = first
        .gate_decision_ref
        .clone()
        .expect("first schedule persists a gate decision");

    let replay = facade.schedule_outbound(&draft).expect("replay");
    assert!(replay.deduped);
    assert_eq!(replay.outcome, "already_scheduled");
    assert_eq!(
        replay.gate_decision_ref,
        Some(gate_ref),
        "retry recovers the original gate decision ref"
    );
    assert_eq!(replay.gate_outcome, first.gate_outcome);
    assert_eq!(replay.gate_reason_codes, first.gate_reason_codes);
}
