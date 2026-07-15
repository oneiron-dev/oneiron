//! BRIDGE-01 acceptance tests, engine side. TS-layer ACs (bun build/test,
//! index.d.ts shape) are owner-deferred with the eiri repo this wave.
//!
//! The harness deliberately KEEPS the default policy manifest seeded by
//! `Vault::open` (unlike the legacy `test_util` opener) so the write gate is
//! live — production reality for the bridge.

use super::*;
use crate::config::VaultConfig;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};

fn open_vault() -> (tempfile::TempDir, crate::Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn test_time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// Puts a PERSON entity usable as a facade actor (the gated candidate path
/// validates actor existence + class).
fn put_person(vault: &crate::Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("person id");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, test_time(1), 1, b"facade person")
        .expect("put person");
    id
}

fn facade_for(vault: &crate::Vault, actor: EntityId) -> MemoryFacade<'_> {
    vault.memory_facade(actor, EdgeActorClass::Human)
}

fn claim_input(
    predicate: &str,
    subject: &EntityId,
    source: &str,
    value: serde_json::Value,
) -> ClaimInput {
    ClaimInput {
        id: None,
        predicate: predicate.to_owned(),
        subject_ref: subject.to_hex(),
        value,
        confidence: 1.0,
        source: source.to_owned(),
        world_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: Some(100),
        learned_at: Some(100),
        salience: None,
    }
}

/// Short refs are `"<short_id>:<body-hash>"`; the hash suffix advances when
/// a claim body is rewritten (supersede/retract), so entity identity is
/// compared on the stable short-id part.
fn short_id_part(reference: &str) -> &str {
    reference.split(':').next().unwrap_or(reference)
}

fn witness_message(order: u32, author: WitnessAuthor, content: &str) -> WitnessMessage {
    WitnessMessage {
        id: None,
        author,
        message_type: "dialogue".to_owned(),
        content: content.to_owned(),
        metadata: None,
        is_visible: true,
        order,
    }
}

// ── actor key grammar (design §4.3) ─────────────────────────────────────

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
        assert_eq!(err.code, FACADE_CODE_BAD_REQUEST, "key {malformed:?}");
        assert!(!err.suggestions.is_empty());
    }
}

// ── witness (AC-3, B2 create-or-get) ────────────────────────────────────

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
            messages: vec![
                witness_message(0, WitnessAuthor::User, "quantum banana ledger"),
                witness_message(1, WitnessAuthor::Companion, "reply about the ledger"),
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
fn witness_create_or_get_reuses_containers_and_rejects_system_author_escalation() {
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
    // Second call reuses BOTH containers (migration composes mixed-author
    // turns as multiple witness calls sharing the same turn id).
    let second = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: Some(turn_hex.clone()),
            messages: vec![witness_message(
                1,
                WitnessAuthor::Companion,
                "companion row",
            )],
            occurred_at: 601,
        })
        .expect("second witness");
    assert_eq!(first.turn_short_id, second.turn_short_id);

    let system_error = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: Some(turn_hex.clone()),
            messages: vec![witness_message(2, WitnessAuthor::System, "system row")],
            occurred_at: 602,
        })
        .expect_err("human actor must not witness a SYSTEM envelope");
    assert_eq!(system_error.code, FACADE_CODE_FORBIDDEN);

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

    // Byte-identical container state across the second call: create-or-get
    // never re-puts an existing container (idempotency-critical for the
    // §3.5 hash checks — counts alone would not catch a body rewrite).
    assert_eq!(
        vault.get_raw(&turn_id).unwrap().expect("turn raw after"),
        turn_raw_before,
        "reused TURN must be byte-identical"
    );
    assert_eq!(
        vault
            .get_raw(&conversation_id)
            .unwrap()
            .expect("conversation raw after"),
        conversation_raw_before,
        "reused CONVERSATION must be byte-identical"
    );

    // The permitted companion transcript row remains actor-attributed; the
    // rejected SYSTEM envelope did not create a third MESSAGE.
    let companion_view = facade
        .get_entity(&second.message_short_ids[0])
        .unwrap()
        .expect("companion message");
    let companion_id = EntityId::from_hex(&companion_view.id_hex).unwrap();
    let kinds: Vec<EdgeKind> = vault
        .edges_out(&companion_id)
        .expect("edges")
        .iter()
        .map(|edge| edge.kind)
        .collect();
    assert!(kinds.contains(&EdgeKind::AuthoredBy));
    assert!(kinds.contains(&EdgeKind::PartOf));
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_MESSAGE).expect("messages").len(),
        2
    );

    // Type mismatch on a container ref fails closed.
    let err = facade
        .witness(&WitnessTurn {
            conversation_ref: turn_hex,
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "x")],
            occurred_at: 602,
        })
        .expect_err("turn id passed as conversation must fail");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
}

// ── commit / approval policy (AC-4) ─────────────────────────────────────

#[test]
fn commit_user_stated_band0_lands_auto_with_resolvable_receipt() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x41);
    let subject = put_person(&vault, 0x42);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("auto claim");
    assert_eq!(receipt.approval, "auto");
    assert!(receipt.receipt_ref.starts_with("gate:"));

    // receipt_ref resolves via receipts().
    let receipts = facade.receipts(50).expect("receipts");
    let decision = receipts
        .iter()
        .find(|r| r.receipt_ref == receipt.receipt_ref)
        .expect("decision resolvable via receipts()");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.actor_class, "human");

    // Nothing parked for consent.
    let pending = facade.pending_writes(50).expect("pending");
    assert!(pending.is_empty());
}

#[test]
fn commit_imported_lands_proposed_and_appears_in_pending_writes() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x51);
    let subject = put_person(&vault, 0x52);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .claim_upsert(&claim_input(
            "eiri.onboarding.answer",
            &subject,
            "imported",
            serde_json::json!({"question_id": "q-1", "selected_option_id": "a"}),
        ))
        .expect("imported claim");
    assert_eq!(receipt.approval, "proposed");
    assert!(receipt.receipt_ref.starts_with("gate:"));

    let pending = facade.pending_writes(50).expect("pending");
    assert_eq!(pending.len(), 1);
    let receipts = facade.receipts(50).expect("receipts");
    assert!(
        receipts
            .iter()
            .any(|r| r.receipt_ref == receipt.receipt_ref),
        "receipt_ref must resolve via receipts()"
    );
    assert!(
        receipts.iter().any(|r| r.outcome == "pending"),
        "gate outcome for the parked write is pending"
    );
}

#[test]
fn commit_auto_request_downgrades_to_proposed_when_gate_pends() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x61);
    let subject = put_person(&vault, 0x62);
    let facade = facade_for(&vault, actor);

    // Unknown predicates default to CRITICAL criticality under the default
    // policy manifest, so the gate pends the auto request; the facade
    // resubmits proposed instead of dropping the write.
    let receipt = facade
        .claim_upsert(&claim_input(
            "eiri.preference.color",
            &subject,
            "user_stated",
            serde_json::json!("teal"),
        ))
        .expect("downgraded claim");
    assert_eq!(receipt.approval, "proposed");
    let pending = facade.pending_writes(50).expect("pending");
    assert_eq!(pending.len(), 1, "downgraded write parks for consent");
}

#[test]
fn commit_sensitivity_scope_key_forces_proposed() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x63);
    let subject = put_person(&vault, 0x64);
    let facade = facade_for(&vault, actor);

    let mut input = claim_input(
        "profile.name",
        &subject,
        "user_stated",
        serde_json::json!("Mira"),
    );
    input.scope = Some(serde_json::json!({"sensitivity": 0}));
    let receipt = facade.claim_upsert(&input).expect("scoped claim");
    assert_eq!(
        receipt.approval, "proposed",
        "explicit sensitivity key ⇒ proposed request"
    );
}

// ── supersession (AC-2 engine side, B1c) ────────────────────────────────

#[test]
fn claim_upsert_supersedes_prior_single_cardinality() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x71);
    let subject = put_person(&vault, 0x72);
    let facade = facade_for(&vault, actor);

    let first = facade
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("first revision");
    let mut second_input = claim_input(
        "profile.name",
        &subject,
        "user_stated",
        serde_json::json!("Ada Lovelace"),
    );
    second_input.learned_at = Some(200);
    second_input.occurred_at = Some(200);
    let second = facade.claim_upsert(&second_input).expect("second revision");

    assert_eq!(
        second.superseded_short_id.as_deref().map(short_id_part),
        Some(short_id_part(&first.claim_short_id)),
        "second revision supersedes the first"
    );

    // Prior claim stays readable with lifecycle superseded.
    let history = facade
        .claim_history(&second.claim_short_id)
        .expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].lifecycle, "superseded");
    assert_eq!(history[0].value, serde_json::json!("Ada"));
    assert_eq!(history[1].lifecycle, "active");

    // Supersedes edge new → old.
    let new_id = EntityId::from_hex(&history[1].claim_ref).unwrap();
    let old_id = EntityId::from_hex(&history[0].claim_ref).unwrap();
    let edges = vault.edges_out(&new_id).expect("edges");
    assert!(
        edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::Supersedes && edge.target == old_id),
        "Supersedes edge must link new → old"
    );
}

#[test]
fn multi_cardinality_supersede_matches_on_question_id() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x81);
    let subject = put_person(&vault, 0x82);
    let facade = facade_for(&vault, actor);

    let answer = |question: &str, option: &str, at: u64| {
        let mut input = claim_input(
            "eiri.onboarding.answer",
            &subject,
            "imported",
            serde_json::json!({"question_id": question, "selected_option_id": option}),
        );
        input.occurred_at = Some(at);
        input.learned_at = Some(at);
        input
    };

    let answer_a = facade
        .claim_upsert(&answer("q-a", "1", 100))
        .expect("answer a");
    let answer_b = facade
        .claim_upsert(&answer("q-b", "2", 101))
        .expect("answer b");
    assert!(answer_a.superseded_short_id.is_none());
    assert!(
        answer_b.superseded_short_id.is_none(),
        "answering question B must never supersede the answer to question A (B1c)"
    );

    let re_answer_a = facade
        .claim_upsert(&answer("q-a", "3", 102))
        .expect("re-answer a");
    assert_eq!(
        re_answer_a
            .superseded_short_id
            .as_deref()
            .map(short_id_part),
        Some(short_id_part(&answer_a.claim_short_id)),
        "re-answer supersedes the same question's prior claim"
    );

    // B's claim is untouched.
    let claims = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: Some("eiri.onboarding.answer".to_owned()),
            lifecycle: Some("active".to_owned()),
            limit: 10,
        })
        .expect("list");
    assert_eq!(claims.len(), 2, "one active claim per question id");
}

// ── per-element gating (AC-5) ───────────────────────────────────────────

#[test]
fn commit_batch_gating_is_per_element() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x91);
    let subject = put_person(&vault, 0x92);
    let facade = facade_for(&vault, actor);

    let receipts = facade
        .commit(&[
            claim_input(
                "profile.name",
                &subject,
                "user_stated",
                serde_json::json!("Ada"),
            ),
            // Violates the predicate ceiling (uppercase, no dot segments).
            claim_input(
                "BadPredicate",
                &subject,
                "user_stated",
                serde_json::json!("x"),
            ),
            claim_input(
                "profile.age",
                &subject,
                "user_stated",
                serde_json::json!(37),
            ),
        ])
        .expect("commit batch");

    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].approval, "auto");
    assert_eq!(receipts[1].approval, "rejected");
    assert!(receipts[1].receipt_ref.starts_with("rejected:"));
    assert_eq!(
        receipts[2].approval, "auto",
        "elements after a rejection still land"
    );

    // Per-element gate decisions exist for both written claims.
    let receipts_list = facade.receipts(50).expect("receipts");
    assert!(
        receipts_list
            .iter()
            .any(|r| r.receipt_ref == receipts[0].receipt_ref)
    );
    assert!(
        receipts_list
            .iter()
            .any(|r| r.receipt_ref == receipts[2].receipt_ref)
    );
    assert_ne!(receipts[0].receipt_ref, receipts[2].receipt_ref);

    // The rejected element persisted nothing.
    let claims = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: None,
            lifecycle: None,
            limit: 10,
        })
        .expect("list");
    assert_eq!(claims.len(), 2);
}

// ── safe delete (AC-6) ──────────────────────────────────────────────────

#[test]
fn safe_delete_requires_named_reason_and_returns_receipt() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xB5);
    let facade = facade_for(&vault, actor);

    let soft_target = put_person(&vault, 0xB6);
    let receipt = facade
        .safe_delete(&soft_target.to_hex(), SafeDeleteReason::UserDelete)
        .expect("user delete");
    assert!(receipt.existed);
    assert_eq!(receipt.reason, "user_delete");
    assert!(
        receipt.receipt_ref.is_none(),
        "tombstone path writes no receipt entity"
    );

    let hard_target = put_person(&vault, 0xB7);
    let receipt = facade
        .safe_delete(&hard_target.to_hex(), SafeDeleteReason::UserHardDelete)
        .expect("hard delete");
    assert!(receipt.existed);
    let receipt_ref = receipt
        .receipt_ref
        .expect("hard delete writes a redaction receipt");
    assert!(receipt_ref.starts_with("redaction:"));
    let receipt_id = EntityId::from_hex(
        receipt_ref
            .strip_prefix("redaction:")
            .expect("redaction receipt prefix"),
    )
    .expect("receipt id");
    let raw = vault
        .get_raw(&receipt_id)
        .expect("read receipt")
        .expect("receipt exists");
    let audit = crate::deletion::decode_redaction_audit_receipt(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )
    .expect("decode redaction audit receipt");
    let request_id = audit.request_id.replace('-', "");
    let actor_hex = actor.to_hex();
    let decision = vault
        .gate_decisions(50)
        .expect("gate decisions")
        .into_iter()
        .find(|decision| decision.decision_id.to_hex() == request_id)
        .expect("deletion decision keyed by redaction request id");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.content_kind, "deletion");
    assert_eq!(decision.actor_class, "human");
    assert_eq!(decision.actor_ref.as_deref(), Some(actor_hex.as_str()));
    assert_eq!(decision.reason_codes, ["gate.allow.owner_delete"]);
    assert!(
        decision.claim_id.is_none(),
        "deletion authority must remain distinct from claim receipts"
    );
    assert!(
        facade
            .get_entity(&hard_target.to_hex())
            .expect("read back")
            .is_none(),
        "hard-deleted entity is purged"
    );

    let gdpr_target = put_person(&vault, 0xB8);
    let receipt = facade
        .safe_delete(&gdpr_target.to_hex(), SafeDeleteReason::GdprDelete)
        .expect("gdpr delete");
    assert!(receipt.receipt_ref.is_some());
}

/// DA-C/DA-E/DA-F: a crash after tombstone-first TXN1 leaves the subject
/// untouched until startup recovery executes the purge; TXN1's request-keyed
/// recovery sidecar lets that TXN3 append the authority record exactly once.
#[cfg(feature = "sync")]
#[test]
fn safe_delete_txn1_crash_recovers_purge_with_one_authority_record() {
    use std::sync::Arc;

    use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let dir = tempfile::tempdir().expect("tempdir");
    let (victim, gate_decision_id) = {
        let vault = Arc::new(
            crate::Vault::open(dir.path(), VaultConfig::default()).expect("open first vault"),
        );
        let actor = put_person(&vault, 0xBC);
        let victim = put_person(&vault, 0xBD);
        // Keep the deletion window live so TXN1 covers the observer-A
        // suppression path as well as the transient document path.
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            "facade-crash-live-window",
        ));
        manager
            .open_window(&WindowKey::from_timestamp(1))
            .expect("open live deletion window");
        let facade = facade_for(&vault, actor);

        crate::deletion::arm_fail_after_tombstone_before_purge();
        facade
            .safe_delete(&victim.to_hex(), SafeDeleteReason::UserHardDelete)
            .expect_err("test crash after durable TXN1");

        assert!(
            vault.get_raw(&victim).expect("read victim").is_some(),
            "TXN1 tombstone must precede, not perform, the active-store purge"
        );
        let deletion = vault
            .entity_deletion_metadata(&victim, 1)
            .expect("read tombstone metadata")
            .expect("TXN1 persisted tombstone metadata");
        let request_id = uuid::Uuid::parse_str(
            deletion
                .request_id
                .as_deref()
                .expect("tombstone request id"),
        )
        .expect("request id UUID")
        .into_bytes();
        let gate_decision_id = crate::store::GateDecisionId::from_bytes(request_id);
        let rtxn = vault.store.env.read_txn().expect("read transaction");
        let staged = vault
            .store
            .pending_deletion_gate_decision_in_txn(&rtxn, gate_decision_id)
            .expect("read TXN1 authority sidecar")
            .expect("TXN1 staged request-keyed authority data");
        assert_eq!(staged.content_kind, "deletion");
        drop(rtxn);
        let unrelated_target = EntityId::from_bytes([0xBE; 16]).expect("unrelated target id");
        let consumed = vault
            .with_write_txn(|wtxn| {
                vault.store.append_pending_deletion_gate_decision_in_txn(
                    wtxn,
                    gate_decision_id,
                    unrelated_target.as_bytes(),
                    crate::deletion::TombstoneReason::UserHardDelete.wire_byte(),
                )
            })
            .expect("mismatched tombstone must not consume sidecar");
        assert!(
            consumed.is_none(),
            "a different target may not consume this request-keyed sidecar"
        );
        assert!(
            vault
                .gate_decisions(50)
                .expect("gate decisions")
                .iter()
                .all(|decision| decision.decision_id != gate_decision_id),
            "TXN1 must not append the final GateDecisionRecord before TXN3"
        );
        assert_eq!(
            vault
                .count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
                .expect("receipt count"),
            0,
            "the execution receipt belongs to the later purge transaction"
        );
        drop(manager);
        (victim, gate_decision_id)
    };

    let recovered = Arc::new(
        crate::Vault::open(dir.path(), VaultConfig::default()).expect("reopen after crash"),
    );
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&recovered),
        Arc::new(Materializer::new()),
        "facade-crash-recovery",
    ));
    manager
        .open_window(&WindowKey::from_timestamp(1))
        .expect("startup recovery drives the pending purge");
    assert!(
        recovered
            .get_raw(&victim)
            .expect("read recovered victim")
            .is_none(),
        "the TXN1 tombstone must drive TXN3 purge completion on recovery"
    );
    assert_eq!(
        recovered
            .gate_decisions(50)
            .expect("gate decisions after recovery")
            .iter()
            .filter(|decision| decision.decision_id == gate_decision_id)
            .count(),
        1,
        "recovery must not multiply the request-keyed authority record"
    );
    assert_eq!(
        recovered
            .count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("receipt count after recovery"),
        1,
        "recovery performs the one delayed execution attestation"
    );

    drop(manager);
    drop(recovered);
    let recovered_again = Arc::new(
        crate::Vault::open(dir.path(), VaultConfig::default()).expect("reopen idempotently"),
    );
    let manager_again = Arc::new(WindowManager::new(
        Arc::clone(&recovered_again),
        Arc::new(Materializer::new()),
        "facade-crash-recovery",
    ));
    manager_again
        .open_window(&WindowKey::from_timestamp(1))
        .expect("second recovery is idempotent");
    assert_eq!(
        recovered_again
            .gate_decisions(50)
            .expect("gate decisions after second recovery")
            .iter()
            .filter(|decision| decision.decision_id == gate_decision_id)
            .count(),
        1,
        "double recovery must preserve exactly once authority evidence"
    );
    assert_eq!(
        recovered_again
            .count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("receipt count after second recovery"),
        1,
        "double recovery must not mint a second execution attestation"
    );
}

/// F1: suppressing Observer A for the authority-atomic tombstone commit must
/// not suppress the steady-state route to an already-connected peer.
#[cfg(feature = "sync")]
#[test]
fn safe_delete_live_tombstone_reaches_attached_outbound_channel() {
    use std::sync::Arc;

    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Arc::new(crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
    let actor = put_person(&vault, 0xC1);
    let victim = put_person(&vault, 0xC2);
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "facade-live-route",
    ));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.outbound().attach(tx);
    let window = manager
        .open_window(&WindowKey::from_timestamp(1))
        .expect("open deletion window");
    let receiver_base = crate::sync::loro_support::export_snapshot(&window.doc)
        .expect("receiver starts from the sender's pre-delete state");

    facade_for(&vault, actor)
        .safe_delete(&victim.to_hex(), SafeDeleteReason::UserHardDelete)
        .expect("safe delete");

    let update = rx
        .try_recv()
        .expect("connected peer receives tombstone without reconnect");
    assert_eq!(update.window_key, WindowKey::from_timestamp(1).as_str());
    let remote = crate::sync::schema::create_window_doc("remote", &WindowKey::from_timestamp(1));
    remote
        .import(&receiver_base)
        .expect("import receiver base state");
    remote
        .import(&update.update_bytes)
        .expect("live-routed update imports");
    assert!(
        remote.get_map("tombstones").get(&victim.to_hex()).is_some(),
        "the live route carries the deletion tombstone"
    );
}

/// F3: a live-doc commit that outlives a failed persistence transaction is
/// already protected by a durable authority-required marker + complete
/// sidecar. If the sidecar is missing, recovery refuses the purge and leaves
/// its durable retry marker;
/// ordinary remote tombstones remain a legitimate sidecar-free control.
#[cfg(feature = "sync")]
#[test]
fn live_tombstone_persist_failure_requires_complete_authority_sidecar() {
    use std::sync::Arc;

    use loro::{LoroValue, ValueOrContainer};

    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let dir = tempfile::tempdir().expect("tempdir");
    let (victim, decision_id) = {
        let vault = Arc::new(
            crate::Vault::open(dir.path(), VaultConfig::default()).expect("open first vault"),
        );
        let actor = put_person(&vault, 0xC3);
        let victim = put_person(&vault, 0xC4);
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            "facade-live-txn1-failure",
        ));
        let window = manager
            .open_window(&WindowKey::from_timestamp(1))
            .expect("open live deletion window");

        crate::deletion::arm_fail_live_tombstone_persist();
        facade_for(&vault, actor)
            .safe_delete(&victim.to_hex(), SafeDeleteReason::UserHardDelete)
            .expect_err("live commit survives a failed persistence transaction");
        assert!(
            vault.get_raw(&victim).expect("read victim").is_some(),
            "failed TXN1 must not reach the purge"
        );
        let raw = match window.doc.get_map("tombstones").get(&victim.to_hex()) {
            Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => bytes.to_vec(),
            other => panic!("committed live tombstone missing: {other:?}"),
        };
        let request_id: [u8; 16] = raw[9..25].try_into().expect("request id bytes");
        let decision_id = crate::store::GateDecisionId::from_bytes(request_id);
        let rtxn = vault.store.env.read_txn().expect("read transaction");
        assert!(
            vault
                .store
                .pending_deletion_gate_decision_in_txn(&rtxn, decision_id)
                .expect("read staged sidecar")
                .is_some(),
            "authority sidecar is durable before the live tombstone commit"
        );
        drop(rtxn);

        // Model the orphan live commit being persisted later by an ordinary
        // full-state flush, then remove only the sidecar while retaining the
        // separate authority-required marker.
        window
            .persist_state(&vault)
            .expect("persist orphan live commit");
        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .remove_pending_deletion_gate_sidecar_for_test(wtxn, decision_id)
            })
            .expect("simulate lost authority sidecar");
        drop(window);
        drop(manager);
        (victim, decision_id)
    };

    let recovered = Arc::new(
        crate::Vault::open(dir.path(), VaultConfig::default()).expect("reopen after failed TXN1"),
    );
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&recovered),
        Arc::new(Materializer::new()),
        "facade-live-txn1-recovery",
    ));
    manager
        .open_window(&WindowKey::from_timestamp(1))
        .expect("recovery keeps the window available while marking the failed purge for retry");
    assert!(
        recovered.get_raw(&victim).expect("read victim").is_some(),
        "failed authority recovery rolls the purge back"
    );
    assert!(
        crate::sync::pending_remat_windows(&recovered)
            .expect("pending recovery markers")
            .contains(&WindowKey::from_timestamp(1).as_str().to_owned()),
        "refused purge remains durably queued for fail-closed retry"
    );
    assert!(
        recovered
            .gate_decisions(50)
            .expect("gate decisions")
            .iter()
            .all(|decision| decision.decision_id != decision_id),
        "no authority record is fabricated from an incomplete sidecar"
    );

    // Legitimate remote control: no local required marker exists, so the
    // same replay boundary accepts and purges a peer-authored hard tombstone.
    let remote_victim = put_person(&recovered, 0xC5);
    let remote = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 42,
        request_id: [0xD5; 16],
    };
    recovered
        .apply_replayed_tombstone_for_sync(&remote_victim, &remote.encode())
        .expect("sidecar-free remote tombstone remains valid");
    assert!(
        recovered
            .get_raw(&remote_victim)
            .expect("read remote victim")
            .is_none(),
        "legitimate remote hard tombstone purges normally"
    );
}

// ── error surface (AC-7) ────────────────────────────────────────────────

#[test]
fn facade_errors_carry_stable_codes_and_suggestions() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xB1);
    let subject = put_person(&vault, 0xB2);
    let facade = facade_for(&vault, actor);

    // Wrong-predicate case.
    let err = facade
        .claim_upsert(&claim_input(
            "Bad Predicate!",
            &subject,
            "user_stated",
            serde_json::json!("x"),
        ))
        .expect_err("bad predicate must fail");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(!err.suggestions.is_empty());

    // Above-ceiling case: confidence outside [0, 1].
    let mut over = claim_input(
        "profile.name",
        &subject,
        "user_stated",
        serde_json::json!("x"),
    );
    over.confidence = 2.0;
    let err = facade.claim_upsert(&over).expect_err("confidence ceiling");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(!err.suggestions.is_empty());

    // Maintenance-band kinds are not writable through the facade.
    let err = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "REDACTION_AUDIT".to_owned(),
            body: serde_json::json!({}),
            text_fields: None,
            edges: None,
            occurred_at: 100,
            learned_at: None,
        })
        .expect_err("maintenance kind must be rejected");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(!err.suggestions.is_empty());

    // Unknown claim source.
    let mut bad_source = claim_input(
        "profile.name",
        &subject,
        "user_stated",
        serde_json::json!(1),
    );
    bad_source.source = "vibes".to_owned();
    let err = facade
        .claim_upsert(&bad_source)
        .expect_err("unknown source");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(err.suggestions.iter().any(|s| s.contains("user_stated")));
}

// ── B2 migrator write-verb group ────────────────────────────────────────

#[test]
fn put_structural_carries_text_index_fields_and_edges() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xC1);
    let facade = facade_for(&vault, actor);

    let asset = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "ASSET".to_owned(),
            body: serde_json::json!({"hash": "abc123", "media_type": "audio/mp4"}),
            text_fields: None,
            edges: None,
            occurred_at: 700,
            learned_at: None,
        })
        .expect("asset put");

    let person = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "Chihiro", "bio": "loves moss gardens"}),
            text_fields: Some(vec![
                TextIndexField {
                    field: "name".to_owned(),
                    value: "Chihiro".to_owned(),
                },
                TextIndexField {
                    field: "bio".to_owned(),
                    value: "loves moss gardens".to_owned(),
                },
            ]),
            edges: Some(vec![StructuralEdgeSpec {
                edge_kind: "attached".to_owned(),
                target_ref: asset.id_hex.clone(),
                weight: None,
            }]),
            occurred_at: 701,
            learned_at: None,
        })
        .expect("person put");

    // Kind + body round-trip.
    let view = facade
        .get_entity(&person.entity_ref)
        .expect("get")
        .expect("exists");
    assert_eq!(view.kind, "PERSON");
    assert_eq!(view.body.unwrap()["name"], serde_json::json!("Chihiro"));

    // Edge landed.
    let person_id = EntityId::from_hex(&person.id_hex).unwrap();
    let asset_id = EntityId::from_hex(&asset.id_hex).unwrap();
    let edges = vault.edges_out(&person_id).expect("edges");
    assert!(
        edges
            .iter()
            .any(|e| e.kind == EdgeKind::Attached && e.target == asset_id)
    );

    // Text fields are BM25-findable.
    let hits = vault.search_text("moss", 10).expect("search");
    assert!(hits.iter().any(|hit| hit.id == person_id));

    // CLAIM kind is rejected on this verb.
    let err = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "CLAIM".to_owned(),
            body: serde_json::json!({}),
            text_fields: None,
            edges: None,
            occurred_at: 702,
            learned_at: None,
        })
        .expect_err("CLAIM kind must go through commit");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(err.suggestions.iter().any(|s| s.contains("commit")));

    // Entities land with correct type bytes.
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_ASSET).unwrap().len(), 1);
}

#[test]
fn put_habit_checkin_appends_child_with_pinned_role() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xD1);
    let facade = facade_for(&vault, actor);

    let habit = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "TASK".to_owned(),
            body: serde_json::json!({"role": 4, "content": "meditate"}),
            text_fields: None,
            edges: None,
            occurred_at: 800,
            learned_at: None,
        })
        .expect("habit put");

    let checkin = facade
        .put_habit_checkin(&HabitCheckinInput {
            habit_ref: habit.id_hex.clone(),
            id: None,
            data: Some(serde_json::json!({"note": "10 minutes"})),
            occurred_at: 801,
            learned_at: None,
        })
        .expect("checkin");

    let checkin_id = EntityId::from_hex(&checkin.id_hex).unwrap();
    let habit_id = EntityId::from_hex(&habit.id_hex).unwrap();
    let edges = vault.edges_out(&checkin_id).expect("edges");
    assert!(
        edges
            .iter()
            .any(|e| e.kind == EdgeKind::ChildOf && e.target == habit_id),
        "checkin carries the pack-contract ChildOf edge"
    );
    let view = facade
        .get_entity(&checkin.entity_ref)
        .unwrap()
        .expect("checkin view");
    let body = view.body.unwrap();
    assert_eq!(
        body["role"],
        serde_json::json!(5),
        "facade stamps HabitCheckin role"
    );
    assert_eq!(body["note"], serde_json::json!("10 minutes"));
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_TASK).unwrap().len(), 2);

    // Caller-supplied role keys are rejected.
    let err = facade
        .put_habit_checkin(&HabitCheckinInput {
            habit_ref: habit.id_hex,
            id: None,
            data: Some(serde_json::json!({"role": 1})),
            occurred_at: 802,
            learned_at: None,
        })
        .expect_err("role key must be facade-stamped");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
}

#[test]
fn put_companion_record_creates_and_optionally_retires() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xE1);
    let owner = put_person(&vault, 0xE2);
    let persona = put_person(&vault, 0xE3);
    let facade = facade_for(&vault, actor);

    let active = facade
        .put_companion_record(&CompanionRecordInput {
            id: None,
            owner_ref: owner.to_hex(),
            persona_ref: persona.to_hex(),
            value: serde_json::json!({"name": "Yuki", "vibes": ["calm"]}),
            source: None,
            retired_at: None,
            learned_at: 900,
        })
        .expect("companion record");
    let record = vault
        .get_companion_record(&EntityId::from_hex(&active.id_hex).unwrap())
        .expect("read record")
        .expect("record exists");
    assert_eq!(record.lifecycle, ClaimLifecycleStatus::Active);
    assert!(!record.lifecycle_events.is_empty(), "created event stamped");

    // A second persona registered retired (migration of isActive == false).
    let persona_two = put_person(&vault, 0xE4);
    let retired = facade
        .put_companion_record(&CompanionRecordInput {
            id: None,
            owner_ref: owner.to_hex(),
            persona_ref: persona_two.to_hex(),
            value: serde_json::json!({"name": "Rei"}),
            source: Some("imported".to_owned()),
            retired_at: Some(950),
            learned_at: 900,
        })
        .expect("retired record");
    let record = vault
        .get_companion_record(&EntityId::from_hex(&retired.id_hex).unwrap())
        .expect("read record")
        .expect("record exists");
    assert_eq!(record.lifecycle, ClaimLifecycleStatus::Retracted);

    // The hard-delete resurrection guard is rechecked in the same write
    // transaction as companion creation, rather than trusting a stale
    // preflight probe for caller-supplied ids.
    let tombstoned_id = put_person(&vault, 0xE5);
    assert!(vault.delete_entity(&tombstoned_id).expect("hard delete"));
    let err = facade
        .put_companion_record(&CompanionRecordInput {
            id: Some(tombstoned_id.to_hex()),
            owner_ref: owner.to_hex(),
            persona_ref: persona.to_hex(),
            value: serde_json::json!({"name": "Never resurrect"}),
            source: None,
            retired_at: None,
            learned_at: 960,
        })
        .expect_err("hard-deleted ids must not become companion records");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        vault
            .get_companion_record(&tombstoned_id)
            .expect("read rejected record")
            .is_none()
    );
}

#[test]
fn admit_imported_claim_rides_the_ingest_trust_ceiling() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xF1);
    let subject = put_person(&vault, 0xF2);
    let facade = facade_for(&vault, actor);

    // The only registered source at base has permits_auto == false, so the
    // admission parks proposed — the gate still decides (B1a).
    let receipt = facade
        .admit_imported_claim(&AdmitImportedClaimInput {
            source_id: "jsonl-transcript".to_owned(),
            source_record_id: "row-42".to_owned(),
            id: None,
            subject_ref: subject.to_hex(),
            predicate: "eiri.onboarding.answer".to_owned(),
            value: serde_json::json!({"question_id": "q-9", "selected_option_id": "b"}),
            occurred_at: 1000,
            learned_at: None,
        })
        .expect("admission");
    assert_eq!(receipt.approval, "proposed");
    assert!(receipt.receipt_ref.starts_with("gate:"));
    let pending = facade.pending_writes(10).expect("pending");
    assert_eq!(pending.len(), 1);

    // Unregistered sources fail closed (convex_migration lands in ONE-258).
    let err = facade
        .admit_imported_claim(&AdmitImportedClaimInput {
            source_id: "convex_migration".to_owned(),
            source_record_id: "row-1".to_owned(),
            id: None,
            subject_ref: subject.to_hex(),
            predicate: "eiri.onboarding.answer".to_owned(),
            value: serde_json::json!({"question_id": "q-1"}),
            occurred_at: 1001,
            learned_at: None,
        })
        .expect_err("unknown ingest source must fail closed");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(err.suggestions.iter().any(|s| s.contains("registry")));
}

#[test]
fn blob_door_round_trips_bytes_and_dedupes_head() {
    // FINDING (flagged in the ONE-1454 report): under the DEFAULT policy
    // manifest, `blob.version` is an unknown predicate ⇒ CRITICAL
    // criticality ⇒ the engine's UserUpload auto-approval is gate-refused
    // (gate.pending.criticality_floor). The engine's own blob tests clear
    // the manifest; this test mirrors that until ONE-258's runbook installs
    // a manifest rule for blob.version.
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let actor = put_person(&vault, 0x12);
    let facade = facade_for(&vault, actor);

    let artifact = facade
        .put_blob_artifact(&BlobArtifactInput {
            id: None,
            name: "voice-note.m4a".to_owned(),
            media_type: "audio/mp4".to_owned(),
            occurred_at: 1100,
            learned_at: None,
        })
        .expect("artifact");

    let mut bytes = vec![0_u8; 2048];
    let mut state: u64 = 0x1234_5678_9ABC_DEF0;
    for chunk in bytes.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let raw = state.to_le_bytes();
        chunk.copy_from_slice(&raw[..chunk.len()]);
    }

    let version = facade
        .append_blob_version(&artifact.id_hex, &bytes, None, 1101, None)
        .expect("append");
    assert_eq!(version.version, 1);
    assert_eq!(version.content_hash_hex.len(), 64);

    let read = facade
        .read_blob_version(&artifact.id_hex, version.version)
        .expect("read")
        .expect("version exists");
    assert_eq!(read, bytes, "byte identity through the blob door");

    // Re-appending identical head bytes is a dedupe no-op.
    let again = facade
        .append_blob_version(&artifact.id_hex, &bytes, None, 1102, None)
        .expect("re-append");
    assert_eq!(again.version, 1);
}

// ── reads: list/history/retract/hydrate ─────────────────────────────────

#[test]
fn claim_retract_preserves_readable_history() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x13);
    let subject = put_person(&vault, 0x14);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("claim");
    let retracted = facade
        .claim_retract(&receipt.claim_short_id)
        .expect("retract");
    assert_eq!(
        short_id_part(&retracted.claim_short_id),
        short_id_part(&receipt.claim_short_id)
    );
    assert!(retracted.receipt_ref.starts_with("gate:"));
    assert_ne!(
        retracted.receipt_ref, receipt.receipt_ref,
        "retraction must return its own gate decision, not the earlier write receipt"
    );
    assert!(
        facade
            .receipts(50)
            .expect("receipts")
            .iter()
            .any(|entry| entry.receipt_ref == retracted.receipt_ref),
        "ordinary retraction receipt_ref must remain resolvable"
    );

    let claims = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: Some("profile.name".to_owned()),
            lifecycle: Some("retracted".to_owned()),
            limit: 10,
        })
        .expect("list retracted");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].lifecycle, "retracted");
}

#[test]
fn agent_retracts_parked_proposal_without_dismissing_unrelated_stale_consent() {
    let (_dir, vault) = open_vault();
    let agent = put_person(&vault, 0x17);
    let subject = put_person(&vault, 0x18);
    let facade = vault.memory_facade(agent, EdgeActorClass::Agent);

    let parked = facade
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("curious"),
        ))
        .expect("agent proposal parks for consent");
    assert_eq!(parked.approval, "proposed");
    let parked_id = EntityId::from_hex(
        &facade
            .get_entity(&parked.claim_short_id)
            .expect("read parked claim")
            .expect("parked claim exists")
            .id_hex,
    )
    .expect("parked claim id");

    let unrelated = facade
        .claim_upsert(&claim_input(
            "profile.color",
            &subject,
            "observed",
            serde_json::json!("teal"),
        ))
        .expect("unrelated agent proposal parks for consent");
    assert_eq!(unrelated.approval, "proposed");
    let unrelated_id = EntityId::from_hex(
        &facade
            .get_entity(&unrelated.claim_short_id)
            .expect("read unrelated claim")
            .expect("unrelated claim exists")
            .id_hex,
    )
    .expect("unrelated claim id");

    let pending_before = vault.pending_gate_consents(10).expect("pending consent");
    let parked_pending = pending_before
        .iter()
        .find(|record| record.claim_id == *parked_id.as_bytes())
        .expect("parked proposal consent")
        .clone();
    assert!(
        pending_before
            .iter()
            .any(|record| record.claim_id == *parked_id.as_bytes()),
        "the self-authored proposal must be parked before retraction"
    );
    assert!(
        pending_before
            .iter()
            .any(|record| record.claim_id == *unrelated_id.as_bytes()),
        "the unrelated proposal must be parked before retraction"
    );

    let retract_receipt = facade
        .claim_retract(&parked.claim_short_id)
        .expect("agent retracts its own parked proposal");
    let retract_decision = vault
        .gate_decisions(10)
        .expect("gate decisions")
        .into_iter()
        .find(|record| {
            retract_receipt.receipt_ref == format!("gate:{}", record.decision_id.to_hex())
        })
        .expect("retraction consent receipt");
    assert_eq!(retract_decision.outcome, "retracted");
    assert_eq!(
        retract_decision.reason_codes,
        vec!["gate.pending.claim_retracted"]
    );
    assert_eq!(retract_decision.diff_handle, parked_pending.diff_handle);
    assert_eq!(
        retract_decision.read_frontier_hash, parked_pending.read_frontier_hash,
        "withdrawal receipt preserves the consent's original policy binding"
    );

    // Retraction is a state transition, not a tray-only dismissal: the
    // claim remains stored as bitemporal history with its lifecycle closed.
    let retracted = vault
        .get_claim(&parked_id)
        .expect("read retracted claim")
        .expect("retracted claim remains stored");
    assert_eq!(retracted.lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(
        retracted.valid_to.is_some(),
        "retraction stamps a valid end"
    );

    let pending_after_retract = vault.pending_gate_consents(10).expect("pending consent");
    assert!(
        !pending_after_retract
            .iter()
            .any(|record| record.claim_id == *parked_id.as_bytes()),
        "retracted proposal must no longer occupy the consent tray"
    );
    assert!(
        pending_after_retract
            .iter()
            .any(|record| record.claim_id == *unrelated_id.as_bytes()),
        "retract must not resolve unrelated parked consent"
    );

    // Ordinary content drift remains fail-closed. The retract-only rebinding
    // must not make a different parked proposal redeemable by changing it.
    let mut drifted = vault
        .get_claim(&unrelated_id)
        .expect("read unrelated claim")
        .expect("unrelated claim remains stored");
    drifted.value = rmpv::Value::from("blue");
    drifted.approval = ClaimApprovalStatus::Approved;
    let err = vault
        .put_claim(&unrelated_id, &drifted, test_time(101), 101)
        .expect_err("unrelated drifted consent remains stale");
    assert!(matches!(err, Error::GateConsentStale { claim_id } if claim_id == unrelated_id));
    assert!(
        vault
            .pending_gate_consents(10)
            .expect("pending consent")
            .iter()
            .any(|record| record.claim_id == *unrelated_id.as_bytes()),
        "stale unrelated proposal must stay parked"
    );
}

#[test]
fn same_id_replacement_cannot_be_retracted_by_the_prior_agent() {
    let (_dir, vault) = open_vault();
    let first_agent = put_person(&vault, 0x19);
    let replacement_agent = put_person(&vault, 0x1A);
    let subject = put_person(&vault, 0x1B);
    let first_facade = vault.memory_facade(first_agent, EdgeActorClass::Agent);
    let replacement_facade = vault.memory_facade(replacement_agent, EdgeActorClass::Agent);
    let claim_id = EntityId::from_bytes([0x1C; 16]).expect("claim id");

    let mut first = claim_input(
        "profile.mood",
        &subject,
        "observed",
        serde_json::json!("curious"),
    );
    first.id = Some(claim_id.to_hex());
    first_facade
        .claim_upsert(&first)
        .expect("first agent parks proposal");

    let mut replacement = claim_input(
        "profile.color",
        &subject,
        "observed",
        serde_json::json!("teal"),
    );
    replacement.id = Some(claim_id.to_hex());
    // Reproduce the former split-transaction race deterministically: the
    // replacement lands after call setup but immediately before the retraction
    // write transaction begins. The fixed path authorizes only after acquiring
    // that transaction, so it observes and rejects the replacement author.
    let err = first_facade
        .claim_retract_with_pre_txn_hook(&claim_id.to_hex(), || {
            replacement_facade
                .claim_upsert(&replacement)
                .expect("second agent replaces same id in former race window");
        })
        .expect_err("prior author has no authority over same-id replacement");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    let current = vault
        .get_claim(&claim_id)
        .expect("read replacement")
        .expect("replacement remains");
    assert_eq!(current.predicate, "profile.color");
    assert_eq!(current.lifecycle, ClaimLifecycleStatus::Active);
    assert!(
        vault
            .pending_gate_consents(10)
            .expect("pending consent")
            .iter()
            .any(|record| record.claim_id == *claim_id.as_bytes()),
        "replacement agent's consent row remains actionable"
    );
}

#[test]
fn hydrate_round_trips_witness_short_ids() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x15);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x16; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "hydrate me")],
            occurred_at: 1200,
        })
        .expect("witness");

    let mut refs = vec![receipt.turn_short_id.clone()];
    refs.extend(receipt.message_short_ids.iter().cloned());
    let views = facade.hydrate(&refs).expect("hydrate");
    assert_eq!(views.len(), 2);
    assert_eq!(views[0].kind, "TURN");
    assert_eq!(views[1].kind, "MESSAGE");
    assert_eq!(
        views[1].body.as_ref().unwrap()["content"],
        serde_json::json!("hydrate me")
    );

    let err = facade
        .hydrate(&["zz999:ff".to_owned()])
        .expect_err("dangling short ref must be a typed error");
    assert_eq!(err.code, FACADE_CODE_NOT_FOUND);
}

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
    for (id_hex, kind, convex_id) in [
        (&conversation_hex, "CONVERSATION", "conv-11"),
        (&turn_hex, "TURN", "turn-77"),
    ] {
        facade
            .put_structural(&StructuralPutInput {
                id: Some(id_hex.clone()),
                kind: kind.to_owned(),
                body: serde_json::json!({"convex_id": convex_id}),
                text_fields: None,
                edges: None,
                occurred_at: 650,
                learned_at: None,
            })
            .expect("pinned parent put");
    }
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

    assert_eq!(
        vault.get_raw(&turn_id).unwrap().expect("turn after"),
        turn_raw,
        "pinned {{convex_id}} TURN body must be byte-identical after witness"
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

    let mint = |facade: &MemoryFacade<'_>, kind: &str| {
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
    // A3 positive case: a SAME-TYPE re-put at a soft-deleted id stays
    // legal — guards against a future over-broadened refusal that would
    // start blocking legitimate soft re-puts.
    let recreated = put_kind("EVENT", &soft_victim.to_hex(), 706)
        .expect("same-type re-put after soft delete must succeed");
    assert_eq!(recreated.id_hex, soft_victim.to_hex());
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
    let subject = put_person(&vault, 0x24);
    let facade = facade_for(&vault, actor);

    facade
        .put_structural(&StructuralPutInput {
            id: Some(subject.to_hex()),
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
        .expect("subject text");

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
    let subject = put_person(&vault, 0x37);
    let facade = facade_for(&vault, actor);

    facade
        .put_structural(&StructuralPutInput {
            id: Some(subject.to_hex()),
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
        .expect("subject");
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
        AdmitDreamerConsolidationJob, AdmitDreamerJob, CompleteDreamerJob,
        CompleteDreamerJobOutcome, DreamerAdmissionOutcome, DreamerClaimAuthoringAdmission,
        DreamerClaimAuthoringBatchTier, DreamerConsolidationAdmissionOutcome,
        DreamerConsolidationScope, DreamerRunnerStore,
    };

    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x51);
    let subject = put_person(&vault, 0x52);
    let facade = facade_for(&vault, actor);

    // Enqueue through the bridge verb; advisory dedupe coalesces re-enqueues.
    let job = facade
        .enqueue_consolidation(&ConsolidationJobInput {
            scope: "micro".to_owned(),
            input: serde_json::json!({"window": "w-1"}),
            run_id: Some("run-bridge-1".to_owned()),
            dedupe_key: Some("bridge-dedupe-1".to_owned()),
            now: Some(2000),
        })
        .expect("enqueue");
    assert_eq!(job.state, "queued");
    assert!(!job.existing);
    let again = facade
        .enqueue_consolidation(&ConsolidationJobInput {
            scope: "micro".to_owned(),
            input: serde_json::json!({"window": "w-1"}),
            run_id: Some("run-bridge-1".to_owned()),
            dedupe_key: Some("bridge-dedupe-1".to_owned()),
            now: Some(2001),
        })
        .expect("re-enqueue");
    assert!(again.existing, "advisory dedupe coalesces");
    assert_eq!(again.job_ref, job.job_ref);

    // Poll model: queued → (admit engine-side) → leased → completed.
    let status = facade
        .dreamer_job_status(&job.job_ref)
        .expect("status")
        .expect("job exists");
    assert_eq!(status.state, "queued");
    assert_eq!(status.run_id.as_deref(), Some("run-bridge-1"));

    let store = DreamerRunnerStore::new(&vault);
    let admitted = store
        .admit_next_consolidation(AdmitDreamerConsolidationJob {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 7,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerJob {
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
        admitted_job,
    )) = admitted
    else {
        panic!("expected admitted consolidation job, got {admitted:?}");
    };
    let leased = facade
        .dreamer_job_status(&job.job_ref)
        .expect("status")
        .expect("job exists");
    assert_eq!(leased.state, "leased");
    assert_eq!(leased.lease_owner.as_deref(), Some("bridge-test-worker"));

    // AC-5 (W3 non-contention): an interactive witness during the running
    // consolidation succeeds without waiting on the job.
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
        .complete(CompleteDreamerJob {
            id: admitted_job.status.job.id,
            lease_owner: "bridge-test-worker".to_owned(),
            attempt_count: admitted_job.status.job.attempt_count,
            now: 2005,
        })
        .expect("complete");
    assert!(matches!(completed, CompleteDreamerJobOutcome::Completed(_)));
    let done = facade
        .dreamer_job_status(&job.job_ref)
        .expect("status")
        .expect("job exists");
    assert_eq!(done.state, "completed");

    // Unknown scope fails closed.
    let err = facade
        .enqueue_consolidation(&ConsolidationJobInput {
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
    let enqueue = |facade: &MemoryFacade<'_>| {
        facade.enqueue_consolidation(&ConsolidationJobInput {
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
    use crate::job_queue::JobQueue;

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
    let queue = JobQueue::new(&vault);
    let scheduled: Vec<_> = queue
        .list()
        .expect("list jobs")
        .into_iter()
        .filter(|job| job.kind == BRIDGE_OUTBOUND_JOB_KIND)
        .collect();
    assert_eq!(scheduled.len(), 1, "one durable schedule row");

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
/// enqueue, so it leaves no orphan job/dedupe entry and a retry (on a
/// supported channel, same idempotency key) is not wedged as an existing
/// dedupe hit.
#[test]
fn schedule_outbound_unsupported_channel_leaves_no_orphan_and_allows_retry() {
    use crate::job_queue::{JobQueue, JobState};

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
    let queue = JobQueue::new(&vault);
    let live: Vec<_> = queue
        .list()
        .expect("list jobs")
        .into_iter()
        .filter(|job| job.kind == BRIDGE_OUTBOUND_JOB_KIND && job.state != JobState::Cancelled)
        .collect();
    assert!(
        live.is_empty(),
        "unsupported channel must not leave a live outbound job"
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
/// surface keyed by job id; the dedupe branch reads it back.
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
