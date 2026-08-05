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
fn witness_create_or_get_reuses_containers_and_skips_system_author_edge() {
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
            conversation_ref: conversation_hex,
            turn_ref: Some(turn_hex.clone()),
            messages: vec![witness_message(1, WitnessAuthor::System, "system row")],
            occurred_at: 601,
        })
        .expect("second witness");
    assert_eq!(first.turn_short_id, second.turn_short_id);

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

    // System-authored rows get no AuthoredBy edge (design §2.1).
    let system_view = facade
        .get_entity(&second.message_short_ids[0])
        .unwrap()
        .expect("system message");
    let system_id = EntityId::from_hex(&system_view.id_hex).unwrap();
    let kinds: Vec<EdgeKind> = vault
        .edges_out(&system_id)
        .expect("edges")
        .iter()
        .map(|edge| edge.kind)
        .collect();
    assert!(!kinds.contains(&EdgeKind::AuthoredBy));
    assert!(kinds.contains(&EdgeKind::PartOf));

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
fn put_structural_mints_but_never_overwrites_task_entities() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xD2);
    let facade = facade_for(&vault, actor);
    let task = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "TASK".to_owned(),
            body: serde_json::json!({"role": 4, "content": "original"}),
            text_fields: None,
            edges: None,
            occurred_at: 810,
            learned_at: None,
        })
        .expect("fresh task mint");
    let task_ref = EntityId::from_hex(&task.id_hex).expect("task id");
    let before = vault
        .get_raw(&task_ref)
        .expect("read task before")
        .expect("task exists");

    let error = facade
        .put_structural(&StructuralPutInput {
            id: Some(task.id_hex),
            kind: "TASK".to_owned(),
            body: serde_json::json!({"role": 1, "owner_ref": actor.to_hex()}),
            text_fields: None,
            edges: None,
            occurred_at: 811,
            learned_at: None,
        })
        .expect_err("TASK overwrite must be refused");
    let after = vault
        .get_raw(&task_ref)
        .expect("read task after")
        .expect("task remains");

    assert_eq!(error.code, FACADE_CODE_FORBIDDEN);
    assert_eq!(usize::from(before == after), 1);

    // A NON-TASK put targeting the same id must also be refused: the guard keys
    // on the STORED type, not the incoming kind, so a TASK body cannot be
    // clobbered by reusing its id with a different kind.
    let non_task_error = facade
        .put_structural(&StructuralPutInput {
            id: Some(task_ref.to_hex()),
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "not-a-task"}),
            text_fields: None,
            edges: None,
            occurred_at: 812,
            learned_at: None,
        })
        .expect_err("non-TASK overwrite of a TASK id must be refused");
    let after_non_task = vault
        .get_raw(&task_ref)
        .expect("read task after non-task")
        .expect("task remains");
    assert_eq!(non_task_error.code, FACADE_CODE_FORBIDDEN);
    assert_eq!(usize::from(before == after_non_task), 1);
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task entities")
            .len(),
        1
    );
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
    let enqueue = |facade: &MemoryFacade<'_>| {
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

// ── RT-03 (ONE-1685): turn-witness bumps the open session ───────────────

#[test]
fn witness_bumps_open_session_activity_atomically() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x71);
    let facade = facade_for(&vault, actor);

    let session = match vault.mint_session(400).expect("mint session") {
        crate::session_lifecycle::SessionMintOutcome::Minted(id) => id,
        other => panic!("expected fresh mint, got {other:?}"),
    };

    let conversation_hex = EntityId::from_bytes([0x72; 16]).expect("conv id").to_hex();
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "hello again")],
            occurred_at: 500,
        })
        .expect("witness turn");

    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session still open");
    assert_eq!(open.session, session);
    assert_eq!(
        open.last_activity, 500,
        "turn-witness bumps last_activity to the turn's occurred_at"
    );

    // An OLDER turn (backfill) never rewinds the activity clock.
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "backfilled note")],
            occurred_at: 450,
        })
        .expect("witness backfill turn");
    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session still open");
    assert_eq!(open.last_activity, 500, "activity clock is monotonic");
}

#[test]
fn witness_without_an_open_session_stays_valid() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x73);
    let facade = facade_for(&vault, actor);

    // ARCH-0002 open-endedness: turns outside any session are valid; the
    // bump is a no-op, not an error, and no session is minted.
    let conversation_hex = EntityId::from_bytes([0x74; 16]).expect("conv id").to_hex();
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "sessionless turn")],
            occurred_at: 600,
        })
        .expect("witness sessionless turn");
    assert_eq!(vault.open_session().expect("open session read"), None);
}

// ── S-AUTH3: owner-verb authority-log teeth (ONE-1633 / ESB-C) ───────────

/// A single-key authority root. One roster key means no peer cosign is
/// required, so a rooted facade fixture is two entries total.
fn authority_root(
    seed: u8,
) -> (
    crate::authority::AuthorityLogEntry,
    ed25519_dalek::SigningKey,
) {
    use crate::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
    };
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let entry = AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [seed.wrapping_add(10); 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
    };
    (sign_authority(entry, &signing), signing)
}

fn sign_authority(
    mut entry: crate::authority::AuthorityLogEntry,
    key: &ed25519_dalek::SigningKey,
) -> crate::authority::AuthorityLogEntry {
    use ed25519_dalek::Signer;
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

/// Roots `vault` and binds `actor` at `class` in ONE atomic ceremony.
fn root_vault_binding(vault: &crate::Vault, seed: u8, actor: EntityId, class: &str) {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (genesis, signing) = authority_root(seed);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let bind = sign_authority(
        AuthorityLogEntry {
            schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: 1,
            parent_hashes: vec![
                crate::authority::authority_entry_hash(&genesis).expect("genesis hash"),
            ],
            op: AuthorityOp::BindActor {
                authority_key: key.clone(),
                actor_ref: actor,
                actor_class: class.to_owned(),
                epoch: 1,
            },
            signer: AuthoritySignature {
                suite: key.suite(),
                public_key: key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: 101,
        },
        &signing,
    );
    vault
        .put_authority_log_entries(&[(genesis, test_time(1), 1), (bind, test_time(2), 2)])
        .expect("atomic genesis owner-binding");
}

/// T9: on a ROOTED vault the three owner verbs demand a folded ACTIVE
/// human-class binding. This is the ESB-C fix: asserting `human` at the
/// facade is no longer enough — the authority log has to agree.
#[test]
fn owner_verbs_require_active_owner_binding_when_rooted() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x5E);
    let agent = put_person(&vault, 0x5F);
    let subject = put_person(&vault, 0x60);
    let owner_facade = facade_for(&vault, owner);
    let agent_facade = vault.memory_facade(agent, EdgeActorClass::Agent);
    let agent_claim = agent_facade
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("calm"),
        ))
        .expect("agent claim");

    root_vault_binding(&vault, 0x71, owner, "human");

    // Bound owner: every owner verb still works. No capability is removed by
    // this lane — the binding just has to exist.
    owner_facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "minted"}),
            text_fields: None,
            edges: None,
            occurred_at: 700,
            learned_at: None,
        })
        .expect("bound owner mints PERSON");
    owner_facade
        .claim_retract(&agent_claim.claim_short_id)
        .expect("bound owner retracts another actor's claim");
    owner_facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("bound owner deletes");

    // An UNBOUND human actor on the same rooted vault is refused on all three.
    let stranger = put_person(&vault, 0x61);
    let stranger_facade = facade_for(&vault, stranger);
    let victim = put_person(&vault, 0x62);
    let other_claim = agent_facade
        .claim_upsert(&claim_input(
            "profile.color",
            &victim,
            "observed",
            serde_json::json!("teal"),
        ))
        .expect("second agent claim");
    for err in [
        stranger_facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "forged"}),
                text_fields: None,
                edges: None,
                occurred_at: 701,
                learned_at: None,
            })
            .expect_err("unbound PERSON mint"),
        stranger_facade
            .claim_retract(&other_claim.claim_short_id)
            .expect_err("unbound cross-actor retract"),
        stranger_facade
            .safe_delete(&victim.to_hex(), SafeDeleteReason::UserDelete)
            .expect_err("unbound delete"),
    ] {
        assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
        assert!(
            err.message.contains("no active owner binding"),
            "{}",
            err.message
        );
    }

    // Retracting your OWN claim is not an owner power and needs no binding.
    let self_claim = stranger_facade
        .claim_upsert(&claim_input(
            "profile.note",
            &victim,
            "user_stated",
            serde_json::json!("mine"),
        ))
        .expect("stranger writes own claim");
    stranger_facade
        .claim_retract(&self_claim.claim_short_id)
        .expect("self-retraction never needs an owner binding");
}

/// T10: an UNROOTED vault keeps today's store-truth behavior exactly.
///
/// This pins the ratified enforcement mode (S-AUTH3 D6 fork (a),
/// "enforce-when-root-exists"): teeth arrive when a host DECLARES authority,
/// not before. Every shipped vault has no authority log at all, so nothing
/// breaks on upgrade. [owner] fork note: under the alternate "hard flip"
/// ruling these three expectations invert to FORBIDDEN.
#[test]
fn unrooted_vault_keeps_store_truth_owner_verbs() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x63);
    let agent = put_person(&vault, 0x64);
    let subject = put_person(&vault, 0x65);
    let owner_facade = facade_for(&vault, owner);
    let agent_claim = vault
        .memory_facade(agent, EdgeActorClass::Agent)
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("calm"),
        ))
        .expect("agent claim");

    assert!(
        vault.authority_fold().expect("fold").vault_id.is_none(),
        "fixture must have no declared authority root"
    );
    owner_facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "minted"}),
            text_fields: None,
            edges: None,
            occurred_at: 702,
            learned_at: None,
        })
        .expect("unrooted PERSON mint unchanged");
    owner_facade
        .claim_retract(&agent_claim.claim_short_id)
        .expect("unrooted cross-actor retract unchanged");
    owner_facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("unrooted delete unchanged");
}

/// T11: the binding class is EXACT and revocation is real.
#[test]
fn exact_class_binding_no_cross_class_satisfaction() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x66);
    let subject = put_person(&vault, 0x67);
    // Bound at "agent" only. A human-class owner verb must NOT be satisfied
    // by an agent-class binding — near-miss classes are the ESB-C defect.
    root_vault_binding(&vault, 0x72, owner, "agent");

    let err = facade_for(&vault, owner)
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("agent-class binding must not satisfy a human-class verb");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        err.message.contains("no active owner binding"),
        "{}",
        err.message
    );
}

/// T11b: a RevokeActor watermark takes the owner's teeth away again.
#[test]
fn revoked_binding_forbids_owner_verbs() {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x68);
    let subject = put_person(&vault, 0x69);
    let facade = facade_for(&vault, owner);

    let (genesis, signing) = authority_root(0x73);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let genesis_hash = crate::authority::authority_entry_hash(&genesis).expect("genesis hash");
    let owner_entry = |seq: u64, op: AuthorityOp, parents: Vec<[u8; 32]>| {
        sign_authority(
            AuthorityLogEntry {
                schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq,
                parent_hashes: parents,
                op,
                signer: AuthoritySignature {
                    suite: key.suite(),
                    public_key: key.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts: 100 + seq,
            },
            &signing,
        )
    };
    let bind = owner_entry(
        1,
        AuthorityOp::BindActor {
            authority_key: key.clone(),
            actor_ref: owner,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        vec![genesis_hash],
    );
    let bind_hash = crate::authority::authority_entry_hash(&bind).expect("bind hash");
    vault
        .put_authority_log_entries(&[(genesis, test_time(1), 1), (bind, test_time(2), 2)])
        .expect("root + bind");
    facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("bound owner deletes");

    let revoke = owner_entry(
        2,
        AuthorityOp::RevokeActor {
            authority_key: key.clone(),
            epoch: 1,
        },
        vec![bind_hash],
    );
    vault
        .put_authority_log_entries(&[(revoke, test_time(3), 3)])
        .expect("revoke binding");

    let victim = put_person(&vault, 0x6A);
    let err = facade
        .safe_delete(&victim.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("a revoked binding must lose its owner teeth");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        err.message.contains("no active owner binding"),
        "{}",
        err.message
    );
}

/// Roots `vault`, binds `actor` as `human`, and returns the SIGNED
/// `RevokeActor` that takes the binding away again — unpersisted, so a caller
/// chooses the exact instant it lands.
fn root_binding_with_pending_revocation(
    vault: &crate::Vault,
    seed: u8,
    actor: EntityId,
) -> crate::authority::AuthorityLogEntry {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (genesis, signing) = authority_root(seed);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let genesis_hash = crate::authority::authority_entry_hash(&genesis).expect("genesis hash");
    let owner_entry = |seq: u64, op: AuthorityOp, parents: Vec<[u8; 32]>| {
        sign_authority(
            AuthorityLogEntry {
                schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq,
                parent_hashes: parents,
                op,
                signer: AuthoritySignature {
                    suite: key.suite(),
                    public_key: key.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts: 100 + seq,
            },
            &signing,
        )
    };
    let bind = owner_entry(
        1,
        AuthorityOp::BindActor {
            authority_key: key.clone(),
            actor_ref: actor,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        vec![genesis_hash],
    );
    let bind_hash = crate::authority::authority_entry_hash(&bind).expect("bind hash");
    vault
        .put_authority_log_entries(&[(genesis, test_time(1), 1), (bind, test_time(2), 2)])
        .expect("root + bind");
    owner_entry(
        2,
        AuthorityOp::RevokeActor {
            authority_key: key.clone(),
            epoch: 1,
        },
        vec![bind_hash],
    )
}

/// fix-leg 5 item 1: the delete owner-gate is TOCTOU-closed.
///
/// `evaluate_deletion_gate` folds the owner binding in a read txn it then
/// DROPS. Everything the destructive transactions do afterwards runs on that
/// dropped snapshot's authority — so a `RevokeActor` committed in the window
/// between the two was, before this fix, never observed and the delete tore
/// anyway. The sibling owner verbs (`claim_retract`, the structural arm) never
/// had the hole because they fold INSIDE their write txns; this drives the race
/// deterministically through the ONE-1149 rendezvous seam and pins the same
/// behavior for deletion.
#[test]
fn revocation_racing_a_gated_delete_refuses_and_tears_nothing() {
    for reason in [
        SafeDeleteReason::UserDelete,
        SafeDeleteReason::UserHardDelete,
    ] {
        let (_dir, vault) = open_vault();
        let owner = put_person(&vault, 0x90);
        let subject = put_person(&vault, 0x91);
        let revoke = root_binding_with_pending_revocation(&vault, 0x92, owner);

        // Control: the binding is live, so the gate passes end to end.
        let warmup = put_person(&vault, 0x93);
        facade_for(&vault, owner)
            .safe_delete(&warmup.to_hex(), reason)
            .expect("control: a bound owner deletes");

        let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
        // The rendezvous fires from inside the delete AFTER its header read
        // proves the target exists and BEFORE it takes any write lock — i.e.
        // squarely inside the gate-to-purge window this test is about.
        let (tx, rx) = std::sync::mpsc::sync_channel::<()>(0);
        crate::deletion::install_after_header_read_signal(tx);

        let err = std::thread::scope(|scope| {
            let deleter_gate = std::sync::Arc::clone(&gate);
            let vault_ref = &vault;
            let deleter = scope.spawn(move || {
                deleter_gate.wait();
                facade_for(vault_ref, owner).safe_delete(&subject.to_hex(), reason)
            });
            // Stage the revocation in a HELD write txn: LMDB MVCC keeps it
            // invisible to the deleter's gate fold, so the gate is guaranteed
            // to evaluate against the still-live binding.
            let mut wtxn = vault.store.env.write_txn().expect("write txn");
            vault
                .put_authority_log_entries_in_txn(&mut wtxn, &[(revoke, test_time(3), 3)])
                .expect("stage revocation");
            gate.wait();
            // The deleter has read its header and signalled; commit the
            // revocation now and release the write lock it is about to want.
            rx.recv()
                .expect("deleter must signal after the header read");
            wtxn.commit().expect("commit revocation");
            deleter
                .join()
                .expect("deleter thread must not panic")
                .expect_err("a revocation landing before the destructive commit must refuse")
        });

        assert_eq!(err.code, FACADE_CODE_FORBIDDEN, "reason {reason:?}");
        assert!(
            err.message.contains("no active owner binding"),
            "reason {reason:?}: the refusal must name the real cause, not a \
             generic concurrency error: {}",
            err.message
        );
        // Nothing torn: the subject survives intact.
        assert_eq!(
            vault.get_entity_type(&subject).expect("get subject"),
            Some(ENTITY_TYPE_PERSON),
            "reason {reason:?}: a refused delete must leave the entity whole"
        );
    }
}

/// fix-leg 6: a refusal must not publish.
///
/// fix-5 re-folded the owner at five destructive sites, but the sync leg's
/// authority lived in `stage_deletion_gate_recovery`'s transaction, which
/// COMMITS and drops its snapshot; `finish_crdt_tombstone_persist` then wrote
/// the CRDT snapshot, the `u:w:` carrier and the delete-bearing `q:` row in a
/// LATER transaction carrying no authority at all. A `RevokeActor` landing
/// between the two therefore let the tombstone reach peers and only the purge
/// re-check refused — `safe_delete` returned FORBIDDEN *after* an unauthorized
/// deletion had already been published, which is unrecoverable: a peer that
/// applied it has hard-deleted the entity.
///
/// The rendezvous fires exactly in that interval. The assertions are the
/// no-publish invariant, carrier by carrier: no live-doc tombstone, no `d:w:`
/// snapshot, no `u:w:` row, no `q:` queue row, and no pending gate sidecar
/// that a later replay could redeem.
#[cfg(feature = "sync")]
#[test]
fn revocation_racing_the_tombstone_publish_refuses_and_publishes_nothing() {
    use std::sync::Arc;

    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let _serial = lock_delete_rendezvous();
    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Arc::new(crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
    let owner = put_person(&vault, 0x94);
    let subject = put_person(&vault, 0x95);
    let revoke = root_binding_with_pending_revocation(&vault, 0x96, owner);

    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "facade-publish-boundary",
    ));
    // A connected peer: `route_live` would hand it the tombstone the instant
    // the publish leaked one.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.outbound().attach(tx);
    let window_key = WindowKey::from_timestamp(1);
    let window = manager
        .open_window(&window_key)
        .expect("open live deletion window");

    // Control: with the binding live, the same path publishes end to end — so
    // the assertions below pin the refusal, not a broken fixture.
    let warmup = put_person(&vault, 0x97);
    facade_for(&vault, owner)
        .safe_delete(&warmup.to_hex(), SafeDeleteReason::UserHardDelete)
        .expect("control: a bound owner publishes a tombstone");
    rx.try_recv().expect("control: the peer receives it");

    // Two-phase rendezvous: `arrived` fires once the deleter's gate sidecar is
    // durably staged (its txn committed, no lock held); `resume` releases it
    // into the publish txn after the revocation has landed. The deleter's own
    // staging txn takes the write lock, so the fix-5 held-txn trick would
    // deadlock here — the revocation has to commit while the deleter parks.
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
    crate::deletion::install_delete_rendezvous(
        crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
        subject,
        arrived_tx,
        resume_rx,
    );

    let (err, staged_decision_id) = std::thread::scope(|scope| {
        let vault_ref = &vault;
        let deleter = scope.spawn(move || {
            facade_for(vault_ref, owner)
                .safe_delete(&subject.to_hex(), SafeDeleteReason::UserHardDelete)
        });
        // The staged decision id: a refused delete returns no request id, so
        // this is the only handle on the sidecar the refusal must withdraw.
        let staged_decision_id = arrived_rx
            .recv()
            .expect("deleter must signal once its gate sidecar is staged")
            .expect("a hard arm stages a gate sidecar and names it here");
        // The pre-txn gate and the staging re-fold have BOTH already passed on
        // the live binding; the delete is parked believing it is authorized.
        vault
            .put_authority_log_entries(&[(revoke, test_time(3), 3)])
            .expect("commit revocation inside the publish window");
        resume_tx.send(()).expect("release the deleter");
        let err = deleter
            .join()
            .expect("deleter thread must not panic")
            .expect_err("a revocation landing before the publish commit must refuse");
        (err, staged_decision_id)
    });

    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        err.message.contains("no active owner binding"),
        "the parked pre-gate error must survive the publish boundary, not \
         degrade to a generic concurrency code: {}",
        err.message
    );

    // Victim intact.
    assert_eq!(
        vault.get_entity_type(&subject).expect("get subject"),
        Some(ENTITY_TYPE_PERSON),
        "a refused delete must leave the entity whole"
    );

    // No carrier published — live doc, snapshot, update row, queue row.
    assert!(
        window
            .doc
            .get_map("tombstones")
            .get(&subject.to_hex())
            .is_none(),
        "a refused delete must not leave a tombstone in the shared live doc"
    );
    assert!(
        rx.try_recv().is_err(),
        "a refused delete must not route an outbound update to the peer"
    );
    let snapshot = vault
        .sync_state_get(&format!("d:w:{window_key}"))
        .expect("read persisted window snapshot");
    if let Some(snapshot) = snapshot {
        let persisted = crate::sync::loro_support::doc_from_snapshot(&snapshot)
            .expect("persisted snapshot decodes");
        assert!(
            persisted
                .get_map("tombstones")
                .get(&subject.to_hex())
                .is_none(),
            "the refused tombstone must not reach the d:w: snapshot"
        );
    }
    for update_key in vault
        .sync_state_keys_with_prefix(&format!("u:w:{window_key}:"))
        .expect("read pending update rows")
    {
        let bytes = vault
            .sync_state_get(&update_key)
            .expect("read update row")
            .expect("update row exists");
        let replayed = crate::sync::schema::create_window_doc("probe", &window_key);
        crate::sync::loro_support::import_doc(&replayed, &bytes).expect("update row imports");
        assert!(
            replayed
                .get_map("tombstones")
                .get(&subject.to_hex())
                .is_none(),
            "the refused tombstone must not reach a u:w: carrier ({update_key})"
        );
    }
    let queue = crate::sync::SyncQueue::new(Arc::clone(&vault)).expect("open sync queue");
    for queued in queue.drain_updates().expect("drain queued updates") {
        let replayed = crate::sync::schema::create_window_doc("probe", &window_key);
        crate::sync::loro_support::import_doc(&replayed, &queued.encoded)
            .expect("queued update imports");
        assert!(
            replayed
                .get_map("tombstones")
                .get(&subject.to_hex())
                .is_none(),
            "the refused tombstone must not reach a delete-bearing q: row"
        );
    }

    // No pending gate sidecar: the staging from the earlier txn must be
    // withdrawn by the refusal itself, or a later replay would redeem it as a
    // pending AUTHORIZED deletion.
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert!(
        vault
            .store
            .pending_deletion_gate_decision_in_txn(&rtxn, staged_decision_id)
            .expect("read sidecar")
            .is_none(),
        "a refused publish must leave no redeemable authority sidecar"
    );
    drop(rtxn);
    // ...and no authority record was minted for a deletion that never happened.
    assert!(
        vault
            .gate_decisions(50)
            .expect("gate decisions")
            .iter()
            .all(|decision| decision.decision_id != staged_decision_id),
        "a refused publish must mint no gate decision"
    );
}

/// A vault wired for the fix-leg 7 publish-boundary regressions: an attached
/// peer channel plus, on the LIVE leg, an open registry window — so both halves
/// of "did this delete publish?" are observable, the shared live doc and the
/// outbound route.
///
/// `window: None` is the TRANSIENT leg (window never opened), where the publish
/// takes the import-merge path instead of the shared doc. It is a genuinely
/// different code path through `write_crdt_tombstone`, so every regression here
/// runs both.
/// Vector width for the orphan-residue fixture. Small and arbitrary — the
/// headerless delete door only cares that a `vectors` row exists.
#[cfg(feature = "sync")]
const RESIDUE_VECTOR_DIMS: usize = 4;

#[cfg(feature = "sync")]
struct PublishBoundaryHarness {
    _dir: tempfile::TempDir,
    vault: std::sync::Arc<crate::Vault>,
    window: Option<std::sync::Arc<crate::sync::window::LoadedWindow>>,
    window_key: crate::sync::WindowKey,
    outbound: tokio::sync::mpsc::UnboundedReceiver<crate::sync::types::LocalUpdate>,
    _manager: std::sync::Arc<crate::sync::WindowManager>,
}

#[cfg(feature = "sync")]
impl PublishBoundaryHarness {
    fn open(label: &str, live_window: bool) -> Self {
        Self::open_with_config(label, live_window, VaultConfig::default())
    }

    /// [`Self::open`] with an embedding model declared, which
    /// `ensure_model_id_for_vector_write` requires before any vector write —
    /// the only way to build the orphan-vector residue the headerless delete
    /// door needs.
    fn open_for_vector_residue(label: &str, live_window: bool) -> Self {
        Self::open_with_config(
            label,
            live_window,
            VaultConfig {
                embedding_model: Some("test-model-v1".to_owned()),
                dimensions: RESIDUE_VECTOR_DIMS,
                ..VaultConfig::default()
            },
        )
    }

    fn open_with_config(label: &str, live_window: bool, config: VaultConfig) -> Self {
        use std::sync::Arc;

        use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(crate::Vault::open(dir.path(), config).expect("open vault"));
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            label,
        ));
        let (tx, outbound) = tokio::sync::mpsc::unbounded_channel();
        manager.outbound().attach(tx);
        // Every fixture entity is put at `learned_at = 1`, so this is the window
        // the headerful deletes address.
        let window_key = WindowKey::from_timestamp(1);
        // `open_window` also attaches the manager to the vault, which is what
        // routes deletes at all — the transient leg does that explicitly so its
        // outbound assertions mean something.
        let window = if live_window {
            Some(
                manager
                    .open_window(&window_key)
                    .expect("open live deletion window"),
            )
        } else {
            manager.attach_to_vault();
            None
        };
        Self {
            _dir: dir,
            vault,
            window,
            window_key,
            outbound,
            _manager: manager,
        }
    }

    /// Whether the shared live doc carries a tombstone for `id`. Vacuously
    /// false on the transient leg, which has no live doc to carry one.
    fn live_doc_tombstoned(&self, id: &EntityId) -> bool {
        self.window
            .as_ref()
            .is_some_and(|window| window.doc.get_map("tombstones").get(&id.to_hex()).is_some())
    }

    /// Whether the persisted `d:w:` snapshot carries a tombstone for `id`.
    /// A window with no snapshot row yet trivially carries none.
    fn snapshot_tombstoned(&self, id: &EntityId) -> bool {
        let Some(snapshot) = self
            .vault
            .sync_state_get(&format!("d:w:{}", self.window_key))
            .expect("read persisted window snapshot")
        else {
            return false;
        };
        crate::sync::loro_support::doc_from_snapshot(&snapshot)
            .expect("persisted snapshot decodes")
            .get_map("tombstones")
            .get(&id.to_hex())
            .is_some()
    }

    /// Whether any pending `u:w:` update row replays a tombstone for `id`.
    fn update_rows_tombstoned(&self, id: &EntityId) -> bool {
        self.vault
            .sync_state_keys_with_prefix(&format!("u:w:{}:", self.window_key))
            .expect("read pending update rows")
            .into_iter()
            .any(|update_key| {
                let bytes = self
                    .vault
                    .sync_state_get(&update_key)
                    .expect("read update row")
                    .expect("update row exists");
                let replayed = crate::sync::schema::create_window_doc("probe", &self.window_key);
                crate::sync::loro_support::import_doc(&replayed, &bytes)
                    .expect("update row imports");
                replayed.get_map("tombstones").get(&id.to_hex()).is_some()
            })
    }

    /// Whether any queued `q:` row replays a tombstone for `id`. DRAINS the
    /// queue, so call it once per subject.
    fn queue_rows_tombstoned(&self, id: &EntityId) -> bool {
        let queue = crate::sync::SyncQueue::new(std::sync::Arc::clone(&self.vault))
            .expect("open sync queue");
        queue
            .drain_updates()
            .expect("drain queued updates")
            .into_iter()
            .any(|queued| {
                let replayed = crate::sync::schema::create_window_doc("probe", &self.window_key);
                crate::sync::loro_support::import_doc(&replayed, &queued.encoded)
                    .expect("queued update imports");
                replayed.get_map("tombstones").get(&id.to_hex()).is_some()
            })
    }

    /// Whether a `pt:` pending-tombstone marker for `id` survives — the
    /// replayable carrier a refusal must withdraw. Checks BOTH candidate window
    /// labels: the soft arm addresses `learned_at`'s window and the headerless
    /// leg addresses NOW's, and at a month boundary those differ.
    fn replayable_pending_marker(&self, id: &EntityId) -> bool {
        [
            self.window_key.as_str().to_owned(),
            crate::deletion::window_label_from_timestamp(crate::unix_seconds_now()),
        ]
        .iter()
        .any(|window_label| {
            self.vault
                .sync_state_get(&crate::deletion::pending_tombstone_key(window_label, id))
                .expect("read pt: marker")
                .is_some()
        })
    }

    /// Every no-publish assertion in one call, for a delete that must have been
    /// refused BEFORE its linearization point.
    fn assert_nothing_published(&mut self, id: &EntityId, context: &str) {
        assert!(
            !self.live_doc_tombstoned(id),
            "{context}: a refused delete must not leave a tombstone in the shared live doc"
        );
        assert!(
            self.outbound.try_recv().is_err(),
            "{context}: a refused delete must not route an outbound update to the peer"
        );
        assert!(
            !self.snapshot_tombstoned(id),
            "{context}: the refused tombstone must not reach the d:w: snapshot"
        );
        assert!(
            !self.update_rows_tombstoned(id),
            "{context}: the refused tombstone must not reach a u:w: carrier"
        );
        assert!(
            !self.queue_rows_tombstoned(id),
            "{context}: the refused tombstone must not reach a delete-bearing q: row"
        );
        assert!(
            !self.replayable_pending_marker(id),
            "{context}: the refused tombstone must not survive as a replayable pt: marker"
        );
    }
}

/// The delete rendezvous is ONE process-global slot, and `cargo test` runs these
/// in parallel threads of a single process. Two tests installing concurrently
/// would clobber each other's channels — one delete parks on a receiver the
/// other test owns, the other gets a `RecvError` from a dropped sender. Every
/// test that installs a rendezvous holds this lock for the whole install→join
/// window. Poison is ignored deliberately: a panicking test has already failed
/// and must not cascade into unrelated ones.
static DELETE_RENDEZVOUS_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_delete_rendezvous() -> std::sync::MutexGuard<'static, ()> {
    DELETE_RENDEZVOUS_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Parks a gated delete at `step`, commits `revoke` while it waits, and returns
/// the delete's result. The two-phase shape is forced: the steps around these
/// seams take the LMDB write lock themselves, so the revocation cannot be
/// pre-staged in a held txn — the deleter must announce while holding nothing.
///
/// Caller must hold [`lock_delete_rendezvous`].
fn safe_delete_with_revocation_at(
    vault: &std::sync::Arc<crate::Vault>,
    owner: EntityId,
    target: EntityId,
    reason: SafeDeleteReason,
    step: crate::deletion::DeleteRendezvous,
    revoke: crate::authority::AuthorityLogEntry,
) -> FacadeResult<DeleteReceipt> {
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
    crate::deletion::install_delete_rendezvous(step, target, arrived_tx, resume_rx);

    std::thread::scope(|scope| {
        let vault_ref = vault.as_ref();
        let deleter =
            scope.spawn(move || facade_for(vault_ref, owner).safe_delete(&target.to_hex(), reason));
        arrived_rx
            .recv()
            .expect("the deleter must reach the installed rendezvous");
        vault
            .put_authority_log_entries(&[(revoke, test_time(3), 3)])
            .expect("commit the revocation while the deleter is parked");
        resume_tx.send(()).expect("release the deleter");
        deleter.join().expect("deleter thread must not panic")
    })
}

/// fix-leg 7 P1-1: the SOFT arm's publish must pass the gate too.
///
/// `user_delete` scrubs the body to a 25 B shell in one txn, then publishes the
/// tombstone. fix-5 re-folded the owner in the scrub txn and fix-6 gated the
/// hard arms' publish — but the soft arm called `write_crdt_tombstone(..., None,
/// None)`, so its publication passed NO gate at all. A `RevokeActor` landing
/// between the scrub commit and the publish was never observed: the tombstone
/// reached the live doc and the peer, the `d:w:`/`u:w:`/`q:` carriers persisted,
/// and the `pt:` marker the scrub txn had already committed stayed on disk as a
/// replayable propagation intent — an unauthorized soft delete, published.
///
/// Both legs, because they are different code paths through the publish: LIVE
/// (window open, registry-owned shared doc, `route_live` on the wire) and
/// TRANSIENT (window closed, doc import-merged from persisted state). fix-6's
/// concern list flagged the transient-leg symmetry as an open follow-up; it is
/// folded in here.
#[cfg(feature = "sync")]
#[test]
fn revocation_racing_the_soft_delete_publish_refuses_and_publishes_nothing() {
    let _serial = lock_delete_rendezvous();
    for live_window in [true, false] {
        let leg = if live_window { "live" } else { "transient" };
        let mut harness = PublishBoundaryHarness::open("facade-soft-publish-boundary", live_window);
        let owner = put_person(&harness.vault, 0x20);
        let subject = put_person(&harness.vault, 0x2A);
        let revoke = root_binding_with_pending_revocation(&harness.vault, 0x2B, owner);

        // Control: with the binding live, the soft arm publishes end to end —
        // so the assertions below pin the refusal, not a broken fixture.
        let warmup = put_person(&harness.vault, 0x2C);
        facade_for(&harness.vault, owner)
            .safe_delete(&warmup.to_hex(), SafeDeleteReason::UserDelete)
            .expect("control: a bound owner soft-deletes");
        assert!(
            harness.snapshot_tombstoned(&warmup),
            "{leg} control: the d:w: snapshot must carry the warmup tombstone — \
             on both legs the publish txn persists it"
        );
        if live_window {
            assert!(
                harness.live_doc_tombstoned(&warmup),
                "{leg} control: the live doc must carry the warmup tombstone"
            );
            // `route_live` is the LIVE leg's last act. The transient leg has no
            // open window to route through — its delivery is the queued `q:`
            // row, which the control below leaves in place deliberately.
            assert!(
                harness.outbound.try_recv().is_ok(),
                "{leg} control: the peer receives the warmup tombstone"
            );
        }
        // Drain the control's outbound traffic so the refusal assertion below
        // reads an empty channel only if the REFUSED delete routed nothing.
        while harness.outbound.try_recv().is_ok() {}

        let err = safe_delete_with_revocation_at(
            &harness.vault,
            owner,
            subject,
            SafeDeleteReason::UserDelete,
            crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
            revoke,
        )
        .expect_err("a revocation landing before the publish commit must refuse");

        assert_eq!(err.code, FACADE_CODE_FORBIDDEN, "{leg}");
        assert!(
            err.message.contains("no active owner binding"),
            "{leg}: the parked pre-gate error must survive the publish boundary, \
             not degrade to a generic concurrency code: {}",
            err.message
        );
        // The shell scrub already committed — that is the pre-publication act
        // this arm is allowed to have done, and fix-5's re-fold gated it. What
        // must NOT exist is any published or replayable carrier.
        harness.assert_nothing_published(&subject, leg);
    }
}

/// fix-leg 7 P1-2 (a): a revocation committed AFTER the publish commit does NOT
/// refuse — the delete COMPLETES.
///
/// The publish commit is the delete's linearization point. fix-5 re-folded the
/// owner at the destructive steps that follow it (soft-erase, purge, headerless
/// purge), which meant a `RevokeActor` landing in the interval publish→purge
/// produced the rejected-call-publishes shape: the caller got FORBIDDEN while
/// the tombstone was already on the wire and peers were already tearing the
/// entity. That refusal is both unactionable and false — sync replay of the
/// published tombstone purges this replica regardless, so the local state the
/// refusal claims to have preserved does not survive anyway.
///
/// Under the ruling the answer is settled at publish: a revocation LMDB-ordered
/// after that commit simply follows an operation that was authorized when it
/// committed, which is ordinary linearizable ordering, not a race. Both
/// post-publication rendezvous points are driven, across every hard reason and
/// the headerless door.
///
/// MUTATION PROBE: re-adding an authority re-fold at any post-publish site
/// fails this test (the delete returns FORBIDDEN and the victim survives) while
/// the pre-publish regressions above still pass — the two directions are pinned
/// independently.
#[cfg(feature = "sync")]
#[test]
fn revocation_after_the_publish_commit_lets_the_delete_complete() {
    let _serial = lock_delete_rendezvous();
    let steps = [
        // Entry to the first post-publication destructive step: the soft-erase
        // for gdpr/policy, the purge for user_hard_delete.
        crate::deletion::DeleteRendezvous::AfterTombstonePublish,
        // Entry to the purge on the arms that ran a soft-erase first.
        crate::deletion::DeleteRendezvous::BeforeHardPurge,
    ];
    let reasons = [
        SafeDeleteReason::UserHardDelete,
        SafeDeleteReason::GdprDelete,
        SafeDeleteReason::PolicyDelete,
    ];
    for live_window in [true, false] {
        for step in steps {
            for reason in reasons {
                let leg = if live_window { "live" } else { "transient" };
                let case = format!("{leg}/{step:?}/{reason:?}");
                let harness =
                    PublishBoundaryHarness::open("facade-post-publish-boundary", live_window);
                let owner = put_person(&harness.vault, 0x2D);
                let subject = put_person(&harness.vault, 0x2E);
                let revoke = root_binding_with_pending_revocation(&harness.vault, 0x2F, owner);

                let receipt = safe_delete_with_revocation_at(
                    &harness.vault,
                    owner,
                    subject,
                    reason,
                    step,
                    revoke,
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "{case}: a revocation ordered AFTER the publish commit must not \
                         refuse a committed deletion, but got {}: {}",
                        err.code, err.message
                    )
                });

                assert!(receipt.existed, "{case}: the delete must claim the erasure");
                assert!(
                    receipt.receipt_ref.is_some(),
                    "{case}: every hard reason writes a REDACTION_AUDIT receipt"
                );
                // Torn for real: the entity row is gone, not merely shelled.
                assert_eq!(
                    harness
                        .vault
                        .get_entity_type(&subject)
                        .expect("get subject"),
                    None,
                    "{case}: the victim must be purged"
                );
                // ...and the `dt:` local hard-delete truth is durable.
                let rtxn = harness.vault.store.env.read_txn().expect("read txn");
                assert!(
                    harness
                        .vault
                        .local_hard_delete_marker_exists_in_txn(&rtxn, &subject)
                        .expect("read dt: marker"),
                    "{case}: the purge txn must write the dt: marker"
                );
            }
        }
    }
}

/// fix-leg 7 P1-2 (a), headerless door: same law where there is no header.
///
/// `delete_entity_without_header` erases orphan residue (a vector with no
/// entities row). It publishes a tombstone first and purges after, so it has the
/// same post-publication interval — and fix-5 put a re-fold in its purge txn
/// too. Driven separately because the residue fixture cannot be built through
/// `put_person`.
#[cfg(feature = "sync")]
#[test]
fn revocation_after_the_publish_commit_lets_a_headerless_delete_complete() {
    let _serial = lock_delete_rendezvous();
    for live_window in [true, false] {
        let leg = if live_window { "live" } else { "transient" };
        let harness = PublishBoundaryHarness::open_for_vector_residue(
            "facade-headerless-boundary",
            live_window,
        );
        let owner = put_person(&harness.vault, 0x34);
        let revoke = root_binding_with_pending_revocation(&harness.vault, 0x35, owner);

        // Headerless residue: a vector with no entities row, so the delete takes
        // `delete_entity_without_header`.
        let subject = EntityId::from_bytes([0x3B; 16]).expect("residue id");
        harness
            .vault
            .put_vector(&subject, &[0.1, 0.2, 0.3, 0.4])
            .expect("put orphan vector");
        assert!(
            harness.vault.get_raw(&subject).expect("get raw").is_none(),
            "{leg}: headerless precondition — no entities row"
        );

        let receipt = safe_delete_with_revocation_at(
            &harness.vault,
            owner,
            subject,
            SafeDeleteReason::GdprDelete,
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            revoke,
        )
        .unwrap_or_else(|err| {
            panic!(
                "{leg}: the headerless purge must not re-decide authority after \
                 publication, but got {}: {}",
                err.code, err.message
            )
        });

        // `existed` tracks the ENTITIES row, which a headerless residue has none
        // of by construction — so the erasure evidence here is the audit receipt
        // and the purged vector, exactly as the pre-existing headerless fixtures
        // assert.
        assert!(
            receipt.receipt_ref.is_some(),
            "{leg}: the headerless purge must write its REDACTION_AUDIT receipt"
        );
        assert_eq!(
            harness.vault.get_vector(&subject).expect("get vector"),
            None,
            "{leg}: the orphan vector must be purged"
        );
        let rtxn = harness.vault.store.env.read_txn().expect("read txn");
        assert!(
            harness
                .vault
                .local_hard_delete_marker_exists_in_txn(&rtxn, &subject)
                .expect("read dt: marker"),
            "{leg}: the headerless purge txn must write the dt: marker"
        );
    }
}

/// fix-leg 8 P1: WITHOUT a publish commit there is no linearization point, so
/// the first destructive transaction must still re-prove authority.
///
/// `write_crdt_tombstone` is a NO-OP in a build without `sync` — it publishes
/// nothing and returns `crdt_persisted: false`. fix-7 read "after the publish
/// commit, do not re-check" as unconditional and removed the soft-erase and
/// purge re-folds, which on this build removed the ONLY in-transaction authority
/// checks the hard arms had: nothing had published, so the check fix-7 relied on
/// never ran. A `RevokeActor` landing after `safe_delete`'s entry fold then let
/// `user_hard_delete` / `gdpr_delete` / `policy_delete` tear the entity locally,
/// append an `allow` gate record, and commit the `pt:` marker whose verbatim
/// tombstone bytes a later sync-enabled boot replays through
/// `replay_pending_tombstones` — an unauthorized deletion, published on a delay.
///
/// The refined rule keys on `crdt_persisted`, not on the cargo feature: a
/// `sync` build path that declines to publish must obey the same law, and a
/// `#[cfg]` here would silently exempt it. The rendezvous parks the deleter in
/// the window after the entry fold and before the first destructive commit —
/// which on this build is where `AfterTombstonePublish` fires, since the
/// "publish" it names did nothing.
///
/// MUTATION PROBE: drop the conditional reverify from the hard arms' first
/// destructive txn and this test fails — the delete succeeds, the victim is
/// purged, and the replayable `pt:` marker survives.
#[cfg(not(feature = "sync"))]
#[test]
fn revocation_after_a_nonpublishing_delete_refuses_and_tears_nothing() {
    let _serial = lock_delete_rendezvous();
    for reason in [
        SafeDeleteReason::UserHardDelete,
        SafeDeleteReason::GdprDelete,
        SafeDeleteReason::PolicyDelete,
    ] {
        let case = format!("{reason:?}");
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = std::sync::Arc::new(
            crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault"),
        );
        let owner = put_person(&vault, 0x40);
        let subject = put_person(&vault, 0x41);
        let revoke = root_binding_with_pending_revocation(&vault, 0x42, owner);

        let err = safe_delete_with_revocation_at(
            &vault,
            owner,
            subject,
            reason,
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            revoke,
        )
        .expect_err(&format!(
            "{case}: nothing published, so the first destructive txn is this \
             delete's linearization point and MUST refuse"
        ));

        assert_eq!(err.code, FACADE_CODE_FORBIDDEN, "{case}");
        assert!(
            err.message.contains("no active owner binding"),
            "{case}: the parked pre-gate error must survive, not degrade to a \
             generic concurrency code: {}",
            err.message
        );
        // Intact, not merely un-purged: the shell scrub must not have run either.
        assert_eq!(
            vault.get_entity_type(&subject).expect("get subject"),
            Some(ENTITY_TYPE_PERSON),
            "{case}: a refused delete must leave the entity whole"
        );
        assert_eq!(
            vault
                .get_raw(&subject)
                .expect("get raw")
                .expect("subject row survives")
                .len(),
            crate::batch::ENTITY_METADATA_HEADER_LEN + b"facade person".len(),
            "{case}: the body must be un-scrubbed — a 25 B shell would mean the \
             soft-erase committed before the refusal"
        );
        assert_no_local_delete_artifacts(&vault, &subject, &case);
    }
}

/// Every durable artifact a REFUSED sync-disabled delete must not leave behind,
/// in one call. Distinct from `PublishBoundaryHarness::assert_nothing_published`,
/// which pins the CRDT carriers a `sync` build could leak; without the feature
/// there are no such carriers, and the whole surface is local:
///
/// - `pt:{window}:{id}` — the pending-tombstone marker. THE one that matters:
///   it holds the verbatim 25 B tombstone wire value, and
///   `sync::window::replay_pending_tombstones` turns it into a published
///   tombstone on the next sync-enabled boot. A revoked owner leaving one behind
///   has published an unauthorized deletion, just deferred.
/// - `dt:{id}` — the permanent local hard-delete marker. It is
///   presence-consulted by the materialization gates, so a stray one bricks the
///   id against every future write.
/// - `h:` sweep rows + REDACTION_AUDIT receipts — a refused delete audits no
///   erasure, because none happened.
/// - gate decisions — the authority ledger must not record an `allow` for a
///   deletion the authority refused.
///
/// Both window labels are probed for `pt:`: the headerful arms address
/// `learned_at`'s window and the headerless leg addresses NOW's, and at a month
/// boundary those differ.
#[cfg(not(feature = "sync"))]
fn assert_no_local_delete_artifacts(vault: &crate::Vault, id: &EntityId, context: &str) {
    use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;

    let rtxn = vault.store.env.read_txn().expect("read txn");
    for window_label in [
        crate::deletion::window_label_from_timestamp(1),
        crate::deletion::window_label_from_timestamp(crate::unix_seconds_now()),
    ] {
        assert!(
            vault
                .store
                .sync_state
                .get(
                    &rtxn,
                    &crate::deletion::pending_tombstone_key(&window_label, id)
                )
                .expect("read pt: marker")
                .is_none(),
            "{context}: a refused delete must leave no replayable pt: marker \
             (a sync-enabled boot would replay it into the very publication the \
             refusal denied)"
        );
    }
    assert!(
        !vault
            .local_hard_delete_marker_exists_in_txn(&rtxn, id)
            .expect("read dt: marker"),
        "{context}: a refused delete must write no dt: local hard-delete marker"
    );
    assert!(
        vault
            .store
            .sync_queue
            .prefix_iter(&rtxn, crate::deletion::HARD_ERASE_SWEEP_PREFIX)
            .expect("iter sweep rows")
            .next()
            .is_none(),
        "{context}: a refused delete must queue no h: hard-erase sweep row"
    );
    drop(rtxn);
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("list receipts")
            .is_empty(),
        "{context}: a refused delete must mint no REDACTION_AUDIT receipt"
    );
    assert!(
        vault
            .gate_decisions(50)
            .expect("gate decisions")
            .iter()
            .all(|decision| decision.content_kind != "deletion"),
        "{context}: a refused delete must append no allow-gate deletion decision"
    );
}

/// fix-leg 8 P1, headerless leg: same law where there is no header.
///
/// `delete_entity_without_header` erases orphan residue (a vector with no
/// entities row). Its pre-publication guards were the scope probe's read txn and
/// the publish txn's re-fold — and on a build with no `sync` the second does not
/// exist, so fix-7's removal of the purge re-fold left this door with NO
/// in-transaction authority check at all. The residue is the part that makes it
/// bite differently from the headerful arms: it is the actual user data (a
/// vector, a BM25 posting), and a refused delete must leave it whole.
///
/// MUTATION PROBE: drop the conditional reverify from the headerless purge txn
/// and this test fails — the residue is erased and the receipt is minted.
#[cfg(not(feature = "sync"))]
#[test]
fn revocation_after_a_nonpublishing_headerless_delete_refuses_and_tears_nothing() {
    let _serial = lock_delete_rendezvous();
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = std::sync::Arc::new(
        crate::Vault::open(
            dir.path(),
            VaultConfig {
                embedding_model: Some("test-model-v1".to_owned()),
                dimensions: 4,
                ..VaultConfig::default()
            },
        )
        .expect("open vault"),
    );
    let owner = put_person(&vault, 0x43);
    let revoke = root_binding_with_pending_revocation(&vault, 0x44, owner);

    // Headerless residue: a vector with no entities row, so the delete takes
    // `delete_entity_without_header`.
    let subject = EntityId::from_bytes([0x45; 16]).expect("residue id");
    vault
        .put_vector(&subject, &[0.1, 0.2, 0.3, 0.4])
        .expect("put orphan vector");
    assert!(
        vault.get_raw(&subject).expect("get raw").is_none(),
        "headerless precondition — no entities row"
    );

    let err = safe_delete_with_revocation_at(
        &vault,
        owner,
        subject,
        SafeDeleteReason::GdprDelete,
        crate::deletion::DeleteRendezvous::AfterTombstonePublish,
        revoke,
    )
    .expect_err(
        "the headerless purge is this delete's ONLY durable act when nothing \
         published, so it MUST re-decide authority",
    );

    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        err.message.contains("no active owner binding"),
        "{}",
        err.message
    );
    // The residue itself survives — the point of the headerless door.
    assert_eq!(
        vault.get_vector(&subject).expect("get vector"),
        Some(vec![0.1, 0.2, 0.3, 0.4]),
        "a refused headerless delete must leave the orphan vector intact"
    );
    assert_no_local_delete_artifacts(&vault, &subject, "headerless");
}

/// fix-leg 9 P1: on the NON-PUBLISHING path the soft erase and the `pt:`
/// propagation intent are ONE transaction.
///
/// fix-8 put the conditional re-fold in the gdpr/policy soft-erase txn, and that
/// txn commits — but the replayable `pt:` marker was only written later, in the
/// purge txn. Between those two commits the erasure had a shape no compliance
/// path may have: the body was scrubbed locally and irreversibly, every peer
/// still held the full data, and NO durable record of the intent to propagate
/// the delete existed. A crash there — or any error on the purge path, which is
/// the ordinary failure this reaches through — silently downgraded a GDPR /
/// policy erasure to a local-only scrub. Nothing would ever heal it: a retry
/// captures the bodiless 25 B shell, and the sync-enabled boot that would have
/// replayed the deletion finds no marker to replay.
///
/// Driven by failing the marker write itself, which is the strongest available
/// statement of atomicity: whatever the transaction had done up to that point
/// must vanish with it. Both reasons that take the soft-erase phase, because
/// they are one arm and a future edit could split them.
///
/// MUTATION PROBE: move the `pt:` write back to the purge txn (drop it from the
/// scrub txn) and this test fails — the injection never fires, the delete
/// SUCCEEDS, and `expect_err` panics.
#[cfg(not(feature = "sync"))]
#[test]
fn a_failed_first_txn_pending_tombstone_rolls_back_the_soft_erase() {
    for reason in [SafeDeleteReason::GdprDelete, SafeDeleteReason::PolicyDelete] {
        let case = format!("{reason:?}");

        // Control, on its OWN vault: unarmed, the same delete completes and
        // leaves the marker. It runs separately so the armed leg's
        // "no artifacts at all" assertion stays absolute — a control delete in
        // the same vault would leave a legitimate receipt and pt: row.
        let (control_dir, control_vault) = open_nonpublishing_delete_vault();
        let control_owner = put_person(&control_vault, 0x50);
        let control_subject = put_person(&control_vault, 0x51);
        root_vault_binding(&control_vault, 0x52, control_owner, "human");
        facade_for(&control_vault, control_owner)
            .safe_delete(&control_subject.to_hex(), reason)
            .unwrap_or_else(|err| panic!("{case} control: {}: {}", err.code, err.message));
        assert!(
            first_txn_pending_tombstone_exists(&control_vault, &control_subject),
            "{case} control: a completed sync-OFF erasure keeps its replayable \
             pt: propagation intent, written in the scrub txn"
        );
        drop(control_dir);

        let (_dir, vault) = open_nonpublishing_delete_vault();
        let owner = put_person(&vault, 0x53);
        let subject = put_person(&vault, 0x54);
        // The soft erase deletes the vector row too, so a surviving vector is
        // independent evidence that the scrub itself rolled back — not merely
        // that the entity body was left alone.
        vault
            .put_vector(&subject, &[0.5, 0.6, 0.7, 0.8])
            .expect("put subject vector");
        root_vault_binding(&vault, 0x55, owner, "human");

        crate::deletion::arm_fail_first_txn_pending_tombstone();
        let err = facade_for(&vault, owner)
            .safe_delete(&subject.to_hex(), reason)
            .expect_err(
                "the pt: marker is written INSIDE the re-verified soft-erase \
                 txn, so failing it must fail the whole delete",
            );
        assert_eq!(err.code, FACADE_CODE_INTERNAL, "{case}");

        // The scrub rolled back with the marker: body whole, vector whole.
        assert_eq!(
            vault
                .get_raw(&subject)
                .expect("get raw")
                .expect("subject row survives")
                .len(),
            crate::batch::ENTITY_METADATA_HEADER_LEN + b"facade person".len(),
            "{case}: a 25 B shell would mean the scrub committed without the \
             marker — the exact split fix-leg 9 closes"
        );
        assert_eq!(
            vault.get_vector(&subject).expect("get vector"),
            Some(vec![0.5, 0.6, 0.7, 0.8]),
            "{case}: the soft erase deletes the vector row, so it must return"
        );
        assert_no_local_delete_artifacts(&vault, &subject, &case);
    }
}

/// fix-leg 9, the `existed` half of the guard: a soft erase that found NOTHING
/// still writes no `pt:`.
///
/// Moving the marker into the scrub txn put a `pt:` write on a path that had
/// none, so it inherits ONE-1149's rule and must be pinned there: a delete whose
/// scope raced away between the header read and the scrub txn erased nothing,
/// and a `pt:` marker is a claim that this delete has data to propagate away.
/// Emitting one would replay a deletion for an id this call never touched.
/// `assert_no_erasure_audit_artifacts` pins the same law for the purge txn's
/// marker; nothing covered the new site, because the pre-existing headerful
/// raced test uses `user_hard_delete`, which has no soft-erase phase at all.
///
/// MUTATION PROBE: drop `existed &&` from the scrub txn's marker guard and this
/// test fails — the raced delete reports `missing()` while leaving a replayable
/// `pt:` behind.
#[cfg(not(feature = "sync"))]
#[test]
fn a_soft_erase_that_erased_nothing_writes_no_pending_tombstone() {
    for reason in [DeleteReason::GdprDelete, DeleteReason::PolicyDelete] {
        let case = format!("{reason:?}");
        let learned_at = 1_772_000_000;

        for attempt in 0..3 {
            let (_dir, vault) = open_nonpublishing_delete_vault();
            let id = EntityId::from_bytes([0x56; 16]).expect("victim id");
            vault
                .batch()
                .put(
                    &id,
                    ENTITY_TYPE_PERSON,
                    TimeRange {
                        start: learned_at,
                        end: learned_at,
                    },
                    learned_at,
                    b"raced-away-before-the-scrub",
                )
                .commit()
                .expect("put victim");

            // The eraser stages the full-scope erase in a HELD write txn, so the
            // deleter's lock-free header read still sees the entity; the commit
            // lands while the deleter blocks on the write lock, and its scrub txn
            // then finds nothing. Identical construction to the ONE-1149
            // raced-to-nothing legs.
            let (tx, rx) = std::sync::mpsc::sync_channel::<()>(0);
            crate::deletion::install_after_header_read_signal(tx);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let outcome = std::thread::scope(|scope| {
                let mut wtxn = vault.store.env.write_txn().expect("write txn");
                crate::batch::deindex_entity(&vault.store, &mut wtxn, &id).expect("stage erase");
                let deleter_barrier = std::sync::Arc::clone(&barrier);
                let vault_ref = &vault;
                let deleter = scope.spawn(move || {
                    deleter_barrier.wait();
                    vault_ref.delete_entity_with_reason(&id, reason)
                });
                barrier.wait();
                rx.recv()
                    .expect("deleter must signal after the header read");
                wtxn.commit().expect("commit the racing erase");
                deleter.join().expect("deleter thread must not panic")
            })
            .expect("a raced delete is not an error");

            if vault.get_raw(&id).expect("get raw").is_some() {
                // Scheduling miss: the deleter never reached the raced branch.
                assert!(attempt < 2, "{case}: raced branch never constructed");
                continue;
            }
            assert!(
                !outcome.existed,
                "{case}: a delete that erased nothing must not claim it did"
            );
            assert!(
                !first_txn_pending_tombstone_exists(&vault, &id),
                "{case}: the scrub txn erased nothing, so it must stage no \
                 replayable pt: propagation intent for it"
            );
            break;
        }
    }
}

/// fix-leg 10 P1: an EMPTY commit settles nothing, so it must not latch
/// `authority_settled`.
///
/// fix-8 latched the flag unconditionally the moment the soft-erase txn ran, on
/// the theory that a committed destructive transaction is this delete's
/// linearization point. It is — when it actually erased something. When the
/// delete's scope raced away between the header read and the scrub txn
/// (`existed == false`, ONE-1149's shape), that transaction commits nothing at
/// all: no body scrubbed, no vector dropped, no `pt:` staged. Latching on it
/// declared a linearization point that does not exist, and the purge txn then
/// asked NO authority question.
///
/// What that bought an attacker: a `RevokeActor` AND a same-id re-put both
/// landing in the window before the purge were ignored wholesale. The purge tore
/// the REPLACEMENT state — data the revoked actor was never authorized to touch
/// and that this delete never even read — wrote the `dt:` marker that bricks the
/// id forever, committed the replayable `pt:` propagation intent, and appended
/// the stale `allow` gate decision minted from a snapshot two commits stale.
///
/// Fully deterministic, using the rendezvous slot TWICE: the deleter parks
/// before its scrub txn while the harness races the scope away, then parks again
/// at `BeforeHardPurge` while the harness commits the revocation and the re-put.
/// No `AFTER_HEADER_READ` contention with the other raced tests, and no retry
/// loop — LMDB's single writer does the ordering.
///
/// MUTATION PROBE: latch unconditionally again (`authority_settled = true;`) and
/// this test fails — the purge re-folds nothing, the delete SUCCEEDS, and
/// `expect_err` panics with the replacement torn and `dt:`/`pt:`/receipt/gate
/// artifacts on disk.
#[cfg(not(feature = "sync"))]
#[test]
fn a_raced_to_nothing_scrub_leaves_authority_unsettled_for_the_purge() {
    const REPLACEMENT: &[u8] = b"state re-put after the empty scrub";
    let _serial = lock_delete_rendezvous();

    for reason in [SafeDeleteReason::GdprDelete, SafeDeleteReason::PolicyDelete] {
        let case = format!("{reason:?}");
        let (_dir, vault) = open_nonpublishing_delete_vault();
        let owner = put_person(&vault, 0x57);
        let revoke = root_binding_with_pending_revocation(&vault, 0x58, owner);
        let subject = EntityId::from_bytes([0x59; 16]).expect("subject id");
        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, test_time(1), 1, b"original")
            .expect("put the original scope");

        // Park #1: after the entry gate and the no-op publish, BEFORE the scrub
        // txn opens — the deleter holds no write lock here.
        let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
        crate::deletion::install_delete_rendezvous(
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            subject,
            arrived_tx,
            resume_rx,
        );

        let result = std::thread::scope(|scope| {
            let vault_ref = &vault;
            let deleter = scope
                .spawn(move || facade_for(vault_ref, owner).safe_delete(&subject.to_hex(), reason));
            arrived_rx
                .recv()
                .expect("the deleter must park before its scrub txn");

            // Race the ORIGINAL scope to nothing. The scrub txn below will find
            // `existed == false` and commit empty.
            let mut wtxn = vault.store.env.write_txn().expect("write txn");
            crate::batch::deindex_entity(&vault.store, &mut wtxn, &subject)
                .expect("race the scope away");
            wtxn.commit().expect("commit the racing erase");
            assert!(
                vault.get_raw(&subject).expect("get raw").is_none(),
                "{case}: precondition — the scrub must find nothing"
            );

            // Park #2, installed while the deleter is still held at park #1: the
            // slot was `take`n when it fired, so this is the next one it hits.
            let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
            let (resume_purge_tx, resume_purge_rx) = std::sync::mpsc::sync_channel::<()>(0);
            crate::deletion::install_delete_rendezvous(
                crate::deletion::DeleteRendezvous::BeforeHardPurge,
                subject,
                arrived_tx,
                resume_purge_rx,
            );
            resume_tx.send(()).expect("release into the empty scrub");
            arrived_rx
                .recv()
                .expect("the deleter must park after the empty scrub commits");

            // The two commits the empty scrub falsely claimed to have ordered
            // behind it: authority is gone, and the id carries NEW state.
            vault
                .put_authority_log_entries(&[(revoke, test_time(3), 3)])
                .expect("commit the revocation");
            vault
                .put_entity(&subject, ENTITY_TYPE_PERSON, test_time(4), 4, REPLACEMENT)
                .expect("re-put the same id");
            vault
                .put_vector(&subject, &[0.9, 0.8, 0.7, 0.6])
                .expect("re-put a vector");
            resume_purge_tx.send(()).expect("release into the purge");
            deleter.join().expect("deleter thread must not panic")
        });

        let err = result.expect_err(&format!(
            "{case}: the empty scrub linearized nothing, so the purge is this \
             delete's first irreversible act and MUST re-prove authority"
        ));
        assert_eq!(err.code, FACADE_CODE_FORBIDDEN, "{case}");
        assert!(
            err.message.contains("no active owner binding"),
            "{case}: the parked pre-gate error must survive, not degrade to a \
             generic concurrency code: {}",
            err.message
        );
        // The replacement is whole — the purge must not tear state this delete
        // never read, on an authority that no longer exists.
        assert_eq!(
            vault
                .get_raw(&subject)
                .expect("get raw")
                .expect("the replacement row survives")
                .len(),
            crate::batch::ENTITY_METADATA_HEADER_LEN + REPLACEMENT.len(),
            "{case}: the re-put body must be untouched"
        );
        assert_eq!(
            vault.get_vector(&subject).expect("get vector"),
            Some(vec![0.9, 0.8, 0.7, 0.6]),
            "{case}: the re-put vector must be untouched"
        );
        assert_no_local_delete_artifacts(&vault, &subject, &case);
    }
}

/// A vault with vectors enabled, for the non-publishing delete regressions that
/// need vector residue as rollback evidence.
#[cfg(not(feature = "sync"))]
fn open_nonpublishing_delete_vault() -> (tempfile::TempDir, crate::Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(
        dir.path(),
        VaultConfig {
            embedding_model: Some("test-model-v1".to_owned()),
            dimensions: 4,
            ..VaultConfig::default()
        },
    )
    .expect("open vault");
    (dir, vault)
}

/// Whether ANY `pt:` marker exists for `id`, in any window.
///
/// Prefix-scanned rather than keyed: the headerful arms address the entity's own
/// `learned_at` window, and a helper that guessed one label would silently pass
/// its "no marker" assertion for a marker written under a different one — the
/// failure mode that hides exactly the leak these regressions hunt.
#[cfg(not(feature = "sync"))]
fn first_txn_pending_tombstone_exists(vault: &crate::Vault, id: &EntityId) -> bool {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let suffix = format!(":{}", id.to_hex());
    vault
        .store
        .sync_state
        .prefix_iter(&rtxn, crate::deletion::PENDING_TOMBSTONE_PREFIX)
        .expect("iter pt: markers")
        .any(|row| row.expect("pt: row").0.ends_with(&suffix))
}

/// P2-b: `fold.vault_id == None` is TWO states, and only one of them may pass.
///
/// A log carrying two independent genesis roots folds to `vault_id: None` with
/// `ConflictingVaultRoot` issues and an EMPTY `actor_bindings` map — the same
/// shape as a vault that never declared authority. Reading that as "unrooted,
/// keep store truth" hands every owner verb to any caller precisely when the
/// authority root is contested, which is the fail-open this pins shut.
#[test]
fn conflicting_vault_roots_fail_owner_verbs_closed() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x6B);
    let subject = put_person(&vault, 0x6C);
    let facade = facade_for(&vault, owner);

    // Two independently rooted genesis entries in one log. Each is internally
    // valid; together they are a collapse.
    let (genesis_a, _) = authority_root(0x74);
    let (genesis_b, _) = authority_root(0x75);
    vault
        .put_authority_log_entries(&[(genesis_a, test_time(1), 1), (genesis_b, test_time(2), 2)])
        .expect("two independent roots are individually valid rows");

    let fold = vault.authority_fold().expect("fold");
    assert!(
        fold.vault_root_is_conflicted(),
        "fixture must produce the conflicting-roots collapse"
    );
    assert!(
        fold.vault_id.is_none() && fold.actor_bindings.is_empty(),
        "the collapse must be indistinguishable from unrooted on shape alone \
         — that indistinguishability IS the bug being pinned"
    );

    // INVALID_STATE, not FORBIDDEN: nothing is wrong with the caller, the
    // vault's authority is. The taxonomy is what tells a host to repair the
    // log rather than to go mint a binding.
    let err = facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("owner verbs must fail closed under conflicting roots");
    assert_eq!(err.code, FACADE_CODE_INVALID_STATE);
    assert!(
        err.message.contains("conflicting vault roots"),
        "{}",
        err.message
    );

    // The other two owner verbs take the same door.
    for err in [
        facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "forged"}),
                text_fields: None,
                edges: None,
                occurred_at: 703,
                learned_at: None,
            })
            .expect_err("conflicted-root PERSON mint"),
        {
            let agent = put_person(&vault, 0x6D);
            let claim = vault
                .memory_facade(agent, EdgeActorClass::Agent)
                .claim_upsert(&claim_input(
                    "profile.mood",
                    &subject,
                    "observed",
                    serde_json::json!("calm"),
                ))
                .expect("agent claim");
            facade
                .claim_retract(&claim.claim_short_id)
                .expect_err("conflicted-root cross-actor retract")
        },
    ] {
        assert_eq!(err.code, FACADE_CODE_INVALID_STATE);
    }
}

/// A sidecar-less rotation must never hand the RETIRED key owner verbs through
/// the facade gate.
///
/// The owner gate reads `authority_fold_readonly_in_txn`, which used to omit
/// entries with no first-seen sidecar — leaving a delayable widen pending
/// forever. For `RotateKey` that is fail-OPEN: pending means the RETIRED key is
/// still a live owner-capable roster key. On a legacy rooted vault whose
/// rotation lost its sidecar, an attacker holding the retired key files a DAG
/// SIBLING `BindActor(retired_key, attacker, "human")` parented at genesis, and
/// the gate hands them every owner verb.
///
/// fix-3 closed that by synthesizing the migration's `learned_at.min(now)`.
/// fix-leg 4 removes `learned_at` from the answer entirely — it is peer-written,
/// so the long-past values in this fixture are the attacker's own claim — and
/// the gate suspends instead: INVALID_STATE while the fold cannot date the
/// rotation, cleared by one write-path fold, after which the rotation serves its
/// delay from local observation. Either way the retired key never authorizes.
#[test]
fn sidecarless_rotation_denies_owner_verbs_through_the_facade() {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (_dir, vault) = open_vault();
    let attacker = put_person(&vault, 0x76);
    let subject = put_person(&vault, 0x77);
    let facade = facade_for(&vault, attacker);

    let (genesis, signing) = authority_root(0x78);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let genesis_hash = crate::authority::authority_entry_hash(&genesis).expect("genesis hash");
    let retired = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let successor = ed25519_dalek::SigningKey::from_bytes(&[0x79; 32]);
    let owner_entry = |seq: u64, op: AuthorityOp, ts: u64| {
        sign_authority(
            AuthorityLogEntry {
                schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq,
                // Every child parents at GENESIS: the squatting bind is a
                // sibling of the rotation, so no topological rule kills it and
                // only the rotation's MATURITY can.
                parent_hashes: vec![genesis_hash],
                op,
                signer: AuthoritySignature {
                    suite: retired.suite(),
                    public_key: retired.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts,
            },
            &signing,
        )
    };
    let rotate = owner_entry(
        1,
        AuthorityOp::RotateKey {
            old_key: retired.clone(),
            new_device: crate::authority::DeviceAuthority {
                key: AuthorityKey::Ed25519(successor.verifying_key().to_bytes()),
                transport_key_binding: [7; 32],
                attestation: crate::authority::AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: crate::authority::AuthorityTier::Software,
                roles: crate::authority::ROLE_OWNER | crate::authority::ROLE_ADMIN,
            },
        },
        101,
    );
    let squat = owner_entry(
        2,
        AuthorityOp::BindActor {
            authority_key: retired.clone(),
            actor_ref: attacker,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        102,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, test_time(1), 1),
            (rotate, test_time(2), 2),
            (squat, test_time(3), 3),
        ])
        .expect("legacy log rows are individually valid");

    // Rewind to the legacy shape: no sidecars, migration marker unset. The
    // long-past `learned_at` values are the attacker's claim that the rotation
    // elapsed ages ago — which fix-leg 4 refuses to act on.
    strip_authority_first_seen_state(&vault);

    // Pre-migration the fold cannot date the rotation, so every owner verb is
    // SUSPENDED — the gate refuses rather than reading maturity out of the
    // attacker's own `learned_at`.
    let agent = put_person(&vault, 0x7A);
    let claim = vault
        .memory_facade(agent, EdgeActorClass::Agent)
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("calm"),
        ))
        .expect("agent claim");
    for err in [
        facade
            .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
            .expect_err("retired key must not delete"),
        facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "forged"}),
                text_fields: None,
                edges: None,
                occurred_at: 704,
                learned_at: None,
            })
            .expect_err("retired key must not mint a PERSON"),
        facade
            .claim_retract(&claim.claim_short_id)
            .expect_err("retired key must not retract another actor's claim"),
    ] {
        assert_eq!(err.code, FACADE_CODE_INVALID_STATE, "{}", err.message);
        assert!(
            err.message.contains("owner verbs are suspended"),
            "{}",
            err.message
        );
    }

    // The suspension is self-clearing, not a brick: one write-path fold records
    // the local observation and the rotation becomes datable. It is freshly
    // observed, so it now sits INSIDE its delay — the veto window a legacy
    // import is supposed to serve — rather than being declared elapsed by the
    // peer that shipped it.
    let full = vault.authority_fold().expect("fold");
    assert!(
        !full.pending_widens.is_empty(),
        "the rotation is dated at migration time, so its delay has not elapsed"
    );
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(
        vault
            .authority_fold_readonly_in_txn(&rtxn)
            .expect("a locally dated log folds"),
        full,
        "once observed locally the gate's fold agrees with the write-path fold"
    );
    drop(rtxn);
}

/// fix-3: a sidecar lost AFTER the one-shot migration is unrecoverable, so the
/// owner gate suspends rather than authorizing on a fold it cannot compute.
///
/// Distinct from the legacy case above: there the migration had not run and the
/// value is reproducible. Once the marker is set the migration will never revisit
/// that row, and both remaining guesses are unsafe — so this is INVALID_STATE
/// (the vault's authority is broken), never a silent pass.
#[test]
fn owner_verbs_suspend_when_a_first_seen_sidecar_is_lost_after_migration() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x7B);
    let subject = put_person(&vault, 0x7C);
    let facade = facade_for(&vault, owner);
    root_vault_binding(&vault, 0x7D, owner, "human");

    // Settle: the full fold is what sets the one-shot marker.
    vault.authority_fold().expect("fold");
    facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the bound owner works before the sidecar is lost");

    let sidecars = authority_first_seen_sidecar_keys(&vault);
    assert!(!sidecars.is_empty(), "the migration must have written rows");
    vault
        .with_write_txn(|wtxn| {
            for key in &sidecars {
                assert!(vault.store.sync_state.delete(wtxn, key.as_str())?);
            }
            Ok(())
        })
        .expect("drop the sidecars");

    let victim = put_person(&vault, 0x7E);
    let err = facade
        .safe_delete(&victim.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("an uncomputable fold must suspend owner verbs");
    assert_eq!(err.code, FACADE_CODE_INVALID_STATE);
    assert!(
        err.message.contains("owner verbs are suspended"),
        "{}",
        err.message
    );
}

/// Every per-entry first-seen sidecar key currently stored.
fn authority_first_seen_sidecar_keys(vault: &crate::Vault) -> Vec<String> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let keys = vault
        .store
        .sync_state
        .iter(&rtxn)
        .expect("iter sync_state")
        .map(|row| row.expect("sync_state row").0.into_owned())
        .filter(|key| {
            key.starts_with("authlog:first_seen:")
                && key != crate::authority::authority_first_seen_clock_sync_key()
                && key != crate::authority::authority_first_seen_backfill_sync_key()
        })
        .collect();
    drop(rtxn);
    keys
}

/// Rewinds a vault to the pre-migration shape: sidecars gone, marker unset.
fn strip_authority_first_seen_state(vault: &crate::Vault) {
    let mut keys = authority_first_seen_sidecar_keys(vault);
    assert!(!keys.is_empty(), "fixture must have written sidecars");
    keys.push(crate::authority::authority_first_seen_backfill_sync_key().to_owned());
    vault
        .with_write_txn(|wtxn| {
            for key in &keys {
                vault.store.sync_state.delete(wtxn, key.as_str())?;
            }
            Ok(())
        })
        .expect("strip first-seen state");
}

// ── ONE-1728 K7 · witness-door ownership backstop (ARCH-0052 D2(a)) ──────

/// The canonical witness door refuses a conversation owned by a live session
/// overlay, before any write, with the typed refusal and its own facade code.
/// This is the backstop the K4 taint guard cannot express: the ops of THIS
/// witness name only fresh ids, so nothing in the batch is tainted — what is
/// wrong is the door, not the payload.
#[test]
fn witness_door_rejects_a_conversation_owned_by_a_live_session() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x41);
    let facade = facade_for(&vault, actor);
    let conversation = EntityId::from_bytes([0x42; 16]).expect("conv id");

    let session = vault
        .off_record_session_vault()
        .enter(
            "sess-witness-door",
            crate::off_record::OffRecordBackendClass::Local,
        )
        .expect("enter session");
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment().expect("segment");
    overlay
        .put(
            crate::session_overlay::OverlayKeyspace::Entities,
            conversation.as_bytes(),
            b"session-owned conversation shell",
        )
        .expect("stage overlay shell");
    segment.commit().expect("commit segment");

    let refused = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "door probe")],
            occurred_at: 700,
        })
        .expect_err("the base door must refuse a session-owned conversation");
    assert_eq!(refused.code, FACADE_CODE_OFF_RECORD_SESSION_DOOR);
    assert!(
        refused.message.contains("sess-witness-door"),
        "the refusal names the owning session: {}",
        refused.message
    );

    // The refusal happens before any write: no TURN, no MESSAGE, no shell.
    let entity_rows = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault.store.entities.len(&rtxn).expect("entity count")
    };
    session.close().expect("close session");
    assert_eq!(
        {
            let rtxn = vault.store.env.read_txn().expect("read txn");
            vault.store.entities.len(&rtxn).expect("entity count")
        },
        entity_rows,
        "a refused witness writes nothing"
    );
    assert_eq!(vault.get_raw(&conversation).expect("get raw"), None);
}

/// Ownership is what the door checks — not the mere existence of a live
/// session. An unrelated conversation stays witnessable while a session is
/// open, so the backstop cannot become a global write freeze.
#[test]
fn witness_door_admits_a_conversation_no_session_owns() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x43);
    let facade = facade_for(&vault, actor);
    let owned = EntityId::from_bytes([0x44; 16]).expect("owned conv id");
    let free = EntityId::from_bytes([0x45; 16]).expect("free conv id");

    let session = vault
        .off_record_session_vault()
        .enter(
            "sess-witness-door-scope",
            crate::off_record::OffRecordBackendClass::Local,
        )
        .expect("enter session");
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment().expect("segment");
    overlay
        .put(
            crate::session_overlay::OverlayKeyspace::Entities,
            owned.as_bytes(),
            b"session-owned conversation shell",
        )
        .expect("stage overlay shell");
    segment.commit().expect("commit segment");

    facade
        .witness(&WitnessTurn {
            conversation_ref: free.to_hex(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "ordinary turn")],
            occurred_at: 800,
        })
        .expect("an unowned conversation stays witnessable");
    assert!(vault.get_raw(&free).expect("get raw").is_some());
    session.close().expect("close session");
}

// ── ONE-1728 · witness through the session vault (ARCH-0052 §7) ──────────

/// Enters a room and returns the handle plus a facade bound to a fresh actor.
fn session_witness_fixture<'v>(
    vault: &'v crate::Vault,
    session_ref: &str,
    actor_seed: u8,
) -> (crate::off_record::OffRecordSession<'v>, EntityId) {
    let actor = put_person(vault, actor_seed);
    let session = vault
        .off_record_session_vault()
        .enter(session_ref, crate::off_record::OffRecordBackendClass::Local)
        .expect("enter session");
    (session, actor)
}

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
    facade
        .witness_into_session(&session, &turn("first", 920), None)
        .expect("first witness");
    let shell = session
        .overlay_conversation_shell()
        .expect("room shell after the first turn");
    facade
        .witness_into_session(&session, &turn("second", 921), None)
        .expect("second witness");
    assert_eq!(
        session.overlay_conversation_shell().expect("room shell"),
        shell,
        "both turns belong to the same room shell"
    );

    // Exactly ONE conversation shell row exists in the room.
    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let shells = view
        .type_index
        .prefix_iter(&rtxn, &[ENTITY_TYPE_CONVERSATION])
        .expect("type scan")
        .count();
    assert_eq!(shells, 1, "a room witnesses into one conversation shell");
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
