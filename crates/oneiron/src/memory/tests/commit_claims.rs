//! Commit gating and trust ceiling, claim upsert/supersede/retract, structural puts, blobs, and edge names.

use super::*;

/// The structural door is not a second MESSAGE ingress. It cannot bind an
/// envelope, so it refuses the kind outright rather than letting a
/// caller-written body walk past the ceiling the witness door enforces.
#[test]
fn put_structural_refuses_message_entities() {
    let (_dir, vault) = open_vault();
    let facade = facade_for(&vault, put_person(&vault, 0xBB));
    let err = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "MESSAGE".to_owned(),
            body: serde_json::json!({
                "author": "system",
                "type": "dialogue",
                "content": "structurally forged",
                "is_visible": false,
                "order": 0,
            }),
            occurred_at: 700,
            learned_at: None,
            edges: None,
            text_fields: None,
        })
        .expect_err("MESSAGE rows are witnessed, never put structurally");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .is_empty(),
        "no MESSAGE row was written"
    );
}

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

    // A Person-backed agent has a valid actor binding, but this explicit
    // ceiling still prevents the Auto request from attaching.
    let mut manifest = crate::gate::default_policy_manifest();
    let mut cursor = std::io::Cursor::new(manifest.as_slice());
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode")
    else {
        panic!("default policy manifest is a map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("actor_ceilings") {
            let rmpv::Value::Array(rows) = value else {
                panic!("actor ceilings are an array");
            };
            rows.push(rmpv::Value::Map(vec![
                (rmpv::Value::from("actor_class"), rmpv::Value::from("agent")),
                (
                    rmpv::Value::from("actor_ref"),
                    rmpv::Value::from(actor.to_hex()),
                ),
                (rmpv::Value::from("ceiling"), rmpv::Value::from("proposed")),
            ]));
        }
    }
    manifest.clear();
    rmpv::encode::write_value(&mut manifest, &rmpv::Value::Map(entries)).expect("encode");
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().expect("default manifest id"),
        &manifest,
    )
    .expect("install agent ceiling");
    let facade = vault.memory(actor, EdgeActorClass::Agent);

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
    assert!(
        pending[0]
            .reason_codes
            .contains(&"gate.pending.actor_ceiling".to_owned()),
        "the non-attachable Agent Auto request must pend for its actor ceiling"
    );
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
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
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
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
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
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
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
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
    assert!(!err.suggestions.is_empty());
}

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
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);

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
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
}

/// ONE-1889: the structural door is create-only for EVERY stored kind, not
/// just TASK. Fixture kinds: TASK (the kind the old special case covered)
/// plus EVENT and ASSET — two non-actor-capable kinds this door can actually
/// create under the existing gates (CLAIM/MACHINE/NOTE are refused at the
/// kind gate and PERSON is owner-gated, so none of them can reach the
/// stored-row check as a fixture).
#[test]
fn put_structural_mints_but_never_overwrites_typed_entities() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xD2);
    let facade = facade_for(&vault, actor);

    for (index, (kind, fresh_body)) in [
        (
            "TASK",
            serde_json::json!({"role": 4, "content": "original"}),
        ),
        ("EVENT", serde_json::json!({"name": "hanami"})),
        ("ASSET", serde_json::json!({"hash": "abc123"})),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 810 + (index as u64) * 10;
        let minted = facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: kind.to_owned(),
                body: fresh_body,
                text_fields: None,
                edges: None,
                occurred_at: at,
                learned_at: None,
            })
            .unwrap_or_else(|err| panic!("fresh {kind} mint: {err}"));
        let id = EntityId::from_hex(&minted.id_hex).expect("minted id");
        let before = vault
            .get_raw(&id)
            .expect("read before")
            .expect("entity exists");

        // Same-kind and cross-kind retries must both be forbidden,
        // regardless of the incoming kind.
        let same_kind = facade
            .put_structural(&StructuralPutInput {
                id: Some(minted.id_hex.clone()),
                kind: kind.to_owned(),
                body: serde_json::json!({"name": "same-kind overwrite"}),
                text_fields: None,
                edges: None,
                occurred_at: at + 1,
                learned_at: None,
            })
            .unwrap_err();
        let cross_kind = facade
            .put_structural(&StructuralPutInput {
                id: Some(minted.id_hex.clone()),
                kind: if kind == "EVENT" { "ASSET" } else { "EVENT" }.to_owned(),
                body: serde_json::json!({"name": "cross-kind overwrite"}),
                text_fields: None,
                edges: None,
                occurred_at: at + 2,
                learned_at: None,
            })
            .unwrap_err();

        assert_eq!(same_kind.code, MEMORY_CODE_FORBIDDEN, "kind {kind}");
        assert_eq!(cross_kind.code, MEMORY_CODE_FORBIDDEN, "kind {kind}");
        assert_eq!(
            vault.get_raw(&id).expect("read after").expect("survives"),
            before,
            "{kind} body must be untouched by the refused overwrites"
        );
    }

    // Exactly one entity of each checked fixture kind exists, and no
    // refusal minted a second row.
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task entities")
            .len(),
        1
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_ASSET)
            .expect("asset entities")
            .len(),
        1
    );
}

/// ONE-1889: reusing a live id with a DIFFERENT kind plus a richer payload
/// (body + text fields + edges) must leave the first entity's every trace
/// byte-for-byte intact — no body, no edge, no text posting, no short id, no
/// temporal row from the refused call.
#[test]
fn put_structural_rejects_cross_kind_id_reuse_without_side_effects() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xD3);
    let facade = facade_for(&vault, actor);

    let neighbor = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "ASSET".to_owned(),
            body: serde_json::json!({"hash": "neighbor"}),
            text_fields: None,
            edges: None,
            occurred_at: 900,
            learned_at: None,
        })
        .expect("neighbor mint");
    let victim = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({"name": "tsukimi"}),
            text_fields: Some(vec![TextIndexField {
                field: "name".to_owned(),
                value: "tsukimi moonviewing".to_owned(),
            }]),
            edges: None,
            occurred_at: 901,
            learned_at: None,
        })
        .expect("victim mint");
    let victim_id = EntityId::from_hex(&victim.id_hex).expect("victim id");
    let neighbor_id = EntityId::from_hex(&neighbor.id_hex).expect("neighbor id");

    let body_before = vault.get_raw(&victim_id).expect("raw").expect("exists");
    let edges_before = vault.edges_out(&victim_id).expect("edges before");
    let view_before = facade
        .get_entity(&victim.entity_ref)
        .expect("get before")
        .expect("view before");
    let text_before = vault.search_text("tsukimi", 10).expect("search before");
    assert!(edges_before.is_empty(), "victim starts with no edges");
    assert!(
        text_before.iter().any(|hit| hit.id == victim_id),
        "victim's own text field must be indexed before the refusal"
    );

    let error = facade
        .put_structural(&StructuralPutInput {
            id: Some(victim.id_hex.clone()),
            kind: "TASK".to_owned(),
            body: serde_json::json!({"role": 4, "content": "clobbered"}),
            text_fields: Some(vec![TextIndexField {
                field: "content".to_owned(),
                value: "clobbered kabuki".to_owned(),
            }]),
            edges: Some(vec![StructuralEdgeSpec {
                edge_kind: "attached".to_owned(),
                target_ref: neighbor.id_hex,
                weight: None,
            }]),
            occurred_at: 902,
            learned_at: None,
        })
        .expect_err("cross-kind id reuse must be refused");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);

    // Every trace of the refused call is absent, and the first state survives.
    assert_eq!(
        vault
            .get_raw(&victim_id)
            .expect("raw after")
            .expect("after"),
        body_before,
        "stored EVENT body must be byte-identical"
    );
    assert_eq!(
        vault.edges_out(&victim_id).expect("edges after").len(),
        0,
        "the refused call's edge must not have landed"
    );
    assert!(
        vault
            .edges_out(&neighbor_id)
            .expect("neighbor edges")
            .is_empty(),
        "no edge may reach the neighbor either"
    );
    let view_after = facade
        .get_entity(&victim.entity_ref)
        .expect("get after")
        .expect("view after");
    assert_eq!(view_after.kind, "EVENT", "stored kind is unchanged");
    assert_eq!(view_after.id_hex, view_before.id_hex);
    assert_eq!(view_after.short_ref, view_before.short_ref);
    assert_eq!(view_after.body, view_before.body);
    assert!(
        vault
            .search_text("clobbered", 10)
            .expect("search clobbered")
            .is_empty(),
        "the refused call's text field must not be indexed"
    );
    assert!(
        vault
            .search_text("tsukimi", 10)
            .expect("search after")
            .iter()
            .any(|hit| hit.id == victim_id),
        "the original text posting survives"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task entities")
            .is_empty(),
        "the refused TASK put must not have created anything"
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
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
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
    assert_eq!(err.code, MEMORY_CODE_BAD_REQUEST);
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
    let facade = vault.memory(agent, EdgeActorClass::Agent);

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
    let first_facade = vault.memory(first_agent, EdgeActorClass::Agent);
    let replacement_facade = vault.memory(replacement_agent, EdgeActorClass::Agent);
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
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
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
    assert_eq!(err.code, MEMORY_CODE_NOT_FOUND);
}

/// ONE-1924 — the facade edge-name seam speaks canonical snake_case in BOTH
/// directions for every minted kind. `blocked_by` parses to the u8-23 kind and
/// renders back as `blocked_by`; the camelCase `blockedBy` spelling is NOT
/// exposed at this engine seam.
#[test]
fn edge_kind_names_round_trip_including_blocked_by() {
    assert_eq!(edge_kind_from_str("blocked_by"), Some(EdgeKind::BlockedBy));
    assert_eq!(edge_kind_name(EdgeKind::BlockedBy), "blocked_by");
    assert_eq!(edge_kind_from_str("blockedBy"), None);

    for kind in [
        EdgeKind::AuthoredBy,
        EdgeKind::ScopedTo,
        EdgeKind::PartOf,
        EdgeKind::Supersedes,
        EdgeKind::BelongsTo,
        EdgeKind::ClaimOf,
        EdgeKind::ChildOf,
        EdgeKind::AssignedTo,
        EdgeKind::DerivedFrom,
        EdgeKind::Mentions,
        EdgeKind::About,
        EdgeKind::Supports,
        EdgeKind::Opposes,
        EdgeKind::ParticipatesIn,
        EdgeKind::Attached,
        EdgeKind::EmployedBy,
        EdgeKind::HasFacet,
        EdgeKind::FacetOf,
        EdgeKind::InWorld,
        EdgeKind::SetIn,
        EdgeKind::MergedInto,
        EdgeKind::SplitInto,
        EdgeKind::BlockedBy,
    ] {
        let name = edge_kind_name(kind);
        assert_eq!(
            edge_kind_from_str(name),
            Some(kind),
            "{kind:?} name {name} must parse back to itself"
        );
    }
}

/// The `same_as` wire name round-trips both directions and resolves to the
/// byte-20 kind. The camelCase spelling is not exposed at this engine seam,
/// exactly as for `blocked_by`.
#[test]
fn same_as_edge_kind_name_round_trips() {
    assert_eq!(edge_kind_from_str("same_as"), Some(EdgeKind::SameAs));
    assert_eq!(edge_kind_name(EdgeKind::SameAs), "same_as");
    assert_eq!(edge_kind_from_str("sameAs"), None);
    assert_eq!(EdgeKind::SameAs as u8, 20);
}

/// ONE-1414 done-means 5 (generic half) — the broad structural door REFUSES to
/// mint a `same_as` link.
///
/// A raw link here would assert cross-vault identity with no status claim, no
/// per-pact consent surface, and no actor — and the export filter reads that
/// consent to decide what crosses a grant, so a forgeable link is a disclosure
/// surface. `federation::put_coreference_link` is the owning write door.
#[test]
fn put_structural_refuses_to_mint_a_same_as_link() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xC7);
    let facade = facade_for(&vault, actor);

    let other = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "Nadeshiko"}),
            text_fields: None,
            edges: None,
            occurred_at: 800,
            learned_at: None,
        })
        .expect("plain person put");

    let err = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "Nadeshiko elsewhere"}),
            text_fields: None,
            edges: Some(vec![StructuralEdgeSpec {
                edge_kind: "same_as".to_owned(),
                target_ref: other.id_hex.clone(),
                weight: None,
            }]),
            occurred_at: 801,
            learned_at: None,
        })
        .expect_err("the structural door must refuse a raw same_as link");
    assert_eq!(err.code, MEMORY_CODE_FORBIDDEN);
    assert!(!err.suggestions.is_empty());

    // Refused before any write: no `same_as` row exists anywhere.
    let other_id = EntityId::from_hex(&other.id_hex).unwrap();
    assert!(
        vault
            .edges_in(&other_id)
            .expect("edges in")
            .iter()
            .all(|edge| edge.kind != EdgeKind::SameAs)
    );
}
