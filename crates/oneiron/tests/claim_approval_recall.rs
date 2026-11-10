#![cfg(oneiron_test_support)]
//! Approval publishes a Generated claim without changing corroboration eligibility.

use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementVerdict, Effort, RecallScope, consolidation::ConsolidationEvidenceRequest,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, Vault, VaultConfig,
};

/// Unique lexical marker, one analyzer token (lowercase alnum, no separators).
const MARKER: &str = "r11fixmark7q2z";

fn put_person(vault: &Vault, id_byte: u8) -> EntityId {
    let id = EntityId::from_bytes([id_byte; 16]).expect("r11 person id");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"r11 person",
        )
        .expect("r11 put person");
    id
}

#[test]
fn approved_generated_claim_reaches_lexical_recall_without_embedder() {
    // The device preset has no embedding model.
    let dir = tempfile::tempdir().expect("r11 tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("r11 open");
    let owner_id = vault
        .ensure_embedded_owner_actor()
        .expect("r11 owner actor");
    let owner = vault
        .authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())
        .expect("r11 owner proof");

    // A distinct PERSON may propose as Agent without an Auto grant.
    let opener = put_person(&vault, 0xA1);
    let subject = put_person(&vault, 0xA2);
    let claim_id = EntityId::from_bytes([0xA3; 16]).expect("r11 claim id");
    let claim_hex = claim_id.to_hex();
    let opener_memory = vault.memory(opener, EdgeActorClass::Agent);
    let owner_memory = vault.memory(owner_id, EdgeActorClass::Human);

    let receipt = opener_memory
        .claim_propose(&ClaimInput {
            id: Some(claim_hex.clone()),
            predicate: "note.topic".to_owned(),
            subject_ref: subject.to_hex(),
            value: serde_json::json!(format!("the lighthouse keeper logs {MARKER} at dawn")),
            confidence: 0.8,
            source: "generated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
            confidence_details: None,
        })
        .expect("r11 propose");
    assert_eq!(receipt.approval, "proposed", "the opener parks a proposal");
    let proposed = vault
        .get_claim(&claim_id)
        .expect("r11 read proposed")
        .expect("r11 proposed row");
    assert_eq!(proposed.approval, ClaimApprovalStatus::Proposed);

    let before = owner_memory
        .recall(
            MARKER,
            Effort::Light,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("r11 recall before");
    assert!(
        !before.items.iter().any(|item| item
            .record
            .as_ref()
            .is_some_and(|record| record.id == claim_hex)),
        "a proposed claim is not lexically recalled"
    );

    let before_evidence = owner_memory
        .consolidation_evidence_as_owner(
            &owner,
            &ConsolidationEvidenceRequest {
                source_refs: vec![claim_hex.clone()],
            },
        )
        .expect("r11 evidence before")
        .value;
    assert_eq!(before_evidence.len(), 1);
    assert!(
        !before_evidence[0].corroboration_eligible,
        "a proposed generated claim corroborates nothing"
    );

    let review = owner_memory
        .claim_review_as_owner(
            &owner,
            &ClaimProposalReviewRequest {
                claim_ref: claim_hex.clone(),
                grant_ref: None,
            },
        )
        .expect("r11 review");
    assert_eq!(
        review.opener_ref.as_deref(),
        Some(opener.to_hex().as_str()),
        "the review names the non-owner opener"
    );
    let settlement = owner_memory
        .claim_settle_as_owner(
            &owner,
            &ClaimSettleRequest {
                claim_ref: claim_hex.clone(),
                review_id: review.review_id.clone(),
                decision: ClaimSettleDecision::Approve,
                grant_ref: None,
            },
        )
        .expect("r11 settle");
    assert_eq!(settlement.verdict, ClaimSettlementVerdict::Landed);

    let live = vault
        .get_claim(&claim_id)
        .expect("r11 read live")
        .expect("r11 live row");
    assert_eq!(live.approval, ClaimApprovalStatus::Approved);
    assert_eq!(live.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(live.source, Some(ClaimSource::Generated));

    let after = owner_memory
        .recall(
            MARKER,
            Effort::Light,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("r11 recall after");
    assert_eq!(
        after.retrieval_meta.sparse,
        Some(true),
        "lexical-only recall without an embedder"
    );
    let hit = after
        .items
        .iter()
        .find(|item| {
            item.record
                .as_ref()
                .is_some_and(|record| record.id == claim_hex && record.kind == "CLAIM")
        })
        .expect("r11 the approved claim is lexically recalled by its marker");
    assert!(
        hit.value_text.contains(MARKER),
        "the hit serves the marker text"
    );
    assert_eq!(hit.predicate.as_deref(), Some("note.topic"));

    let after_evidence = owner_memory
        .consolidation_evidence_as_owner(
            &owner,
            &ConsolidationEvidenceRequest {
                source_refs: vec![claim_hex.clone()],
            },
        )
        .expect("r11 evidence after")
        .value;
    assert_eq!(after_evidence.len(), 1);
    assert!(
        !after_evidence[0].corroboration_eligible,
        "an approved generated claim still corroborates nothing"
    );
}
