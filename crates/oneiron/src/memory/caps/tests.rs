use super::*;
use crate::memory::MEMORY_CODE_BAD_REQUEST;

fn claim() -> ClaimInput {
    crate::memory::tests::claim_input(
        "test.payload",
        &crate::EntityId::from_bytes([7; 16]).expect("id"),
        "user_stated",
        serde_json::json!("small"),
    )
}

#[test]
fn complete_claim_payload_counts_scope_refs_utf8_and_json_escaping() {
    let mut input = claim();
    input.scope = Some(serde_json::json!({"opaque": "é\""}));
    let baseline = serde_json::to_vec(&input).expect("JSON").len();
    input
        .predicate
        .push_str(&"x".repeat(MAX_ENTITY_PAYLOAD_BYTES - baseline));
    assert_eq!(
        serde_json::to_vec(&input).expect("JSON").len(),
        MAX_ENTITY_PAYLOAD_BYTES
    );
    check_claim_input(&input).expect("exact cap accepted");
    input.predicate.push('x');
    assert_eq!(
        check_claim_input(&input).expect_err("one byte over").code,
        MEMORY_CODE_BAD_REQUEST
    );

    let mut input = claim();
    input.scope = Some(serde_json::json!({"opaque": "x".repeat(MAX_ENTITY_PAYLOAD_BYTES)}));
    assert_eq!(
        check_claim_input(&input).expect_err("large scope").code,
        MEMORY_CODE_BAD_REQUEST
    );
    input.scope = None;
    input.world_ref = Some("x".repeat(MAX_ENTITY_PAYLOAD_BYTES));
    assert_eq!(
        check_claim_input(&input).expect_err("large ref").code,
        MEMORY_CODE_BAD_REQUEST
    );
}

#[test]
fn witness_caps_accept_edges_and_refuse_over_cap() {
    use crate::memory::{WitnessAuthor, WitnessMessage};
    let mut turn = WitnessTurn {
        conversation_ref: "00000000000000000000000000000007".to_owned(),
        turn_ref: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "text".to_owned(),
            content: "x".repeat(MAX_ENTITY_PAYLOAD_BYTES),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
        occurred_at: 1,
    };
    check_witness_turn(&turn).expect("exact content cap");
    turn.messages[0].content.push('x');
    assert_eq!(
        check_witness_turn(&turn)
            .expect_err("oversized message")
            .code,
        MEMORY_CODE_BAD_REQUEST
    );
    turn.messages[0].content.clear();
    turn.messages = vec![turn.messages[0].clone(); MAX_BATCH_ENTITIES];
    check_witness_turn(&turn).expect("exact batch cap");
    turn.messages.push(turn.messages[0].clone());
    assert_eq!(
        check_witness_turn(&turn).expect_err("oversized batch").code,
        MEMORY_CODE_BAD_REQUEST
    );
}
