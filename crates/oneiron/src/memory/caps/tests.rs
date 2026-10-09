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
