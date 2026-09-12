//! The canonical text projection every host embeds.

use rmpv::Value;

use super::{PendingEmbeddingPayload, payload_text};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::Result;

fn subject_id() -> Result<EntityId> {
    let mut bytes = [0xC1; 16];
    bytes[0] = 0x7e;
    EntityId::from_bytes(bytes)
}

fn claim_bytes(value: Value) -> Result<Vec<u8>> {
    let body = ClaimBody::new(
        "test.status",
        ClaimSubject::Entity(subject_id()?),
        value,
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    crate::claim::encode_claim_body(&body)
}

#[test]
fn a_summary_payload_projects_to_its_own_prose() -> Result<()> {
    let payload = PendingEmbeddingPayload::SummaryText("the epoch prose".to_owned());
    assert_eq!(payload_text(&payload)?, "the epoch prose");
    Ok(())
}

#[test]
fn a_claim_payload_projects_to_the_claim_value_text() -> Result<()> {
    let payload = PendingEmbeddingPayload::ClaimBody(claim_bytes(Value::from("claim prose"))?);
    assert_eq!(payload_text(&payload)?, "claim prose");
    Ok(())
}

/// A structured claim value has no prose to project, and refusing it would
/// strand the row pending forever. It embeds its canonical rendering instead —
/// deterministic for identical bytes, so every host still lands in one space.
#[test]
fn a_structured_claim_value_projects_deterministically() -> Result<()> {
    let value = Value::Map(vec![(Value::from("role"), Value::from("owner"))]);
    let first = PendingEmbeddingPayload::ClaimBody(claim_bytes(value.clone())?);
    let second = PendingEmbeddingPayload::ClaimBody(claim_bytes(value)?);
    let projected = payload_text(&first)?;
    assert!(
        projected.contains("owner"),
        "the rendering carries the value: {projected}"
    );
    assert_eq!(projected, payload_text(&second)?);
    Ok(())
}

/// The projection decodes through the engine's own claim decoder, so a body
/// that is not a claim is refused rather than embedded as raw bytes.
#[test]
fn a_claim_payload_that_is_not_a_claim_body_is_refused() {
    let payload = PendingEmbeddingPayload::ClaimBody(b"not messagepack at all".to_vec());
    assert!(payload_text(&payload).is_err());
}
