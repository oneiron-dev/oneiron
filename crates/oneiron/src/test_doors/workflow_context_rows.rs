//! Open the workflow model-context row and section builders so integration
//! tests can check their prompt text without a vault (FIX WORKFLOW-CONTEXT-ROWS-UNFENCED).

use rmpv::Value;

use crate::agent_dispatch::context_rows_for_test;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    encode_claim_body,
};
use crate::entity_id::EntityId;

/// Render the memory section for one encoded claim.
pub fn memory_section_for_claim(
    predicate: &str,
    value: &str,
    source: Option<&str>,
) -> Option<String> {
    let subject = ClaimSubject::Entity(EntityId::from_bytes([8; 16]).ok()?);
    let mut claim = ClaimBody::new(
        predicate,
        subject,
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .ok()?;
    if let Some(source) = source {
        claim.source = Some(ClaimSource::parse(source)?);
    }
    let body = encode_claim_body(&claim).ok()?;
    context_rows_for_test::memory_section(&body)
}

/// Render the chat section for one encoded turn.
pub fn chat_section_for_turn(speaker: Option<&str>, text: &str) -> Option<String> {
    let mut entries = vec![(Value::from("text"), Value::from(text))];
    if let Some(speaker) = speaker {
        entries.push((Value::from("speaker"), Value::from(speaker)));
    }
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(entries)).ok()?;
    context_rows_for_test::chat_section(&body)
}

/// Render the sibling results section for one note's markdown.
pub fn sibling_section_for_note(markdown: &str) -> Option<String> {
    context_rows_for_test::sibling_section(markdown)
}
