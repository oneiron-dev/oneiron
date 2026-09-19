use super::*;
#[test]
fn human_named_match_holds_queues_and_notifies_both_readers_without_plaintext() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut row = owner_row_with_action("owner:spoilers", "Avoid spoilers.", "warn");
    let Value::Map(ref mut fields) = row else {
        unreachable!()
    };
    fields.push((Value::from("human"), Value::from("moderator:offline")));
    let manifest = patterned_owner_manifest(
        vec![row],
        vec![owner_pattern(
            "owner.spoilers",
            "(?i)spoiler",
            "owner:spoilers",
            Some("decide"),
        )],
    );
    put_policy_manifest_bytes(&vault, test_id(0x78), &manifest)?;
    let request = PolicyClassifyRequest::outbound_content("a unique spoiler to be held");
    let outcome = vault.enforce_policy_model(request.clone())?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Hold);
    assert_eq!(outcome.verdict.decision, PolicyClassifyDecision::Hold);
    assert!(outcome.outbound_halted);
    assert!(outcome.final_content.is_none());
    assert_eq!(outcome.notice_voice, Some(PolicyEnforcementVoice::System));
    assert!(
        outcome
            .system_notices
            .iter()
            .any(|n| n.audience == "user_and_model"
                && n.voice == "system"
                && n.notice_type == "policy_hold")
    );
    let queue = vault.policy_holds(5)?;
    assert_eq!(queue.len(), 1);
    assert_eq!(
        outcome.moderation_ref.as_deref(),
        Some(queue[0].queue_ref.as_str())
    );
    assert_eq!(queue[0].human, "moderator:offline");
    assert_eq!(queue[0].content_hash, outcome.verdict.binding.content_hash);
    assert_eq!(
        outcome.receipt_ref.as_deref(),
        Some(queue[0].receipt_ref.as_str())
    );
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert!(has_trace(
        &receipts[0],
        &format!(
            "gate.policy_model.hold_queued.{}",
            queue[0].queue_ref.rsplit(':').next().unwrap()
        )
    ));
    let queue_wire = serde_json::to_string(&queue).unwrap();
    assert!(!queue_wire.contains(&request.content));
    Ok(())
}
