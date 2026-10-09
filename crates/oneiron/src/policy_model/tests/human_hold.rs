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
    let config = PolicyModelConfig {
        owner_hold_notice: Some("Review is queued; delivery remains on hold.".to_owned()),
        ..PolicyModelConfig::default()
    };
    let outcome = vault.enforce_policy_model_with_config(request.clone(), &config)?;
    assert_eq!(outcome.system_notice, config.owner_hold_notice);
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

#[test]
fn project_scoped_human_override_queues_the_project_assignee() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut vault_row = owner_row("owner:review", "Vault warning.");
    let Value::Map(ref mut fields) = vault_row else {
        unreachable!()
    };
    fields.push((Value::from("human"), Value::from("moderator:vault")));
    let mut project_row = owner_row("owner:review", "Project warning.");
    let Value::Map(ref mut fields) = project_row else {
        unreachable!()
    };
    fields.push((Value::from("project_ref"), Value::from("p-1")));
    fields.push((Value::from("human"), Value::from("moderator:project")));
    put_policy_manifest_bytes(
        &vault,
        test_id(0x99),
        &patterned_owner_manifest(
            vec![vault_row, project_row],
            vec![owner_pattern(
                "owner.review",
                "review-needed",
                "owner:review",
                Some("decide"),
            )],
        ),
    )?;
    let request = PolicyClassifyRequest::outbound_content("review-needed").with_project_ref("p-1");
    let held = vault.enforce_policy_model(request)?;
    assert_eq!(held.action, PolicyEnforcementAction::Hold);
    let queue = vault.policy_holds(5)?;
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].human, "moderator:project");
    assert_eq!(queue[0].content_hash, held.verdict.binding.content_hash);
    Ok(())
}

fn moderator(
    vault: &Vault,
    seed: u8,
    principal: &str,
) -> Result<crate::consent::AuthenticatedOwner> {
    let actor = test_id(seed);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"moderator",
    )?;
    vault.authenticate_owner(actor, principal, true, crate::store::GateDecisionId::now())
}

fn install_moderated_policy(vault: &Vault) -> Result<()> {
    let mut row = owner_row_with_action("owner:spoilers", "Avoid spoilers.", "warn");
    let Value::Map(ref mut fields) = row else {
        unreachable!()
    };
    fields.push((Value::from("human"), Value::from("moderator:offline")));
    put_policy_manifest_bytes(
        vault,
        test_id(0x78),
        &patterned_owner_manifest(
            vec![row],
            vec![owner_pattern(
                "owner.spoilers",
                "(?i)spoiler",
                "owner:spoilers",
                Some("decide"),
            )],
        ),
    )
}

#[test]
fn named_moderator_rulings_bind_content_and_survive_reclassification() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let assigned = moderator(&vault, 0x70, "moderator:offline")?;
    let other = moderator(&vault, 0x71, "moderator:other")?;
    install_moderated_policy(&vault)?;
    for (content, ruling, action) in [
        (
            "spoiler clear",
            PolicyHoldResolution::Cleared,
            PolicyEnforcementAction::Allow,
        ),
        (
            "spoiler decline",
            PolicyHoldResolution::Declined,
            PolicyEnforcementAction::Block,
        ),
    ] {
        let request = PolicyClassifyRequest::outbound_content(content);
        let held = vault.enforce_policy_model(request.clone())?;
        let reference = held.moderation_ref.as_deref().unwrap();
        assert!(matches!(
            vault.resolve_policy_hold(&other, reference, ruling),
            Err(Error::Relay(
                crate::error::RelayError::PolicyVerdictNotInForce
            ))
        ));
        vault.resolve_policy_hold(&assigned, reference, ruling)?;
        let replay = vault.enforce_policy_model_verdict(
            request.clone(),
            &PolicyModelConfig::default(),
            held.verdict.clone(),
            false,
        )?;
        assert_eq!(replay.action, action);
        assert_eq!(replay.outbound_halted, action.halts());
        assert_eq!(
            replay.final_content.as_deref(),
            (!action.halts()).then_some(content)
        );
        assert_eq!(vault.enforce_policy_model(request)?.action, action);
    }
    assert_eq!(
        vault
            .enforce_policy_model(PolicyClassifyRequest::outbound_content("spoiler different"))?
            .action,
        PolicyEnforcementAction::Hold
    );
    let receipts = gate_receipts(&vault)?.len();
    assert_eq!(vault.prune_policy_holds(&assigned, u64::MAX, 10)?, 2);
    assert_eq!(gate_receipts(&vault)?.len(), receipts);
    assert_eq!(vault.policy_holds(10)?.len(), 1);
    Ok(())
}
