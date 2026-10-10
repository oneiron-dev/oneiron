//! Manifest-granted auto write: first-party, dreamer, and foreign tool output.

use super::*;

#[test]
fn first_party_tool_output_auto_write_reaches_auto() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_first_party_default_policy_manifest();
    put_policy_manifest_bytes(&vault, test_id(0xB4), &data)?;

    let claim_id = test_id(0xB5);
    let body = public_stamped(source_trust_claim(ClaimSource::ToolOutput));
    let (candidate, envelope) = claim_candidate_write_parts_for_actor(
        &vault,
        &body,
        first_party_connector_actor_id(),
        EdgeActorClass::Agent,
    )?;

    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    let stored = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert_eq!(stored.source, Some(ClaimSource::ToolOutput));

    let decisions = vault.store.gate_decisions(10)?;
    let decision = decisions
        .iter()
        .find(|decision| decision.claim_id == Some(*claim_id.as_bytes()))
        .expect("first-party Eiri write must record a gate decision");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.reason_codes, vec!["gate.allow"]);
    assert_eq!(decision.actor_class, "agent");
    assert_eq!(
        decision.actor_ref.as_deref(),
        Some(first_party_connector_actor_ref().as_str())
    );
    Ok(())
}

#[test]
fn system_dreamer_auto_write_still_requires_a_signed_manifest() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let dreamer = vault.dreamer_authority()?;
    let mut data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Generated, 0)]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("system", &dreamer.entity_ref().to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC9), &data)?;

    let claim_id = test_id(0xCA);
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.evidence = Some(precommit_evidence(vec![first_party_connector_actor_id()]));
    let (candidate, dummy_envelope) = dreamer_claim_candidate_write_parts(
        &vault,
        &body,
        first_party_connector_actor_id(),
        "dreamer-system-run",
    )?;
    let envelope = crate::WriteEnvelope::new(
        dreamer,
        dummy_envelope.source(),
        dummy_envelope.provenance().clone(),
        dummy_envelope.approval(),
    );
    let err = vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("switching to system must not bypass the Dreamer signature gate");
    assert_gate_rejected(err, "pending", &["gate.pending.policy_manifest_authority"]);
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn dreamer_generated_auto_write_with_signed_manifest_reaches_auto() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::Generated, 0),
        signatures_entry(),
    ]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &first_party_connector_actor_ref(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC6), &data)?;

    let claim_id = test_id(0xC7);
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.evidence = Some(precommit_evidence(vec![first_party_connector_actor_id()]));
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(
        &vault,
        &body,
        first_party_connector_actor_id(),
        "dreamer-run-auth",
    )?;

    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    let stored = stored_claim_body(&vault, &claim_id)?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert_eq!(stored.source, Some(ClaimSource::Generated));

    let decisions = vault.store.gate_decisions(10)?;
    let decision = decisions
        .iter()
        .find(|decision| decision.claim_id == Some(*claim_id.as_bytes()))
        .expect("signed Dreamer Auto write must record a gate decision");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.reason_codes, vec!["gate.allow"]);
    assert_eq!(decision.actor_class, "agent");
    assert_eq!(
        decision.actor_ref.as_deref(),
        Some(first_party_connector_actor_ref().as_str())
    );
    Ok(())
}

#[test]
fn unknown_and_revoked_connector_refs_fail_closed_to_pending() -> Result<()> {
    let (_unknown_tmp, unknown_vault) = temp_vault();
    let data = encode_first_party_default_policy_manifest();
    put_policy_manifest_bytes(&unknown_vault, test_id(0xB9), &data)?;

    let unknown_claim = test_id(0xBA);
    let body = public_stamped(source_trust_claim(ClaimSource::ToolOutput));
    let (candidate, envelope) = claim_candidate_write_parts_for_actor(
        &unknown_vault,
        &body,
        test_id(0xBB),
        EdgeActorClass::Agent,
    )?;
    let err = unknown_vault
        .batch()
        .claim_candidate(&unknown_claim, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("unknown connector key must remain pending");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(unknown_vault.get_raw(&unknown_claim)?.is_none());

    let (_revoked_tmp, revoked_vault) = temp_vault();
    let mut revoked_policy = encode_first_party_default_policy_manifest();
    append_actor_ceiling(
        &mut revoked_policy,
        actor_ceiling_row_for_ref("agent", &first_party_connector_actor_ref(), "proposed"),
    );
    put_policy_manifest_bytes(&revoked_vault, test_id(0xBC), &revoked_policy)?;

    let revoked_claim = test_id(0xBD);
    let (candidate, envelope) = claim_candidate_write_parts_for_actor(
        &revoked_vault,
        &body,
        first_party_connector_actor_id(),
        EdgeActorClass::Agent,
    )?;
    let err = revoked_vault
        .batch()
        .claim_candidate(&revoked_claim, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("revoked connector key must remain pending");
    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(revoked_vault.get_raw(&revoked_claim)?.is_none());
    Ok(())
}
