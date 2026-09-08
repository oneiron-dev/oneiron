//! Manifest-granted auto write: first-party, dreamer, and foreign tool output.

use super::*;

#[test]
fn policy_manifest_valid_fixture_resolves_gate_inputs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::ToolOutput, 0),
        scoped_grants_entry(),
        signatures_entry(),
    ]);
    replace_actor_ceilings(
        &mut data,
        vec![
            actor_ceiling_row("first_party", "auto"),
            actor_ceiling_row_for_ref("first_party", "probation", "proposed"),
            actor_ceiling_row_for_ref("agent", &first_party_connector_actor_ref(), "auto"),
            actor_ceiling_row("human", "auto"),
        ],
    );
    put_policy_manifest_bytes(&vault, test_id(0x51), &data)?;

    let policy = resolve(&vault)?;
    assert!(!policy.is_fail_closed());
    assert_eq!(policy.diagnostics().manifest_count, 1);
    assert_eq!(
        policy.actor_ceiling("first_party", None),
        PolicyApprovalCeiling::Auto
    );
    assert_eq!(
        policy.actor_ceiling("first_party", Some("probation")),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        policy.actor_ceiling("agent", Some(&first_party_connector_actor_ref())),
        PolicyApprovalCeiling::Auto
    );
    assert_eq!(
        policy.criticality_for_predicate("health.allergy"),
        PolicyCriticality::Critical
    );
    assert_eq!(
        policy.sensitivity_for_predicate("health.allergy"),
        PolicySensitivity::Sensitive
    );
    assert_eq!(policy.scoped_grants().len(), 1);
    assert_eq!(policy.signatures().len(), 1);

    let id = test_id(0x63);
    let body = public_stamped(source_trust_claim(ClaimSource::ToolOutput));
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    reset_claim_body_decode_count();
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
        .commit()?;
    assert!(vault.get_raw(&id)?.is_some());
    assert_eq!(
        claim_body_decode_count(),
        1,
        "policy gate must reuse the write-door decode"
    );
    Ok(())
}

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
fn dreamer_generated_auto_write_requires_manifest_signature() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Generated, 0)]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &first_party_connector_actor_ref(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC4), &data)?;

    let claim_id = test_id(0xC5);
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    // The evidence floor applies to every Dreamer-authored write; the fixture
    // actor is a real seeded entity, so the signature denial (not the floor)
    // is what this test observes.
    body.evidence = Some(precommit_evidence(vec![first_party_connector_actor_id()]));
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(
        &vault,
        &body,
        first_party_connector_actor_id(),
        "dreamer-run-auth",
    )?;

    let err = vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("unsigned manifest must not grant Dreamer Auto writes");

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
fn foreign_tool_output_connector_stays_pending_actor_ceiling() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_first_party_default_policy_manifest();
    put_policy_manifest_bytes(&vault, test_id(0xB6), &data)?;

    let claim_id = test_id(0xB7);
    let body = public_stamped(source_trust_claim(ClaimSource::ToolOutput));
    let (candidate, envelope) =
        claim_candidate_write_parts_for_actor(&vault, &body, test_id(0xB8), EdgeActorClass::Agent)?;

    let err = vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("foreign connector must not inherit first-party Auto");

    assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn default_policy_vad_rule_is_exact() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_first_party_default_policy_manifest();
    put_policy_manifest_bytes(&vault, test_id(0xC0), &data)?;
    let policy = resolve(&vault)?;

    assert_eq!(
        policy.criticality_for_predicate("affect.vad"),
        PolicyCriticality::Normal
    );
    for predicate in ["affect.vad.extra", "affect.vader.note"] {
        assert_eq!(
            policy.criticality_for_predicate(predicate),
            PolicyCriticality::Critical,
            "{predicate} must not inherit the internal VAD exemption"
        );
    }

    let claim_id = test_id(0xC1);
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.predicate = "affect.vad.extra".to_owned();
    body.approval = ClaimApprovalStatus::Approved;
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    let err = vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()
        .expect_err("VAD-like predicates must stay subject to the criticality floor");
    assert_gate_rejected(err, "pending", &["gate.pending.criticality_floor"]);
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

/// Without a row of its own a recorder's committed segment claim would pend
/// forever under the shipped default policy: no axes row means Critical, and
/// Critical with no consent context is `gate.pending.criticality_floor`.
#[test]
fn default_policy_voice_segment_rule_is_exact() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_first_party_default_policy_manifest();
    put_policy_manifest_bytes(&vault, test_id(0xC8), &data)?;
    let policy = resolve(&vault)?;

    assert_eq!(
        policy.criticality_for_predicate(crate::voice_segment::PREDICATE_VOICE_SEGMENT),
        PolicyCriticality::Normal
    );
    assert_eq!(
        policy.sensitivity_for_predicate(crate::voice_segment::PREDICATE_VOICE_SEGMENT),
        PolicySensitivity::Normal
    );

    // The row is keyed exactly: neither a refinement of the segment predicate
    // nor the transcript family inherits it, so both stay at the fail-closed
    // default criticality.
    for predicate in ["voice.segment.extra", "voice.transcript"] {
        assert_eq!(
            policy.criticality_for_predicate(predicate),
            PolicyCriticality::Critical,
            "{predicate} must not inherit the voice.segment row"
        );
        assert_eq!(
            policy.sensitivity_for_predicate(predicate),
            PolicySensitivity::Normal,
            "{predicate} takes the manifest default sensitivity"
        );
    }
    Ok(())
}

#[test]
fn default_policy_preserves_non_eiri_edge_provenance_writers() -> Result<()> {
    for (seed, actor_entity_type, actor_class) in [
        (0xC2, ENTITY_TYPE_PERSON, EdgeActorClass::Agent),
        (0xD2, ENTITY_TYPE_MACHINE, EdgeActorClass::System),
    ] {
        let (_tmp, vault) = temp_vault();
        let data = encode_first_party_default_policy_manifest();
        put_policy_manifest_bytes(&vault, test_id(seed), &data)?;

        let src = test_id(seed + 1);
        let tgt = test_id(seed + 2);
        let actor = test_id(seed + 3);
        let claim_id = test_id(seed + 4);
        let occurred = test_time(8);
        vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
        vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
        vault.put_entity(&actor, actor_entity_type, occurred, 8, b"actor")?;
        vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

        let subject = EdgeRef {
            source: src,
            kind: EdgeKind::Mentions,
            target: tgt,
        };
        let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
        vault.put_edge_provenance(&claim_id, &subject, &body, actor_class, 9)?;

        assert!(
            vault.get_raw(&claim_id)?.is_some(),
            "{actor_class:?} edge provenance write should persist under the default policy"
        );
    }
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
