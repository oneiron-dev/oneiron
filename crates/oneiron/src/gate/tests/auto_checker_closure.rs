use super::*;

#[test]
fn a_short_stored_value_closes_with_no_checker_injected() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let claim = test_id(0x34);
    let evidence = test_id(0x36);
    seed_precommit_evidence_entity(&vault, &evidence)?;
    let body = precommit_body(
        Value::from("Ada Lovelace"),
        Some(precommit_evidence(vec![evidence])),
    );
    let mut entries = vec![
        source_trust_entry(ClaimSource::Generated, 0),
        signatures_entry(),
    ];
    crate::test_util::add_default_teacher_probe_policy(&mut entries);
    let mut manifest = encode_policy_manifest(entries);
    append_actor_ceiling(
        &mut manifest,
        actor_ceiling_row_for_ref("agent", &first_party_connector_actor_ref(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0x22), &manifest)?;
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(
        &vault,
        &body,
        first_party_connector_actor_id(),
        "short-value-closure",
    )?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time(3), 3)
        .commit()?;
    let before = stored_claim_body(&vault, &claim)?;
    assert_eq!(
        before.approval,
        ClaimApprovalStatus::Auto,
        "Dreamer Auto fixture must land"
    );
    assert_eq!(
        before.lifecycle,
        ClaimLifecycleStatus::Active,
        "closure fixture must land"
    );
    assert_eq!(
        before.value,
        Value::from("Ada Lovelace"),
        "closure fixture must stay short"
    );
    assert!(
        !has_pending_gate_consent(&vault, &claim)?,
        "closure fixture must not be parked"
    );

    rewrite_policy_manifest_entries(&mut manifest, |entries| {
        entries.push((
            Value::from(POLICY_AUTO_CHECKER_KEY),
            Value::from("host-checker-v1"),
        ));
    });
    put_policy_manifest_bytes(&vault, test_id(0x22), &manifest)?;
    assert_eq!(
        resolve(&vault)?.auto_checker(),
        Some("host-checker-v1"),
        "host must name the checker before closing",
    );
    let result = vault.retract_claim(&claim, 10);
    assert!(
        result.is_ok(),
        "FAILBEFORE H282 closure: short stored Dreamer value must close without an injected checker: {result:?}"
    );
    let after = stored_claim_body(&vault, &claim)?;
    assert_eq!(
        after.lifecycle,
        ClaimLifecycleStatus::Retracted,
        "FAILBEFORE H282 closure: successful retraction must leave the claim closed",
    );
    assert_eq!(
        after.value, before.value,
        "closure must preserve the stored value"
    );
    assert!(
        !has_pending_gate_consent(&vault, &claim)?,
        "closure must not create a checker hold"
    );
    Ok(())
}
