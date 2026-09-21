use super::*;

#[test]
fn untrusted_source_rows_only_narrow_present_slots_independent_of_scan_order() -> Result<()> {
    for (trusted, peer) in [
        (test_id(0x70), test_id(0x80)),
        (test_id(0x80), test_id(0x70)),
    ] {
        let (_dir, vault) = temp_vault();
        let body = source_trust_claim(ClaimSource::ToolOutput); // unstamped band 2
        let trusted_data =
            encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 2)]);
        put_policy_manifest_bytes(&vault, trusted, &trusted_data)?;
        crate::gate::resolution::check_claim_source_trust(&body, None, &resolve(&vault)?, None)
            .expect("trusted source permit applies");
        let narrower = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
        vault
            .batch()
            .put_replicated(
                &peer,
                ENTITY_TYPE_POLICY_MANIFEST,
                test_time(1),
                1,
                &narrower,
            )
            .commit()?;
        assert!(
            crate::gate::resolution::check_claim_source_trust(&body, None, &resolve(&vault)?, None)
                .is_err()
        );
        let public = public_stamped(body);
        crate::gate::resolution::check_claim_source_trust(&public, None, &resolve(&vault)?, None)
            .expect("narrowed public permit still applies");
        let unreceipted = encode_policy_manifest(vec![source_trust_entry_without_auto_permit(
            ClaimSource::ToolOutput,
            0,
        )]);
        vault
            .batch()
            .put_replicated(
                &peer,
                ENTITY_TYPE_POLICY_MANIFEST,
                test_time(1),
                2,
                &unreceipted,
            )
            .commit()?;
        assert!(
            crate::gate::resolution::check_claim_source_trust(
                &public,
                None,
                &resolve(&vault)?,
                None
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn product_band_permit_needs_explicit_owner_reauthoring() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let owner_ref = test_id(0x52);
    vault.put_entity(
        &owner_ref,
        crate::registry::ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_ref,
        &owner_ref.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let legacy = test_id(0x72);
    let target = test_id(0x73);
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 2)]);
    vault.put_entity(
        &legacy,
        crate::registry::ENTITY_TYPE_TASK_LIST,
        test_time(1),
        1,
        &data,
    )?;
    let body = source_trust_claim(ClaimSource::ToolOutput);
    assert!(
        crate::gate::resolution::check_claim_source_trust(&body, None, &resolve(&vault)?, None)
            .is_err()
    );
    vault.reauthor_legacy_policy_manifest(&owner, legacy, target, 2)?;
    crate::gate::resolution::check_claim_source_trust(&body, None, &resolve(&vault)?, None)?;
    let peer = test_id(0x74);
    let narrowing = encode_policy_manifest(vec![source_trust_entry_without_auto_permit(
        ClaimSource::ToolOutput,
        0,
    )]);
    vault
        .batch()
        .put_replicated(
            &peer,
            ENTITY_TYPE_POLICY_MANIFEST,
            test_time(1),
            3,
            &narrowing,
        )
        .commit()?;
    assert!(
        crate::gate::resolution::check_claim_source_trust(&body, None, &resolve(&vault)?, None)
            .is_err()
    );
    assert!(
        vault
            .manifest_contributions()?
            .iter()
            .any(|row| row.id == peer.to_hex() && row.restrict_only)
    );
    vault.quarantine_manifest_contribution(&owner, peer)?;
    crate::gate::resolution::check_claim_source_trust(&body, None, &resolve(&vault)?, None)?;
    Ok(())
}
