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

#[test]
fn owner_mints_one_foreign_principal_grant_into_the_trusted_default_policy() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    let owner_ref = test_id(0x52);
    let subject = test_id(0x53);
    for id in [owner_ref, subject] {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            test_time(1),
            1,
            b"person",
        )?;
    }
    let owner = vault.authenticate_owner(
        owner_ref,
        &owner_ref.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let relay = "oauth-relay:relay-subject";
    let reads = |principal: &str| -> Result<bool> {
        Ok(vault
            .scoped_read(ScopedReadActorKey::new(principal).expect("principal key"))
            .get(&subject)?
            .value
            .is_some())
    };
    assert!(
        !reads(relay)?,
        "a transport identity alone is not authority"
    );
    let receipt = vault.grant_foreign_principal(&owner, relay)?;
    assert_eq!(
        receipt.grant_ref.as_deref(),
        Some("foreign:oauth-relay:relay-subject")
    );
    assert_eq!(receipt.actor_ref, Some(owner_ref.to_hex()));
    assert!(reads(relay)?);
    assert!(!reads("oauth-relay:other-subject")?);
    assert_eq!(
        resolve(&vault)?.actor_ceiling("agent", Some(relay)),
        PolicyApprovalCeiling::Proposed
    );
    vault.grant_foreign_principal(&owner, relay)?;
    let policy = resolve(&vault)?;
    assert_eq!(
        policy
            .scoped_grants()
            .iter()
            .filter(|grant| grant.actor_ref.as_deref() == Some(relay))
            .count(),
        1,
        "reminting keeps one Grant"
    );
    assert_eq!(
        vault
            .store
            .gate_decisions_for_grant_ref("foreign:oauth-relay:relay-subject")?
            .len(),
        2,
        "every mint leaves its receipt"
    );
    vault
        .batch()
        .put_replicated(
            &crate::gate::default_policy_manifest_id()?,
            ENTITY_TYPE_POLICY_MANIFEST,
            test_time(1),
            1,
            &crate::gate::default_policy_manifest(),
        )
        .commit()?;
    assert!(
        matches!(
            vault.grant_foreign_principal(&owner, "oauth-relay:late-subject"),
            Err(crate::Error::InvalidConfig(_))
        ),
        "a replicated default policy is never re-stamped as trusted"
    );
    Ok(())
}
