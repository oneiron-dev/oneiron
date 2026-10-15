use super::*;

#[test]
fn a_replicated_critical_claim_waits_for_a_clear_on_the_device_it_reaches() -> Result<()> {
    let (_tmp_a, vault_a) = temp_vault();
    let (_tmp_b, vault_b) = temp_vault();
    let claim = test_id(0x8e);
    let pending_a = put_critical_auto_claim(&vault_a, claim)?;
    let mut policy = encode_policy_manifest(vec![source_trust_entry(ClaimSource::UserStated, 0)]);
    trust_human_candidate_actor(&mut policy);
    put_policy_manifest_bytes(&vault_b, test_id(0xee), &policy)?;

    // Replicate the committed revision, including its provenance, not a rebuilt body.
    let raw = vault_a.get_raw(&claim)?.expect("A's critical Auto claim");
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    let data = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    let occurred = TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    vault_b
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, occurred, header.learned_at, data)
        .commit()?;

    assert!(
        vault_b.consolidate_claim_vad_now(&claim, 10).is_err(),
        "FAILBEFORE Q1 replica: B consolidated a critical claim without a local Clear"
    );
    let pending_b = vault_b
        .pending_gate_consents(10)?
        .into_iter()
        .find(|row| row.claim_id == *claim.as_bytes())
        .expect("B's tray must offer a local confirmation");
    assert_eq!(
        pending_b.reason_codes,
        vec![GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED.to_owned()]
    );
    assert_eq!(
        stored_claim_body(&vault_b, &claim)?.approval,
        ClaimApprovalStatus::Auto
    );

    let binding_b = critical_write_confirm_binding(&pending_b)?;
    let (genesis, clear) = critical_confirm_owner_entry(
        &pending_b,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0x8e,
    );
    vault_b.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault_b.settle_critical_write_confirm(binding_b.confirm_id)?,
        CriticalWriteConfirmResolution::Cleared
    );
    vault_b.consolidate_claim_vad_now(&claim, 11)?;

    // Positive control: an exact replay does not reopen B's settled revision.
    vault_b
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, occurred, header.learned_at, data)
        .commit()?;
    assert!(
        vault_b
            .pending_gate_consents(10)?
            .iter()
            .all(|row| row.claim_id != *claim.as_bytes()),
        "an exact replay must attach no new confirmation"
    );
    assert_eq!(
        vault_a
            .pending_gate_consents(10)?
            .into_iter()
            .find(|row| row.claim_id == *claim.as_bytes()),
        Some(pending_a),
        "B's Clear must not settle A's device-local confirmation"
    );
    Ok(())
}

/// A's committed revision of `claim` as a replicated put's parts.
fn committed_parts(vault: &crate::Vault, claim: &EntityId) -> Result<(TimeRange, u64, Vec<u8>)> {
    let raw = vault.get_raw(claim)?.expect("A's critical Auto claim");
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    let occurred = TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    Ok((
        occurred,
        header.learned_at,
        raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec(),
    ))
}

fn device_b_with_critical_policy() -> Result<(tempfile::TempDir, crate::Vault)> {
    let (tmp, vault) = temp_vault();
    let mut policy = encode_policy_manifest(vec![source_trust_entry(ClaimSource::UserStated, 0)]);
    trust_human_candidate_actor(&mut policy);
    put_policy_manifest_bytes(&vault, test_id(0xee), &policy)?;
    Ok((tmp, vault))
}

/// B held an earlier Proposed body of the claim under an ordinary review. That
/// review saw another body, so it cannot hold A's Auto revision: B attaches
/// its own confirm over it.
#[test]
fn a_replicated_revision_over_an_ordinary_review_waits_for_a_clear() -> Result<()> {
    let (_tmp_a, vault_a) = temp_vault();
    let (_tmp_b, vault_b) = device_b_with_critical_policy()?;
    let claim = test_id(0x8f);
    let pending_a = put_critical_auto_claim(&vault_a, claim)?;
    let (occurred, learned_at, data) = committed_parts(&vault_a, &claim)?;
    let mut earlier = stored_claim_body(&vault_a, &claim)?;
    earlier.approval = ClaimApprovalStatus::Proposed;
    vault_b
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            &crate::claim::encode_claim_body(&earlier)?,
        )
        .commit()?;
    let mut ordinary = pending_a;
    ordinary.reason_codes = vec!["gate.pending.criticality_floor".to_owned()];
    vault_b.with_write_txn(|txn| {
        vault_b
            .store
            .put_pending_gate_consent_in_txn(txn, &ordinary)
    })?;

    vault_b
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, occurred, learned_at, &data)
        .commit()?;
    assert!(
        vault_b.consolidate_claim_vad_now(&claim, 10).is_err(),
        "FAILBEFORE Q1 replica: an ordinary review let B consolidate a replicated critical revision"
    );
    let pending_b = vault_b
        .pending_gate_consents(10)?
        .into_iter()
        .find(|row| row.claim_id == *claim.as_bytes())
        .expect("B's tray must offer a local confirmation");
    assert_eq!(
        pending_b.reason_codes,
        vec![GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED.to_owned()]
    );
    Ok(())
}

/// A changed revision that overwrites B's attached confirm invalidates that
/// ceremony and lands Proposed. The ceremony was never settled, so every
/// reader that asks the barrier still holds the claim.
#[test]
fn an_overwritten_replicated_confirm_is_never_read_as_settled() -> Result<()> {
    let (_tmp_a, vault_a) = temp_vault();
    let (_tmp_b, vault_b) = device_b_with_critical_policy()?;
    let claim = test_id(0x90);
    put_critical_auto_claim(&vault_a, claim)?;
    let (occurred, learned_at, data) = committed_parts(&vault_a, &claim)?;
    vault_b
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, occurred, learned_at, &data)
        .commit()?;
    let mut changed = stored_claim_body(&vault_a, &claim)?;
    changed.confidence = 0.5;
    vault_b
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            &crate::claim::encode_claim_body(&changed)?,
        )
        .commit()?;
    assert_eq!(
        stored_claim_body(&vault_b, &claim)?.approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(
        vault_b
            .pending_gate_consents(10)?
            .iter()
            .all(|row| row.claim_id != *claim.as_bytes()),
        "the overwrite closes B's ceremony"
    );
    assert!(
        !vault_b.claim_consolidation_eligible(
            &claim,
            crate::gate::ConsolidationReader::VadAnnotation
        )?,
        "FAILBEFORE Q1 replica: an invalidated ceremony read as settled"
    );
    Ok(())
}
