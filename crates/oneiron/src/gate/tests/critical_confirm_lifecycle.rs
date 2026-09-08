//! Critical-write confirm lifecycle: binding, expiry, sweep, and overwrite invalidation.

use super::*;

pub(super) fn critical_confirm_pending(
    claim: EntityId,
    decision: u8,
    created_at: u64,
) -> PendingGateConsentRecord {
    PendingGateConsentRecord {
        version: 0,
        claim_id: *claim.as_bytes(),
        decision_id: GateDecisionId::from_bytes([decision; 16]),
        created_at,
        diff_handle: vec![decision, decision.wrapping_add(1)],
        read_frontier_hash: [decision.wrapping_add(2); 32],
        reason_codes: vec!["gate.pending.critical_confirm_attached".to_owned()],
        dreamer_run_id: None,
    }
}

#[test]
fn critical_write_confirm_binding_is_deterministic_and_fail_closed_on_non_attachment() {
    let claim = test_id(0x74);
    let pending = critical_confirm_pending(claim, 31, 100);
    let binding = critical_write_confirm_binding(&pending).expect("attached pending row binds");
    assert_eq!(binding.nonce, [31; 16]);
    assert_eq!(
        binding.expires_at,
        100 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS
    );
    assert_ne!(binding.confirm_id, [0; 32]);

    let mut stale = pending;
    stale.read_frontier_hash[0] ^= 1;
    assert_ne!(
        binding.confirm_id,
        critical_write_confirm_binding(&stale).unwrap().confirm_id,
        "a frontier mismatch must derive a different confirmation id"
    );
    stale.reason_codes.clear();
    assert!(
        critical_write_confirm_binding(&stale).is_err(),
        "unmarked pending consent must not be interpreted as a critical confirmation"
    );
}

#[test]
fn critical_write_confirm_expiry_is_a_terminal_demotion_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x75);
    let subject = test_id(0x21);
    put_raw_entity_row(
        &vault,
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        b"subject",
    )?;
    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.approval = ClaimApprovalStatus::Auto;
    put_claim_body(&vault, &claim, &body)?;
    let pending = critical_confirm_pending(claim, 32, 100);
    vault.with_write_txn(|wtxn| vault.store.put_pending_gate_consent_in_txn(wtxn, &pending))?;

    assert_eq!(vault.expire_critical_write_confirms_at(399)?, 0);
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Auto
    );
    assert_eq!(vault.expire_critical_write_confirms_at(400)?, 1);
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Proposed,
        "expiry must demote rather than delete or approve the claim"
    );
    let timed_out = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::CorruptedIndex("timed-out pending gate consent"))
    })?;
    assert_eq!(
        timed_out.reason_codes,
        vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()],
        "expiry must replace every pending reason with its sole terminal marker"
    );
    assert_eq!(
        stored_claim_body(&vault, &claim)?.approval,
        ClaimApprovalStatus::Proposed,
        "expiry must demote rather than delete or approve the claim"
    );
    assert!(
        critical_write_confirm_binding(&timed_out).is_ok(),
        "the terminal marker remains a valid binding for audit/replay safety"
    );
    assert!(
        vault.pending_critical_write_confirms(10)?.is_empty(),
        "an expired attachment is not an outstanding confirmation"
    );
    Ok(())
}

#[test]
fn pending_critical_confirms_sweep_bounded_pages_and_demotes_every_expired_claim() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let now = crate::unix_seconds_now();
    let expiring = [sweep_id(0xf0, 1), sweep_id(0xf0, 2), sweep_id(0xf0, 3)];
    let live = [sweep_id(0xf0, 4), sweep_id(0xf0, 5)];
    vault.with_write_txn(|wtxn| {
        // 600 non-critical rows plus five critical rows require more than two pages.
        for ordinal in 0..600u16 {
            let claim = EntityId::from_bytes([
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
                0x10,
                (ordinal >> 8) as u8,
                ordinal as u8,
                0x5a,
            ])
            .expect("sweep fixture id");
            let ordinary = PendingGateConsentRecord {
                version: 0,
                claim_id: *claim.as_bytes(),
                decision_id: GateDecisionId::from_bytes([(ordinal % 251) as u8 + 1; 16]),
                created_at: now,
                diff_handle: vec![ordinal as u8],
                read_frontier_hash: [((ordinal + 1) & 0xff) as u8; 32],
                reason_codes: vec!["gate.pending.ordinary".to_owned()],
                dreamer_run_id: None,
            };
            vault
                .store
                .put_pending_gate_consent_in_txn(wtxn, &ordinary)?;
        }
        for (ordinal, claim) in expiring.iter().enumerate() {
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(*claim, 240 + ordinal as u8, 1),
            )?;
        }
        for (ordinal, claim) in live.iter().enumerate() {
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(*claim, 250 + ordinal as u8, now),
            )?;
        }
        Ok(())
    })?;
    for claim in expiring {
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Auto;
        put_claim_body(&vault, &claim, &body)?;
    }

    // Each invocation inspects only a single 256-row page. The two cursors
    // nevertheless reach critical rows after an ordinary first page.
    assert!(vault.pending_critical_write_confirms(1)?.is_empty());
    assert!(vault.pending_critical_write_confirms(1)?.is_empty());
    let outstanding = vault.pending_critical_write_confirms(305)?;
    assert_eq!(outstanding.len(), 2);
    assert_eq!(
        outstanding
            .iter()
            .map(|binding| binding.claim_id)
            .collect::<Vec<_>>(),
        live,
        "live critical rows past the first store page remain discoverable"
    );
    for claim in expiring {
        assert_eq!(
            stored_claim_body(&vault, &claim)?.approval,
            ClaimApprovalStatus::Proposed
        );
    }

    // Re-arm the three already-demoted claims to make the explicit sweep count deterministic.
    for (ordinal, claim) in expiring.iter().enumerate() {
        vault.with_write_txn(|wtxn| {
            vault.store.put_pending_gate_consent_in_txn(
                wtxn,
                &critical_confirm_pending(*claim, 240 + ordinal as u8, 1),
            )
        })?;
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Auto;
        put_claim_body(&vault, claim, &body)?;
    }
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        0
    );
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        0
    );
    assert_eq!(
        vault.expire_critical_write_confirms_at(1 + CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS)?,
        3
    );
    Ok(())
}

#[test]
fn timeout_marker_remains_a_valid_critical_confirm_binding() {
    let pending = critical_confirm_pending(test_id(0x76), 33, 100);
    let original = critical_write_confirm_binding(&pending).unwrap();
    let mut timed_out = pending;
    timed_out.reason_codes = vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()];
    assert_eq!(
        critical_write_confirm_binding(&timed_out).unwrap(),
        original
    );
}

pub(super) fn critical_confirm_owner_entry(
    pending: &PendingGateConsentRecord,
    disposition: crate::authority::CriticalWriteConfirmDisposition,
    seed: u8,
) -> (
    crate::authority::AuthorityLogEntry,
    crate::authority::AuthorityLogEntry,
) {
    use crate::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, CriticalWriteConfirmAction, CriticalWriteConfirmMethod, DeviceAuthority,
        ROLE_ADMIN, ROLE_OWNER,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let sign = |mut entry: AuthorityLogEntry| {
        let transcript =
            crate::authority::authority_transcript(&entry).expect("authority transcript");
        entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
        entry
    };
    let genesis = sign(AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 1,
    });
    let binding = critical_write_confirm_binding(pending).expect("critical pending binding");
    let confirmation = sign(AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(crate::authority::genesis_vault_id(&genesis).expect("vault id")),
        seq: 1,
        parent_hashes: vec![
            crate::authority::authority_entry_hash(&genesis).expect("genesis hash"),
        ],
        op: AuthorityOp::CriticalWriteConfirm(CriticalWriteConfirmAction {
            schema_version: crate::authority::CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
            confirm_id: binding.confirm_id,
            gate_decision_id: binding.gate_decision_id.as_bytes(),
            claim_id: binding.claim_id,
            effect_digest: binding.effect_digest,
            read_frontier_hash: binding.read_frontier_hash,
            nonce: binding.nonce,
            expires_at: binding.expires_at,
            disposition,
            method: CriticalWriteConfirmMethod::TokenReauth,
        }),
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 2,
    });
    (genesis, confirmation)
}

pub(super) fn put_critical_auto_claim(
    vault: &crate::Vault,
    claim: EntityId,
) -> Result<PendingGateConsentRecord> {
    let mut data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::UserStated, 0)]);
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(vault, test_id(0xee), &data)?;
    let mut body = public_stamped(source_trust_claim(ClaimSource::UserStated));
    body.predicate = "health.allergy".to_owned();
    let (candidate, envelope) = claim_candidate_write_parts(vault, &body)?;
    vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time(3), 3)
        .commit()?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::EntityNotFound)
    })
}

#[test]
fn pending_critical_confirms_limit_zero_is_a_true_noop() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    crate::panic_on_unix_seconds_now_for_current_thread(true);
    crate::store::panic_on_active_write_txn_for_current_thread(true);
    let result = vault.pending_critical_write_confirms(0);
    crate::store::panic_on_active_write_txn_for_current_thread(false);
    crate::panic_on_unix_seconds_now_for_current_thread(false);
    assert!(result?.is_empty());
    vault.with_write_txn(|wtxn| {
        assert_eq!(
            vault
                .store
                .critical_confirm_list_sweep_state_in_txn(&*wtxn)?,
            (None, None),
            "limit zero must not create or advance list state",
        );
        assert_eq!(
            vault
                .store
                .critical_confirm_expiry_sweep_state_in_txn(&*wtxn)?,
            (None, None),
            "limit zero must not invoke the expiry sweep",
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn pending_critical_confirms_limit_one_advances_through_same_page_matches() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let first = sweep_id(0xd0, 1);
    let second = sweep_id(0xd0, 2);
    vault.with_write_txn(|wtxn| {
        vault.store.put_pending_gate_consent_in_txn(
            wtxn,
            &critical_confirm_pending(first, 1, crate::unix_seconds_now()),
        )?;
        vault.store.put_pending_gate_consent_in_txn(
            wtxn,
            &critical_confirm_pending(second, 2, crate::unix_seconds_now()),
        )
    })?;
    assert_eq!(
        vault.pending_critical_write_confirms(1)?[0].claim_id,
        first,
        "the first returned row is the first inspected key"
    );
    assert_eq!(
        vault.pending_critical_write_confirms(1)?[0].claim_id,
        second,
        "the cursor must not advance past a same-page match withheld by limit"
    );
    Ok(())
}

#[test]
fn critical_auto_batch_write_attaches_pending_confirm_and_allow_receipt() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x81);
    let pending = put_critical_auto_claim(&vault, claim)?;
    assert_eq!(
        pending.reason_codes,
        vec![GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED.to_owned()]
    );
    let decision = vault
        .store
        .gate_decisions(10)?
        .into_iter()
        .find(|row| row.claim_id == Some(*claim.as_bytes()))
        .expect("write receipt");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(
        decision.receipt_reasons,
        vec![GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED.to_owned()]
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn rematerialized_critical_claim_overwrite_invalidates_attachment_and_rejects_stale_clear()
-> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb1);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let window_key = WindowKey::new("2026-04");
    let doc = create_window_doc("peer", &window_key);
    let original = vault.get_raw(&claim)?.expect("attached claim row");

    // An unchanged rematerialization is idempotent: it preserves the live
    // attachment and its original persisted binding.
    map_insert_bytes(&doc.get_map("entities"), &claim.to_hex(), &original)?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    let unchanged = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim)?
            .ok_or(Error::EntityNotFound)
    })?;
    assert_eq!(critical_write_confirm_binding(&unchanged)?, binding);

    // A peer body change must consume neither the old binding nor its Auto
    // status. Rebinding the changed bytes to the old ceremony would be unsafe.
    let mut replacement = vault.get_claim(&claim)?.expect("claim body");
    replacement.value = Value::from("changed by peer");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;
    map_insert_bytes(
        &doc.get_map("entities"),
        &claim.to_hex(),
        &entity_record(ENTITY_TYPE_CLAIM, test_time(3), 3, &replacement_data),
    )?;
    doc.commit();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert!(
        vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .is_none(),
        "changed replay must atomically invalidate the persisted attachment"
    );
    assert_eq!(
        vault.get_claim(&claim)?.expect("changed claim").approval,
        ClaimApprovalStatus::Proposed,
        "changed replay must not leave a critical claim Auto"
    );
    // The CRDT continues to carry the peer's Auto bytes, so rematerializing it
    // again must converge on the closed/tombstoned Proposed representation.
    forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replayed changed claim")
            .approval,
        ClaimApprovalStatus::Proposed,
        "replaying the same changed peer body must not re-promote Auto"
    );

    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0xb1,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled,
        "a stale Clear cannot consume a ceremony for the changed body"
    );
    assert_eq!(
        vault.get_claim(&claim)?.expect("changed claim").approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_critical_claim_overwrite_invalidates_attachment_before_stale_clear() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb2);
    let pending = put_critical_auto_claim(&vault, claim)?;
    let binding = critical_write_confirm_binding(&pending)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("replicated replacement");
    replacement.approval = ClaimApprovalStatus::Auto;
    let replacement_data = crate::claim::encode_claim_body(&replacement)?;

    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(4),
            4,
            &replacement_data,
        )
        .commit()?;
    assert!(
        vault
            .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
            .is_none(),
        "the replicated door must invalidate in its overwrite transaction"
    );
    assert!(
        vault
            .store
            .gate_decisions(20)?
            .iter()
            .any(|row| row.claim_id == Some(*claim.as_bytes())
                && row.outcome == "invalidated"
                && row.reason_codes == [GATE_REASON_CRITICAL_CONFIRM_REPLICATED_OVERWRITE]),
        "invalidation leaves a distinct durable closure receipt"
    );
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replacement claim")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    vault
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time(4),
            4,
            &replacement_data,
        )
        .commit()?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replayed replacement claim")
            .approval,
        ClaimApprovalStatus::Proposed,
        "a repeated changed replication must remain demoted"
    );

    // A new local ceremony is distinct from the invalidated one. The old Clear
    // must neither settle it nor disturb its pending attachment.
    let fresh = put_critical_auto_claim(&vault, claim)?;
    let fresh_binding = critical_write_confirm_binding(&fresh)?;
    assert_ne!(fresh_binding.confirm_id, binding.confirm_id);

    let (genesis, clear) = critical_confirm_owner_entry(
        &pending,
        crate::authority::CriticalWriteConfirmDisposition::Clear,
        0xb2,
    );
    vault.put_authority_log_entries(&[(genesis, test_time(1), 1), (clear, test_time(2), 2)])?;
    assert_eq!(
        vault.settle_critical_write_confirm(binding.confirm_id)?,
        CriticalWriteConfirmResolution::AlreadySettled
    );
    assert_eq!(
        critical_write_confirm_binding(
            &vault
                .with_write_txn(|wtxn| vault.store.pending_gate_consent_in_txn(wtxn, &claim))?
                .expect("fresh ceremony remains pending"),
        )?,
        fresh_binding,
        "a stale old Clear cannot consume a fresh ceremony"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_changed_claim_duplicate_in_one_batch_stays_proposed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0xb3);
    put_critical_auto_claim(&vault, claim)?;
    let mut replacement = vault.get_claim(&claim)?.expect("attached claim");
    replacement.value = Value::from("same batch replacement");
    replacement.approval = ClaimApprovalStatus::Auto;
    let data = crate::claim::encode_claim_body(&replacement)?;
    vault
        .batch()
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
        .put_replicated(&claim, ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
        .commit()?;
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("replacement claim")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    Ok(())
}
