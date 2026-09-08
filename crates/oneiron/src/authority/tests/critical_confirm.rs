//! Critical-write confirm fold, wire strictness and poisoning.

use super::support::*;
use super::*;

fn critical_confirm_action(
    confirm: u8,
    nonce: u8,
    disposition: CriticalWriteConfirmDisposition,
    method: CriticalWriteConfirmMethod,
) -> CriticalWriteConfirmAction {
    CriticalWriteConfirmAction {
        schema_version: CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
        confirm_id: [confirm; 32],
        gate_decision_id: [confirm; 16],
        claim_id: EntityId::from_bytes([confirm.wrapping_add(1); 16]).unwrap(),
        effect_digest: [confirm.wrapping_add(2); 32],
        read_frontier_hash: [confirm.wrapping_add(3); 32],
        nonce: [nonce; 16],
        expires_at: 600,
        disposition,
        method,
    }
}

fn critical_confirm_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    action: CriticalWriteConfirmAction,
) -> AuthorityLogEntry {
    let key = authority_key_from_ed(signer);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::CriticalWriteConfirm(action),
            key,
            seq + 10,
        ),
        signer,
    )
}

#[test]
fn critical_write_confirm_owner_methods_fold_and_replay_keeps_first_confirmation() {
    let owner = ed_key(240);
    let genesis = genesis_entry(240, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let clear = critical_confirm_entry(
        vault_id,
        &genesis,
        &owner,
        1,
        critical_confirm_action(
            9,
            10,
            CriticalWriteConfirmDisposition::Clear,
            CriticalWriteConfirmMethod::TokenReauth,
        ),
    );
    let replay = critical_confirm_entry(
        vault_id,
        &clear,
        &owner,
        2,
        critical_confirm_action(
            9,
            11,
            CriticalWriteConfirmDisposition::Clear,
            CriticalWriteConfirmMethod::PassphraseReentry,
        ),
    );
    let fold = fold_authority_log(&[genesis, clear, replay]);
    let state = fold
        .critical_write_confirms
        .get(&[9; 32])
        .expect("first owner confirmation must fold");
    assert_eq!(state.action.method, CriticalWriteConfirmMethod::TokenReauth);
    assert_eq!(state.action.nonce, [10; 16]);
    assert!(
        fold.consumed_critical_write_confirm_nonces
            .contains(&[10; 16])
    );
    assert!(
        !fold
            .consumed_critical_write_confirm_nonces
            .contains(&[11; 16]),
        "ancestry-scoped confirm-id reuse is fold-invalid"
    );
    assert!(
        fold.issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::InvalidEntry(_)))
    );
}

#[test]
fn critical_write_confirm_agent_cannot_self_clear() {
    let owner = ed_key(241);
    let agent = ed_key(242);
    let genesis = genesis_entry(241, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 242,
            roles: ROLE_AGENT,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let clear = critical_confirm_entry(
        vault_id,
        &enroll,
        &agent,
        1,
        critical_confirm_action(
            12,
            13,
            CriticalWriteConfirmDisposition::Clear,
            CriticalWriteConfirmMethod::TokenReauth,
        ),
    );
    let fold = fold_authority_log(&[genesis, enroll, clear]);
    assert!(
        !fold.critical_write_confirms.contains_key(&[12; 32]),
        "an agent-only signature must never clear a critical attachment"
    );
}

#[test]
fn critical_write_confirm_wire_round_trip_is_strict() {
    let signer = ed_key(244);
    let key = authority_key_from_ed(&signer);
    let entry = sign_ed(
        unsigned_entry(
            Some([3; 32]),
            7,
            vec![[4; 32]],
            AuthorityOp::CriticalWriteConfirm(critical_confirm_action(
                16,
                17,
                CriticalWriteConfirmDisposition::Decline,
                CriticalWriteConfirmMethod::PassphraseReentry,
            )),
            key,
            8,
        ),
        &signer,
    );
    let wire = encode_authority_log_entry_body(&entry).expect("critical confirmation encodes");
    assert_eq!(
        decode_authority_log_entry_body(&wire).expect("critical confirmation decodes"),
        entry,
        "the signed critical-confirm wire form round-trips exactly"
    );

    let mut cursor = wire.as_slice();
    let Value::Map(mut top) = rmpv::decode::read_value(&mut cursor).expect("entry is map") else {
        panic!("entry is map");
    };
    let op = top
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("op"))
        .expect("op field");
    let Value::Map(op_fields) = &mut op.1 else {
        panic!("op is map");
    };
    let method = op_fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("method"))
        .expect("method field");
    method.1 = Value::from("unapproved_method");
    let mut malformed = Vec::new();
    rmpv::encode::write_value(&mut malformed, &Value::Map(top)).expect("map encodes");
    assert!(
        decode_authority_log_entry_body(&malformed).is_err(),
        "unknown critical-confirm methods must fail closed"
    );
}

#[test]
fn critical_write_confirm_wire_rejects_zero_binding_material() {
    let key = authority_key_from_ed(&ed_key(243));
    let mut action = critical_confirm_action(
        14,
        15,
        CriticalWriteConfirmDisposition::Decline,
        CriticalWriteConfirmMethod::PassphraseReentry,
    );
    action.effect_digest = [0; 32];
    let entry = unsigned_entry(
        Some([1; 32]),
        1,
        vec![[2; 32]],
        AuthorityOp::CriticalWriteConfirm(action),
        key,
        1,
    );
    assert!(encode_authority_log_entry_body(&entry).is_err());
}

#[test]
fn critical_write_confirm_sibling_collision_is_fold_invalid() {
    let owner = ed_key(245);
    let genesis = genesis_entry(245, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let clear = critical_confirm_entry(
        vault_id,
        &genesis,
        &owner,
        1,
        critical_confirm_action(
            18,
            19,
            CriticalWriteConfirmDisposition::Clear,
            CriticalWriteConfirmMethod::TokenReauth,
        ),
    );
    let decline = critical_confirm_entry(
        vault_id,
        &genesis,
        &owner,
        2,
        critical_confirm_action(
            18,
            20,
            CriticalWriteConfirmDisposition::Decline,
            CriticalWriteConfirmMethod::PassphraseReentry,
        ),
    );
    let fold = fold_authority_log(&[genesis, clear, decline]);
    assert!(fold.conflicted_critical_write_confirms.contains(&[18; 32]));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::CriticalWriteConfirmConflict { confirm_id } if *confirm_id == [18; 32]
    )), "a sibling collision must be visible as a fold-invalid issue");
}

#[test]
fn critical_write_confirm_three_sibling_nonce_collision_keeps_provenance_associative() {
    let (_owner, owner_key, _, base) = single_owner_state(208);
    let contender = |confirm_id, nonce, hash| {
        let mut state = base.clone();
        apply_op(
            &mut state,
            &AuthorityOp::CriticalWriteConfirm(critical_confirm_action(
                confirm_id,
                nonce,
                CriticalWriteConfirmDisposition::Clear,
                CriticalWriteConfirmMethod::TokenReauth,
            )),
            [hash; 32],
            false,
            &owner_key,
        );
        state
    };
    // W and Z share an id, so W wins the lossy id map. Z and Y share a
    // nonce; Z must remain in provenance after its id-map eviction.
    let w = contender(40, 50, 1);
    let z = contender(40, 51, 3);
    let y = contender(41, 51, 2);
    let expected_conflicts = BTreeSet::from([[40; 32], [41; 32]]);

    let left_then_right = merge_states(&merge_states(&w, &z), &y);
    let right_then_left = merge_states(&w, &merge_states(&z, &y));
    assert_eq!(
        left_then_right.conflicted_critical_write_confirms,
        expected_conflicts
    );
    assert_eq!(left_then_right, right_then_left);
    assert_eq!(
        left_then_right.critical_write_confirm_nonce_provenance[&[51; 16]],
        BTreeSet::from([[40; 32], [41; 32]]),
        "the evicted Z id remains a nonce contender"
    );

    for ordered in [
        [&w, &z, &y],
        [&w, &y, &z],
        [&z, &w, &y],
        [&z, &y, &w],
        [&y, &w, &z],
        [&y, &z, &w],
    ] {
        let merged = merge_states(&merge_states(ordered[0], ordered[1]), ordered[2]);
        assert_eq!(
            merged.conflicted_critical_write_confirms,
            expected_conflicts
        );
        assert_eq!(
            merged.critical_write_confirm_nonce_provenance,
            left_then_right.critical_write_confirm_nonce_provenance
        );
    }
}

#[test]
fn critical_write_confirm_three_siblings_replay_reopen_poison_every_contender() {
    let owner = ed_key(209);
    let genesis = genesis_entry(209, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending = |claim: u8, decision: u8, diff: u8| crate::store::PendingGateConsentRecord {
        version: 0,
        claim_id: *EntityId::from_bytes([claim; 16]).unwrap().as_bytes(),
        decision_id: crate::store::GateDecisionId::from_bytes([decision; 16]),
        created_at: crate::unix_seconds_now(),
        diff_handle: vec![diff],
        read_frontier_hash: [diff; 32],
        reason_codes: vec!["gate.pending.critical_confirm_attached".to_owned()],
        dreamer_run_id: None,
    };
    let w_pending = pending(30, 50, 1);
    let w_action = raw_critical_confirm_action(
        &w_pending,
        CriticalWriteConfirmDisposition::Clear,
        CriticalWriteConfirmMethod::TokenReauth,
    );
    let w_id = w_action.confirm_id;
    // Build both same-id contenders before deriving Y's nonce from the actual
    // hash loser, so this fixture stays valid if canonical entry hashes change.
    let mut z_action = w_action.clone();
    z_action.nonce = [51; 16];
    let w = critical_confirm_entry(vault_id, &genesis, &owner, 1, w_action.clone());
    let z = critical_confirm_entry(vault_id, &genesis, &owner, 2, z_action.clone());
    let w_hash = authority_entry_hash(&w).unwrap();
    let z_hash = authority_entry_hash(&z).unwrap();
    let (survivor, survivor_action, evictee, evictee_action) = if w_hash < z_hash {
        (&w, &w_action, &z, &z_action)
    } else {
        (&z, &z_action, &w, &w_action)
    };
    assert!(
        authority_entry_hash(survivor).unwrap() < authority_entry_hash(evictee).unwrap(),
        "the lower-hash same-id contender must survive"
    );

    let y_pending = pending(31, evictee_action.nonce[0], 2);
    let y_action = raw_critical_confirm_action(
        &y_pending,
        CriticalWriteConfirmDisposition::Decline,
        CriticalWriteConfirmMethod::PassphraseReentry,
    );
    let y_id = y_action.confirm_id;
    assert_ne!(w_id, y_id);
    assert_eq!(y_action.nonce, evictee_action.nonce);
    let y = critical_confirm_entry(vault_id, &genesis, &owner, 3, y_action);
    let expected_conflicts = BTreeSet::from([w_id, y_id]);

    for ordered in [
        [&w, &z, &y],
        [&w, &y, &z],
        [&z, &w, &y],
        [&z, &y, &w],
        [&y, &w, &z],
        [&y, &z, &w],
    ] {
        let fold = fold_authority_log(&[
            genesis.clone(),
            ordered[0].clone(),
            ordered[1].clone(),
            ordered[2].clone(),
        ]);
        assert_eq!(fold.conflicted_critical_write_confirms, expected_conflicts);
        assert_eq!(
            fold.critical_write_confirms[&w_id].action.nonce,
            survivor_action.nonce
        );
    }

    let dir = tempfile::tempdir().unwrap();
    {
        let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        vault
            .put_authority_log_entries(&[
                (genesis, TimeRange { start: 1, end: 1 }, 1),
                (w, TimeRange { start: 2, end: 2 }, 2),
                (z, TimeRange { start: 3, end: 3 }, 3),
                (y, TimeRange { start: 4, end: 4 }, 4),
            ])
            .unwrap();
        put_critical_confirm_claim(&vault, EntityId::from_bytes([30; 16]).unwrap());
        put_critical_confirm_claim(&vault, EntityId::from_bytes([31; 16]).unwrap());
        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .put_pending_gate_consent_in_txn(wtxn, &w_pending)?;
                vault
                    .store
                    .put_pending_gate_consent_in_txn(wtxn, &y_pending)
            })
            .unwrap();
    }
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let replayed = reopened.authority_fold().unwrap();
    assert_eq!(
        replayed.conflicted_critical_write_confirms,
        expected_conflicts
    );
    assert_eq!(
        replayed.critical_write_confirms[&w_id].action.nonce,
        survivor_action.nonce
    );
    for confirm_id in [w_id, y_id] {
        assert_eq!(
            reopened.settle_critical_write_confirm(confirm_id).unwrap(),
            crate::gate::CriticalWriteConfirmResolution::AlreadySettled
        );
    }
}

#[test]
fn critical_write_confirm_revoked_signer_is_fold_invalid() {
    let owner = ed_key(200);
    let second = ed_key(201);
    let peer = ed_key(202);
    let genesis = genesis_entry(200, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 201,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    // The roster is already two active devices at this point, so `enroll_peer`
    // is subject to the peer-cosign quorum: a single-signer widen folds
    // `MissingQuorum`, `peer` never enters the roster, and the revoke below then
    // fails `SignerNotInAncestry` on its own cosigner instead of revoking the
    // target. Cosign the second widen with `second` so all three devices are
    // genuinely active before the revoke under test.
    let enroll_peer = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 202,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let revoke = cosign_ed(
        revoke_entry(
            vault_id,
            &enroll_peer,
            &owner,
            authority_key_from_ed(&second),
            3,
        ),
        &owner,
        &peer,
    );
    let confirm = critical_confirm_entry(
        vault_id,
        &revoke,
        &second,
        1,
        critical_confirm_action(
            22,
            31,
            CriticalWriteConfirmDisposition::Clear,
            CriticalWriteConfirmMethod::TokenReauth,
        ),
    );
    let seen = BTreeMap::from([
        (authority_entry_hash(&enroll_second).unwrap(), 1_000),
        (authority_entry_hash(&enroll_peer).unwrap(), 1_000),
    ]);
    let fold = fold_authority_log_with_seen_times(
        &[genesis, enroll_second, enroll_peer, revoke, confirm.clone()],
        &seen,
        1_000 + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1,
    );
    assert!(fold.roster[&authority_key_from_ed(&second)].revoked);
    assert!(fold.issues.iter().any(|issue| matches!(issue,
        AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == authority_entry_hash(&confirm).unwrap())));
    assert!(!fold.critical_write_confirms.contains_key(&[22; 32]));
    assert!(
        !fold
            .consumed_critical_write_confirm_nonces
            .contains(&[31; 16])
    );
}

#[test]
fn critical_write_confirm_admin_only_signer_is_fold_invalid() {
    let owner = ed_key(202);
    let admin = ed_key(203);
    let genesis = genesis_entry(202, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 203,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let confirm = critical_confirm_entry(
        vault_id,
        &enroll,
        &admin,
        1,
        critical_confirm_action(
            23,
            32,
            CriticalWriteConfirmDisposition::Clear,
            CriticalWriteConfirmMethod::TokenReauth,
        ),
    );
    let mut seen = BTreeMap::new();
    seen.insert(authority_entry_hash(&enroll).unwrap(), 1_000);
    let fold = fold_authority_log_with_seen_times(
        &[genesis, enroll, confirm.clone()],
        &seen,
        1_000 + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1,
    );
    let device = &fold.roster[&authority_key_from_ed(&admin)];
    assert!(!device.revoked && device.roles & ROLE_ADMIN != 0 && device.roles & ROLE_OWNER == 0);
    assert!(fold.issues.iter().any(|issue| matches!(issue,
        AuthorityFoldIssue::MissingAuthorityConsent(hash) if *hash == authority_entry_hash(&confirm).unwrap())));
    assert!(!fold.critical_write_confirms.contains_key(&[23; 32]));
    assert!(
        !fold
            .consumed_critical_write_confirm_nonces
            .contains(&[32; 16])
    );
}

#[test]
fn critical_write_confirm_both_methods_fold_validly() {
    let owner_a = ed_key(204);
    let genesis_a = genesis_entry(204, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let confirm_a = critical_confirm_entry(
        genesis_vault_id(&genesis_a).unwrap(),
        &genesis_a,
        &owner_a,
        1,
        critical_confirm_action(
            24,
            33,
            CriticalWriteConfirmDisposition::Clear,
            CriticalWriteConfirmMethod::TokenReauth,
        ),
    );
    let owner_b = ed_key(205);
    let genesis_b = genesis_entry(205, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let confirm_b = critical_confirm_entry(
        genesis_vault_id(&genesis_b).unwrap(),
        &genesis_b,
        &owner_b,
        1,
        critical_confirm_action(
            25,
            34,
            CriticalWriteConfirmDisposition::Decline,
            CriticalWriteConfirmMethod::PassphraseReentry,
        ),
    );
    let fold_a = fold_authority_log(&[genesis_a, confirm_a.clone()]);
    let fold_b = fold_authority_log(&[genesis_b, confirm_b.clone()]);
    let state_a = &fold_a.critical_write_confirms[&[24; 32]];
    let state_b = &fold_b.critical_write_confirms[&[25; 32]];
    assert_eq!(
        state_a.action.method,
        CriticalWriteConfirmMethod::TokenReauth
    );
    assert_eq!(
        state_b.action.method,
        CriticalWriteConfirmMethod::PassphraseReentry
    );
    assert_eq!(state_a.signer, confirm_a.signer.public_key);
    assert_eq!(state_b.signer, confirm_b.signer.public_key);
    assert!(fold_a.issues.is_empty() && fold_b.issues.is_empty());
}

#[test]
fn critical_write_confirm_ancestry_nonce_reuse_distinct_id_is_fold_invalid() {
    let owner = ed_key(206);
    let genesis = genesis_entry(206, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let first = critical_confirm_entry(
        vault_id,
        &genesis,
        &owner,
        1,
        critical_confirm_action(
            26,
            35,
            CriticalWriteConfirmDisposition::Clear,
            CriticalWriteConfirmMethod::TokenReauth,
        ),
    );
    let second = critical_confirm_entry(
        vault_id,
        &first,
        &owner,
        2,
        critical_confirm_action(
            27,
            35,
            CriticalWriteConfirmDisposition::Decline,
            CriticalWriteConfirmMethod::PassphraseReentry,
        ),
    );
    let fold = fold_authority_log(&[genesis, first, second.clone()]);
    assert!(
        fold.issues.iter().any(|issue| matches!(issue,
        AuthorityFoldIssue::InvalidEntry(hash) if *hash == authority_entry_hash(&second).unwrap()))
    );
    assert!(fold.critical_write_confirms.contains_key(&[26; 32]));
    assert!(!fold.critical_write_confirms.contains_key(&[27; 32]));
    assert!(
        fold.consumed_critical_write_confirm_nonces
            .contains(&[35; 16])
    );
}

fn raw_critical_confirm_action(
    pending: &crate::store::PendingGateConsentRecord,
    disposition: CriticalWriteConfirmDisposition,
    method: CriticalWriteConfirmMethod,
) -> CriticalWriteConfirmAction {
    let claim_id = EntityId::from_bytes(pending.claim_id).unwrap();
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:critical-confirm:v1");
    digest.update(claim_id.as_bytes());
    digest.update(&pending.decision_id.as_bytes());
    digest.update(&pending.diff_handle);
    digest.update(&pending.read_frontier_hash);
    let effect_digest = *digest.finalize().as_bytes();
    let nonce = pending.decision_id.as_bytes();
    let expires_at = pending.created_at + crate::gate::CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS;
    let mut confirm = Sha256::new();
    confirm.update(CRITICAL_WRITE_CONFIRM_DOMAIN);
    confirm.update(pending.decision_id.as_bytes());
    confirm.update(claim_id.as_bytes());
    confirm.update(effect_digest);
    confirm.update(pending.read_frontier_hash);
    confirm.update(nonce);
    confirm.update(expires_at.to_be_bytes());
    CriticalWriteConfirmAction {
        schema_version: CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
        confirm_id: confirm.finalize().into(),
        gate_decision_id: pending.decision_id.as_bytes(),
        claim_id,
        effect_digest,
        read_frontier_hash: pending.read_frontier_hash,
        nonce,
        expires_at,
        disposition,
        method,
    }
}

fn put_critical_confirm_claim(vault: &crate::Vault, id: EntityId) {
    let body = crate::claim::ClaimBody::new(
        "profile.name",
        crate::claim::ClaimSubject::Entity(EntityId::from_bytes([27; 16]).unwrap()),
        rmpv::Value::from("critical confirm fixture"),
        1.0,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    let data = crate::claim::encode_claim_body(&body).unwrap();
    let payload = crate::test_util::entity_record(
        crate::registry::ENTITY_TYPE_CLAIM,
        TimeRange { start: 1, end: 1 },
        1,
        &data,
    );
    vault
        .with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key =
                crate::store::Store::encode_type_key(crate::registry::ENTITY_TYPE_CLAIM, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn same_nonce_distinct_id_sibling_merge_poisons_both() {
    let owner = ed_key(207);
    let genesis = genesis_entry(207, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending = |claim: u8, diff: u8| crate::store::PendingGateConsentRecord {
        version: 0,
        claim_id: *EntityId::from_bytes([claim; 16]).unwrap().as_bytes(),
        decision_id: crate::store::GateDecisionId::from_bytes([36; 16]),
        created_at: crate::unix_seconds_now(),
        diff_handle: vec![diff],
        read_frontier_hash: [diff; 32],
        reason_codes: vec!["gate.pending.critical_confirm_attached".to_owned()],
        dreamer_run_id: None,
    };
    let clear_pending = pending(28, 1);
    let decline_pending = pending(29, 2);
    let clear_action = raw_critical_confirm_action(
        &clear_pending,
        CriticalWriteConfirmDisposition::Clear,
        CriticalWriteConfirmMethod::TokenReauth,
    );
    let decline_action = raw_critical_confirm_action(
        &decline_pending,
        CriticalWriteConfirmDisposition::Decline,
        CriticalWriteConfirmMethod::PassphraseReentry,
    );
    let clear_id = clear_action.confirm_id;
    let decline_id = decline_action.confirm_id;
    let clear = critical_confirm_entry(vault_id, &genesis, &owner, 1, clear_action);
    let decline = critical_confirm_entry(vault_id, &genesis, &owner, 2, decline_action);
    let fold = fold_authority_log(&[genesis.clone(), clear.clone(), decline.clone()]);
    for confirm_id in [clear_id, decline_id] {
        assert!(
            fold.conflicted_critical_write_confirms
                .contains(&confirm_id)
        );
        assert!(fold.critical_write_confirms.contains_key(&confirm_id));
    }
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(
                issue,
                AuthorityFoldIssue::CriticalWriteConfirmConflict { .. }
            ))
            .count(),
        2
    );
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (clear, TimeRange { start: 2, end: 2 }, 2),
            (decline, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();
    put_critical_confirm_claim(&vault, EntityId::from_bytes([28; 16]).unwrap());
    put_critical_confirm_claim(&vault, EntityId::from_bytes([29; 16]).unwrap());
    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .put_pending_gate_consent_in_txn(wtxn, &clear_pending)?;
            vault
                .store
                .put_pending_gate_consent_in_txn(wtxn, &decline_pending)
        })
        .unwrap();
    let persisted = vault.authority_fold().unwrap();
    for confirm_id in [clear_id, decline_id] {
        assert!(
            persisted
                .conflicted_critical_write_confirms
                .contains(&confirm_id)
        );
        assert_eq!(
            vault.settle_critical_write_confirm(confirm_id).unwrap(),
            crate::gate::CriticalWriteConfirmResolution::AlreadySettled
        );
        assert_eq!(
            vault.settle_critical_write_confirm(confirm_id).unwrap(),
            crate::gate::CriticalWriteConfirmResolution::AlreadySettled
        );
    }
}
