//! Persisted anti-rollback, bounded stale-roster approvals and advisory ingest checks.

use super::support::*;
use super::*;

fn put_replay(vault: &crate::Vault, entry: &AuthorityLogEntry, learned: u64) -> EntityId {
    let id = authority_log_entity_id(entry).unwrap();
    let body = encode_authority_log_entry_body(entry).unwrap();
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_AUTHORITY_LOG,
            TimeRange { start: 1, end: 1 },
            learned,
            &body,
        )
        .commit()
        .unwrap();
    id
}

fn slip_withdrawal(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    owner: &ed25519_dalek::SigningKey,
    seq: u64,
    id: u8,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::SlipRevoke { slip_id: [id; 32] },
            authority_key_from_ed(owner),
            u64::from(id),
        ),
        owner,
    )
}

fn stale_approval_fixture() -> (Vec<AuthorityLogEntry>, AuthorityKey, EntityId) {
    let owner = ed_key(184);
    let successor = ed_key(185);
    let witness = ed_key(186);
    let owner_key = authority_key_from_ed(&owner);
    let successor_key = authority_key_from_ed(&successor);
    let mut genesis = genesis_entry(184, DEFAULT_PENDING_WIDEN_DELAY_SECS, u64::MAX);
    if let AuthorityOp::Genesis { device, .. } = &mut genesis.op {
        device.tier = AuthorityTier::Hardware;
    }
    genesis = sign_ed(genesis, &owner);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 185,
            roles: ROLE_OWNER,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 0,
        },
    );
    let third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll,
            &owner,
            EnrollSpec {
                seed: 186,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 0,
            },
        ),
        &owner,
        &successor,
    );
    let actor = scope_entity(187);
    let approval = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            3,
            vec![authority_entry_hash(&third).unwrap()],
            bind_op(&successor_key, actor, "human", 1),
            owner_key.clone(),
            u64::MAX,
        ),
        &owner,
        &successor,
    );
    // The revoke is a DESCENDANT of the approval that will expire. The fold
    // must retain that ancestry link, or the expired grant resurrects its signer.
    let revoke = cosign_ed(
        revoke_entry(vault_id, &approval, &successor, owner_key.clone(), 1),
        &successor,
        &witness,
    );
    (
        vec![genesis, enroll, third, approval, revoke],
        owner_key,
        actor,
    )
}

#[test]
fn stale_approval_expires_by_first_seen_age_without_losing_descendant_revoke() {
    let (entries, revoked_key, actor) = stale_approval_fixture();
    let approval_hash = authority_entry_hash(&entries[3]).unwrap();
    let revoke_hash = authority_entry_hash(&entries[4]).unwrap();
    let first_seen = entries
        .iter()
        .map(|entry| (authority_entry_hash(entry).unwrap(), 100))
        .collect::<BTreeMap<_, _>>();
    let inside = fold_legacy_authority_log_with_seen_times(
        &entries,
        &first_seen,
        100 + DEFAULT_STALE_ROSTER_WINDOW_SECS,
    );
    assert!(inside.valid_entries.contains(&approval_hash));
    assert!(actor_binding_is_active(&inside, &actor, "human"));
    assert!(inside.roster[&revoked_key].revoked);
    let outside = fold_legacy_authority_log_with_seen_times(
        &entries,
        &first_seen,
        101 + DEFAULT_STALE_ROSTER_WINDOW_SECS,
    );
    assert!(
        outside
            .issues
            .contains(&AuthorityFoldIssue::StaleRosterApproval(approval_hash))
    );
    assert!(!outside.valid_entries.contains(&approval_hash));
    assert!(!actor_binding_is_active(&outside, &actor, "human"));
    assert!(outside.valid_entries.contains(&revoke_hash));
    assert!(outside.roster[&revoked_key].revoked);
    let mut late_seen = first_seen.clone();
    late_seen.insert(approval_hash, 101 + DEFAULT_STALE_ROSTER_WINDOW_SECS);
    assert!(
        fold_legacy_authority_log_with_seen_times(
            &entries,
            &late_seen,
            101 + DEFAULT_STALE_ROSTER_WINDOW_SECS,
        )
        .issues
        .contains(&AuthorityFoldIssue::StaleRosterApproval(approval_hash))
    );
    // Fresh successor authority can renew the binding. Expiring its old
    // parent must not turn a valid RebindActor into BindingMissing.
    let successor = ed_key(185);
    let fresh_actor = scope_entity(188);
    let fresh = cosign_ed(
        unsigned_entry(
            entries[4].vault_id,
            2,
            vec![revoke_hash],
            rebind_op(&authority_key_from_ed(&successor), fresh_actor, "human", 2),
            authority_key_from_ed(&successor),
            0,
        ),
        &successor,
        &ed_key(186),
    );
    let fresh_hash = authority_entry_hash(&fresh).unwrap();
    let mut renewed = entries.clone();
    renewed.push(fresh);
    late_seen.insert(fresh_hash, 101 + DEFAULT_STALE_ROSTER_WINDOW_SECS);
    let renewed_fold = fold_legacy_authority_log_with_seen_times(
        &renewed,
        &late_seen,
        101 + DEFAULT_STALE_ROSTER_WINDOW_SECS,
    );
    assert!(renewed_fold.valid_entries.contains(&fresh_hash));
    assert!(actor_binding_is_active(
        &renewed_fold,
        &fresh_actor,
        "human"
    ));
    assert!(renewed_fold.roster[&revoked_key].revoked);
    let reversed = entries.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(
        outside,
        fold_legacy_authority_log_with_seen_times(
            &reversed,
            &first_seen,
            101 + DEFAULT_STALE_ROSTER_WINDOW_SECS,
        )
    );
}

#[test]
fn signer_hwm_survives_reopen_without_rejecting_original_withdrawals() {
    let dir = tempfile::tempdir().unwrap();
    let owner = ed_key(181);
    let genesis = genesis_entry(181, DEFAULT_PENDING_WIDEN_DELAY_SECS, u64::MAX);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let first = slip_withdrawal(vault_id, &genesis, &owner, 1, 1);
    let high = slip_withdrawal(vault_id, &first, &owner, 10, 2);
    let old = slip_withdrawal(vault_id, &genesis, &owner, 5, 3);
    let old_hash = authority_entry_hash(&old).unwrap();
    assert!(
        fold_authority_log(&[genesis.clone(), old.clone()])
            .valid_entries
            .contains(&old_hash)
    );
    {
        let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        for entry in [&genesis, &first, &high] {
            vault
                .put_authority_log_entry(entry, TimeRange { start: 1, end: 1 }, 1)
                .unwrap();
        }
    }
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let id = put_replay(&vault, &old, u64::MAX);
    assert_eq!(
        vault.get_authority_log_entry(&id).unwrap(),
        Some(old.clone())
    );
    let fold = vault.authority_fold().unwrap();
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::NonMonotonicSeq(old_hash))
    );
    assert!(!fold.valid_entries.contains(&old_hash));
    for entry in [&genesis, &first, &high] {
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(entry).unwrap())
        );
        put_replay(&vault, entry, 999);
    }
    put_replay(&vault, &old, 999);
    assert_eq!(vault.authority_fold().unwrap(), fold);
    drop(vault);
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    assert_eq!(reopened.authority_fold().unwrap(), fold);
}

#[test]
fn late_causal_withdrawal_ancestors_heal_without_unrelated_rollback() {
    let owner = ed_key(181);
    let genesis = genesis_entry(181, DEFAULT_PENDING_WIDEN_DELAY_SECS, u64::MAX);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let middle = slip_withdrawal(vault_id, &genesis, &owner, 5, 11);
    let tip = slip_withdrawal(vault_id, &middle, &owner, 10, 12);
    let old = slip_withdrawal(vault_id, &genesis, &owner, 4, 13);
    let mut outputs = Vec::new();
    for order in [[&genesis, &middle, &tip], [&genesis, &tip, &middle]] {
        let dir = tempfile::tempdir().unwrap();
        {
            let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
            vault
                .put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)
                .unwrap();
            for entry in order {
                put_replay(&vault, entry, 1);
            }
            put_replay(&vault, &old, 1);
            let outsider = ed_key(182);
            put_replay(
                &vault,
                &slip_withdrawal(vault_id, &old, &outsider, 20, 14),
                1,
            );
        }
        let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        let fold = vault.authority_fold().unwrap();
        for entry in [&genesis, &middle, &tip] {
            assert!(
                fold.valid_entries
                    .contains(&authority_entry_hash(entry).unwrap())
            );
        }
        assert!(fold.issues.contains(&AuthorityFoldIssue::NonMonotonicSeq(
            authority_entry_hash(&old).unwrap()
        )));
        outputs.push(fold);
    }
    assert_eq!(outputs[0], outputs[1]);
}

#[test]
fn authority_replay_admits_withdrawals_and_raises_one_typed_peer_check() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let policy = AuthorityObservationPolicy {
        ingest_check_threshold: 2,
        ..AuthorityObservationPolicy::default()
    };
    vault.set_authority_observation_policy(policy).unwrap();
    let owner = ed_key(190);
    let genesis = genesis_entry(190, DEFAULT_PENDING_WIDEN_DELAY_SECS, 0);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    vault
        .put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 0)
        .unwrap();
    let mut parent = genesis;
    let mut rows = Vec::new();
    for seq in 1..=5 {
        let entry = slip_withdrawal(vault_id, &parent, &owner, seq, seq as u8);
        let id = put_replay(&vault, &entry, 0);
        assert_eq!(
            vault.get_authority_log_entry(&id).unwrap(),
            Some(entry.clone())
        );
        rows.push(entry.clone());
        parent = entry;
    }
    let checks = vault.authority_ingest_checks().unwrap();
    assert_eq!(checks.len(), 1);
    assert_eq!(
        checks[0].peer_id,
        AuthorityIngestCheck::peer_id_for_signer(&authority_key_from_ed(&owner))
    );
    assert_eq!(checks[0].count, 3);
    assert_eq!(checks[0].threshold, 2);
    let fold = vault.authority_fold().unwrap();
    for entry in &rows {
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(entry).unwrap())
        );
        put_replay(&vault, entry, 1);
    }
    assert_eq!(vault.authority_ingest_checks().unwrap(), checks);
    drop(vault);
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    assert_eq!(reopened.authority_ingest_checks().unwrap(), checks);
}

fn store_re_rooted_confirm(vault: &crate::Vault) -> (AuthorityEntryHash, AuthorityKey) {
    let owner = ed_key(194);
    let owner_key = authority_key_from_ed(&owner);
    let host_key = authority_key_from_ed(&ed_key(195));
    let genesis = genesis_entry(194, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let confirm = sign_ed(
        unsigned_entry(
            Some(id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::CriticalWriteConfirm(CriticalWriteConfirmAction {
                schema_version: CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
                confirm_id: [194; 32],
                gate_decision_id: [195; 16],
                claim_id: scope_entity(196),
                effect_digest: [197; 32],
                read_frontier_hash: [198; 32],
                nonce: [199; 16],
                expires_at: u64::MAX,
                disposition: CriticalWriteConfirmDisposition::Clear,
                method: CriticalWriteConfirmMethod::TokenReauth,
            }),
            owner_key.clone(),
            2,
        ),
        &owner,
    );
    let hash = authority_entry_hash(&confirm).unwrap();
    let handoff = sign_ed(
        unsigned_entry(
            Some(id),
            2,
            vec![hash],
            AuthorityOp::ReRoot {
                new_device: device(
                    host_key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            owner_key,
            3,
        ),
        &owner,
    );
    for entry in [&genesis, &confirm, &handoff] {
        vault
            .put_authority_log_entry(entry, TimeRange { start: 1, end: 1 }, 1)
            .unwrap();
    }
    let fold = vault.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash));
    assert!(fold.critical_write_confirms.contains_key(&[194; 32]));
    assert!(!fold.roster[&host_key].revoked);
    (hash, host_key)
}

fn advance_observation_floor(vault: &crate::Vault, now: u64) {
    vault
        .with_write_txn(|txn| {
            vault.store.sync_state.put(
                txn,
                authority_first_seen_clock_sync_key(),
                &encode_authority_first_seen_secs(now),
            )?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn observation_duration_persists_and_expires_re_rooted_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault_at(dir.path(), 1_000);
    let policy = AuthorityObservationPolicy {
        stale_roster_window_secs: 10,
        ..AuthorityObservationPolicy::default()
    };
    vault.set_authority_observation_policy(policy).unwrap();
    let (hash, host_key) = store_re_rooted_confirm(&vault);
    advance_observation_floor(&vault, 1_020);
    let expired = vault.authority_fold().unwrap();
    assert!(
        expired
            .issues
            .contains(&AuthorityFoldIssue::StaleRosterApproval(hash))
    );
    assert!(!expired.valid_entries.contains(&hash));
    assert!(!expired.critical_write_confirms.contains_key(&[194; 32]));
    assert!(!expired.roster[&host_key].revoked);
    let txn = vault.store.env.read_txn().unwrap();
    assert_eq!(vault.authority_fold_readonly_in_txn(&txn).unwrap(), expired);
    drop(txn);
    drop(vault);
    let reopened = open_vault_at(dir.path(), 1_000);
    assert_eq!(reopened.authority_observation_policy().unwrap(), policy);
    assert_eq!(reopened.authority_fold().unwrap(), expired);
}

#[test]
fn warm_authority_cache_rechecks_changed_observation_policy_after_handoff() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault_at(dir.path(), 1_000);
    let (hash, host_key) = store_re_rooted_confirm(&vault);
    advance_observation_floor(&vault, 1_020);
    let txn = vault.store.env.read_txn().unwrap();
    let warm = vault.authority_view_readonly_in_txn(&txn).unwrap();
    assert!(warm.valid_entries.contains(&hash));
    assert!(warm.critical_write_confirms.contains_key(&[194; 32]));
    drop(txn);
    vault
        .set_authority_observation_policy(AuthorityObservationPolicy {
            stale_roster_window_secs: 10,
            ..AuthorityObservationPolicy::default()
        })
        .unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let changed = vault.authority_view_readonly_in_txn(&txn).unwrap();
    assert_eq!(changed.generation(), warm.generation());
    assert!(
        changed
            .issues
            .contains(&AuthorityFoldIssue::StaleRosterApproval(hash))
    );
    assert!(!changed.critical_write_confirms.contains_key(&[194; 32]));
    assert!(!changed.roster[&host_key].revoked);
    drop(txn);
    assert!(
        !vault
            .authority_fold()
            .unwrap()
            .valid_entries
            .contains(&hash)
    );
}
