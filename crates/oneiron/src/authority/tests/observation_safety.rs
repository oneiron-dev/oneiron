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

#[test]
fn signer_hwm_survives_reopen_without_rejecting_its_original_history() {
    let dir = tempfile::tempdir().unwrap();
    let owner = ed_key(181);
    let genesis = genesis_entry(181, DEFAULT_PENDING_WIDEN_DELAY_SECS, u64::MAX);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let first = set_tier_floor_entry(vault_id, &genesis, &owner, 1, AuthorityTier::Software);
    let high = set_tier_floor_entry(vault_id, &first, &owner, 10, AuthorityTier::Software);
    let old = set_tier_floor_entry_at(vault_id, &genesis, &owner, 5, AuthorityTier::Software, 0);
    // This is a fresh, canonical hash with an old seq. Its OWN ancestry does
    // not reject it; the persisted local observation must do that work.
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
        // Do not call a fold before closing: the write transaction owns HWM
        // durability, not a later opportunistic read.
    }
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let old_id = put_replay(&vault, &old, u64::MAX);
    assert_eq!(
        vault.get_authority_log_entry(&old_id).unwrap(),
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
    // Metadata echoes cannot refresh either an accepted or a rejected receipt.
    put_replay(&vault, &old, 999);
    assert_eq!(vault.authority_fold().unwrap(), fold);
    let txn = vault.store.env.read_txn().unwrap();
    assert_eq!(vault.authority_fold_readonly_in_txn(&txn).unwrap(), fold);
    drop(txn);
    drop(vault);
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    assert_eq!(reopened.authority_fold().unwrap(), fold);
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
    let inside = fold_authority_log_with_seen_times(
        &entries,
        &first_seen,
        100 + DEFAULT_STALE_ROSTER_WINDOW_SECS,
    );
    assert!(inside.valid_entries.contains(&approval_hash));
    assert!(actor_binding_is_active(&inside, &actor, "human"));
    assert!(inside.roster[&revoked_key].revoked);
    let outside = fold_authority_log_with_seen_times(
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
        fold_authority_log_with_seen_times(
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
    let renewed_fold = fold_authority_log_with_seen_times(
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
        fold_authority_log_with_seen_times(
            &reversed,
            &first_seen,
            101 + DEFAULT_STALE_ROSTER_WINDOW_SECS,
        )
    );
}

#[test]
fn duration_v1_is_stored_and_changes_the_live_authority_fold() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    authority_observation_secs(&vault.store, 0, 1_000);
    let policy = AuthorityObservationPolicy {
        stale_roster_window_secs: 10,
        ..AuthorityObservationPolicy::default()
    };
    vault.set_authority_observation_policy(policy).unwrap();
    let (entries, revoked_key, actor) = stale_approval_fixture();
    for entry in &entries {
        vault
            .put_authority_log_entry(entry, TimeRange { start: 1, end: 1 }, 0)
            .unwrap();
    }
    let approval_hash = authority_entry_hash(&entries[3]).unwrap();
    assert!(actor_binding_is_active(
        &vault.authority_fold().unwrap(),
        &actor,
        "human"
    ));
    authority_observation_secs(&vault.store, 1_020, 0);
    let outside = vault.authority_fold().unwrap();
    assert!(
        outside
            .issues
            .contains(&AuthorityFoldIssue::StaleRosterApproval(approval_hash))
    );
    assert!(!actor_binding_is_active(&outside, &actor, "human"));
    assert!(outside.roster[&revoked_key].revoked);
    let txn = vault.store.env.read_txn().unwrap();
    assert_eq!(vault.authority_fold_readonly_in_txn(&txn).unwrap(), outside);
    drop(txn);
    drop(vault);
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    assert_eq!(reopened.authority_observation_policy().unwrap(), policy);
    assert_eq!(reopened.authority_fold().unwrap(), outside);
}

#[test]
fn authority_replay_admits_every_row_and_raises_one_typed_peer_check() {
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
        let entry = set_tier_floor_entry(vault_id, &parent, &owner, seq, AuthorityTier::Software);
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
        AuthorityIngestCheck::peer_id_for_signer(&authority_key_from_ed(&owner),)
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
