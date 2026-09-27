//! Persisted anti-rollback, bounded stale-roster approvals and advisory ingest checks.

use super::support::*;
use super::*;

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
