//! Readonly fold against full fold under clock skew and sidecars.

use super::support::*;
use super::*;

/// Reference evaluation from one raw LMDB snapshot. Deliberately bypasses
/// AuthorityView and its cache, including their committed-generation shortcut.
pub(super) fn uncached_reference_fold(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
) -> AuthorityFold {
    let entries = authority_log_rows_in_txn(&vault.store, txn)
        .unwrap()
        .into_iter()
        .map(|(_, body)| decode_authority_log_entry_body(&body).unwrap())
        .collect::<Vec<_>>();
    let first_seen = entries
        .iter()
        .filter_map(|entry| {
            let hash = authority_entry_hash(entry).unwrap();
            vault
                .store
                .sync_state
                .get(txn, &authority_first_seen_sync_key(&hash))
                .unwrap()
                .and_then(|raw| decode_authority_first_seen_secs(&raw).map(|seen| (hash, seen)))
        })
        .collect::<BTreeMap<_, _>>();
    let floor = vault
        .store
        .sync_state
        .get(txn, authority_first_seen_clock_sync_key())
        .unwrap()
        .and_then(|raw| decode_authority_first_seen_secs(&raw))
        .unwrap_or(0);
    let now = authority_observation_secs(&vault.store, floor, vault.store.clock.now_recorded_at());
    let peers =
        crate::federation::admitted_peer_consent_roots_for_store_in_txn(&vault.store, txn).unwrap();
    let observations = authority_local_observations_in_txn(&vault.store, txn, &entries).unwrap();
    fold_authority_log_with_local_observations_and_posture_with_deadline(
        &entries,
        &first_seen,
        now,
        &peers,
        &observations,
        vault.privacy_posture(),
    )
    .0
}

#[test]
fn warm_view_matches_uncached_roster_and_slip_decisions() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let issuer = HostSlipIssuer::from_secret(b"reference fold host").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    vault.authority_fold().unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let cached = vault.authority_view_readonly_in_txn(&txn).unwrap();
    let reference = uncached_reference_fold(&vault, &txn);
    assert_eq!(cached.roster, reference.roster);
    assert_eq!(cached.vault_id, reference.vault_id);
    assert_eq!(
        cached.slip_is_live(&root.claims.slip_id),
        reference.slip_is_live(&root.claims.slip_id)
    );
    assert!(cached.slip_is_live(&root.claims.slip_id));
}

/// Manual diagnostic: reports unchanged-view cost against independent raw-log
/// replay; no timing threshold is used as a correctness assertion.
#[test]
#[ignore = "manual authority cache benchmark"]
fn benchmark_cached_authority_reads_against_full_replay() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let issuer = HostSlipIssuer::from_secret(b"authority cache benchmark").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let mut parent = vault.authority_fold().unwrap().slips.mints[&root.claims.slip_id].entry_hash;
    for seq in 2..50 {
        let entry = issuer
            .sign_entry(
                Some(root.claims.vault_id),
                seq,
                vec![parent],
                AuthorityOp::SetTierFloor {
                    tier_floor: AuthorityTier::Software,
                },
                root.claims.issued_at,
            )
            .unwrap();
        parent = authority_entry_hash(&entry).unwrap();
        vault
            .put_authority_log_entry(
                &entry,
                TimeRange {
                    start: seq,
                    end: seq,
                },
                seq,
            )
            .unwrap();
    }
    let txn = vault.store.env.read_txn().unwrap();
    let warm = vault.authority_view_readonly_in_txn(&txn).unwrap();
    let started = Instant::now();
    for _ in 0..300 {
        let view = vault.authority_view_readonly_in_txn(&txn).unwrap();
        std::hint::black_box(view.slip_is_live(&root.claims.slip_id));
    }
    let cached = started.elapsed();
    let started = Instant::now();
    for _ in 0..3 {
        let reference = uncached_reference_fold(&vault, &txn);
        assert_eq!(
            warm.slip_is_live(&root.claims.slip_id),
            reference.slip_is_live(&root.claims.slip_id)
        );
        std::hint::black_box(reference);
    }
    let full = started.elapsed();
    eprintln!(
        "authority cache: 300 unchanged views {cached:?}; 3 full-log folds {full:?}; 50 signed entries"
    );
}

#[test]
fn readonly_fold_matches_full_fold_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // A settled single-key roster has no enrollment widen in flight.
    let genesis = genesis_entry(208, DEFAULT_PENDING_WIDEN_DELAY_SECS, 200);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let owner = ed_key(208);
    let owner_key = authority_key_from_ed(&owner);
    let actor = scope_entity(0x5d);
    let bind = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            bind_op(&owner_key, actor, "human", 1),
            owner_key,
            201,
        ),
        &owner,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (bind, TimeRange { start: 2, end: 2 }, 2),
        ])
        .unwrap();

    // Settle backfill and the persisted clock before checking for writes.
    let full = vault.authority_fold().unwrap();
    assert!(actor_binding_is_active(&full, &actor, "human"));

    let sync_state_before = sync_state_snapshot(&vault);
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(actor_binding_is_active(&readonly, &actor, "human"));
    assert_eq!(
        sync_state_snapshot(&vault),
        sync_state_before,
        "the readonly fold must not write a single sync_state byte",
    );
}

/// A sidecar missing AFTER the one-shot migration ran is unrecoverable, so the
/// readonly fold must refuse rather than pick a side.
///
/// Synthesis is only sound while the backfill has not run: it reproduces what
/// the migration WOULD write. Once the marker is set the migration will never
/// visit that row again, so a re-synthesized `learned_at.min(now)` would silently
/// disagree with every sidecar its peers kept — and both available guesses are
/// unsafe (mature early = skipped veto window; stay pending = live retired key).
/// An undecodable row is the same state and takes the same door.
#[test]
fn readonly_fold_rejects_sidecar_lost_after_backfill() {
    for corrupt_in_place in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        let owner = ed_key(223);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(223, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        let genesis_hash = authority_entry_hash(&genesis).unwrap();
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let actor = scope_entity(0x63);
        let bind = sign_ed(
            unsigned_entry(
                Some(vault_id),
                1,
                vec![genesis_hash],
                bind_op(&owner_key, actor, "human", 1),
                owner_key,
                2,
            ),
            &owner,
        );
        let bind_hash = authority_entry_hash(&bind).unwrap();
        vault
            .put_authority_log_entries(&[
                (genesis, TimeRange { start: 1, end: 1 }, 1),
                (bind, TimeRange { start: 2, end: 2 }, 2),
            ])
            .unwrap();
        // Settle: this is what sets the one-shot marker.
        vault.authority_fold().unwrap();
        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_state
                .get(&rtxn, authority_first_seen_backfill_sync_key())
                .unwrap()
                .is_some(),
            "the full fold must have set the one-shot marker"
        );
        drop(rtxn);

        let sidecar = authority_first_seen_sync_key(&bind_hash);
        vault
            .with_write_txn(|wtxn| {
                if corrupt_in_place {
                    // Present but undecodable: not 8 bytes.
                    vault.store.sync_state.put(wtxn, sidecar.as_str(), &[9])?;
                } else {
                    assert!(vault.store.sync_state.delete(wtxn, sidecar.as_str())?);
                }
                advance_authority_cache_generation(&vault.store, wtxn)?;
                Ok(())
            })
            .unwrap();

        let rtxn = vault.store.env.read_txn().unwrap();
        let err = vault
            .authority_fold_readonly_in_txn(&rtxn)
            .expect_err("a post-migration sidecar gap must refuse the fold");
        drop(rtxn);
        assert!(
            is_corrupt_first_seen_sidecar(&err),
            "corrupt_in_place={corrupt_in_place}: {err}"
        );
    }
}

#[test]
fn authority_cache_is_bound_to_snapshot_and_abort_does_not_publish_a_mint() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = ed_key(243);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(243, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    vault
        .put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let actor = scope_entity(0x83);
    let mint = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            bind_op(&owner_key, actor, "human", 1),
            owner_key.clone(),
            2,
        ),
        &owner,
    );
    let revoke = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![authority_entry_hash(&mint).unwrap()],
            AuthorityOp::RevokeActor {
                authority_key: owner_key,
                epoch: 1,
            },
            authority_key_from_ed(&owner),
            3,
        ),
        &owner,
    );
    let row = |entry: AuthorityLogEntry| (entry, TimeRange { start: 1, end: 1 }, 1);

    // LMDB's default reader slot is thread-local: distinct simultaneous
    // snapshots must be held on distinct threads, not opened twice here.
    let before_generation = std::thread::scope(|scope| {
        let vault = &vault;
        let (ready, started) = std::sync::mpsc::sync_channel(0);
        let (check, checked) = std::sync::mpsc::sync_channel(0);
        let old = scope.spawn(move || {
            let before = vault.store.env.read_txn().unwrap();
            let before_view = vault.authority_view_readonly_in_txn(&before).unwrap();
            assert!(!actor_binding_is_active(&before_view, &actor, "human"));
            ready.send(before_view.generation()).unwrap();
            checked.recv().unwrap();
            assert!(!actor_binding_is_active(
                &vault.authority_view_readonly_in_txn(&before).unwrap(),
                &actor,
                "human"
            ));
        });
        let before_generation = started.recv().unwrap();
        let mut aborted = vault.store.env.write_txn().unwrap();
        vault
            .put_authority_log_entries_in_txn(&mut aborted, &[row(mint.clone())])
            .unwrap();
        let writer_view = vault.authority_view_readonly_in_txn(&aborted).unwrap();
        assert!(writer_view.generation() > before_generation);
        assert!(actor_binding_is_active(&writer_view, &actor, "human"));
        check.send(()).unwrap();
        old.join().unwrap();
        aborted.abort();
        before_generation
    });
    let after_abort = vault.store.env.read_txn().unwrap();
    let after_abort_view = vault.authority_view_readonly_in_txn(&after_abort).unwrap();
    assert_eq!(after_abort_view.generation(), before_generation);
    assert!(!actor_binding_is_active(&after_abort_view, &actor, "human"));
    drop(after_abort);

    vault
        .put_authority_log_entry(&mint, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    std::thread::scope(|scope| {
        let vault = &vault;
        let (ready, started) = std::sync::mpsc::sync_channel(0);
        let (check, checked) = std::sync::mpsc::sync_channel(0);
        let old = scope.spawn(move || {
            let before = vault.store.env.read_txn().unwrap();
            let before_view = vault.authority_view_readonly_in_txn(&before).unwrap();
            assert!(actor_binding_is_active(&before_view, &actor, "human"));
            ready.send(before_view.generation()).unwrap();
            checked.recv().unwrap();
            assert!(actor_binding_is_active(
                &vault.authority_view_readonly_in_txn(&before).unwrap(),
                &actor,
                "human"
            ));
        });
        let before_generation = started.recv().unwrap();
        vault
            .put_authority_log_entry(&revoke, TimeRange { start: 1, end: 1 }, 1)
            .unwrap();
        let after = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .authority_view_readonly_in_txn(&after)
                .unwrap()
                .generation()
                > before_generation
        );
        for _ in 0..2 {
            assert!(!actor_binding_is_active(
                &vault.authority_view_readonly_in_txn(&after).unwrap(),
                &actor,
                "human"
            ));
        }
        check.send(()).unwrap();
        old.join().unwrap();
        drop(after);
    });
    assert!(!actor_binding_is_active(
        &vault.authority_fold().unwrap(),
        &actor,
        "human"
    ));
}

#[test]
fn pre_handoff_rotation_deadline_rechecks_cached_root_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault_at(dir.path(), 1_000);
    let owner = ed_key(126);
    let replacement = ed_key(127);
    let host = ed_key(128);
    let owner_key = authority_key_from_ed(&owner);
    let replacement_key = authority_key_from_ed(&replacement);
    let host_key = authority_key_from_ed(&host);
    let genesis = genesis_entry(126, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let rotation = rotate_entry(id, &genesis, &owner, owner_key.clone(), 127, 1);
    let rotation_hash = authority_entry_hash(&rotation).unwrap();
    let handoff = sign_ed(
        unsigned_entry(
            Some(id),
            0,
            vec![rotation_hash],
            AuthorityOp::ReRoot {
                new_device: device(
                    host_key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            replacement_key.clone(),
            3,
        ),
        &replacement,
    );
    let handoff_hash = authority_entry_hash(&handoff).unwrap();
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (rotation.clone(), TimeRange { start: 2, end: 2 }, 2),
            (handoff, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let before = vault.authority_view_readonly_in_txn(&txn).unwrap();
    assert!(before.pending_widens.contains_key(&rotation_hash));
    assert!(!before.valid_entries.contains(&handoff_hash));
    assert!(!before.roster[&owner_key].revoked);
    assert!(!before.roster.contains_key(&host_key));
    assert_eq!(
        *vault.authority_view_readonly_in_txn(&txn).unwrap(),
        *before
    );
    drop(txn);
    mature_observed_widen(&vault, &rotation);
    let txn = vault.store.env.read_txn().unwrap();
    let after = vault.authority_view_readonly_in_txn(&txn).unwrap();
    assert!(after.valid_entries.contains(&handoff_hash));
    assert!(after.pending_widens.is_empty());
    assert!(after.roster[&owner_key].revoked);
    assert!(after.roster[&replacement_key].revoked);
    assert!(!after.roster[&host_key].revoked);
    drop(txn);
    drop(vault);
    let reopened = open_vault_at(dir.path(), 1_000);
    assert!(
        reopened
            .authority_fold()
            .unwrap()
            .valid_entries
            .contains(&handoff_hash)
    );
    assert!(reopened.authority_fold().unwrap().roster[&owner_key].revoked);
}

#[test]
fn pre_handoff_rotation_without_local_observation_refuses_readonly_authority() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault_at(dir.path(), 1_000);
    let owner = ed_key(129);
    let replacement = ed_key(130);
    let genesis = genesis_entry(129, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let rotation = rotate_entry(id, &genesis, &owner, authority_key_from_ed(&owner), 130, 1);
    let rotation_hash = authority_entry_hash(&rotation).unwrap();
    let handoff = sign_ed(
        unsigned_entry(
            Some(id),
            0,
            vec![rotation_hash],
            AuthorityOp::ReRoot {
                new_device: device(
                    authority_key_from_ed(&ed_key(131)),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            authority_key_from_ed(&replacement),
            3,
        ),
        &replacement,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (rotation, TimeRange { start: 2, end: 2 }, 0),
            (handoff, TimeRange { start: 3, end: 3 }, 0),
        ])
        .unwrap();
    assert!(
        vault
            .authority_fold()
            .unwrap()
            .pending_widens
            .contains_key(&rotation_hash)
    );
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .sync_state
                .delete(txn, &authority_first_seen_sync_key(&rotation_hash))?;
            vault
                .store
                .sync_state
                .delete(txn, authority_first_seen_backfill_sync_key())?;
            advance_authority_cache_generation(&vault.store, txn)?;
            Ok(())
        })
        .unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let err = vault.authority_fold_readonly_in_txn(&txn).unwrap_err();
    assert!(is_indeterminate_first_seen(&err), "{err}");
    drop(txn);
    let backfilled = vault.authority_fold().unwrap();
    assert!(backfilled.pending_widens.contains_key(&rotation_hash));
}
