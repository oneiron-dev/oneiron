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
    fold_authority_log_with_local_observations_and_posture(
        &entries,
        &first_seen,
        now,
        &peers,
        &observations,
        vault.privacy_posture(),
    )
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

#[test]
fn readonly_fold_injected_clock_behind_real_time_keeps_owner_enrollment_pending() {
    let dir = tempfile::tempdir().unwrap();
    // Open seeds this vault's monotonic clock from its injected clock, far
    // behind real Unix time.
    let vault = open_vault_at(dir.path(), 1_000);
    let seeded_at = authority_observation_secs(&vault.store, 0, 1_000);
    assert!(seeded_at >= 1_000);
    assert!(seeded_at < 1_000 + DEFAULT_PENDING_WIDEN_DELAY_SECS);

    let owner = ed_key(213);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(213, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let second = ed_key(214);
    let second_key = authority_key_from_ed(&second);
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 214,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let actor = scope_entity(0x5e);
    // Cosigning lets the child authorize if the enrollment incorrectly matures.
    let bind = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![enroll_hash],
            bind_op(&second_key, actor, "human", 1),
            owner_key,
            3,
        ),
        &owner,
        &second,
    );

    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (enroll, TimeRange { start: 2, end: 2 }, 2),
            (bind, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();

    let full = vault.authority_fold().unwrap();
    assert!(
        full.pending_widens.contains_key(&enroll_hash),
        "the monotonic clock keeps the enrollment inside its delay",
    );
    assert!(!full.roster.contains_key(&second_key));
    assert!(!actor_binding_is_active(&full, &actor, "human"));

    let sync_state_before = sync_state_snapshot(&vault);
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(readonly.pending_widens.contains_key(&enroll_hash));
    assert!(!readonly.roster.contains_key(&second_key));
    assert!(
        !actor_binding_is_active(&readonly, &actor, "human"),
        "an injected clock behind real time must not expose an owner binding inside the veto window",
    );
    assert_eq!(
        sync_state_snapshot(&vault),
        sync_state_before,
        "deriving the observation time must not make the readonly fold write",
    );
}

#[test]
fn readonly_fold_for_store_uses_injected_clock_for_owner_enrollment() {
    let dir = tempfile::tempdir().unwrap();
    let clock = crate::ports::ManualClock::new(1_000);
    let mut config = crate::VaultConfig::device();
    config.store_clock = crate::ports::StoreClock::new(clock.clone(), clock);
    let vault = crate::Vault::open(dir.path(), config.clone()).unwrap();
    let owner = ed_key(213);
    let genesis = genesis_entry(213, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let second_key = authority_key_from_ed(&ed_key(214));
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 214,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (enroll, TimeRange { start: 2, end: 2 }, 2),
        ])
        .unwrap();
    // An existing anchor or persisted floor would mask which clock the fold reads.
    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .sync_state
                .delete(wtxn, authority_first_seen_clock_sync_key())?;
            Ok(())
        })
        .unwrap();
    drop(vault);
    let vault = crate::Vault::open(dir.path(), config).unwrap();
    let sync_state_before = sync_state_snapshot(&vault);
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly =
        authority_fold_readonly_for_store_in_txn(&vault.store, vault.privacy_posture(), &rtxn)
            .unwrap();
    drop(rtxn);
    assert!(readonly.pending_widens.contains_key(&enroll_hash));
    assert_eq!(
        readonly.pending_widens[&enroll_hash].first_seen_at_secs,
        Some(1_000),
    );
    assert!(!readonly.roster.contains_key(&second_key));
    assert_eq!(sync_state_snapshot(&vault), sync_state_before);
}

#[test]
fn readonly_fold_rolled_back_injected_clock_keeps_elapsed_rotation_applied() {
    let dir = tempfile::tempdir().unwrap();
    // The reopen's clock is ten days behind the injected local authority clock.
    let rolled_back = 1_000;
    let future = rolled_back + 10 * 24 * 60 * 60;
    let vault = open_vault_at(dir.path(), future);
    let seeded_at = authority_observation_secs(&vault.store, 0, future);
    assert!(seeded_at >= future);
    assert!(seeded_at < future + DEFAULT_PENDING_WIDEN_DELAY_SECS);

    let owner = ed_key(215);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(215, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let actor = scope_entity(0x5f);
    let bind = sign_ed(
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
    // Bindings do not migrate to the replacement key.
    let rotated = ed_key(216);
    let rotate = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![authority_entry_hash(&bind).unwrap()],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(
                    authority_key_from_ed(&rotated),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            owner_key.clone(),
            3,
        ),
        &owner,
    );
    let rotate_hash = authority_entry_hash(&rotate).unwrap();

    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (bind, TimeRange { start: 2, end: 2 }, 2),
            (rotate, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();

    let pending = vault.authority_fold().unwrap();
    assert!(
        pending.pending_widens.contains_key(&rotate_hash),
        "the rotation starts inside its delay",
    );
    assert!(actor_binding_is_active(&pending, &actor, "human"));

    // Advance only the local monotonic clock, not the wall clock.
    let elapsed_at = future + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    assert!(authority_observation_secs(&vault.store, elapsed_at, 0) >= elapsed_at);
    let full = vault.authority_fold().unwrap();
    assert!(
        !full.pending_widens.contains_key(&rotate_hash),
        "the rotation must mature once the local clock passes the delay",
    );
    assert!(
        !actor_binding_is_active(&full, &actor, "human"),
        "the applied rotation must kill the retired key's binding",
    );

    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(!readonly.pending_widens.contains_key(&rotate_hash));
    assert!(
        !readonly
            .roster
            .get(&owner_key)
            .is_some_and(folded_device_can_authority_consent),
        "the retired key must no longer provide authority consent",
    );
    assert!(
        !actor_binding_is_active(&readonly, &actor, "human"),
        "a rolled-back injected clock must not resurrect the retired key's owner binding",
    );

    // Reopen drops the old handle's clock; only the persisted floor remains.
    drop(vault);
    let reopened = open_vault_at(dir.path(), rolled_back);
    let rtxn = reopened.store.env.read_txn().unwrap();
    let after_reopen = reopened.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !after_reopen.pending_widens.contains_key(&rotate_hash),
        "the persisted clock floor must keep the rotation applied after reopen",
    );
    assert!(
        !after_reopen
            .roster
            .get(&owner_key)
            .is_some_and(folded_device_can_authority_consent),
        "reopening must not restore the retired key's authority consent",
    );
    assert!(
        !actor_binding_is_active(&after_reopen, &actor, "human"),
        "a reopen under a rolled-back injected clock must not resurrect the owner binding",
    );
}

/// Rewinds a vault to the pre-migration shape a legacy rooted store has: every
/// first-seen sidecar gone and the one-shot backfill marker unset.
fn strip_first_seen_sidecars(vault: &crate::Vault, drop_backfill_marker: bool) {
    let rtxn = vault.store.env.read_txn().unwrap();
    let keys: Vec<String> = vault
        .store
        .sync_state
        .iter(&rtxn)
        .unwrap()
        .map(|row| row.unwrap().0.into_owned())
        .filter(|key| {
            key.starts_with("authlog:first_seen:")
                && key != authority_first_seen_clock_sync_key()
                && (drop_backfill_marker || key != authority_first_seen_backfill_sync_key())
        })
        .collect();
    drop(rtxn);
    assert!(
        !keys.is_empty(),
        "fixture must have written sidecars to strip"
    );
    vault
        .with_write_txn(|wtxn| {
            for key in &keys {
                assert!(vault.store.sync_state.delete(wtxn, key.as_str())?);
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn readonly_fold_refuses_when_a_sidecarless_rotation_decides_the_roster() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = ed_key(219);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(219, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let vault_id = genesis_vault_id(&genesis).unwrap();

    let rotated = ed_key(220);
    let rotate = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![genesis_hash],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(
                    authority_key_from_ed(&rotated),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            owner_key.clone(),
            2,
        ),
        &owner,
    );
    let rotate_hash = authority_entry_hash(&rotate).unwrap();
    let attacker = scope_entity(0x62);
    // A sibling at genesis is not topologically blocked behind the rotation.
    let squat = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![genesis_hash],
            bind_op(&owner_key, attacker, "human", 1),
            owner_key.clone(),
            3,
        ),
        &owner,
    );

    // The peer's long-past learned_at claims cannot establish local maturity.
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (rotate, TimeRange { start: 2, end: 2 }, 2),
            (squat, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();
    strip_first_seen_sidecars(&vault, true);

    let rtxn = vault.store.env.read_txn().unwrap();
    let err = vault
        .authority_fold_readonly_in_txn(&rtxn)
        .expect_err("an undatable rotation must not silently decide the roster");
    drop(rtxn);
    assert!(
        is_indeterminate_first_seen(&err),
        "a pre-migration gap is recoverable, not corruption: {err}",
    );

    // Migration starts the delay at local observation, making readonly usable.
    let full = vault.authority_fold().unwrap();
    assert!(
        full.pending_widens.contains_key(&rotate_hash),
        "migration dates the rotation locally, so its delay has not elapsed",
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    let after_backfill = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(after_backfill.pending_widens.contains_key(&rotate_hash));
    assert!(
        after_backfill
            .roster
            .get(&owner_key)
            .is_some_and(folded_device_can_authority_consent),
        "the locally pending rotation must not yet retire the consenting key",
    );
    assert!(
        actor_binding_is_active(&after_backfill, &attacker, "human"),
        "before the freshly dated rotation matures the sibling binding is live",
    );
}

#[test]
fn readonly_fold_ignores_future_learned_at_and_assumes_local_observation() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = ed_key(221);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(221, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enrolled = ed_key(222);
    let enroll = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![genesis_hash],
            AuthorityOp::EnrollDevice {
                device: device(
                    authority_key_from_ed(&enrolled),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            owner_key,
            2,
        ),
        &owner,
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let far_future = crate::unix_seconds_now() + 3650 * 24 * 60 * 60;
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (
                enroll,
                TimeRange {
                    start: 2,
                    end: far_future,
                },
                far_future,
            ),
        ])
        .unwrap();
    strip_first_seen_sidecars(&vault, true);

    let rtxn = vault.store.env.read_txn().unwrap();
    let err = vault
        .authority_fold_readonly_in_txn(&rtxn)
        .expect_err("an undated pending enrollment must refuse, not authorize");
    drop(rtxn);
    assert!(is_indeterminate_first_seen(&err), "{err}");

    // Bound the recorded timestamp by local observations, not peer metadata.
    let observation_before = readonly_observation_secs(&vault);
    let full = vault.authority_fold().unwrap();
    let observation_after = readonly_observation_secs(&vault);
    assert!(observation_after < far_future);
    let pending = full
        .pending_widens
        .get(&enroll_hash)
        .expect("a freshly observed enrollment must still be inside its delay");
    let first_seen = pending
        .first_seen_at_secs
        .expect("migration must record a local first-seen time");
    assert!(first_seen >= observation_before);
    assert!(first_seen <= observation_after);

    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    let pending = readonly
        .pending_widens
        .get(&enroll_hash)
        .expect("the readonly enrollment must remain inside its local delay");
    let first_seen = pending
        .first_seen_at_secs
        .expect("the readonly fold must use the locally recorded observation");
    assert!(first_seen >= observation_before);
    assert!(first_seen <= observation_after);
}

#[test]
fn zero_learned_at_enrollment_cannot_instantly_authorize_a_child_bind() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = ed_key(225);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(225, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();

    // The enrolled key can own a human binding as soon as enrollment applies.
    let attacker_signing = ed_key(226);
    let attacker_key = authority_key_from_ed(&attacker_signing);
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 226,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let attacker = scope_entity(0x64);
    // Cosigning avoids a missing quorum masking premature enrollment maturity.
    let bind = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![enroll_hash],
            bind_op(&attacker_key, attacker, "human", 1),
            owner_key,
            3,
        ),
        &owner,
        &attacker_signing,
    );

    // All rows claim learned_at = 0, including the delayable enrollment.
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 0),
            (enroll, TimeRange { start: 1, end: 1 }, 0),
            (bind, TimeRange { start: 1, end: 1 }, 0),
        ])
        .unwrap();
    strip_first_seen_sidecars(&vault, true);

    let rtxn = vault.store.env.read_txn().unwrap();
    let err = vault
        .authority_fold_readonly_in_txn(&rtxn)
        .expect_err("a `learned_at = 0` enrollment must not date itself into maturity");
    drop(rtxn);
    assert!(is_indeterminate_first_seen(&err), "{err}");

    // Migration must also deny the attack by dating the entry locally.
    let full = vault.authority_fold().unwrap();
    assert!(
        full.pending_widens.contains_key(&enroll_hash),
        "an enrollment first observed just now is inside its delay, whatever it claims",
    );
    assert!(
        !full.roster.contains_key(&attacker_key),
        "a pending enrollment must not put the attacker's key in the roster",
    );
    assert!(
        !actor_binding_is_active(&full, &attacker, "human"),
        "the child bind must not authorize inside the enrollment's veto window",
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(readonly.pending_widens.contains_key(&enroll_hash));
    assert!(!readonly.roster.contains_key(&attacker_key));
    assert!(
        !actor_binding_is_active(&readonly, &attacker, "human"),
        "the readonly fold must also deny the child binding",
    );
}

#[test]
fn locally_matured_enrollment_still_authorizes_its_child_bind() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = ed_key(227);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(227, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let second = ed_key(228);
    let second_key = authority_key_from_ed(&second);
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 228,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let actor = scope_entity(0x65);
    let bind = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![enroll_hash],
            bind_op(&second_key, actor, "human", 1),
            owner_key,
            3,
        ),
        &owner,
        &second,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (enroll, TimeRange { start: 2, end: 2 }, 2),
            (bind, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();

    // Existing sidecars make the initially pending enrollment computable.
    let before = vault.authority_fold().unwrap();
    assert!(before.pending_widens.contains_key(&enroll_hash));
    assert!(!actor_binding_is_active(&before, &actor, "human"));

    // Advance the local monotonic clock past the locally observed delay.
    let matured_at = readonly_observation_secs(&vault) + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    assert!(authority_observation_secs(&vault.store, matured_at, 0) >= matured_at);

    let full = vault.authority_fold().unwrap();
    assert!(
        !full.pending_widens.contains_key(&enroll_hash),
        "a locally matured enrollment must apply",
    );
    assert!(full.roster.contains_key(&second_key));
    assert!(
        actor_binding_is_active(&full, &actor, "human"),
        "the child bind must authorize once its enrollment has genuinely matured",
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(!readonly.pending_widens.contains_key(&enroll_hash));
    assert!(readonly.roster.contains_key(&second_key));
    assert!(actor_binding_is_active(&readonly, &actor, "human"));
}

/// The observation seconds a readonly fold would derive right now, without
/// disturbing the persisted floor.
fn readonly_observation_secs(vault: &crate::Vault) -> u64 {
    let rtxn = vault.store.env.read_txn().unwrap();
    let floor = vault
        .store
        .sync_state
        .get(&rtxn, authority_first_seen_clock_sync_key())
        .unwrap()
        .and_then(|raw| decode_authority_first_seen_secs(&raw))
        .unwrap_or(0);
    drop(rtxn);
    authority_observation_secs(&vault.store, floor, vault.now_recorded_at())
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
fn matured_rotation_with_corrupt_sidecar_refuses_public_and_snapshot_folds() {
    for malformed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let clock = 1_000_000;
        let vault = open_vault_at(dir.path(), clock);
        let owner = ed_key(230);
        let owner_key = authority_key_from_ed(&owner);
        let actor = scope_entity(0x85);
        let genesis = genesis_entry(230, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let bind = sign_ed(
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
        let rotate = sign_ed(
            unsigned_entry(
                Some(vault_id),
                2,
                vec![authority_entry_hash(&bind).unwrap()],
                AuthorityOp::RotateKey {
                    old_key: owner_key.clone(),
                    new_device: device(
                        authority_key_from_ed(&ed_key(231)),
                        ROLE_OWNER | ROLE_ADMIN,
                        AuthorityTier::Software,
                    ),
                },
                owner_key.clone(),
                3,
            ),
            &owner,
        );
        let rotate_hash = authority_entry_hash(&rotate).unwrap();
        vault
            .put_authority_log_entries(&[
                (genesis, TimeRange { start: 1, end: 1 }, 1),
                (bind, TimeRange { start: 2, end: 2 }, 2),
                (rotate, TimeRange { start: 3, end: 3 }, 3),
            ])
            .unwrap();
        let pending = vault.authority_fold().unwrap();
        assert!(pending.pending_widens.contains_key(&rotate_hash));
        authority_observation_secs(
            &vault.store,
            clock + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1,
            0,
        );
        let settled = vault.authority_fold().unwrap();
        assert!(!actor_binding_is_active(&settled, &actor, "human"));
        assert!(
            !settled
                .roster
                .get(&owner_key)
                .is_some_and(folded_device_can_authority_consent)
        );

        let sidecar = authority_first_seen_sync_key(&rotate_hash);
        vault
            .with_write_txn(|txn| {
                if malformed {
                    vault.store.sync_state.put(txn, &sidecar, &[9])?;
                } else {
                    assert!(vault.store.sync_state.delete(txn, &sidecar)?);
                }
                Ok(())
            })
            .unwrap();
        drop(vault); // A new handle cannot hide the missing evidence behind a warm view.
        let reopened = open_vault_at(dir.path(), clock);
        let txn = reopened.store.env.read_txn().unwrap();
        let readonly_error = reopened.authority_fold_readonly_in_txn(&txn).unwrap_err();
        drop(txn);
        let public_error = reopened.authority_fold().unwrap_err();
        assert!(
            is_corrupt_first_seen_sidecar(&readonly_error),
            "{readonly_error}"
        );
        assert!(
            is_corrupt_first_seen_sidecar(&public_error),
            "{public_error}"
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
