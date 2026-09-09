//! Readonly fold against full fold under clock skew and sidecars.

use super::support::*;
use super::*;

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
fn readonly_fold_forward_wall_clock_skew_keeps_owner_enrollment_pending() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // Seed the untouched monotonic domain far behind real Unix time.
    let domain = vault.store.authority_clock_domain;
    let seeded_at = authority_observation_secs_for_domain(domain, 0, 1_000);
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
        "wall-clock skew must not expose an owner binding inside the veto window",
    );
    assert_eq!(
        sync_state_snapshot(&vault),
        sync_state_before,
        "deriving the observation time must not make the readonly fold write",
    );
}

#[test]
fn readonly_fold_backward_wall_clock_skew_keeps_elapsed_rotation_applied() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // Real Unix time is behind the injected local authority clock.
    let domain = vault.store.authority_clock_domain;
    let future = crate::unix_seconds_now() + 10 * 24 * 60 * 60;
    let seeded_at = authority_observation_secs_for_domain(domain, 0, future);
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
    assert!(authority_observation_secs_for_domain(domain, elapsed_at, 0) >= elapsed_at);
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
        "wall-clock rollback must not resurrect the retired key's owner binding",
    );

    // Reopen removes the process-local clock; only the persisted floor remains.
    drop(vault);
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
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
        "a reopen under wall-clock rollback must not resurrect the owner binding",
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
    assert!(
        authority_observation_secs_for_domain(vault.store.authority_clock_domain, matured_at, 0)
            >= matured_at,
    );

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
    authority_observation_secs_for_domain(
        vault.store.authority_clock_domain,
        floor,
        crate::unix_seconds_now(),
    )
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
