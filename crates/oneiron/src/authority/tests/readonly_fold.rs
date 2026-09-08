//! Readonly fold against full fold under clock skew and sidecars.

use super::support::*;
use super::*;

#[test]
fn readonly_fold_matches_full_fold_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // A settled store: single-key roster, so no enroll widen is in flight and
    // the binding is live. (A pending widen would make dependent entries
    // Waiting in BOTH fold variants identically — the divergence D5 bounds.)
    //
    // Coverage boundary (fix-leg 2): being settled is exactly why this test is
    // BLIND to which clock the readonly fold reads. With no widen in flight
    // every observation time folds to the same roster, so wall-clock skew is
    // invisible here. The two `readonly_fold_*_wall_clock_skew_*` tests below
    // build logs with a widen actually pending — the only shape that can drive
    // the two folds apart on the clock alone.
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

    // Settle first: the full fold backfills sidecars and advances the
    // first-seen clock, so compare against a settled baseline.
    let full = vault.authority_fold().unwrap();
    assert!(actor_binding_is_active(&full, &actor, "human"));

    let sync_state_before = sync_state_snapshot(&vault);
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert_eq!(
        readonly, full,
        "the in-txn fold must agree with the full fold on a settled store"
    );
    assert_eq!(
        sync_state_snapshot(&vault),
        sync_state_before,
        "the readonly fold must not write a single sync_state byte"
    );
}

/// Forward wall-clock skew must not mature a pending widen in the readonly fold.
///
/// `readonly_fold_matches_full_fold_and_writes_nothing` above CANNOT see this:
/// its log is settled — no widen in flight — so every clock value folds to the
/// same roster and the two variants agree by construction. Only a log with a
/// widen actually pending can drive the folds apart on the clock alone, which
/// is what this fixture builds.
///
/// The skew modelled: the device's monotonic authority clock has barely moved
/// (it sits at 1_000) while the wall clock reads real Unix time, far past the
/// 24h delay. A readonly fold on the raw wall clock would mature the owner
/// enrollment, fold the cosigned `BindActor` child, and hand the facade's
/// owner gate an Active human binding INSIDE the veto window.
#[test]
fn readonly_fold_forward_wall_clock_skew_keeps_owner_enrollment_pending() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // A freshly opened vault owns an untouched clock domain; seed it low so
    // the monotonic reading stays far behind real Unix time for the whole test.
    let domain = vault.store.authority_clock_domain;
    assert_eq!(
        authority_observation_secs_for_domain(domain, 0, 1_000),
        1_000
    );

    let owner = ed_key(213);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(213, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let second = ed_key(214);
    let second_key = authority_key_from_ed(&second);
    // Owner-capable, so a "human" bind on it is admissible the moment the
    // enrollment lands — the whole point of the delay.
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
    // Cosigned: once the enrollment applies the roster holds two active keys,
    // so the bind needs a quorum. A lone-signed bind would be rejected for
    // MissingQuorum on the skewed path and hide the divergence.
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
        "the monotonic clock keeps the enrollment inside its delay"
    );
    assert!(!full.roster.contains_key(&second_key));
    assert!(!actor_binding_is_active(&full, &actor, "human"));

    let sync_state_before = sync_state_snapshot(&vault);
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !actor_binding_is_active(&readonly, &actor, "human"),
        "wall-clock skew must not mature the enrollment and expose an owner binding inside the veto window"
    );
    assert_eq!(
        readonly, full,
        "both folds must read the same monotonic observation time"
    );
    assert_eq!(
        sync_state_snapshot(&vault),
        sync_state_before,
        "deriving the observation time must not make the readonly fold write"
    );
}

/// Backward wall-clock skew must not un-apply an elapsed widen.
///
/// Mirror of the forward case: here the device's authority clock has legitimately
/// advanced past a rotation's delay (so the rotation APPLIED and killed the old
/// key's owner binding), and the wall clock then reads far BELOW the persisted
/// floor. A readonly fold on the raw wall clock would put the rotation back in
/// `pending_widens`, leaving the retired key unrevoked and its owner binding
/// Active again — a revoked device speaking for the owner.
///
/// Checked TWICE, because the monotonic clock has two layers and only the
/// second pins the persisted floor:
///
/// 1. same process — the process-local clock alone already refuses the
///    rollback;
/// 2. after a reopen — the process-local clock is gone with the old vault, so
///    the ONLY thing standing between the rolled-back wall clock and a
///    resurrected owner binding is the floor this fold reads through `txn`.
#[test]
fn readonly_fold_backward_wall_clock_skew_keeps_elapsed_rotation_applied() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // Park the authority clock well ahead of real Unix time. Every first-seen
    // sidecar and the persisted floor are then written from that future
    // reading, so `unix_seconds_now()` is the BACKWARD-skewed clock here.
    let domain = vault.store.authority_clock_domain;
    let future = crate::unix_seconds_now() + 10 * 24 * 60 * 60;
    assert_eq!(
        authority_observation_secs_for_domain(domain, 0, future),
        future
    );

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
    // A rotation retires `owner_key`; bindings deliberately do not migrate, so
    // the human binding dies with the key the moment this widen applies.
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
            owner_key,
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
        "the rotation starts inside its delay"
    );
    assert!(actor_binding_is_active(&pending, &actor, "human"));

    // Let the MONOTONIC clock run past the delay (raising the floor is the only
    // way time moves here; the wall clock stays where it is).
    let elapsed_at = future + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    assert_eq!(
        authority_observation_secs_for_domain(domain, elapsed_at, 0),
        elapsed_at
    );
    let full = vault.authority_fold().unwrap();
    assert!(
        !full.pending_widens.contains_key(&rotate_hash),
        "the rotation must mature once the local clock passes the delay"
    );
    assert!(
        !actor_binding_is_active(&full, &actor, "human"),
        "the applied rotation retires the bound key, so the binding must die with it"
    );

    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !actor_binding_is_active(&readonly, &actor, "human"),
        "wall-clock rollback must not un-apply the rotation and resurrect the retired key's owner binding"
    );
    assert_eq!(
        readonly, full,
        "both folds must read the same monotonic observation time"
    );

    // Layer 2: reopen. Dropping the vault releases its clock domain, so the
    // process-local floor is gone and the rolled-back wall clock is the only
    // candidate reading left. The persisted floor read through the txn is what
    // must hold the line now.
    drop(vault);
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let rtxn = reopened.store.env.read_txn().unwrap();
    let after_reopen = reopened.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !after_reopen.pending_widens.contains_key(&rotate_hash),
        "the persisted clock floor must survive a reopen and keep the rotation applied"
    );
    assert!(
        !actor_binding_is_active(&after_reopen, &actor, "human"),
        "a reopen under a rolled-back wall clock must not resurrect the retired key's owner binding"
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

/// A SIDECAR-LESS rotation must not leave the retired key authorizing — pending
/// is fail-OPEN for the mixed ops, so the readonly fold refuses instead.
///
/// The naive readonly fold simply omitted an entry with no sidecar from
/// `first_seen_at_secs`, on the reasoning that a widen without a first-seen time
/// stays pending and pending is conservative. It is not, for the two ops that
/// revoke while they grant. Here a legacy rooted vault's `RotateKey` K→K2 is
/// sidecar-less; an attacker still holding the RETIRED K files a DAG SIBLING
/// `BindActor(K, attacker, "human")` parented at genesis, so no topological rule
/// kills it. Leave the rotation pending and K is still a live owner-capable
/// roster key, so that binding folds Active and the attacker passes every owner
/// verb.
///
/// fix-leg 4 rewrites the answer. `learned_at` is peer-written metadata, so the
/// long-past values here prove nothing about when THIS vault saw the rows; the
/// fold assumes first-seen-now, which leaves the rotation pending, and then
/// refuses because a pending entry it cannot date is deciding the roster. The
/// attacker is denied through the refusal rather than through a maturity verdict
/// synthesized from their own claim.
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
    // Sibling, not descendant: parented at GENESIS, so it does not sit behind
    // the rotation in the DAG and only the rotation's own maturity can kill it.
    let squat = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![genesis_hash],
            bind_op(&owner_key, attacker, "human", 1),
            owner_key,
            3,
        ),
        &owner,
    );

    // `learned_at` values sit far in the past, which is what a legacy vault's
    // stored rows look like — the rotation's delay elapsed long ago.
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
        "a pre-migration gap is recoverable, not corruption: {err}"
    );

    // The refusal is not a permanent brick. One write-path fold records the
    // local observation, and the rotation then serves its delay from THERE —
    // still pending (it was observed moments ago, not at its long-past claimed
    // `learned_at`), but now on a time this vault actually witnessed, so the
    // readonly fold computes instead of refusing.
    let full = vault.authority_fold().unwrap();
    assert!(
        full.pending_widens.contains_key(&rotate_hash),
        "migration dates the rotation at local observation time, so its delay has NOT elapsed"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    let after_backfill = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert_eq!(
        after_backfill, full,
        "once observed locally, both folds must agree"
    );
    // The attacker's sibling bind rides a key the rotation has not yet retired,
    // so it is live here — and that is correct: the rotation genuinely has not
    // matured on any clock this vault can vouch for. What fix-leg 4 removes is
    // the ability to reach a MATURE verdict from the attacker's own metadata.
    assert!(
        actor_binding_is_active(&after_backfill, &attacker, "human"),
        "before the freshly dated rotation matures the retired key is still live"
    );
}

/// The assumed first-seen time is the LOCAL observation regardless of what
/// `learned_at` claims — in either direction.
///
/// Fix-leg 3 clamped with `min(learned_at, now)`, which handled a forged FUTURE
/// claim (park past every reachable deadline) but swallowed a forged PAST one.
/// Taking the observation outright covers both: this fixture ships the future
/// claim, its twin below ships `learned_at = 0`, and neither moves the value.
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

    // The migration records the local observation, and the forged future date
    // leaves no trace in it.
    let full = vault.authority_fold().unwrap();
    let pending = full
        .pending_widens
        .get(&enroll_hash)
        .expect("a freshly observed enrollment must still be inside its delay");
    assert_eq!(
        pending.first_seen_at_secs,
        Some(readonly_observation_secs(&vault)),
        "first-seen must be the local observation, never the forged future"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(vault.authority_fold_readonly_in_txn(&rtxn).unwrap(), full);
    drop(rtxn);
}

/// The P2 this leg exists for: `learned_at = 0` must not read as "first seen in
/// the distant past, delay long elapsed".
///
/// Mirror of the future-dated case, and the dangerous direction. A legacy,
/// sidecar-less `EnrollDevice` of an OWNER-CAPABLE key is shipped claiming
/// `learned_at = 0`; a child `BindActor(new_key, attacker, "human")` rides it.
/// Under `learned_at.min(floor)` the enrollment dates to 1970, folds MATURE on
/// arrival, puts the attacker's key in the owner-capable roster, and the child
/// bind folds ACTIVE — every owner verb, no veto window, straight through both
/// folds. `observed_floor` never caught this: it clamps FUTURE claims only.
///
/// Local observation is the whole fix. Neither fold can date the row, so the
/// readonly fold refuses; the migration then dates it NOW, which keeps it
/// pending for the full delay and the bind non-authorizing.
#[test]
fn zero_learned_at_enrollment_cannot_instantly_authorize_a_child_bind() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = ed_key(225);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(225, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();

    // Owner-capable, so a "human" bind on it is admissible the instant the
    // enrollment applies — which is exactly what the delay exists to prevent.
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
    // Cosigned: once the enrollment applies the roster holds two active keys,
    // so a lone-signed bind would die on MissingQuorum and hide the divergence.
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

    // `learned_at = 0` on every row: the peer's claim that these were learned at
    // the epoch. Only the ENROLL's claim matters — it is the delayable widen.
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

    // The migration is the other half: it must date the row at local observation
    // too, or the attack simply moves one fold over.
    let full = vault.authority_fold().unwrap();
    assert!(
        full.pending_widens.contains_key(&enroll_hash),
        "an enrollment first observed just now is inside its delay, whatever it claims"
    );
    assert!(
        !full.roster.contains_key(&attacker_key),
        "a pending enrollment must not put the attacker's key in the roster"
    );
    assert!(
        !actor_binding_is_active(&full, &attacker, "human"),
        "the child bind must not authorize while its enrollment is inside the veto window"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !actor_binding_is_active(&readonly, &attacker, "human"),
        "both folds must deny; divergence here is the bug class this leg kills"
    );
    assert_eq!(readonly, full);
}

/// The denial above must not be a blanket "nothing ever matures": an enrollment
/// this vault has genuinely held past its delay still matures and still
/// authorizes its child bind, through BOTH folds.
///
/// Without this row the fix is indistinguishable from breaking the feature.
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

    // Sidecars exist (the write path recorded them), so the fold is computable
    // from the start and the enrollment begins inside its delay.
    let before = vault.authority_fold().unwrap();
    assert!(before.pending_widens.contains_key(&enroll_hash));
    assert!(!actor_binding_is_active(&before, &actor, "human"));

    // Advance the LOCAL monotonic clock past the delay — the only kind of time
    // that counts here.
    let matured_at = readonly_observation_secs(&vault) + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    assert_eq!(
        authority_observation_secs_for_domain(vault.store.authority_clock_domain, matured_at, 0),
        matured_at
    );

    let full = vault.authority_fold().unwrap();
    assert!(
        !full.pending_widens.contains_key(&enroll_hash),
        "a locally matured enrollment must apply"
    );
    assert!(full.roster.contains_key(&second_key));
    assert!(
        actor_binding_is_active(&full, &actor, "human"),
        "the child bind must authorize once its enrollment has genuinely matured"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert_eq!(
        readonly, full,
        "both folds must agree on the matured roster"
    );
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
