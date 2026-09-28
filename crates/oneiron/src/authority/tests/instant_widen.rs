//! Widening lands at once: no pending state, no seen-time delay, no freeze.
//!
//! The device-key widen ceremony and its delayed-broadcast veto died
//! 2026-08-05 (identity canon, "Device-key widen ceremony (dead 2026-08-05)";
//! ARCH-0040 ONE-AUTHLOG-F6). Widening is owner action through the host, so an
//! owner-signed enrollment, rotation or lowered floor is the whole ceremony.
//! The vault door now retires client device-key ops (see `retired_device_ops`),
//! so the legacy-history rows here fold through the legacy reference fold; the
//! vault row uses the agent-only enrollment the host still lands.

use super::support::*;
use super::*;

/// Every hash first seen at `now`: the worst case under the dead delay, which
/// would have held every widen pending for the full window.
fn all_first_seen_at(entries: &[AuthorityLogEntry], now: u64) -> BTreeMap<AuthorityEntryHash, u64> {
    entries
        .iter()
        .map(|entry| (authority_entry_hash(entry).unwrap(), now))
        .collect()
}

struct EnrollmentWithVeto {
    entries: Vec<AuthorityLogEntry>,
    roles: u16,
    class: &'static str,
    phone_key: AuthorityKey,
    actor: crate::entity_id::EntityId,
    enroll_hash: AuthorityEntryHash,
    bind_hash: AuthorityEntryHash,
    veto_hash: AuthorityEntryHash,
}

/// A software owner enrolls a software phone; the phone's human binding
/// descends from the enrollment; a legacy veto names the enrollment.
fn enrollment_with_veto(seed: u8) -> EnrollmentWithVeto {
    enrollment_with_veto_as(seed, ROLE_OWNER | ROLE_ADMIN, "human")
}

fn enrollment_with_veto_as(seed: u8, roles: u16, class: &'static str) -> EnrollmentWithVeto {
    let owner = ed_key(seed);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(seed, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let phone = ed_key(seed.wrapping_add(1));
    let phone_key = authority_key_from_ed(&phone);
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: seed.wrapping_add(1),
            roles,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let actor = scope_entity(seed);
    // The two-device roster requires a cosign; the new key provides it.
    let bind = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![enroll_hash],
            bind_op(&phone_key, actor, class, 1),
            owner_key,
            3,
        ),
        &owner,
        &phone,
    );
    let bind_hash = authority_entry_hash(&bind).unwrap();
    let veto = veto_entry(vault_id, &genesis, &owner, enroll_hash, 3);
    let veto_hash = authority_entry_hash(&veto).unwrap();
    EnrollmentWithVeto {
        entries: vec![genesis, enroll, bind, veto],
        roles,
        class,
        phone_key,
        actor,
        enroll_hash,
        bind_hash,
        veto_hash,
    }
}

fn assert_enrollment_landed_and_veto_rejected(fold: &AuthorityFold, fixture: &EnrollmentWithVeto) {
    let phone = fold
        .roster
        .get(&fixture.phone_key)
        .expect("an owner-signed software enrollment lands at once");
    assert!(!phone.revoked);
    assert_eq!(phone.roles, fixture.roles);
    assert!(fold.valid_entries.contains(&fixture.enroll_hash));
    assert!(
        fold.valid_entries.contains(&fixture.bind_hash),
        "an entry descending from the enrollment folds at once: nothing freezes"
    );
    assert!(actor_binding_is_active(fold, &fixture.actor, fixture.class));
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::InvalidEntry(fixture.veto_hash)),
        "a legacy veto has nothing to veto and folds as InvalidEntry"
    );
    assert!(!fold.valid_entries.contains(&fixture.veto_hash));
}

#[test]
fn software_owner_enrollment_lands_at_once_and_a_legacy_veto_is_invalid() {
    let fixture = enrollment_with_veto(150);
    let now = 10_000_000;
    let first_seen = all_first_seen_at(&fixture.entries, now);

    let fold = fold_legacy_authority_log_with_seen_times(&fixture.entries, &first_seen, now);
    assert_enrollment_landed_and_veto_rejected(&fold, &fixture);
    assert_eq!(fold_legacy_authority_log(&fixture.entries), fold);

    // The vault door retires the client enrollment itself; the veto stays
    // invalid there too.
    let door = fold_authority_log_with_seen_times(&fixture.entries, &first_seen, now);
    assert!(!door.valid_entries.contains(&fixture.enroll_hash));
    assert!(!door.roster.contains_key(&fixture.phone_key));
    assert!(
        door.issues
            .contains(&AuthorityFoldIssue::InvalidEntry(fixture.veto_hash))
    );

    let mut reversed = fixture.entries;
    reversed.reverse();
    assert_eq!(
        fold_legacy_authority_log_with_seen_times(&reversed, &first_seen, now),
        fold
    );
}

#[test]
fn vault_fold_lands_a_just_observed_enrollment_at_once() {
    let fixture = enrollment_with_veto_as(152, ROLE_AGENT, "system");
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // One put per row, in causal order, so each signer's observed sequence
    // high-water mark only ever rises.
    for (entry, at) in fixture.entries.iter().zip(1_u64..) {
        vault
            .put_authority_log_entries(&[(entry.clone(), TimeRange { start: at, end: at }, at)])
            .unwrap();
    }

    // Every row is first observed by this vault right now.
    let fold = vault.authority_fold().unwrap();
    assert_enrollment_landed_and_veto_rejected(&fold, &fixture);
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert_eq!(readonly, fold);
}

#[test]
fn lowered_tier_floor_and_its_descendant_land_at_once() {
    let hardware = p256_key(154);
    let key = authority_key_from_p256(&hardware);
    let genesis = sign_p256(
        unsigned_entry(
            None,
            0,
            vec![],
            AuthorityOp::Genesis {
                device: device(
                    key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Hardware,
                ),
                genesis_nonce: [154; 32],
                tier_floor: AuthorityTier::Hardware,
                pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
                recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            },
            key.clone(),
            1,
        ),
        &hardware,
    );
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let lower = sign_p256(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Software,
            },
            key.clone(),
            2,
        ),
        &hardware,
    );
    let lower_hash = authority_entry_hash(&lower).unwrap();
    let laptop_key = authority_key_from_ed(&ed_key(155));
    let enroll = sign_p256(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![lower_hash],
            AuthorityOp::EnrollDevice {
                device: device(laptop_key.clone(), ROLE_AGENT, AuthorityTier::Software),
            },
            key,
            3,
        ),
        &hardware,
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let entries = vec![genesis, lower, enroll];
    let now = 10_000_000;

    let fold =
        fold_legacy_authority_log_with_seen_times(&entries, &all_first_seen_at(&entries, now), now);
    assert_eq!(fold.tier_floor, Some(AuthorityTier::Software));
    assert!(fold.valid_entries.contains(&lower_hash));
    assert!(
        fold.valid_entries.contains(&enroll_hash),
        "an entry descending from the lowered floor folds at once"
    );
    assert!(fold.roster.contains_key(&laptop_key));
    assert_eq!(fold_legacy_authority_log(&entries), fold);
}

#[test]
fn rotation_lands_at_once_and_retires_the_old_key() {
    let owner = ed_key(156);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(156, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let actor = scope_entity(0x9c);
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
    let new_key = authority_key_from_ed(&ed_key(157));
    let rotate = rotate_entry(vault_id, &bind, &owner, owner_key.clone(), 157, 2);
    let entries = vec![genesis, bind, rotate];
    let now = 10_000_000;

    let fold =
        fold_legacy_authority_log_with_seen_times(&entries, &all_first_seen_at(&entries, now), now);
    assert!(fold.roster[&owner_key].revoked);
    assert!(
        fold.roster
            .get(&new_key)
            .is_some_and(folded_device_can_authority_consent)
    );
    assert!(
        !actor_binding_is_active(&fold, &actor, "human"),
        "the retired key's binding dies with the rotation, at once"
    );
}

#[test]
fn first_seen_times_do_not_change_the_structural_fold() {
    let owner = ed_key(66);
    let genesis = genesis_entry(66, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 67,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let new_key = authority_key_from_ed(&ed_key(67));
    let entries = [genesis, enroll];
    let early = fold_legacy_authority_log_with_seen_times(
        &entries,
        &BTreeMap::from([(enroll_hash, 0)]),
        50,
    );
    let late = fold_legacy_authority_log_with_seen_times(
        &entries,
        &BTreeMap::from([(enroll_hash, 50)]),
        50,
    );
    assert!(early.roster.contains_key(&new_key));
    assert_eq!(early, late);
    assert_eq!(early, fold_legacy_authority_log(&entries));
}

#[test]
fn concurrent_restriction_beats_an_enrollment() {
    let owner = ed_key(68);
    let second = ed_key(69);
    let target_key = authority_key_from_ed(&ed_key(70));
    let genesis = genesis_entry(68, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 69,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Hardware,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_target = enroll_device_entry(
        vault_id,
        &enroll_second,
        &owner,
        EnrollSpec {
            seed: 70,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 2,
            ts: 3,
        },
    );
    let revoke = cosign_ed(
        revoke_entry(vault_id, &enroll_second, &second, target_key.clone(), 0),
        &second,
        &owner,
    );
    let entries = [enroll_target, revoke, enroll_second, genesis];
    let now = 10_000_000;

    for fold in [
        fold_legacy_authority_log(&entries),
        fold_legacy_authority_log_with_seen_times(&entries, &all_first_seen_at(&entries, now), now),
    ] {
        let folded = fold
            .roster
            .get(&target_key)
            .expect("restriction tombstone should keep the target visible");
        assert!(folded.revoked);
        assert_eq!(folded.roles, 0);
    }
}

/// Ancestry invalidation (identity canon, 2026-08-03): a verified
/// `RevokeActor` whose parent grant is rejected still lands its epoch floor,
/// while a bad co-signature cannot inherit that exception.
#[test]
fn revoke_floor_survives_an_invalid_grant_parent() {
    let fixture = bind_fixture(253);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let key = fixture.owner_key.clone();
    let bind = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, fixture.actor, "human", 1),
        102,
    );
    let bind_hash = authority_entry_hash(&bind).unwrap();
    // A second BindActor on a live key is rejected: BindingExists.
    let invalid_grant = cosigned_entry(
        &fixture,
        vec![bind_hash],
        3,
        bind_op(&key, scope_entity(0x76), "human", 10),
        103,
    );
    let invalid_hash = authority_entry_hash(&invalid_grant).unwrap();
    let revoke = cosigned_entry(
        &fixture,
        vec![invalid_hash],
        4,
        revoke_actor_op(&key, 10),
        104,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();
    let mut entries = vec![
        fixture.genesis.clone(),
        fixture.enroll.clone(),
        bind,
        invalid_grant.clone(),
        revoke.clone(),
    ];

    let fold = fold_authority_log(&entries);
    assert_eq!(
        binding_rejection(&fold, &invalid_grant),
        Some(ActorBindingRejection::BindingExists)
    );
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::InvalidAncestry(revoke_hash))
    );
    assert!(!fold.valid_entries.contains(&invalid_hash));
    assert_eq!(
        folded_status(&fold, &key),
        Some(ActorBindingStatus::Revoked)
    );
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "human"));

    let mut bad_revoke = revoke;
    bad_revoke.cosigns[0].signature[0] ^= 1;
    entries[4] = bad_revoke;
    assert_eq!(
        folded_status(&fold_authority_log(&entries), &key),
        Some(ActorBindingStatus::Active)
    );
}
