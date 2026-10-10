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
