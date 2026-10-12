//! Handoff settlement (engine-crates-03, Sol review 2): forks and cycles of
//! handoffs install no successor and keep their fences closed, a handoff
//! that stands on fenced rows retires nothing, a handoff its own collision
//! prunes retires nothing, and only an authority row is resident history.
use super::history_transfer::{re_root_entry, store};
use super::support::*;
use super::*;
use crate::{TimeRange, Vault, VaultConfig};

fn hash(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).unwrap()
}

fn is_live(fold: &AuthorityFold, key: &SigningKey) -> bool {
    fold.roster
        .get(&authority_key_from_ed(key))
        .is_some_and(|device| !device.revoked)
}

/// Two forks the retired root signs build no quorum that replaces its
/// successor (Sol review 2, finding 1). Their merge stands on rows the
/// handoff fenced, so it installs nothing and retires nothing; the forks and
/// the handoff conflict, so the old root stays retired.
#[test]
fn forks_of_a_retired_root_build_no_quorum_over_its_successor() {
    let old = ed_key(180);
    let next = ed_key(181);
    let (first_heir, second_heir, merged_heir) = (ed_key(182), ed_key(183), ed_key(184));
    let genesis = genesis_entry(180, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let handoff = re_root_entry(id, &genesis, &old, 1, &next);
    let first_fork = re_root_entry(id, &genesis, &old, 2, &first_heir);
    let second_fork = re_root_entry(id, &genesis, &old, 3, &second_heir);
    let mut merge = re_root_entry(id, &handoff, &first_heir, 1, &merged_heir);
    merge.parent_hashes = vec![hash(&handoff), hash(&first_fork), hash(&second_fork)];
    merge.parent_hashes.sort();
    let merge = cosign_ed(merge, &first_heir, &second_heir);

    let fold = fold_authority_log(&[genesis, handoff, first_fork, second_fork, merge.clone()]);
    assert!(!fold.valid_entries.contains(&hash(&merge)));
    assert!(!is_live(&fold, &merged_heir));
    assert!(!fold.retired_keys.contains(&authority_key_from_ed(&next)));
    assert!(fold.retired_keys.contains(&authority_key_from_ed(&old)));
}

/// Three handoffs whose fences run round a cycle install no successor, and
/// every fence stays closed (Sol review 2, finding 6). On each branch the
/// retired root rotates to a fresh key, which enrolls the next branch's key
/// as a system writer, revokes it, and hands the vault on.
#[test]
fn a_cycle_of_fenced_handoffs_installs_no_successor() {
    let old = ed_key(190);
    let next = ed_key(191);
    let genesis = genesis_entry(190, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let handoff = re_root_entry(id, &genesis, &old, 1, &next);
    let rotated: [u8; 3] = [192, 193, 194];
    let heirs: [u8; 3] = [195, 196, 197];
    let mut entries = vec![genesis.clone(), handoff.clone()];
    let mut branches = vec![handoff];
    for (branch, (&seed, &heir)) in rotated.iter().zip(&heirs).enumerate() {
        let owner = ed_key(seed);
        let writer_seed = rotated[(branch + 1) % rotated.len()];
        let writer = authority_key_from_ed(&ed_key(writer_seed));
        let rotation = rotate_entry(id, &genesis, &old, authority_key_from_ed(&old), seed, 1);
        let enroll = enroll_device_entry(
            id,
            &rotation,
            &owner,
            EnrollSpec {
                seed: writer_seed,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 3,
            },
        );
        let bind = cosign_ed(
            unsigned_entry(
                Some(id),
                2,
                vec![hash(&enroll)],
                bind_op(&writer, scope_entity(seed), "system", 1),
                authority_key_from_ed(&owner),
                4,
            ),
            &owner,
            &ed_key(writer_seed),
        );
        let revoke = revoke_entry(id, &bind, &owner, writer, 3);
        let branch_handoff = re_root_entry(id, &revoke, &owner, 4, &ed_key(heir));
        branches.push(branch_handoff.clone());
        entries.extend([rotation, enroll, bind, revoke, branch_handoff]);
    }

    let fold = fold_authority_log(&entries);
    for branch in &branches {
        assert!(!fold.valid_entries.contains(&hash(branch)));
    }
    for heir in heirs {
        assert!(!is_live(&fold, &ed_key(heir)));
    }
    assert!(fold.retired_keys.contains(&authority_key_from_ed(&old)));
}

/// A handoff that its own confirmation collision prunes retires nothing
/// (Sol review 2, finding 3): the root that signed both confirmations stays
/// live, and one of them stands.
#[test]
fn a_handoff_its_own_collision_prunes_retires_nothing() {
    let old = ed_key(185);
    let next = ed_key(186);
    let genesis = genesis_entry(185, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let confirm = |confirm: u8| {
        sign_ed(
            unsigned_entry(
                Some(id),
                1,
                vec![hash(&genesis)],
                AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                    kind: AuthorityConfirmKind::Accept,
                    confirm_id: [confirm; 32],
                    peer_vault_id: [86; 32],
                    epoch: 1,
                    nonce: [87; 16],
                }),
                authority_key_from_ed(&old),
                2,
            ),
            &old,
        )
    };
    let (first, second) = (confirm(1), confirm(2));
    let mut handoff = re_root_entry(id, &first, &old, 2, &next);
    handoff.parent_hashes = vec![hash(&first), hash(&second)];
    handoff.parent_hashes.sort();
    let handoff = sign_ed(handoff, &old);

    let fold = fold_authority_log(&[genesis, first.clone(), second.clone(), handoff.clone()]);
    assert!(!fold.valid_entries.contains(&hash(&handoff)));
    assert_ne!(
        fold.valid_entries.contains(&hash(&first)),
        fold.valid_entries.contains(&hash(&second))
    );
    assert!(fold.retired_keys.is_empty());
    assert!(is_live(&fold, &old));
    assert!(!is_live(&fold, &next));
}

/// An EVENT that carries a fork's exact bytes at the fork's id is no resident
/// history (Sol review 2, finding 4): the append door still refuses the fork
/// for its retired signer, and the successor stays the root.
#[cfg(feature = "sync")]
#[test]
fn an_event_carrying_a_forks_bytes_replays_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let old = ed_key(187);
    let next = ed_key(188);
    let fork = ed_key(189);
    let genesis = genesis_entry(187, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    store(&vault, &genesis);
    vault
        .apply_signed_re_root(&re_root_entry(id, &genesis, &old, 1, &next))
        .unwrap();
    let forked = re_root_entry(id, &genesis, &old, 1, &fork);
    vault
        .put_entity(
            &authority_log_entity_id(&forked).unwrap(),
            crate::registry::ENTITY_TYPE_EVENT,
            TimeRange { start: 2, end: 2 },
            2,
            &encode_authority_log_entry_body(&forked).unwrap(),
        )
        .unwrap();

    assert!(
        vault
            .put_authority_log_entry(&forked, TimeRange { start: 3, end: 3 }, 3)
            .is_err()
    );
    let fold = vault.authority_fold().unwrap();
    assert!(!fold.valid_entries.contains(&hash(&forked)));
    assert!(is_live(&fold, &next));
}
