//! Handoff settlement does not depend on the order rows arrive in (Astra
//! review 1 of #1410, Engine ruling 2026-10-14). The old root A hands the
//! vault to B at sequence 1; a forger holding A's key signs a sibling handoff
//! to D at a higher sequence. Whichever of the two this vault saw first, a
//! history that holds both installs neither successor. A door that settled
//! one first refuses the other and records the refusal.
use super::history_transfer::{re_root_entry, replica_with, store};
use super::support::*;
use super::*;
use crate::{TimeRange, Vault, VaultConfig};

fn hash(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).unwrap()
}

fn body(entry: &AuthorityLogEntry) -> Vec<u8> {
    encode_authority_log_entry_body(entry).unwrap()
}

fn is_live(fold: &AuthorityFold, key: &SigningKey) -> bool {
    fold.roster
        .get(&authority_key_from_ed(key))
        .is_some_and(|device| !device.revoked)
}

fn withdrawal(
    id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    slip: u8,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(id),
            seq,
            vec![hash(parent)],
            AuthorityOp::SlipRevoke {
                slip_id: [slip; 32],
            },
            authority_key_from_ed(signer),
            2,
        ),
        signer,
    )
}

fn put(vault: &Vault, entries: &[&AuthorityLogEntry]) -> crate::error::Result<Vec<EntityId>> {
    let rows: Vec<_> = entries
        .iter()
        .map(|entry| ((*entry).clone(), TimeRange { start: 2, end: 2 }, 2))
        .collect();
    vault.put_authority_log_entries(&rows)
}

struct Fork {
    old: SigningKey,
    next: SigningKey,
    forger_heir: SigningKey,
    genesis: AuthorityLogEntry,
    handoff: AuthorityLogEntry,
    forged: AuthorityLogEntry,
}

/// G by A; H = ReRoot(A→B) at sequence 1 and F = ReRoot(A→D) at sequence 2,
/// both on G.
fn fork(seed: u8) -> Fork {
    let old = ed_key(seed);
    let next = ed_key(seed + 1);
    let forger_heir = ed_key(seed + 2);
    let genesis = genesis_entry(seed, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let handoff = re_root_entry(id, &genesis, &old, 1, &next);
    let forged = re_root_entry(id, &genesis, &old, 2, &forger_heir);
    Fork {
        old,
        next,
        forger_heir,
        genesis,
        handoff,
        forged,
    }
}

/// A history that holds both handoffs has no live root, and the forger's
/// heir signs nothing a door admits.
fn assert_no_live_root(vault: &Vault, fork: &Fork) {
    let fold = vault.authority_fold().unwrap();
    assert!(!fold.valid_entries.contains(&hash(&fork.handoff)));
    assert!(!fold.valid_entries.contains(&hash(&fork.forged)));
    assert!(fold.roster.values().all(|device| device.revoked));
    assert!(!is_live(&fold, &fork.next));
    assert!(!is_live(&fold, &fork.forger_heir));
    let id = genesis_vault_id(&fork.genesis).unwrap();
    let heir_row = withdrawal(id, &fork.forged, &fork.forger_heir, 1, 1);
    assert!(put(vault, &[&heir_row]).is_err());
}

/// Check 1: one atomic import of the complete history, in either blob order.
/// Before the fix, [G, F, H] installed D: H failed on the sequence floor F's
/// earlier arrival set, so it never fenced.
#[test]
fn an_import_of_both_handoffs_installs_no_successor_in_either_order() {
    let fork = fork(230);
    for (first, second) in [(&fork.forged, &fork.handoff), (&fork.handoff, &fork.forged)] {
        let (_dir, replica) = replica_with(vec![body(&fork.genesis), body(first)], second);
        assert_no_live_root(&replica, &fork);
    }
}

/// Check 2: the same rows through one append batch, in either order.
#[test]
fn one_append_batch_of_both_handoffs_installs_no_successor_in_either_order() {
    let fork = fork(233);
    for (first, second) in [(&fork.forged, &fork.handoff), (&fork.handoff, &fork.forged)] {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        put(&vault, &[&fork.genesis, first, second]).unwrap();
        assert_no_live_root(&vault, &fork);
    }
}

/// Check 3: sequential arrival. F arrives while its parent P (A, sequence 2)
/// is still in flight, so F cannot settle and no door refuses H. F's arrival
/// leaves A's sequence floor at 3 for every later row of A.
/// (a) H arrives alone: H settles, the door then refuses P, records it, and
///     B is the root.
/// (b) H and P arrive together: the history holds both handoffs, so neither
///     successor installs.
///
/// Before the fix, H failed on F's floor in both, and F installed D.
#[test]
fn a_handoff_that_arrives_after_its_siblings_floor_still_settles() {
    let base = fork(236);
    let id = genesis_vault_id(&base.genesis).unwrap();
    let in_flight = withdrawal(id, &base.genesis, &base.old, 2, 7);
    let forged = re_root_entry(id, &in_flight, &base.old, 3, &base.forger_heir);
    let fork = Fork { forged, ..base };

    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    store(&vault, &fork.genesis);
    put(&vault, &[&fork.forged]).unwrap();
    put(&vault, &[&fork.handoff]).unwrap();
    assert!(put(&vault, &[&in_flight]).is_err());
    let fold = vault.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash(&fork.handoff)));
    assert!(is_live(&fold, &fork.next));
    assert!(!is_live(&fold, &fork.old));
    assert!(
        !fold
            .roster
            .contains_key(&authority_key_from_ed(&fork.forger_heir))
    );
    assert_eq!(
        vault.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: authority_key_from_ed(&fork.old),
            handoffs: BTreeSet::from([hash(&fork.handoff)]),
            refused: hash(&in_flight),
        }]
    );

    for together in [[&fork.handoff, &in_flight], [&in_flight, &fork.handoff]] {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        store(&vault, &fork.genesis);
        put(&vault, &[&fork.forged]).unwrap();
        put(&vault, &together).unwrap();
        assert_no_live_root(&vault, &fork);
    }
}

/// Control 5: local sequence floors still refuse every row outside a
/// handoff's line. After H settles, a row the successor B signs below B's
/// own observed floor is refused, though H's line stands unfloored.
#[test]
fn a_row_below_its_floor_outside_any_handoffs_line_stays_refused() {
    let fork = fork(239);
    let id = genesis_vault_id(&fork.genesis).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    store(&vault, &fork.genesis);
    vault.apply_signed_re_root(&fork.handoff).unwrap();
    let high = withdrawal(id, &fork.handoff, &fork.next, 5, 8);
    let rollback = withdrawal(id, &fork.handoff, &fork.next, 2, 9);
    put(&vault, &[&high]).unwrap();
    put(&vault, &[&rollback]).unwrap();
    let fold = vault.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash(&high)));
    assert!(!fold.valid_entries.contains(&hash(&rollback)));
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::NonMonotonicSeq(hash(&rollback)))
    );
    assert!(is_live(&fold, &fork.next));
}

/// Sol review 6: a door records every retired key whose row it refuses, and
/// only a row whose signatures verify. A roster key the handoff fenced without
/// signing it is recorded with no handoff of its own. A row that names the
/// old root as its signer under a signature that does not verify records
/// nothing, so no one without the key can plant a record.
#[test]
fn a_door_records_each_retired_signer_and_only_rows_that_verify() {
    let old = ed_key(240);
    let (first, second, next) = (ed_key(241), ed_key(242), ed_key(243));
    let genesis = genesis_entry(240, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let enroll_first = enroll_entry(id, &genesis, &old, 241, 1, 2);
    let enroll_second = cosign_ed(enroll_entry(id, &enroll_first, &old, 242, 2, 2), &old, &first);
    let handoff = cosign_ed(re_root_entry(id, &enroll_second, &old, 3, &next), &old, &first);
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    put(&vault, &[&genesis, &enroll_first, &enroll_second, &handoff]).unwrap();
    assert!(is_live(&vault.authority_fold().unwrap(), &next));

    let fenced_peer_row = withdrawal(id, &enroll_second, &second, 1, 3);
    assert!(put(&vault, &[&fenced_peer_row]).is_err());
    let mut forged = withdrawal(id, &enroll_second, &old, 4, 4);
    forged.seq = 5;
    assert!(put(&vault, &[&forged]).is_err());
    assert_eq!(
        vault.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: authority_key_from_ed(&second),
            handoffs: BTreeSet::new(),
            refused: hash(&fenced_peer_row),
        }]
    );
}
