//! World privacy P6b acceptance for held chains (the Engine's ruling on the
//! P2 port, 2026-10-14): a chain whose head reached this install past its
//! signer's sequence floor is held here. It grants nothing and acknowledges
//! nothing, but its narrowing still lands and its keys must agree with every
//! other chain of the pinned trust set. A chain of that set that admitted
//! the machine in full, with the same keys, still counts.
use super::machine_identity::{Host, host, request_for};
use super::owner_anchor::{YOURS, rekeyed};
use super::support::ed_key;
use super::world_kit_gate::publish_root;
use super::*;
use crate::world_keys::RecoveryRootSeed;
use crate::{Vault, VaultConfig};

fn revision_of(
    host: &Host,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
    revision: u64,
) -> MachineProfile {
    MachineProfile {
        machine: request.machine,
        owner: host.owner.actor(),
        machine_key: request.machine_key,
        encryption_key: request.encryption_key.clone(),
        role,
        revision,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
    }
}

/// A root of the owner's on the host's vault, whose anchor marks
/// `request`'s machine "yours" in its own chain, in full.
fn anchored(host: &Host, request: &MachineEnrolmentRequest) -> PinnedRoot {
    let seed = RecoveryRootSeed::generate().unwrap();
    let id = publish_root(host, &seed);
    let fold = host.vault.authority_fold().unwrap();
    let op = AuthorityOp::MachineProfile(revision_of(host, request, YOURS, 1));
    let mark = anchor_signed_entry(&fold, &seed.anchor(), op, 2).unwrap();
    host.vault
        .put_authority_log_entry(&mark, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
    PinnedRoot {
        id,
        anchor_key: seed.anchor().verifying_key().to_bytes(),
    }
}

/// The host roster's next two rows on its current heads: `first`, and a
/// concurrent row of another machine at the next sequence. Neither is
/// stored on the host.
fn concurrent_pair(host: &Host, first: MachineProfile) -> (AuthorityLogEntry, AuthorityLogEntry) {
    let fold = host.vault.authority_fold().unwrap();
    let seq = fold.append_sequences[&host.issuer.public_key()];
    let heads: Vec<_> = fold.append_heads.iter().copied().collect();
    let sign = |seq, profile| {
        host.issuer
            .sign_entry(
                Some(host.vault_id),
                seq,
                heads.clone(),
                AuthorityOp::MachineProfile(profile),
                2,
            )
            .unwrap()
    };
    let other = request_for(host.vault_id, EntityId::now(), &ed_key(209));
    (
        sign(seq + 1, first),
        sign(seq + 2, revision_of(host, &other, YOURS, 1)),
    )
}

/// A replica of the host's history that stores `later` before `first`, each
/// in a write of its own, so `first` lands past its signer's floor; pinned
/// to `pin` when one is given.
fn replica_holding(
    host: &Host,
    first: &AuthorityLogEntry,
    later: &AuthorityLogEntry,
    pin: Option<PinnedRoot>,
) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    replica
        .import_signed_authority_history(&host.vault.export_signed_authority_history().unwrap())
        .unwrap();
    for row in [later, first] {
        replica
            .put_authority_log_entry(row, TimeRange { start: 3, end: 3 }, 3)
            .unwrap();
    }
    if let Some(pin) = pin {
        replica
            .with_write_txn_grouped(|wtxn| {
                write_pinned_root_in_txn(&replica.store, wtxn, pin, None)
            })
            .unwrap();
    }
    (dir, replica)
}

/// (a) The roster's mark of M reached this install past the roster key's
/// floor, while the pinned anchor's mark of M, with the same keys, landed in
/// full. M is mine here through the anchor's chain. With the roster alone (an
/// unpinned install) the held mark counts for nothing, as in P2.
#[test]
fn a_held_roster_mark_beside_an_anchor_mark_in_full_counts_through_the_anchor() {
    let host = host();
    let request = request_for(host.vault_id, EntityId::now(), &ed_key(201));
    let pin = anchored(&host, &request);
    let (mark, later) = concurrent_pair(&host, revision_of(&host, &request, YOURS, 1));
    let (_pinned_dir, pinned) = replica_holding(&host, &mark, &later, Some(pin));
    let fold = pinned.authority_fold().unwrap();
    let trusted = fold.trusted_machine(request.machine).unwrap();
    assert_eq!(trusted.chain, MachineAdmitter::Anchor(pin.anchor_key));
    assert_eq!(trusted.profile.machine_key, request.machine_key);
    assert_eq!(trusted.profile.encryption_key, request.encryption_key);

    let (_unpinned_dir, unpinned) = replica_holding(&host, &mark, &later, None);
    assert!(
        unpinned
            .authority_fold()
            .unwrap()
            .trusted_machine(request.machine)
            .is_none()
    );
}

/// (b) The roster rotates M's encryption key in a revision that reached this
/// install past the floor, while the pinned anchor's chain still names the
/// old key. The held head's keys disagree with the anchor's, so M is not
/// mine here: a held rotation never leaves the old key standing through
/// another chain.
#[test]
fn a_held_rotation_never_leaves_the_old_key_standing_through_the_anchor() {
    let host = host();
    let key = ed_key(202);
    let request = request_for(host.vault_id, EntityId::now(), &key);
    host.vault
        .enroll_machine(&host.issuer, &host.owner, &request, YOURS)
        .unwrap();
    let pin = anchored(&host, &request);
    let rotated = rekeyed(host.vault_id, &request, &key);
    let (rotation, later) = concurrent_pair(&host, revision_of(&host, &rotated, YOURS, 2));
    let (_dir, replica) = replica_holding(&host, &rotation, &later, Some(pin));
    let fold = replica.authority_fold().unwrap();
    assert!(fold.machine(request.machine).is_some());
    assert!(fold.trusted_machine(request.machine).is_none());
}

/// (c) The roster removes M in a revision that reached this install past
/// the floor, while the pinned anchor's chain is live. The removal still
/// lands on the roster's chain and blocks M: removed, never mine here.
#[test]
fn a_held_roster_removal_still_removes_beside_a_live_anchor() {
    let host = host();
    let request = request_for(host.vault_id, EntityId::now(), &ed_key(203));
    host.vault
        .enroll_machine(&host.issuer, &host.owner, &request, YOURS)
        .unwrap();
    let pin = anchored(&host, &request);
    let (removal, later) =
        concurrent_pair(&host, revision_of(&host, &request, MachineRole::Removed, 2));
    let (_dir, replica) = replica_holding(&host, &removal, &later, Some(pin));
    let fold = replica.authority_fold().unwrap();
    let folded = fold.machine(request.machine).unwrap();
    assert!(folded.roster.as_ref().is_some_and(|roster| roster.removed));
    assert!(folded.anchored[&pin.anchor_key].says_yours());
    assert!(fold.trusted_machine(request.machine).is_none());
}
