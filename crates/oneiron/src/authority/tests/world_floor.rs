//! A restriction still lands past a sequence floor (Astra #1430). A replica
//! that stored a later row of a signer first keeps that signer's earlier
//! world edit and its "yours"-ending revision as restriction only, so every
//! arrival order reads the same narrow world.
use std::collections::BTreeSet;

use super::machine_identity::{Host, host};
use super::support::{authority_key_from_ed, sign_ed, unsigned_entry};
use super::world_privacy::{edit_by, land, other_machine, read_of, settings, world_row};
use super::*;
use crate::{Vault, VaultConfig};

/// A replica of the host's history so far that then stores `rows` in this
/// order, each in a write of its own, as sync delivers them.
fn replica_storing(host: &Host, rows: &[&AuthorityLogEntry]) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let replica = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    replica
        .import_signed_authority_history(&host.vault.export_signed_authority_history().unwrap())
        .unwrap();
    for row in rows {
        replica
            .put_authority_log_entry(row, TimeRange { start: 3, end: 3 }, 3)
            .unwrap();
    }
    (dir, replica)
}

/// The world's read on `replica`, and whether an unknown destination may
/// hold it.
fn judged(replica: &Vault, world: EntityId) -> (EffectiveRead, bool) {
    let read = replica.world_privacy(world).unwrap().read;
    let txn = replica.store.env.read_txn().unwrap();
    let readable =
        world_readable_on_machine_in(replica, &txn, world, Destination::Unknown).unwrap();
    (read, readable)
}

/// The owner's revision of a machine at `seq`, on the main-log heads of `fold`.
fn revision(
    host: &Host,
    fold: &AuthorityFold,
    seq: u64,
    profile: MachineProfile,
) -> AuthorityLogEntry {
    host.issuer
        .sign_entry(
            Some(host.vault_id),
            seq,
            fold.append_heads.iter().copied().collect(),
            AuthorityOp::MachineProfile(profile),
            2,
        )
        .unwrap()
}

/// Astra #1430, shape A: a removed machine's key signs a widening at a high
/// sequence. The fold refuses it, but storing it raised that key's floor for
/// the world, and the owner's earlier narrowing arrives after it. The
/// narrowing still lands: both orders read the world on the removed machine
/// alone, withheld from an unknown destination.
#[test]
fn a_narrowing_that_arrives_after_a_refused_row_still_narrows() {
    let host = host();
    let world = world_row(&host);
    let (laptop, laptop_key) =
        other_machine(&host, 91, MachineRole::Owned(MachineOwnership::Yours));
    let narrowing = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::OneMachine(laptop)),
    );
    let fold = host.vault.authority_fold().unwrap();
    let seq = fold.append_sequences[&host.issuer.public_key()];
    let removal = revision(
        &host,
        &fold,
        seq + 1,
        MachineProfile {
            role: MachineRole::Removed,
            revision: 2,
            ..fold.machine(laptop).unwrap().profile.clone()
        },
    );
    let refused = sign_ed(
        unsigned_entry(
            Some(host.vault_id),
            100,
            vec![authority_entry_hash(&removal).unwrap()],
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                owner: host.owner.actor(),
                machine: laptop,
                settings: settings(ReadLocation::Everywhere),
            }),
            authority_key_from_ed(&laptop_key),
            2,
        ),
        &laptop_key,
    );
    for (order, rows) in [
        ("narrowing first", [&narrowing, &removal, &refused]),
        ("refused row first", [&removal, &refused, &narrowing]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        assert!(
            !replica
                .authority_fold()
                .unwrap()
                .valid_entries
                .contains(&authority_entry_hash(&refused).unwrap()),
            "{order}"
        );
        assert_eq!(
            judged(&replica, world),
            (EffectiveRead::OneMachine(laptop), false),
            "{order}"
        );
    }
}

/// Astra #1430, shape B: two concurrent owner revisions of a machine that
/// narrowed and then widened a world. A demotion saw only the narrowing; a
/// removal at a higher sequence saw the widening. A replica that stores the
/// removal first still races the widening against the demotion, so in both
/// orders the widening keeps no full strength.
#[test]
fn a_demotion_that_arrives_after_a_removal_still_races_a_widening() {
    let host = host();
    let world = world_row(&host);
    let (laptop, laptop_key) =
        other_machine(&host, 92, MachineRole::Owned(MachineOwnership::Yours));
    let narrowing = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::OneMachine(laptop)),
    );
    land(&host, std::slice::from_ref(&narrowing));
    let widening = edit_by(
        &host,
        laptop,
        &laptop_key,
        world,
        settings(ReadLocation::Everywhere),
    );
    land(&host, std::slice::from_ref(&widening));
    assert_eq!(read_of(&host, world), EffectiveRead::Everywhere);

    let fold = host.vault.authority_fold().unwrap();
    let seq = fold.append_sequences[&host.issuer.public_key()];
    let profile = fold.machine(laptop).unwrap().profile.clone();
    let demotion = revision(
        &host,
        &fold,
        seq + 1,
        MachineProfile {
            role: MachineRole::Owned(MachineOwnership::WorkSchool),
            revision: 2,
            seen_world_edits: BTreeSet::from([authority_entry_hash(&narrowing).unwrap()]),
            ..profile.clone()
        },
    );
    let removal = revision(
        &host,
        &fold,
        seq + 2,
        MachineProfile {
            role: MachineRole::Removed,
            revision: 3,
            seen_world_edits: BTreeSet::from([authority_entry_hash(&widening).unwrap()]),
            ..profile
        },
    );
    for (order, rows) in [
        ("demotion first", [&demotion, &removal]),
        ("removal first", [&removal, &demotion]),
    ] {
        let (_dir, replica) = replica_storing(&host, &rows);
        assert_eq!(
            judged(&replica, world),
            (EffectiveRead::OneMachine(laptop), false),
            "{order}"
        );
    }
}
