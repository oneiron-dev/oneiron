//! World privacy P6b acceptance for the kit-restored seed rule (contract §4,
//! check 7f): a seed rebuilt from one stored piece and the passphrase never
//! pins by itself, since anyone who knows the passphrase could have written
//! that piece. Two genuine stored pieces, a fingerprint the owner carried,
//! or the owner's explicit go-ahead do, and the owner is never locked out.
use super::machine_identity::{Host, host, request_for};
use super::support::ed_key;
use super::world_key_doors::{Fresh, enrol_own, fresh_install, own_request};
use super::world_privacy::stored_entries;
use super::*;
use crate::Vault;
use crate::error::{Error, KitRecord, SecretError};
use crate::recovery::{
    KitIssue, KitPassphrase, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit,
    restore_kit,
};
use crate::world_keys::{KitConfirmation, RecoveryRootSeed};

/// `drawn` rebuilt from its kit: from two stored pieces, or from one stored
/// piece and the passphrase.
fn rebuilt(vault_id: [u8; 32], drawn: &RecoveryRootSeed, stored: u8) -> RecoveryRootSeed {
    // A throwaway passphrase made in the test; never a real one.
    let mut raw = [0u8; 12];
    crate::world_keys::os_fill(&mut raw).unwrap();
    let text: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
    let passphrase = KitPassphrase::new(&text).unwrap();
    let issue = KitIssue {
        vault_id,
        homes: [
            PieceHome::ThisMachine,
            PieceHome::OtherMachine(EntityId::now()),
            PieceHome::Passphrase,
        ],
        passphrase: Some(&passphrase),
        cost: PassphraseCost::FLOOR,
        only_machine: false,
    };
    let pieces = issue_recovery_root_kit(&issue, &drawn.kit_bytes())
        .unwrap()
        .into_pieces();
    let restored = match stored {
        2 => restore_kit(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &[&pieces[0], &pieces[1]],
            None,
        ),
        _ => restore_kit(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &[&pieces[1]],
            Some(&passphrase),
        ),
    }
    .unwrap();
    assert_eq!(restored.stored_pieces(), stored);
    RecoveryRootSeed::from_restored_kit(restored).unwrap()
}

/// `seed`'s root, published on the host's vault by its own anchor.
pub(super) fn publish_root(host: &Host, seed: &RecoveryRootSeed) -> RecoveryRootId {
    let root = seed.public(&host.vault_id).unwrap();
    let record = OwnerRootRecord {
        owner: host.owner.actor(),
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    let fold = host.vault.authority_fold().unwrap();
    let entry =
        anchor_signed_entry(&fold, &seed.anchor(), AuthorityOp::OwnerRoot(record), 2).unwrap();
    host.vault
        .put_authority_log_entry(&entry, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
    root.id
}

/// `seed`'s root, published as [`publish_root`] does, whose anchor then
/// marks a machine of its holder's "yours": a host that holds a seed.
fn publish_with_machine(host: &Host, seed: &RecoveryRootSeed, key: u8) -> RecoveryRootId {
    let root = publish_root(host, seed);
    let at = TimeRange { start: 2, end: 2 };
    let request = request_for(host.vault_id, EntityId::now(), &ed_key(key));
    let mark = AuthorityOp::MachineProfile(MachineProfile {
        machine: request.machine,
        owner: host.owner.actor(),
        machine_key: request.machine_key,
        encryption_key: request.encryption_key.clone(),
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
    });
    let fold = host.vault.authority_fold().unwrap();
    let entry = anchor_signed_entry(&fold, &seed.anchor(), mark, 2).unwrap();
    host.vault.put_authority_log_entry(&entry, at, 2).unwrap();
    root
}

fn unverified<T>(result: crate::error::Result<T>, expected: KitRecord) -> bool {
    matches!(
        result,
        Err(Error::Secret(SecretError::UnverifiedKitRestore { record, .. })) if record == expected
    )
}

fn pinned(vault: &Vault) -> Option<RecoveryRootId> {
    vault.owner_root_view(None, 0).unwrap().pinned
}

/// A host that holds a passphrase forges a kit piece for a seed of its own,
/// publishes that seed's root and anchors a machine of its own under it. On
/// a new install the forged seed neither restores nor anchors this install's
/// request, with or without the owner's fingerprint, and writes nothing;
/// two genuine stored pieces restore and pin the owner's root, through
/// either door, and the host's machine is never mine.
#[test]
fn a_forged_kit_piece_never_pins() {
    let host = host();
    enrol_own(&host);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let genuine = rebuilt(host.vault_id, prepared.seed(), 2);
    let owners = prepared.seed().public(&host.vault_id).unwrap().id;
    host.vault
        .activate_owner_root(
            &host.owner,
            EditOrigin::ThisMachine,
            prepared,
            &BTreeSet::new(),
        )
        .unwrap();
    let theirs_seed = RecoveryRootSeed::generate().unwrap();
    let theirs = publish_with_machine(&host, &theirs_seed, 61);
    let forged = rebuilt(host.vault_id, &theirs_seed, 1);

    let Fresh { vault, owner, .. } = &fresh_install(&host);
    let own = own_request(vault);
    let stored = stored_entries(vault).len();
    let here = EditOrigin::ThisMachine;
    assert!(unverified(
        vault.restore_world_keys(owner, here, &forged, None),
        KitRecord::Stored
    ));
    assert!(unverified(
        vault.anchor_machine(owner, here, &forged, &own, None, None),
        KitRecord::Stored
    ));
    let owners_print = Some(KitConfirmation::Fingerprint(owners));
    assert!(
        vault
            .restore_world_keys(owner, here, &forged, owners_print)
            .is_err()
    );
    assert!(
        vault
            .anchor_machine(owner, here, &forged, &own, None, owners_print)
            .is_err()
    );
    assert_eq!(stored_entries(vault).len(), stored);
    assert_eq!(pinned(vault), None);

    vault
        .restore_world_keys(owner, here, &genuine, None)
        .unwrap();
    let view = vault.owner_root_view(None, 16).unwrap();
    assert_eq!(view.pinned, Some(owners));
    assert!(view.foreign.contains_key(&theirs));

    let Fresh { vault, owner, .. } = &fresh_install(&host);
    let own = own_request(vault);
    let anchored = vault
        .anchor_machine(owner, here, &genuine, &own, None, None)
        .unwrap();
    assert!(anchored.repin.is_some());
    assert_eq!(pinned(vault), Some(owners));
    assert!(vault.local_machine().unwrap().unwrap().mine);
}

/// The host withholds the owner's root record and shows its own. A seed
/// rebuilt from one genuine piece is not verified against a different
/// stored root; with the owner's go-ahead it publishes the owner's root and
/// pins it, and two genuine stored pieces do so by themselves. The host's
/// root stays foreign.
#[test]
fn a_withheld_owner_root_is_published_again_from_the_kit() {
    let host = host();
    enrol_own(&host);
    let owners_seed = RecoveryRootSeed::generate().unwrap();
    let owners = owners_seed.public(&host.vault_id).unwrap().id;
    let theirs = publish_with_machine(&host, &RecoveryRootSeed::generate().unwrap(), 62);
    let one = rebuilt(host.vault_id, &owners_seed, 1);
    let two = rebuilt(host.vault_id, &owners_seed, 2);
    let here = EditOrigin::ThisMachine;

    let Fresh { vault, owner, .. } = &fresh_install(&host);
    assert!(unverified(
        vault.restore_world_keys(owner, here, &one, None),
        KitRecord::Mismatch
    ));
    assert_eq!(pinned(vault), None);
    assert!(vault.local_machine().unwrap().is_none());
    vault
        .restore_world_keys(owner, here, &one, Some(KitConfirmation::Owner))
        .unwrap();
    let view = vault.owner_root_view(None, 16).unwrap();
    assert_eq!(view.pinned, Some(owners));
    assert!(view.foreign.contains_key(&theirs));

    let Fresh { vault, owner, .. } = &fresh_install(&host);
    vault.restore_world_keys(owner, here, &two, None).unwrap();
    assert_eq!(pinned(vault), Some(owners));
    assert!(vault.owner_root_records().unwrap().contains_key(&owners));
}

/// With no root stored anywhere the kit is never a lockout: one genuine
/// piece asks for the owner's go-ahead and then publishes and pins, and two
/// stored pieces publish and pin by themselves. A refusal on a fresh install
/// leaves no machine identity behind.
#[test]
fn with_no_root_stored_the_kit_is_never_a_lockout() {
    let host = host();
    enrol_own(&host);
    let seed = RecoveryRootSeed::generate().unwrap();
    let root = seed.public(&host.vault_id).unwrap().id;
    let one = rebuilt(host.vault_id, &seed, 1);
    let two = rebuilt(host.vault_id, &seed, 2);
    let here = EditOrigin::ThisMachine;

    let Fresh { vault, owner, .. } = &fresh_install(&host);
    assert!(unverified(
        vault.restore_world_keys(owner, here, &one, None),
        KitRecord::None
    ));
    assert!(
        vault
            .pin_owner_root(owner, here, RecoveryRootId([7; 32]))
            .is_err()
    );
    // Both refusals came before any write: this genuinely fresh install
    // minted no machine identity, so no keystore slot either, since a slot
    // is named by the identity.
    assert!(vault.local_machine().unwrap().is_none());
    vault
        .restore_world_keys(owner, here, &one, Some(KitConfirmation::Owner))
        .unwrap();
    assert_eq!(pinned(vault), Some(root));

    let Fresh { vault, owner, .. } = &fresh_install(&host);
    vault.restore_world_keys(owner, here, &two, None).unwrap();
    assert_eq!(pinned(vault), Some(root));
}

/// An old machine, pinned to the owner's root or unpinned, that holds a
/// forged one-piece seed whose root the host published never anchors a new
/// machine's request with it, whatever it is told, and writes nothing.
#[test]
fn an_old_machine_never_approves_a_new_one_with_a_forged_piece() {
    let host = host();
    enrol_own(&host);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let owners = prepared.seed().public(&host.vault_id).unwrap().id;
    host.vault
        .activate_owner_root(
            &host.owner,
            EditOrigin::ThisMachine,
            prepared,
            &BTreeSet::new(),
        )
        .unwrap();
    let theirs_seed = RecoveryRootSeed::generate().unwrap();
    publish_with_machine(&host, &theirs_seed, 63);
    let forged = rebuilt(host.vault_id, &theirs_seed, 1);
    let new = request_for(host.vault_id, EntityId::now(), &ed_key(64));
    let unpinned = fresh_install(&host);

    for (vault, owner, pin) in [
        (&host.vault, &host.owner, Some(owners)),
        (&unpinned.vault, &unpinned.owner, None),
    ] {
        let stored = stored_entries(vault).len();
        for confirm in [None, Some(KitConfirmation::Owner)] {
            assert!(
                vault
                    .anchor_machine(
                        owner,
                        EditOrigin::ThisMachine,
                        &forged,
                        &new,
                        Some(new.code()),
                        confirm,
                    )
                    .is_err()
            );
        }
        assert_eq!(stored_entries(vault).len(), stored);
        assert_eq!(pinned(vault), pin);
        assert!(
            vault
                .authority_fold()
                .unwrap()
                .trusted_machine(new.machine)
                .is_none()
        );
    }
}
