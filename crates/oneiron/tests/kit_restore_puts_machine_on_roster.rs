//! FIX KIT-RESTORE-ANCHOR-ONLY-INSTALL-COUNTS-NO-WRAP (Engine TASK 16 Nov
//! 06:34; ANCHORSEC, Astra T3 on #8673; ANCHORS-1 = A): a kit restore on a
//! fresh machine with no issuer puts the machine on the roster through the
//! kit's root authority key R, in the restore's write transaction and
//! before its re-wraps. Under #8673 only the roster's chain admits an owner
//! act's carrier and a world key wrap's publisher, so with the kit's anchor
//! mark alone the re-wrap of a live private world never counts (the restore
//! fails) and, with no private world, the next owner act refuses "no
//! carrier". A kit whose R is no longer live on the roster, because a newer
//! kit replaced it, is refused before any write
//! (WAYBACK-KIT-RESTORE-NO-LIVE-R = A).
//!
//! The first live test of the restore flow. The source is a self-hosted
//! vault whose kit was confirmed (the activation enrols R). The fresh
//! machine is a direct checkpoint restore of it: it joins as a new machine,
//! opens unpinned and holds an empty keystore, so no issuer.
//!
//! On the kit-only rotation PR the restore signs with the kit's live
//! generation of R: after the switch to kit-only the same kit restores and
//! its rotated R puts the machine on the roster.
//!
//! Red at the signed merge of R4 PR 2 and #8673 without the fix: the
//! private-world restore fails, the owner act refuses "no carrier", and the
//! replaced kit restores. Red at R4 PR 2 alone: no roster row, and the
//! replaced kit restores.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test kit_restore_puts_machine_on_roster`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, AuthorityLogEntry, AuthorityOp, EnrolledOwnerKeyKind,
    MachineOwnership, MachineRole, ReadLocation, WorldPrivacy, decode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::checkpoint::RestoreReason;
use oneiron::recovery::{CodeKeeping, KitIssue, PassphraseCost, PieceHome};
use oneiron::store::GateDecisionId;
use oneiron::store::recovery_kit::KitPiece;
use oneiron::test_support::{bind_host_owner, restore_tempdir};
use oneiron::world_keys::{
    ConfirmedWorldKit, IssuedWorldKit, KitConfirmation, NoRecoveryBox, RecoveryPreset,
    RecoveryRootId, WorldKitRestore,
};
use oneiron::{EntityId, ErrorKind, Vault, VaultConfig};

/// The restore's refusal of a kit whose R is not live on the roster.
const KIT_NOT_CURRENT: &str = "this recovery kit is not the vault's current kit: a newer kit \
                               replaced it, or it was never confirmed; use your newest kit, or \
                               sign in from a device that is still yours; nothing was written";

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn keep_on_my_machines() -> WorldPrivacy {
    WorldPrivacy {
        read: ReadLocation::MyMachines,
        ..WorldPrivacy::default()
    }
}

fn rows(vault: &Vault) -> Vec<AuthorityLogEntry> {
    vault
        .export_signed_authority_history()
        .expect("the history")
        .iter()
        .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
        .collect()
}

/// A self-hosted vault whose host seed this install holds, with its data key.
struct Source {
    dir: tempfile::TempDir,
    vault: Vault,
    person: EntityId,
}

fn source() -> Source {
    let dir = restore_tempdir();
    let vault =
        Vault::open(dir.path().join("source"), VaultConfig::device()).expect("the source vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("the host seed");
    vault.ensure_host_root_slip(&issuer).expect("the host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machines");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    vault.ensure_vault_key().expect("the vault's data key");
    Source { dir, vault, person }
}

impl Source {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn issue(&self) -> IssuedWorldKit {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("a rooted vault");
        self.vault
            .issue_world_kit(
                &self.owner(),
                &KitIssue {
                    vault_id,
                    homes: [
                        PieceHome::RecoveryCode(CodeKeeping::Paper),
                        PieceHome::TrustedPerson,
                        PieceHome::SecurityKey,
                    ],
                    passphrase: None,
                    cost: PassphraseCost::FLOOR,
                    only_machine: false,
                },
            )
            .expect("a kit")
    }

    fn confirm(&self, issued: &IssuedWorldKit) -> ConfirmedWorldKit {
        let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
        self.vault
            .confirm_world_kit(&self.owner(), &pieces, None, &BTreeSet::new())
            .expect("the kit confirms")
    }

    fn world(&self, name: &str) -> EntityId {
        self.vault
            .create_world(&self.owner(), name, self.vault.now_recorded_at())
            .expect("a world")
    }

    /// A live private world: kept on the owner's machines, its key minted
    /// and wrapped to this machine and to the pinned root.
    fn private_world(&self, name: &str) -> EntityId {
        let world = self.world(name);
        self.vault
            .set_world_privacy_as(
                &self.owner(),
                ActSurface::ThisInstall,
                world,
                keep_on_my_machines(),
                None,
            )
            .expect("the owner keeps the world on their machines");
        self.vault
            .world_key(world)
            .expect("the private world's key opens on the source");
        world
    }

    /// The one live R, kind `RecoveryAuthority`.
    fn live_r(&self) -> AuthorityKey {
        let live: Vec<_> = self
            .vault
            .enrolled_owner_keys()
            .expect("the list")
            .into_iter()
            .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
            .map(|key| AuthorityKey::Ed25519(key.public_key))
            .collect();
        assert_eq!(live.len(), 1, "one live R");
        live[0].clone()
    }

    /// A fresh machine of this vault: a direct checkpoint restore, which
    /// joins as a new machine, unpinned, with an empty keystore of its own.
    fn fresh(&self) -> Fresh {
        let key = self.vault.checkpoint_key().expect("the checkpoint key");
        let image = self.dir.path().join("image");
        self.vault
            .snapshot_checkpoint(&image, 100)
            .expect("the checkpoint");
        let (vault, _) = Vault::restore_checkpoint(
            &image,
            &key,
            &self.dir.path().join("fresh"),
            VaultConfig::device(),
            RestoreReason::Restore,
            200,
        )
        .expect("the fresh machine's copy of the vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        Fresh {
            vault,
            person: self.person,
        }
    }
}

struct Fresh {
    vault: Vault,
    person: EntityId,
}

impl Fresh {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    /// The kit restore from `issued`'s pieces, the owner carrying `root`'s
    /// fingerprint.
    fn restore(
        &self,
        issued: &IssuedWorldKit,
        root: RecoveryRootId,
    ) -> oneiron::Result<WorldKitRestore> {
        let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
        self.vault.restore_world_kit(
            &self.owner(),
            &pieces,
            None,
            Some(KitConfirmation::Fingerprint(root)),
        )
    }

    /// This install's machine and its install key.
    fn me(&self) -> (EntityId, [u8; 32]) {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("a rooted vault");
        let encryption = self
            .vault
            .machine_encryption_key(vault_id)
            .expect("this install's encryption key");
        let request = self
            .vault
            .machine_enrolment_request(vault_id, encryption)
            .expect("this install's request");
        (request.machine, request.machine_key)
    }

    /// The roster's chain names this install live, `Owned(Yours)`, with its
    /// install key, signed by `r`.
    fn assert_on_roster_by(&self, r: &AuthorityKey) {
        let (machine, key) = self.me();
        let fold = self.vault.authority_fold().expect("the fold");
        let roster = fold
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .expect("the roster's chain names the restored machine");
        assert!(roster.is_live(), "the roster revision is live: {roster:?}");
        assert_eq!(roster.profile.machine_key, key, "with its install key");
        assert_eq!(
            roster.profile.role,
            MachineRole::Owned(MachineOwnership::Yours)
        );
        assert_eq!(&roster.signer, r, "the kit's R signs it");
    }

    /// How many roster rows `r` signed for this install.
    fn roster_rows_by(&self, r: &AuthorityKey) -> usize {
        let (machine, _) = self.me();
        rows(&self.vault)
            .iter()
            .filter(|row| {
                row.signer_key() == r
                    && matches!(&row.op, AuthorityOp::MachineProfile(profile) if profile.machine == machine)
            })
            .count()
    }

    /// One owner act this install carries: `world` kept on the owner's
    /// machines, its key minted and wrapped here.
    fn keep_on_my_machines(&self, world: EntityId) -> oneiron::Result<()> {
        self.vault
            .set_world_privacy_as(
                &self.owner(),
                ActSurface::ThisInstall,
                world,
                keep_on_my_machines(),
                None,
            )
            .map(drop)
    }
}

#[test]
fn a_restore_with_a_live_private_world_counts_its_rewrap_and_the_next_owner_act_stands() {
    let source = source();
    let issued = source.issue();
    let confirmed = source.confirm(&issued);
    let r = source.live_r();
    let private = source.private_world("Kept on my machines");
    let other = source.world("Another world");
    let fresh = source.fresh();

    let restored = fresh
        .restore(&issued, confirmed.activated.root)
        .expect("the kit restores on the fresh machine");
    assert!(
        !restored.keys.usable.is_empty(),
        "the private world's key is usable here: {:?}",
        restored.keys
    );
    fresh
        .vault
        .world_key(private)
        .expect("the restored machine's re-wrap counts: the key opens here");
    fresh.assert_on_roster_by(&r);
    assert_eq!(fresh.roster_rows_by(&r), 1, "R signs one roster row");

    fresh
        .keep_on_my_machines(other)
        .expect("the next owner act stands, carried by the restored machine");
    fresh
        .vault
        .world_key(other)
        .expect("the owner act's new key opens here");

    fresh
        .restore(&issued, confirmed.activated.root)
        .expect("a second restore of the same kit");
    assert_eq!(
        fresh.roster_rows_by(&r),
        1,
        "a machine the roster already holds live with its keys gets no new row"
    );
}

#[test]
fn a_restore_with_no_private_world_lets_the_next_owner_act_stand() {
    let source = source();
    let issued = source.issue();
    let confirmed = source.confirm(&issued);
    let r = source.live_r();
    let world = source.world("A world");
    let fresh = source.fresh();

    let restored = fresh
        .restore(&issued, confirmed.activated.root)
        .expect("the kit restores on the fresh machine");
    assert!(
        restored.keys.usable.is_empty(),
        "no private world: {:?}",
        restored.keys
    );
    fresh.assert_on_roster_by(&r);

    fresh
        .keep_on_my_machines(world)
        .expect("the next owner act stands, carried by the restored machine");
    fresh
        .vault
        .world_key(world)
        .expect("the owner act's new key opens here");
}

#[test]
fn a_kit_a_newer_kit_replaced_is_refused_before_any_write() {
    let source = source();
    let old_issued = source.issue();
    let old = source.confirm(&old_issued);
    let new_issued = source.issue();
    let new = source.confirm(&new_issued);
    let r = source.live_r();
    let fresh = source.fresh();

    let history = rows(&fresh.vault).len();
    let machine = fresh
        .vault
        .local_machine()
        .expect("this install's machine")
        .map(|machine| machine.id);
    let pin = fresh.vault.authority_fold().expect("the fold").pinned_root;

    let refused = fresh
        .restore(&old_issued, old.activated.root)
        .expect_err("the replaced kit's R is not live: the restore is refused");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains(KIT_NOT_CURRENT),
        "the exact words: {refused}"
    );
    assert_eq!(
        rows(&fresh.vault).len(),
        history,
        "no authority row written"
    );
    assert_eq!(
        fresh
            .vault
            .local_machine()
            .expect("this install's machine")
            .map(|machine| machine.id),
        machine,
        "no machine identity minted"
    );
    assert_eq!(
        fresh.vault.authority_fold().expect("the fold").pinned_root,
        pin,
        "no pin written"
    );

    fresh
        .restore(&new_issued, new.activated.root)
        .expect("the newest kit restores");
    fresh.assert_on_roster_by(&r);
}

#[test]
fn after_the_switch_to_kit_only_the_kits_rotated_r_puts_the_machine_on_the_roster() {
    let source = source();
    let issued = source.issue();
    let confirmed = source.confirm(&issued);
    let first = source.live_r();
    let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
    source
        .vault
        .set_recovery_preset_with_kit_as(
            &ActAuthority::Owner(source.owner(), ActSurface::ThisInstall),
            RecoveryPreset::NobodyButMe,
            &pieces,
            None,
            |_| Ok(()),
            &NoRecoveryBox,
        )
        .expect("the switch to kit-only with the kit");
    let rotated = source.live_r();
    assert_ne!(rotated, first, "the switch rotates R");
    let fresh = source.fresh();

    fresh
        .restore(&issued, confirmed.activated.root)
        .expect("the same kit restores after the rotation");
    fresh.assert_on_roster_by(&rotated);
}
