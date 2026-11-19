//! REVIEW-9534 round 2 P1 (restored_join_door.rs:281; Engine ANSWER
//! KIT-JOIN-ONE-R-ROW = A): a kit restore files and joins an install born of
//! a restore in one row of the kit's root authority key R, as main's kit
//! restore puts a machine on the roster in one R row. Two copies of one
//! image that each restore the current kit, on installs that have not seen
//! each other, so stay equal-sequence siblings under R, and neither floors
//! the other's roster revision (`rows_floor`).
//!
//! Copy B joins first by the owner's word under another owner key (the host
//! root), as an unanswered install, then restores the kit: R writes one
//! roster row above that. Copy A, unjoined and never synced with B, restores
//! the same kit. Red at #9534 1a534adf: A's restore writes R's enrolment and
//! then R's join one sequence above it, which floors B's R row once B
//! imports A's history, so B's "yours" revision lands restriction only.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test kit_restore_restored_copies_one_r_row`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::checkpoint::RestoreReason;
use oneiron::recovery::{CodeKeeping, KitIssue, PassphraseCost, PieceHome};
use oneiron::store::GateDecisionId;
use oneiron::store::recovery_kit::KitPiece;
use oneiron::test_support::{bind_host_owner, restore_tempdir, test_host_issuer};
use oneiron::world_keys::{ConfirmedWorldKit, IssuedWorldKit, KitConfirmation, RecoveryRootId};
use oneiron::{EntityId, Vault, VaultConfig};

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// The source vault: rooted by the test host, its install serving, its
/// owner bound and its data key made, so it can issue and confirm a kit.
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
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    vault.ensure_vault_key().expect("the vault's data key");
    Source { dir, vault, person }
}

impl Source {
    fn issue(&self) -> IssuedWorldKit {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("a rooted vault");
        self.vault
            .issue_world_kit(
                &proof(&self.vault, self.person),
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
            .confirm_world_kit(
                &proof(&self.vault, self.person),
                &pieces,
                None,
                &BTreeSet::new(),
            )
            .expect("the kit confirms")
    }

    /// A copy of the vault restored from a checkpoint image, with an empty
    /// keystore of its own: an install born of a restore.
    fn copy(&self, name: &str) -> Copy {
        let key = self.vault.checkpoint_key().expect("the checkpoint key");
        let image = self.dir.path().join(format!("{name}.image"));
        self.vault
            .snapshot_checkpoint(&image, 100)
            .expect("the checkpoint");
        let (vault, _) = Vault::restore_checkpoint(
            &image,
            &key,
            &self.dir.path().join(name),
            VaultConfig::device(),
            RestoreReason::Restore,
            200,
        )
        .expect("the copy of the vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        Copy {
            vault,
            person: self.person,
        }
    }
}

struct Copy {
    vault: Vault,
    person: EntityId,
}

impl Copy {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    /// The kit restore from `issued`'s pieces, the owner carrying `root`'s
    /// fingerprint.
    fn restore(&self, issued: &IssuedWorldKit, root: RecoveryRootId) {
        let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
        self.vault
            .restore_world_kit(
                &self.owner(),
                &pieces,
                None,
                Some(KitConfirmation::Fingerprint(root)),
            )
            .expect("the kit restores on the copy");
    }

    /// This install's machine.
    fn machine(&self) -> EntityId {
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
        self.vault
            .machine_enrolment_request(vault_id, encryption)
            .expect("this install's request")
            .machine
    }
}

/// Every authority row `from` holds, landed on `to`.
fn sync_authority(from: &Vault, to: &Vault) {
    let history = from
        .export_signed_authority_history()
        .expect("export authority history");
    to.import_signed_authority_history(&history)
        .expect("import authority history");
}

/// Whether the roster's head names `machine` live as the owner's own on
/// `vault`'s fold.
fn yours_on_roster(vault: &Vault, machine: EntityId) -> bool {
    vault
        .authority_fold()
        .expect("the fold")
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .is_some_and(|roster| {
            roster.is_live() && roster.profile.role == MachineRole::Owned(MachineOwnership::Yours)
        })
}

#[test]
fn kit_restores_of_two_copies_of_one_image_leave_both_on_the_roster() {
    let source = source();
    let issued = source.issue();
    let root = source.confirm(&issued).activated.root;
    let a = source.copy("a");
    let b = source.copy("b");

    // Copy B joins first by the owner's word under another owner key, the
    // host root, as an unanswered install; then its kit restore has R put it
    // on the roster as the owner's own, in one R row.
    b.vault
        .hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    b.vault
        .join_restored_install(&test_host_issuer(), &b.owner(), MachineRole::Unanswered)
        .expect("FIXTURE: the owner's word joins copy B");
    b.restore(&issued, root);
    let b_machine = b.machine();
    assert!(
        yours_on_roster(&b.vault, b_machine),
        "FIXTURE: R's roster row makes copy B the owner's own"
    );

    // Copy A, unjoined and never synced with B, restores the same kit.
    a.restore(&issued, root);
    let a_machine = a.machine();
    assert!(
        yours_on_roster(&a.vault, a_machine),
        "FIXTURE: the kit restore joins copy A on its own branch"
    );

    sync_authority(&a.vault, &b.vault);
    assert!(
        yours_on_roster(&b.vault, b_machine),
        "a sibling copy's kit restore leaves copy B's R roster row live"
    );
    assert!(
        yours_on_roster(&b.vault, a_machine),
        "copy A stands beside it"
    );
}
