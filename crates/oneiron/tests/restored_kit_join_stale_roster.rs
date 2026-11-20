//! REVIEW-9539 round 2 P1 (stale_roster.rs:141): a kit restore's inline join
//! of an install born of a restore is the kit root key R's roster revision
//! of that machine (KIT-JOIN-ONE-R-ROW = A), so it goes stale with every
//! other approval R signed once R is revoked, unless a key still on the
//! roster signs the same standing again.
//!
//! Copy A of the source's checkpoint restores the source's kit: R writes one
//! `RestoredMachineJoin` row that carries A's enrolment inline. The source,
//! which has not seen A, confirms a new kit, whose activation revokes R and
//! carries only the standings the source knows. The source then imports A's
//! history: the join is valid on its own parents, where R was live, and
//! heads A's roster chain there. One stale-roster window past the
//! revocation, A's roster head is stale on the source and no longer the
//! owner's own. Red at 2efec88a: the window read only `MachineProfile` rows,
//! so the join never expired, and A stayed the owner's own on the source.
//!
//! A kit change on an install that knows A carries A's standing as it
//! carries a profile row (`kit_change_carries_root_key_approvals.rs`).
//!
//! Time, as in `kit_change_carries_root_key_approvals.rs`: every vault opens
//! on one `ManualClock` at `T0`, and authority time moves with `clock.set`,
//! `advance_authority_clock_for_test` and a fresh fold. The stale deadline
//! is `min(approval_seen, revoked_seen) + window + 1`; a 60 s margin passes
//! it.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test restored_kit_join_stale_roster`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{AuthorityKey, EnrolledOwnerKeyKind, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::checkpoint::RestoreReason;
use oneiron::recovery::{CodeKeeping, KitIssue, PassphraseCost, PieceHome};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::store::recovery_kit::KitPiece;
use oneiron::test_support::{bind_host_owner, restore_tempdir};
use oneiron::world_keys::{ConfirmedWorldKit, IssuedWorldKit, KitConfirmation, RecoveryRootId};
use oneiron::{EntityId, Vault, VaultConfig};

/// Authority wall time for all setup: every first-seen lands here.
const T0: u64 = 1_800_000_000;
/// The stale-roster window (`DEFAULT_STALE_ROSTER_WINDOW_SECS`): 24 h.
const WINDOW_SECS: u64 = 24 * 60 * 60;
/// Margin past the window, so the `+ window + 1` deadline is safely passed.
const MARGIN_SECS: u64 = 60;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// The source vault on a manual clock: rooted by the test host, its install
/// serving, its owner bound and its data key made, so it can issue and
/// confirm kits.
struct Source {
    dir: tempfile::TempDir,
    vault: Vault,
    clock: Arc<ManualClock>,
    person: EntityId,
}

fn source() -> Source {
    let clock = ManualClock::new(T0);
    let dir = restore_tempdir();
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path().join("source"), config).expect("the source vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    vault.ensure_vault_key().expect("the vault's data key");
    Source {
        dir,
        vault,
        clock,
        person,
    }
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

    /// The one live R, kind `RecoveryAuthority`.
    fn live_r(&self) -> AuthorityKey {
        let live: Vec<AuthorityKey> = self
            .vault
            .enrolled_owner_keys()
            .expect("the list")
            .into_iter()
            .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
            .map(|key| AuthorityKey::Ed25519(key.public_key))
            .collect();
        assert_eq!(live.len(), 1, "one live R");
        live.into_iter().next().expect("one live R")
    }

    /// A copy of the vault restored from a checkpoint image on the same
    /// clock, with an empty keystore of its own: an install born of a
    /// restore.
    fn copy(&self, name: &str) -> Copy {
        let key = self.vault.checkpoint_key().expect("the checkpoint key");
        let image = self.dir.path().join(format!("{name}.image"));
        self.vault
            .snapshot_checkpoint(&image, 100)
            .expect("the checkpoint");
        let mut config = VaultConfig::device();
        config.store_clock = self.clock.bundle();
        let (vault, _) = Vault::restore_checkpoint(
            &image,
            &key,
            &self.dir.path().join(name),
            config,
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
    /// The kit restore from `issued`'s pieces, the owner carrying `root`'s
    /// fingerprint.
    fn restore(&self, issued: &IssuedWorldKit, root: RecoveryRootId) {
        let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
        self.vault
            .restore_world_kit(
                &proof(&self.vault, self.person),
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

/// Whether `key` is on `vault`'s roster and not revoked.
fn key_is_live(vault: &Vault, key: &AuthorityKey) -> bool {
    vault
        .authority_fold()
        .expect("the fold")
        .roster
        .get(key)
        .is_some_and(|device| !device.revoked)
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

/// Moves authority time to `now` on `vault`: the wall clock plus the
/// persisted floor, then a fresh fold observes it.
fn advance_to(vault: &Vault, clock: &Arc<ManualClock>, now: u64) {
    clock.set(now);
    vault
        .advance_authority_clock_for_test(now)
        .expect("the authority clock moves");
    vault.authority_fold().expect("the fold at the new time");
}

#[test]
fn a_kit_restores_join_goes_stale_once_its_root_key_is_revoked() {
    let source = source();
    let first = source.issue();
    let root = source.confirm(&first).activated.root;
    let a = source.copy("a");
    a.restore(&first, root);
    let machine = a.machine();
    assert!(
        yours_on_roster(&a.vault, machine),
        "FIXTURE: the kit restore joins copy A on its own branch"
    );

    // The source, which has not seen copy A, changes its kit: the new kit's
    // activation revokes R.
    let r = source.live_r();
    let second = source.issue();
    source.confirm(&second);
    assert!(
        !key_is_live(&source.vault, &r),
        "FIXTURE: the new kit revokes R on the source"
    );

    sync_authority(&a.vault, &source.vault);
    assert!(
        yours_on_roster(&source.vault, machine),
        "FIXTURE: inside the window, R's join of copy A stands on the source"
    );

    advance_to(&source.vault, &source.clock, T0 + WINDOW_SECS + MARGIN_SECS);
    let fold = source.vault.authority_fold().expect("the source's fold");
    let folded = fold
        .machine(machine)
        .expect("copy A's machine on the source");
    let roster = folded.roster.as_ref().expect("copy A's roster head");
    assert!(
        roster.stale && !roster.is_live(),
        "a window past R's revocation, R's join of copy A is stale on the source"
    );
    assert!(
        folded
            .roster_trusted
            .as_ref()
            .is_none_or(|trusted| !trusted.is_live()),
        "and the accepted chain no longer takes copy A as the owner's own"
    );
    assert!(
        !yours_on_roster(&source.vault, machine),
        "copy A is not the owner's own on the source"
    );
}
