//! Pass 27 R4 PR 2 (WAYBACK-R4-FIRST-KEY = B, WAYBACK-R4-NO-PREDECESSOR = A):
//! the kit's activation enrols the root's authority key R in the same write
//! txn, kind `RecoveryAuthority`, predecessor = this install's live owner key
//! or this vault's host root on a self-hosted vault, and hands R's seed out
//! once. A second confirmation keeps one R row. With neither predecessor the
//! activation is refused with the exact words and nothing is written. A
//! device key enrols with kind `Device`.
//!
//! Red on PR 2's base `1b0ef517a29e`: the file compiles there (only APIs that
//! exist at that head) and fails at runtime, since the activation enrols no
//! R and refuses no predecessor-less confirm.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test kit_activation_enrols_authority_key`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, AuthorityOp, EnrolledOwnerKeyKind, HostSlipIssuer,
    MachineRole, decode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{CodeKeeping, KitIssue, PassphraseCost, PieceHome};
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::world_keys::{ConfirmedWorldKit, IssuedWorldKit};
use oneiron::{EntityId, ErrorKind, HostingPrivacyPosture, Vault, VaultConfig};

/// The exact refusal when this install holds no predecessor
/// (WAYBACK-R4-NO-PREDECESSOR = A).
const NO_PREDECESSOR: &str =
    "this device's owner key is not enrolled; enrol it, then confirm the kit; nothing was written";

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// A self-hosted vault whose host seed this install holds in its keystore.
struct SelfHosted {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    person: EntityId,
}

fn self_hosted() -> SelfHosted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault");
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
    SelfHosted {
        _dir: dir,
        vault,
        issuer,
        person,
    }
}

impl SelfHosted {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner(), ActSurface::ThisInstall)
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

    fn confirm(&self, issued: &IssuedWorldKit) -> oneiron::Result<ConfirmedWorldKit> {
        let pieces: Vec<&oneiron::store::recovery_kit::KitPiece> =
            issued.pieces.iter().take(2).collect();
        self.vault
            .confirm_world_kit(&self.owner(), &pieces, None, &BTreeSet::new())
    }

    /// R's enrol row's signer, for the enrolled `public_key`.
    fn enrol_signer(&self, public_key: &[u8; 32]) -> AuthorityKey {
        self.vault
            .export_signed_authority_history()
            .expect("the history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .find_map(|row| match &row.op {
                AuthorityOp::OwnerKeyEnroll(enroll)
                    if enroll.device.key == AuthorityKey::Ed25519(*public_key) =>
                {
                    Some(row.signer_key().clone())
                }
                _ => None,
            })
            .expect("R's enrol row is stored")
    }

    /// How many enrol rows the history holds for `public_key`.
    fn enrol_rows(&self, public_key: &[u8; 32]) -> usize {
        self.vault
            .export_signed_authority_history()
            .expect("the history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .filter(|row| match &row.op {
                AuthorityOp::OwnerKeyEnroll(enroll) => {
                    enroll.device.key == AuthorityKey::Ed25519(*public_key)
                }
                _ => false,
            })
            .count()
    }
}

#[test]
fn confirming_the_kit_on_a_self_hosted_vault_enrols_r_under_the_host_root() {
    let fixture = self_hosted();
    let issued = fixture.issue();
    fixture.confirm(&issued).expect("the kit confirms");

    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    let live_r: Vec<_> = enrolled
        .iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .collect();
    assert_eq!(live_r.len(), 1, "one live R, kind RecoveryAuthority");
    assert_eq!(
        fixture.enrol_signer(&live_r[0].public_key),
        fixture.issuer.public_key(),
        "the host root signs R's row"
    );
}

#[test]
fn with_this_installs_device_key_the_row_is_signed_by_that_key() {
    let fixture = self_hosted();
    let device = fixture
        .vault
        .enrol_device_owner_signing_key(&fixture.authority(), &fixture.issuer)
        .expect("the owner enrols this install's device key");
    let issued = fixture.issue();
    fixture.confirm(&issued).expect("the kit confirms");

    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    let live_r: Vec<_> = enrolled
        .iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .collect();
    assert_eq!(live_r.len(), 1, "one live R");
    assert_eq!(
        fixture.enrol_signer(&live_r[0].public_key),
        AuthorityKey::Ed25519(device.public_key),
        "this install's device key signs R's row, not the host root"
    );
}

#[test]
fn a_second_confirmation_of_the_same_kit_keeps_one_r_row() {
    let fixture = self_hosted();
    let issued = fixture.issue();
    fixture.confirm(&issued).expect("the first confirm");

    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    let live_r: Vec<_> = enrolled
        .iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .collect();
    assert_eq!(live_r.len(), 1, "one live R after the first confirm");

    let again = fixture.confirm(&issued);
    assert!(
        again.is_err(),
        "confirming an already-confirmed kit is refused"
    );
    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    let live_r: Vec<_> = enrolled
        .iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .collect();
    assert_eq!(live_r.len(), 1, "still one live R");
    assert_eq!(
        fixture.enrol_rows(&live_r[0].public_key),
        1,
        "still one R row"
    );
}

#[test]
fn without_a_predecessor_the_activation_is_refused_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open(dir.path(), config).expect("the hosted vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let owner = proof(&vault, person);

    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let issued = vault
        .issue_world_kit(
            &owner,
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
        .expect("a kit");

    let before_fold = vault.authority_fold().expect("the fold");
    let before_history = vault
        .export_signed_authority_history()
        .expect("the history")
        .len();
    let pieces: Vec<&oneiron::store::recovery_kit::KitPiece> =
        issued.pieces.iter().take(2).collect();
    let refused = vault
        .confirm_world_kit(&owner, &pieces, None, &BTreeSet::new())
        .expect_err("a confirm with no predecessor is refused");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains(NO_PREDECESSOR),
        "the exact words: {refused}"
    );

    let after_fold = vault.authority_fold().expect("the fold");
    assert_eq!(
        after_fold.roster, before_fold.roster,
        "the roster is unchanged"
    );
    assert_eq!(
        after_fold.pinned_root, before_fold.pinned_root,
        "the pin is unchanged"
    );
    assert_eq!(
        vault
            .export_signed_authority_history()
            .expect("the history")
            .len(),
        before_history,
        "the history is unchanged"
    );
}

#[test]
fn a_device_keys_enrolled_kind_is_device() {
    let fixture = self_hosted();
    let receipt = fixture
        .vault
        .enrol_device_owner_signing_key(&fixture.authority(), &fixture.issuer)
        .expect("the owner enrols this install's device key");
    let listed = fixture
        .vault
        .enrolled_owner_keys()
        .expect("the list")
        .into_iter()
        .find(|key| key.public_key == receipt.public_key)
        .expect("the device key is listed");
    assert_eq!(listed.kind, EnrolledOwnerKeyKind::Device);
    assert!(listed.live);
}
