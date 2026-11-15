//! Pass 27 R4 PR 2: the `ways_back` read and the handed-out seed. Before the
//! kit's activation the kit root is not enrolled; after it, it is, the device
//! count is unchanged, no passkey appears, and the box PIN reads false. The
//! handed-out seed derives R's public key.
//!
//! Red on PR 2's base `1b0ef517a29e`: the file does not compile there (no
//! `Vault::ways_back`, `WaysBack`, or `ActivatedRoot::authority_seed`).
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test ways_back`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, EnrolledOwnerKeyKind, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{CodeKeeping, KitIssue, PassphraseCost, PieceHome};
use oneiron::store::GateDecisionId;
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::{ConfirmedWorldKit, IssuedWorldKit, RecoveryAuthoritySigner};
use oneiron::{EntityId, Vault, VaultConfig};
use zeroize::Zeroizing;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    person: EntityId,
}

fn self_hosted() -> Fixture {
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
    Fixture {
        _dir: dir,
        vault,
        issuer,
        person,
    }
}

impl Fixture {
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
        let pieces: Vec<&oneiron::store::recovery_kit::KitPiece> =
            issued.pieces.iter().take(2).collect();
        self.vault
            .confirm_world_kit(&self.owner(), &pieces, None, &BTreeSet::new())
            .expect("the kit confirms")
    }
}

#[test]
fn ways_back_before_and_after_the_kits_activation() {
    let fixture = self_hosted();

    let before = fixture.vault.ways_back().expect("the read");
    assert_eq!(before.owner_devices, 0);
    assert_eq!(before.passkeys, 0);
    assert!(!before.kit_root_enrolled);
    assert!(!before.box_pin_set);

    fixture
        .vault
        .enrol_device_owner_signing_key(
            &ActAuthority::Owner(fixture.owner(), ActSurface::ThisInstall),
            &fixture.issuer,
        )
        .expect("the owner enrols this install's device key");
    let with_device = fixture.vault.ways_back().expect("the read");
    assert_eq!(with_device.owner_devices, 1);
    assert_eq!(with_device.passkeys, 0);
    assert!(!with_device.kit_root_enrolled);
    assert!(!with_device.box_pin_set);

    let issued = fixture.issue();
    fixture.confirm(&issued);
    let after = fixture.vault.ways_back().expect("the read");
    assert_eq!(after.owner_devices, 1, "R is no device");
    assert_eq!(after.passkeys, 0);
    assert!(after.kit_root_enrolled);
    assert!(!after.box_pin_set);
}

#[test]
fn the_handed_out_seed_derives_rs_public_key() {
    let fixture = self_hosted();
    let issued = fixture.issue();
    let confirmed = fixture.confirm(&issued);

    let vault_id = fixture
        .vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let rebuilt = RecoveryAuthoritySigner::from_released_seed(
        Zeroizing::new(*confirmed.activated.authority_seed.bytes()),
        &vault_id,
        confirmed.activated.root,
    )
    .expect("the released key rebuilds");
    let enrolled = fixture.vault.enrolled_owner_keys().expect("the list");
    let live_r: Vec<_> = enrolled
        .iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .collect();
    assert_eq!(live_r.len(), 1, "one live R");
    assert_eq!(
        AuthorityKey::Ed25519(live_r[0].public_key),
        rebuilt.authority_key(),
        "the handed-out seed derives R"
    );
}
