//! Custody follows the act, not the key (census L7-14; Engine RULING
//! L7-14-CUT = A, 14 Nov 03:02). identity.md #machine-profile-built says
//! sticky custody is to be "re-cut under will over substrate" (DEC-0005
//! #will-sweep): owner acts reach every linked machine, while the operator
//! alone acts as nobody and custody labels stay truthful (#will-sweep-kept).
//! On main that re-cut is the act path. The owner's machine answers stand
//! through any carrier whatever its custody (#2982), his enrolled key starts
//! its own custody line (FIX 5896), and a key the host admits alone stays
//! the host's (Astra #1423 F1).
//!
//! Proof tests of built behaviour, green on main and on the head, each on its
//! own vault under the Hosted posture.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test custody_will_over_substrate`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityAttestation, AuthorityKey, AuthorityTier, DeviceAuthority,
    HostSlipIssuer, MachineOwnership, MachineRole, ROLE_ADMIN, ROLE_CLOUD, ROLE_OWNER,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::steward::recover_cloud_account_signed_by_host_root;
use oneiron::{EntityId, HostingPrivacyPosture, Vault, VaultConfig};

/// One vault under the Hosted posture, rooted under the test host (a
/// `ROLE_CLOUD`, `CloudCustodial` root), with this install's machine profile
/// enrolled and the embedded owner authenticated. The vault drops first.
struct HostedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl HostedVault {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let vault = Vault::open(dir.path(), config).expect("hosted vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (owner, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            vault,
            issuer,
            owner,
            proof,
            _dir: dir,
        }
    }

    fn in_host_custody(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_key_in_host_custody(key)
            .expect("custody read")
    }
}

/// The roster row a managed host's new root holds, as the host stamps its
/// own root on a hosted vault: attested as its root, `ROLE_CLOUD`,
/// `CloudCustodial`.
fn hosted_root(issuer: &HostSlipIssuer) -> DeviceAuthority {
    DeviceAuthority {
        key: issuer.public_key(),
        transport_key_binding: issuer.binding_key(),
        attestation: AuthorityAttestation {
            kind: "HostRoot".into(),
            evidence: Vec::new(),
        },
        tier: AuthorityTier::CloudCustodial,
        roles: ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
    }
}

/// A roster row whose own labels say owner-held: no host attestation, no
/// `ROLE_CLOUD`, `Software` tier.
fn owner_labelled(key: AuthorityKey) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".into(),
            evidence: Vec::new(),
        },
        tier: AuthorityTier::Software,
        roles: ROLE_OWNER | ROLE_ADMIN,
    }
}

/// Will over substrate: after the managed host migrates its root (a ReRoot,
/// which retires every roster key), the owner's "yours" for this install,
/// given under his act from his authenticated surface, stands. The new root
/// is the host's, and no custody check stands in the owner's way.
#[test]
fn the_owners_answer_stands_on_a_hosted_vault_after_a_host_reroot() {
    let hosted = HostedVault::open();
    let next = HostSlipIssuer::from_secret(b"custody will over substrate next host root")
        .expect("the managed host's next root");
    recover_cloud_account_signed_by_host_root(
        &hosted.vault,
        &hosted.proof,
        &hosted.issuer,
        hosted_root(&next),
    )
    .expect("the managed host migrates its root under the owner's account");
    assert!(
        hosted.in_host_custody(&next.public_key()),
        "guard: the new hosted root is the host's"
    );

    // As a managed host does when it starts serving under its new root: it
    // binds the owner's account and registers this install again.
    oneiron::test_support::bind_host_owner(&hosted.vault, &next, hosted.owner)
        .expect("the owner's account bound under the new root");
    let proof = hosted
        .vault
        .authenticate_owner(
            hosted.owner,
            &hosted.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the owner authenticated under the new root");
    hosted
        .vault
        .ensure_serving_install_profile(&next, MachineRole::Unanswered)
        .expect("this install registered under the new root");
    let install = hosted
        .vault
        .local_machine()
        .expect("local machine read")
        .expect("this install's machine")
        .id;

    hosted
        .vault
        .set_machine_role(
            &proof,
            ActSurface::ThisInstall,
            install,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner answers yours for this install on the hosted vault");
    let fold = hosted.vault.authority_fold().expect("authority fold");
    assert!(
        fold.machine(install)
            .is_some_and(|machine| machine.is_mine(None)),
        "the owner's answer stands after the host ReRoot: his act passes custody"
    );
}

/// The owner's act starts its own custody line: the signing key he enrols
/// on a hosted vault, carried by this install under his act, is not in the
/// host's custody, though the host root that preceded it is.
#[test]
fn an_owner_enrolled_key_signs_as_owner_held_on_a_hosted_vault() {
    let hosted = HostedVault::open();
    assert!(
        hosted.in_host_custody(&hosted.issuer.public_key()),
        "guard: the hosted root is the host's"
    );
    let receipt = hosted
        .vault
        .enrol_device_owner_signing_key(
            &ActAuthority::Owner(hosted.proof.clone(), ActSurface::ThisInstall),
            &hosted.issuer,
        )
        .expect("the owner enrols this install's owner signing key");
    let key = AuthorityKey::Ed25519(receipt.public_key);
    let fold = hosted.vault.authority_fold().expect("authority fold");
    assert!(
        fold.roster.get(&key).is_some_and(|device| !device.revoked),
        "the owner's key is live on the roster"
    );
    assert!(
        !hosted.in_host_custody(&key),
        "the owner's enrolled key starts its own custody line on a hosted vault"
    );
}

/// The kept rule: a key the host's root re-roots to alone stays in the
/// host's custody, whatever its own labels say (the public twin of the lib
/// pin `a_custodians_successor_never_vouches_for_a_machine`, Astra #1423 F1).
#[test]
fn a_host_reroot_successor_stays_in_the_hosts_custody() {
    let hosted = HostedVault::open();
    let successor = HostSlipIssuer::from_secret(b"custody will over substrate labelled successor")
        .expect("successor key")
        .public_key();
    recover_cloud_account_signed_by_host_root(
        &hosted.vault,
        &hosted.proof,
        &hosted.issuer,
        owner_labelled(successor.clone()),
    )
    .expect("the host root re-roots to a key labelled owner-held");
    let fold = hosted.vault.authority_fold().expect("authority fold");
    assert!(
        fold.roster
            .get(&successor)
            .is_some_and(|device| !device.revoked),
        "guard: the successor is the vault's live root"
    );
    assert!(
        hosted.in_host_custody(&successor),
        "a key the host's root re-roots to alone stays in the host's custody, whatever its labels say"
    );
}
