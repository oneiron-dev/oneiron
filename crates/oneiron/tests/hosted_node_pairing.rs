//! L10-16 PR 1: the owner's link for a hosted node (plan
//! `lanes/post-untangle/plans/PLAN-L10-16.md`, Design 3). `oneiron link`
//! pairs the cloud's always-on peer of a person's vault through the built
//! machine pairing. Its machine joins as a hosted node: never mine (DEC-0005:
//! "Hosted nodes and rented execution nodes start not-mine"), and none of the
//! owner's three answers to whose a machine is.
//!
//! The link redeems on either arm the redeem takes: on an install whose own
//! profile is still unanswered, as at its first serving start (the host root
//! enrols the machine, with no owner act), and on an install the owner
//! answered for (this install carries his act, a machine answer, since the
//! roster takes a pairing act only for an `Owned(..)` first revision).
//!
//! Run: `cargo test -p oneiron --all-features --test hosted_node_pairing`
//! (the fixtures are `oneiron::test_support`, built with `test-support`).
#![cfg(feature = "test-support")]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, CapabilitySlip, FoldedMachine, HostSlipIssuer, MachineEnrolmentRequest,
    MachineOwnership, MachineRole, OwnerActKind, PairingLink, PairingPrincipal,
    pairing_binding_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{EntityId, Vault, VaultConfig};

/// The person's own machine, serving the vault.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    vault_id: [u8; 32],
    /// This install's own machine.
    install: EntityId,
}

/// A rooted vault whose install holds its unanswered profile, as its first
/// serving start leaves it (FIX 4648).
fn host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    let person = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    bind_host_owner(&vault, &issuer, person).expect("FIXTURE: the owner's host binding");
    let install = vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("FIXTURE: this install's unanswered profile")
        .roster
        .expect("FIXTURE: a roster revision")
        .profile
        .machine;
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the owner's proof");
    let vault_id = vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("FIXTURE: a rooted vault");
    Host {
        _dir: dir,
        vault,
        issuer,
        owner,
        vault_id,
        install,
    }
}

/// A host whose own install the owner answered for as his, so it carries
/// his acts.
fn answered_host() -> Host {
    let host = host();
    host.vault
        .set_machine_role(
            &host.owner,
            ActSurface::ThisInstall,
            host.install,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("FIXTURE: the owner answers yours for this install");
    host
}

/// The machine that joins: its own install, asking to join `vault_id`.
fn joining(vault_id: [u8; 32]) -> (tempfile::TempDir, Vault, MachineEnrolmentRequest) {
    let dir = tempfile::tempdir().expect("tempdir");
    let install = Vault::open(dir.path(), VaultConfig::default()).expect("the joining install");
    install.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = install
        .machine_encryption_key(vault_id)
        .expect("FIXTURE: its encryption key");
    let request = install
        .machine_enrolment_request(vault_id, key)
        .expect("FIXTURE: its enrolment request");
    (dir, install, request)
}

fn hosted_node_link(host: &Host) -> PairingLink {
    host.vault
        .issue_hosted_node_pairing_link(
            &host.issuer,
            &host.owner,
            ActSurface::ThisInstall,
            Scope::top(),
            3600,
            PairingPrincipal::default(),
        )
        .expect("the owner issues a hosted-node link")
}

/// The joining machine redeems `link` with its request, under a throwaway
/// pairing key drawn from `seed`.
fn redeem(
    host: &Host,
    link: &PairingLink,
    request: &MachineEnrolmentRequest,
    seed: u8,
) -> oneiron::Result<(CapabilitySlip, FoldedMachine)> {
    let pairing_key = SigningKey::from_bytes(&[seed; 32]);
    let device_key = pairing_key.verifying_key().to_bytes();
    let holder = request.machine.to_hex();
    let transcript = pairing_binding_transcript(&link.code, &device_key, &holder)
        .expect("the binding transcript");
    let proof = pairing_key.sign(&transcript).to_bytes();
    host.vault.redeem_machine_pairing_link(
        &host.issuer,
        &link.code,
        &holder,
        device_key,
        &proof,
        request,
    )
}

/// `machine`'s roster role, and whether it is mine, as the vault's fold
/// reads it now.
fn standing(host: &Host, machine: EntityId) -> Option<(MachineRole, bool)> {
    let fold = host.vault.authority_fold().expect("authority fold");
    let folded = fold.machine(machine)?;
    let roster = folded.roster.as_ref()?;
    Some((roster.profile.role, folded.is_mine(None)))
}

#[test]
fn a_hosted_node_link_enrols_its_machine_as_a_hosted_node_never_mine() {
    let host = host();
    let (_dir, _install, request) = joining(host.vault_id);
    let link = hosted_node_link(&host);

    let (_slip, folded) = redeem(&host, &link, &request, 11).expect("the machine redeems");

    let roster = folded.roster.as_ref().expect("a roster revision");
    assert_eq!(roster.profile.role, MachineRole::HostedNode);
    assert!(roster.is_live(), "the hosted node stands");
    assert!(!folded.is_mine(None), "a hosted node is never mine");
    assert_eq!(
        standing(&host, request.machine),
        Some((MachineRole::HostedNode, false)),
        "the vault's fold holds it as a hosted node, not mine"
    );
}

#[test]
fn a_hosted_node_link_redeemed_on_an_answered_install_lands_under_the_owners_act() {
    let host = answered_host();
    let (_dir, _install, request) = joining(host.vault_id);
    let link = hosted_node_link(&host);

    let (_slip, folded) = redeem(&host, &link, &request, 12)
        .expect("the machine redeems on an install that carries the owner's act");

    let roster = folded.roster.as_ref().expect("a roster revision");
    assert_eq!(roster.profile.role, MachineRole::HostedNode);
    assert_eq!(
        roster.profile.carrier,
        Some(host.install),
        "this install carried the owner's act"
    );
    let act = roster.profile.act.as_ref().expect("the owner's act");
    assert_eq!(
        act.act,
        OwnerActKind::MachineAnswer,
        "a hosted node lands under a machine answer, never the pairing act"
    );
    assert_eq!(act.target, request.machine);
    assert!(!folded.is_mine(None), "a hosted node is never mine");
    assert_eq!(
        standing(&host, request.machine),
        Some((MachineRole::HostedNode, false))
    );
}

#[test]
fn a_hosted_node_link_is_one_use() {
    let host = answered_host();
    let (_first_dir, _first, first) = joining(host.vault_id);
    let (_second_dir, _second, second) = joining(host.vault_id);
    let link = hosted_node_link(&host);
    redeem(&host, &link, &first, 13).expect("the first machine redeems");

    assert!(
        redeem(&host, &link, &second, 14).is_err(),
        "a second redeem of the same code is refused"
    );
    assert_eq!(standing(&host, second.machine), None, "nothing enrolled it");
    assert_eq!(
        standing(&host, first.machine),
        Some((MachineRole::HostedNode, false))
    );
}

/// A guard, green before and after: the owner's three answers still land as
/// his answer, under the pairing act.
#[test]
fn the_three_answers_still_land_as_owned() {
    let host = answered_host();
    for (seed, ownership, mine) in [
        (21, MachineOwnership::Yours, true),
        (22, MachineOwnership::WorkSchool, false),
        (23, MachineOwnership::Rented, false),
    ] {
        let (_dir, _install, request) = joining(host.vault_id);
        let link = host
            .vault
            .issue_machine_pairing_link(
                &host.issuer,
                &host.owner,
                ActSurface::ThisInstall,
                Scope::top(),
                3600,
                PairingPrincipal::default(),
                ownership,
            )
            .expect("the owner issues a machine link");
        let (_slip, folded) = redeem(&host, &link, &request, seed).expect("the machine redeems");
        let roster = folded.roster.as_ref().expect("a roster revision");
        assert_eq!(
            roster.profile.role,
            MachineRole::Owned(ownership),
            "{ownership:?}"
        );
        assert_eq!(
            roster.profile.act.as_ref().map(|act| act.act),
            Some(OwnerActKind::Pairing),
            "{ownership:?}"
        );
        assert_eq!(
            standing(&host, request.machine),
            Some((MachineRole::Owned(ownership), mine)),
            "{ownership:?}"
        );
    }
}
