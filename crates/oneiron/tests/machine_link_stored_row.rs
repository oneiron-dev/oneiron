//! L10-16 PR 1, stored change: keep (M-1). Main stored the owner's approval
//! of a machine link with his answer under the key `ownership`. This PR keeps
//! that key and leaves it out of a hosted node's link, so a machine link
//! issued before the upgrade and redeemed after it lands as it would have.
//!
//! The pending row is read and rewritten as JSON through the hidden door
//! `oneiron::test_doors::pairing_pending_rows`, built only under
//! `--cfg oneiron_test_support`; every assertion is here. Without that cfg
//! this target is empty. Run:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test machine_link_stored_row`.
#![cfg(all(feature = "test-support", oneiron_test_support))]

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
use oneiron::test_doors::pairing_pending_rows::{
    pending_machine_approvals, rewrite_pending_machine_approvals,
};
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{Vault, VaultConfig};

/// The keys main's approval of a machine link held, in sorted order.
const MAIN_APPROVAL_KEYS: [&str; 5] = ["by", "kind", "owner", "ownership", "surface"];

/// The person's own machine, serving the vault.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    vault_id: [u8; 32],
}

/// A rooted vault whose own install the owner answered for as his, so it
/// carries his acts.
fn answered_host() -> Host {
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
    vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            install,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("FIXTURE: the owner answers yours for this install");
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
    }
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

fn machine_link(host: &Host, ownership: MachineOwnership) -> PairingLink {
    host.vault
        .issue_machine_pairing_link(
            &host.issuer,
            &host.owner,
            ActSurface::ThisInstall,
            Scope::top(),
            3600,
            PairingPrincipal::default(),
            ownership,
        )
        .expect("the owner issues a machine link")
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

fn sorted_keys(approval: &serde_json::Map<String, serde_json::Value>) -> Vec<&str> {
    let mut keys: Vec<&str> = approval.keys().map(String::as_str).collect();
    keys.sort_unstable();
    keys
}

#[test]
fn a_machine_link_stored_as_main_stored_it_still_redeems() {
    let host = answered_host();
    let (_dir, _install, request) = joining(host.vault_id);
    let link = machine_link(&host, MachineOwnership::Yours);

    // Main's approval: the same four act fields, and his answer under
    // `ownership`, with no other key.
    let rewritten = rewrite_pending_machine_approvals(&host.vault, |approval| {
        approval.remove("role");
        approval.insert(
            "ownership".to_owned(),
            serde_json::to_value(MachineOwnership::Yours).expect("the answer as JSON"),
        );
    })
    .expect("the door rewrites the stored link");
    assert_eq!(rewritten, 1, "the one outstanding machine link");
    let stored = pending_machine_approvals(&host.vault).expect("the door reads the stored link");
    assert_eq!(stored.len(), 1);
    assert_eq!(sorted_keys(&stored[0]), MAIN_APPROVAL_KEYS);

    let (_slip, folded) = redeem(&host, &link, &request, 31)
        .expect("a machine link stored as main stored it still redeems");

    let roster = folded.roster.as_ref().expect("a roster revision");
    assert_eq!(
        roster.profile.role,
        MachineRole::Owned(MachineOwnership::Yours)
    );
    assert_eq!(
        roster.profile.act.as_ref().map(|act| act.act),
        Some(OwnerActKind::Pairing),
        "it lands under the pairing act, as on main"
    );
    assert!(folded.is_mine(None), "his answer yours makes it mine");
}

#[test]
fn a_machine_link_stores_mains_keys_and_a_hosted_node_link_names_no_answer() {
    let host = answered_host();
    machine_link(&host, MachineOwnership::WorkSchool);
    let stored = pending_machine_approvals(&host.vault).expect("the door reads the stored link");
    assert_eq!(stored.len(), 1);
    assert_eq!(
        sorted_keys(&stored[0]),
        MAIN_APPROVAL_KEYS,
        "a machine link stores main's keys and no other"
    );
    assert_eq!(
        stored[0].get("ownership"),
        Some(&serde_json::to_value(MachineOwnership::WorkSchool).expect("the answer as JSON")),
        "his answer, as main stored it"
    );

    let host = answered_host();
    host.vault
        .issue_hosted_node_pairing_link(
            &host.issuer,
            &host.owner,
            ActSurface::ThisInstall,
            Scope::top(),
            3600,
            PairingPrincipal::default(),
        )
        .expect("the owner issues a hosted-node link");
    let stored = pending_machine_approvals(&host.vault).expect("the door reads the stored link");
    assert_eq!(stored.len(), 1);
    assert_eq!(
        sorted_keys(&stored[0]),
        ["by", "kind", "owner", "surface"],
        "a hosted node's link holds no answer"
    );
}
