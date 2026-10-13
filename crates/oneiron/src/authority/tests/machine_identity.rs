//! World privacy P1 acceptance: a machine is the owner's only by the owner's
//! own answer at enrolment ("yours, work/school, or rented"; only yours counts),
//! signed into the authority log. No MACHINE body, actor class, host-root
//! derivation or forged entry sets it, and a mesh address bind keeps it.
use super::support::{authority_key_from_ed, ed_key, sign_ed, unsigned_entry};
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::store::GateDecisionId;
use crate::{Vault, VaultConfig};

pub(super) struct Host {
    pub(super) _dir: tempfile::TempDir,
    pub(super) vault: Vault,
    pub(super) issuer: HostSlipIssuer,
    pub(super) owner: AuthenticatedOwner,
    pub(super) vault_id: [u8; 32],
}

pub(super) fn host() -> Host {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let issuer = crate::test_support::test_host_issuer();
    vault.ensure_host_root_slip(&issuer).unwrap();
    let person = crate::vault::embedded_owner_actor_id().unwrap();
    vault.bind_host_owner_for_test(&issuer, person).unwrap();
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let vault_id = vault.authority_fold().unwrap().vault_id.unwrap();
    Host {
        _dir: dir,
        vault,
        issuer,
        owner,
        vault_id,
    }
}

pub(super) fn encryption_key() -> MachineEncryptionKey {
    MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    }
}

/// The machine that joins: its own install, asking to join `vault_id`.
fn joining(vault_id: [u8; 32]) -> (tempfile::TempDir, Vault, MachineEnrolmentRequest) {
    let dir = tempfile::tempdir().unwrap();
    let install = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let request = install
        .machine_enrolment_request(vault_id, encryption_key())
        .unwrap();
    (dir, install, request)
}

/// An enrolment request for an arbitrary row, signed by `key`.
pub(super) fn request_for(
    vault_id: [u8; 32],
    machine: EntityId,
    key: &SigningKey,
) -> MachineEnrolmentRequest {
    let machine_key = key.verifying_key().to_bytes();
    MachineEnrolmentRequest {
        vault_id,
        machine,
        machine_key,
        encryption_key: encryption_key(),
        machine_proof: key
            .sign(&machine_profile_proof_transcript(
                &vault_id,
                machine,
                &machine_key,
                &encryption_key(),
            ))
            .to_bytes(),
    }
}

fn is_mine(vault: &Vault, machine: EntityId) -> bool {
    vault
        .authority_fold()
        .unwrap()
        .machine(machine)
        .is_some_and(FoldedMachine::is_mine)
}

#[test]
fn only_the_owners_yours_makes_a_machine_mine() {
    let host = host();
    for (role, mine) in [
        (MachineRole::Owned(MachineOwnership::Yours), true),
        (MachineRole::Owned(MachineOwnership::WorkSchool), false),
        (MachineRole::Owned(MachineOwnership::Rented), false),
        (MachineRole::HostedNode, false),
        (MachineRole::ExecutionNode, false),
    ] {
        let (_dir, install, request) = joining(host.vault_id);
        let folded = host
            .vault
            .enroll_machine(&host.issuer, &host.owner, &request, role)
            .unwrap();
        assert_eq!(folded.is_mine(), mine, "{role:?}");
        assert_eq!(is_mine(&host.vault, request.machine), mine, "{role:?}");
        // The joining install keeps its own machine id beside its key; it is
        // not the CRDT client id.
        assert_eq!(
            install.local_machine().unwrap().unwrap().id,
            request.machine
        );
    }

    // The engine's own writers are MACHINE actors derived from the host root.
    // They are never the owner's machines, and the owner cannot profile one.
    host.vault
        .provision_engine_machine_identities(&host.issuer)
        .unwrap();
    for writer in host.vault.engine_machine_actors().unwrap() {
        assert!(
            host.vault
                .authority_fold()
                .unwrap()
                .machine(writer)
                .is_none()
        );
        let request = request_for(host.vault_id, writer, &ed_key(41));
        assert!(
            host.vault
                .enroll_machine(
                    &host.issuer,
                    &host.owner,
                    &request,
                    MachineRole::Owned(MachineOwnership::Yours)
                )
                .is_err()
        );
        assert!(!is_mine(&host.vault, writer));
    }

    // The answer moves only by a later owner revision, and removal is final.
    let (_dir, _install, request) = joining(host.vault_id);
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &request,
            MachineRole::Owned(MachineOwnership::Rented),
        )
        .unwrap();
    assert!(!is_mine(&host.vault, request.machine));
    host.vault
        .set_machine_role(
            &host.issuer,
            &host.owner,
            request.machine,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    assert!(is_mine(&host.vault, request.machine));

    // A machine joins once: a later enrolment naming it, with another key,
    // never takes its place.
    let taken = request_for(host.vault_id, request.machine, &ed_key(42));
    assert!(
        host.vault
            .enroll_machine(
                &host.issuer,
                &host.owner,
                &taken,
                MachineRole::Owned(MachineOwnership::Yours)
            )
            .is_err()
    );
    assert_eq!(
        host.vault
            .authority_fold()
            .unwrap()
            .machine(request.machine)
            .unwrap()
            .profile
            .machine_key,
        request.machine_key
    );
}

#[test]
fn a_removed_machine_never_comes_back() {
    let host = host();
    let (_dir, _install, request) = joining(host.vault_id);
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    host.vault
        .enroll_machine(&host.issuer, &host.owner, &request, yours)
        .unwrap();
    let removed = host
        .vault
        .set_machine_role(
            &host.issuer,
            &host.owner,
            request.machine,
            MachineRole::Removed,
        )
        .unwrap();
    assert!(removed.removed && !removed.is_live());
    assert!(!is_mine(&host.vault, request.machine));
    for retry in [
        host.vault
            .set_machine_role(&host.issuer, &host.owner, request.machine, yours),
        host.vault
            .enroll_machine(&host.issuer, &host.owner, &request, yours),
    ] {
        assert!(retry.is_err());
    }
    assert!(!is_mine(&host.vault, request.machine));
}

#[test]
fn a_forged_mark_never_makes_a_machine_mine() {
    let host = host();
    let machine_key = ed_key(51);
    let machine = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };

    // A MACHINE body is public address data: no field in it is a mark.
    host.vault
        .put_entity(
            &machine,
            ENTITY_TYPE_MACHINE,
            at,
            1,
            br#"{"role":"yours","mine":true}"#,
        )
        .unwrap();
    assert!(
        host.vault
            .authority_fold()
            .unwrap()
            .machine(machine)
            .is_none()
    );

    let request = request_for(host.vault_id, machine, &machine_key);
    let profile = MachineProfile {
        machine,
        owner: host.owner.actor(),
        machine_key: request.machine_key,
        encryption_key: request.encryption_key.clone(),
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof: request.machine_proof,
    };
    let forge = |signer: &SigningKey| {
        let fold = host.vault.authority_fold().unwrap();
        let key = authority_key_from_ed(signer);
        let seq = fold.append_sequences.get(&key).map_or(0, |seq| seq + 1);
        sign_ed(
            unsigned_entry(
                fold.vault_id,
                seq,
                fold.append_heads.iter().copied().collect(),
                AuthorityOp::MachineProfile(profile.clone()),
                key,
                1,
            ),
            signer,
        )
    };

    // A generic Put of a signed-looking entry: the store or the fold refuses it.
    let stranger = forge(&ed_key(52));
    let bytes = encode_authority_log_entry_body(&stranger).unwrap();
    let _ = host.vault.put_entity(
        &authority_log_entity_id(&stranger).unwrap(),
        crate::registry::ENTITY_TYPE_AUTHORITY_LOG,
        at,
        1,
        &bytes,
    );
    assert!(!is_mine(&host.vault, machine));

    // The replay door admits well-shaped entries; the fold still refuses a
    // signer outside the roster, the machine's own key (a self-asserted
    // mark), and an engine writer's agent key.
    host.vault
        .put_authority_log_entries(&[(forge(&ed_key(53)), at, 1)])
        .unwrap();
    host.vault
        .put_authority_log_entries(&[(forge(&machine_key), at, 1)])
        .unwrap();
    let writer = EntityId::now();
    host.vault
        .put_entity(&writer, ENTITY_TYPE_MACHINE, at, 1, b"writer")
        .unwrap();
    let writer_key = ed_key(54);
    host.vault
        .enroll_machine_identity(
            &host.issuer,
            writer,
            writer_key.verifying_key().to_bytes(),
            [9; 32],
            |transcript| Ok(writer_key.sign(transcript).to_bytes()),
        )
        .unwrap();
    host.vault
        .put_authority_log_entries(&[(forge(&writer_key), at, 1)])
        .unwrap();
    assert!(!is_mine(&host.vault, machine));
    assert!(
        host.vault
            .authority_fold()
            .unwrap()
            .machine(machine)
            .is_none()
    );

    // Only the owner's door lands it.
    host.vault
        .enroll_machine(
            &host.issuer,
            &host.owner,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    assert!(is_mine(&host.vault, machine));
}

/// A checkpoint restored directly may land on any install, so it never takes
/// this machine's identity with it; a restore that keeps this vault's
/// authority, on this install, keeps it.
#[test]
fn a_restored_image_never_carries_the_machine_to_another_install() {
    let Host {
        _dir,
        vault,
        issuer,
        owner,
        vault_id,
    } = host();
    let request = vault
        .machine_enrolment_request(vault_id, encryption_key())
        .unwrap();
    vault
        .enroll_machine(
            &issuer,
            &owner,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
        )
        .unwrap();
    let local = |vault: &Vault| vault.local_machine().unwrap();
    assert!(
        local(&vault)
            .is_some_and(|machine| machine.profile.is_some_and(|profile| profile.is_mine()))
    );
    let backups = tempfile::tempdir().unwrap();
    let image = backups.path().join("image");
    vault.snapshot_checkpoint(&image, 100).unwrap();

    let (here, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("here"),
        VaultConfig::default(),
        &vault,
        200,
    )
    .unwrap();
    assert_eq!(
        local(&here).map(|machine| machine.id),
        Some(request.machine)
    );
    drop((here, vault));

    let (elsewhere, _) = Vault::restore_checkpoint(
        &image,
        &backups.path().join("elsewhere"),
        VaultConfig::default(),
        crate::recovery::checkpoint::RestoreReason::Restore,
        300,
    )
    .unwrap();
    assert_eq!(local(&elsewhere), None);
    // It joins as a new machine, never with this one's key.
    let joined = elsewhere
        .machine_enrolment_request(vault_id, encryption_key())
        .unwrap();
    assert_ne!(joined.machine, request.machine);
    assert_ne!(joined.machine_key, request.machine_key);
}

/// The pairing ceremony for `machine`: the owner answers "yours" on the link,
/// `pairing_key` redeems it with `request`, and the host binds the paired
/// machine's mesh address, which replaces the MACHINE body.
fn pair_and_bind(
    host: &Host,
    machine: EntityId,
    request: &MachineEnrolmentRequest,
    pairing_key: &SigningKey,
    transport: &SigningKey,
) -> MeshMachineAddress {
    let link = host
        .vault
        .issue_machine_pairing_link(
            &host.issuer,
            &host.owner,
            crate::federation::Scope::top(),
            3600,
            PairingPrincipal::default(),
            MachineOwnership::Yours,
        )
        .unwrap();
    let device_key = pairing_key.verifying_key().to_bytes();
    let pair_proof = pairing_key
        .sign(&pairing_binding_transcript(&link.code, &device_key, &machine.to_hex()).unwrap())
        .to_bytes();
    // A machine link enrols its machine, or nothing.
    assert!(
        host.vault
            .redeem_pairing_link(
                &host.issuer,
                &link.code,
                &machine.to_hex(),
                device_key,
                &pair_proof
            )
            .is_err()
    );
    let (pair, folded) = host
        .vault
        .redeem_machine_pairing_link(
            &host.issuer,
            &link.code,
            &machine.to_hex(),
            device_key,
            &pair_proof,
            request,
        )
        .unwrap();
    assert!(folded.is_mine());
    let address = MeshMachineAddress {
        endpoint_key: transport.verifying_key().to_bytes(),
        direct_addrs: vec![],
        relay_url: None,
    };
    let mut transcript = b"oneiron/mesh-machine-binding/v1\0".to_vec();
    transcript.extend_from_slice(machine.as_bytes());
    transcript.extend_from_slice(&address.endpoint_key);
    host.vault
        .bind_mesh_machine(
            &host.issuer,
            machine,
            address.clone(),
            device_key,
            pair.claims.slip_id,
            [
                &pairing_key.sign(&transcript).to_bytes(),
                &transport.sign(&transcript).to_bytes(),
            ],
        )
        .unwrap();
    host.vault
        .set_mesh_alpn_grant(
            &host.issuer,
            machine,
            address.endpoint_key,
            b"mesh/sync",
            true,
        )
        .unwrap();
    address
}

#[test]
fn a_mesh_address_bind_keeps_the_mark() {
    let host = host();
    let install_key = ed_key(61);
    let machine = EntityId::now();
    let request = request_for(host.vault_id, machine, &install_key);
    let address = pair_and_bind(&host, machine, &request, &install_key, &ed_key(62));
    // The bind replaced the MACHINE body; the mark lives in the authority log.
    assert!(is_mine(&host.vault, machine));
    assert_eq!(
        host.vault
            .mesh_peer_machine(address.endpoint_key, b"mesh/sync")
            .unwrap(),
        PeerMachine::Proven(machine)
    );
    // Only through a live grant.
    assert_eq!(
        host.vault
            .mesh_peer_machine(address.endpoint_key, b"mesh/other")
            .unwrap(),
        PeerMachine::Unknown
    );
    // An address rewrite through the public door keeps the mark too.
    let envelope =
        rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(address.clone())).unwrap();
    host.vault
        .put_entity(
            &machine,
            ENTITY_TYPE_MACHINE,
            TimeRange { start: 2, end: 2 },
            2,
            &envelope,
        )
        .unwrap();
    assert!(is_mine(&host.vault, machine));
    assert_eq!(
        host.vault
            .mesh_peer_machine(address.endpoint_key, b"mesh/sync")
            .unwrap(),
        PeerMachine::Proven(machine)
    );

    // A mesh pairing by any key other than the profile's install key never
    // borrows the machine's standing.
    let other = EntityId::now();
    let request = request_for(host.vault_id, other, &ed_key(63));
    let address = pair_and_bind(&host, other, &request, &ed_key(64), &ed_key(65));
    assert!(is_mine(&host.vault, other));
    assert_eq!(
        host.vault
            .mesh_peer_machine(address.endpoint_key, b"mesh/sync")
            .unwrap(),
        PeerMachine::Unknown
    );
}
