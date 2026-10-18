//! World privacy P6b acceptance on a hosted vault (contract §8, checks 6 and
//! 7): the host stores and relays every record and opens none. The owner's
//! kit alone brings a world's key back to a fresh install, and a host that
//! publishes a root of its own, first or last, never gets a machine counted
//! as the owner's or a wrap of a world key.
use super::machine_identity::{Host, request_for};
use super::owner_anchor::YOURS;
use super::support::ed_key;
use super::world_key_doors::{
    Fresh, fresh_install_with, key_records, kit_seed, opened_by, own_request,
};
use super::world_kit_gate::publish_root;
use super::world_privacy::{settings, world_row};
use super::world_reissue::sync;
use super::*;
use crate::store::GateDecisionId;
use crate::world_keys::{RecoveryRootSeed, machine_secret};
use crate::{Vault, VaultConfig};

const HERE: EditOrigin = EditOrigin::ThisMachine;

pub(super) fn hosted() -> VaultConfig {
    let mut config = VaultConfig::default();
    config.privacy = crate::config::VaultPrivacyConfig {
        posture: crate::HostingPrivacyPosture::Hosted,
        data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
            key_ref: "world-keys-hosted".into(),
        },
    };
    config
}

/// A hosted vault under the host's stamped root, with the owner bound.
pub(super) fn hosted_host() -> Host {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), hosted()).unwrap();
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

/// `seed`'s anchor marks `request`'s machine "yours" on the host's vault.
pub(super) fn anchor_on(host: &Host, seed: &RecoveryRootSeed, request: &MachineEnrolmentRequest) {
    let fold = host.vault.authority_fold().unwrap();
    let mark = AuthorityOp::MachineProfile(MachineProfile {
        machine: request.machine,
        owner: host.owner.actor(),
        machine_key: request.machine_key,
        encryption_key: request.encryption_key.clone(),
        role: YOURS,
        revision: 1,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
    });
    let entry = anchor_signed_entry(&fold, &seed.anchor(), mark, 2).unwrap();
    host.vault
        .put_authority_log_entry(&entry, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
}

/// The host's stamped root answers "yours" for a machine: refused.
fn host_root_marks_refused(host: &Host, seed: u8) -> bool {
    let request = request_for(host.vault_id, EntityId::now(), &ed_key(seed));
    host.vault
        .enroll_machine(&host.issuer, &host.owner, &request, YOURS)
        .is_err()
        && host
            .vault
            .authority_fold()
            .unwrap()
            .machine(request.machine)
            .is_none_or(|folded| !folded.admits(&MachineAdmitter::Roster))
}

/// Check 6: on a hosted vault the owner's machine, marked by the kit's
/// anchor, mints a world's key and is then lost. On a fresh install with an
/// empty keystore the kit alone restores: it anchors the install's own
/// request, opens the key and wraps it to the new machine, which opens it
/// after a reopen; an explicit own-request anchoring does the same. The
/// host's own node secret opens no wrap and is never a recipient, and the
/// host's stamped root answers "yours" for no machine, before the root and
/// after.
#[test]
fn a_hosted_vaults_kit_restores_and_the_hosts_material_opens_nothing() {
    let host = hosted_host();
    assert!(host_root_marks_refused(&host, 221));
    let world = world_row(&host);
    let (root, seed, id, first_machine) = {
        let first = fresh_install_with(&host, hosted());
        let prepared = first.vault.prepare_owner_root(&first.owner).unwrap();
        let root = prepared.seed().public(&host.vault_id).unwrap().id;
        let seed = kit_seed(host.vault_id, prepared.seed());
        first
            .vault
            .activate_owner_root(&first.owner, HERE, prepared, &BTreeSet::new())
            .unwrap();
        first
            .vault
            .set_world_privacy_as(
                &first.owner,
                ActSurface::ThisInstall,
                world,
                settings(ReadLocation::MyMachines),
                None,
            )
            .unwrap();
        let id = *first.vault.world_key(world).unwrap().id();
        sync(&first.vault, &host.vault);
        (root, seed, id, first.machine())
    };
    assert!(host_root_marks_refused(&host, 222));

    let restored = fresh_install_with(&host, hosted());
    let restore = restored
        .vault
        .restore_world_keys(&restored.owner, HERE, &seed, None)
        .unwrap();
    assert_eq!(restore.usable, vec![id]);
    assert!(restore.withheld.is_empty() && restore.needs_rehome.is_empty());
    let restored = restored.reopen();
    assert_eq!(restored.vault.world_key(world).unwrap().id(), &id);

    let anchored = fresh_install_with(&host, hosted());
    let request = own_request(&anchored.vault);
    let report = anchored
        .vault
        .anchor_machine(&anchored.owner, HERE, &seed, &request, None, None)
        .unwrap()
        .repin
        .unwrap();
    assert_eq!(report.rewrapped, vec![id]);
    let anchored = anchored.reopen();
    assert_eq!(anchored.vault.world_key(world).unwrap().id(), &id);

    // The host's own node, with its secret in the host's keystore.
    let keys = std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new());
    host.vault.install_device_keystore(
        keys.clone() as std::sync::Arc<dyn oneiron_keystore::DeviceKeystore>
    );
    host.vault.provision_host_node(&host.issuer).unwrap();
    let node = host.vault.local_machine().unwrap().unwrap().id;
    let node_secret = machine_secret(keys.as_ref(), host.vault_id, *node.as_bytes()).unwrap();
    sync(&restored.vault, &host.vault);
    sync(&anchored.vault, &host.vault);
    for opener in [
        WrapRecipient::Machine(node),
        WrapRecipient::Machine(first_machine),
        WrapRecipient::Machine(restored.machine()),
        WrapRecipient::Machine(anchored.machine()),
        WrapRecipient::RecoveryRoot(root),
    ] {
        assert!(opened_by(&host.vault, host.vault_id, id, opener, &node_secret).is_empty());
    }
    assert!(key_records(&host.vault, world).iter().all(|record| {
        record
            .wraps
            .iter()
            .all(|(to, _)| *to != WrapRecipient::Machine(node))
    }));
    assert!(host_root_marks_refused(&host, 223));
}

/// One install's view of the machines check 7 names.
fn trusted(install: &Fresh, machine: EntityId) -> bool {
    install
        .vault
        .authority_fold()
        .unwrap()
        .trusted_machine(machine)
        .is_some()
}

/// Check 7 (R1): on a hosted vault the host publishes a root of its own,
/// before the owner's kit or after it, anchors a machine of its own, and
/// anchors the owner's new machine from the enrolment request that passed
/// through it. On the owner's issuing install none of the host's anchorings
/// counts, the owner's activation pins the owner's root, and the host's root
/// shows as foreign. Once the owner approves the new machine from the code
/// it shows, a world's key is wrapped only to the owner's root and to the
/// machines the owner's anchor admitted. A fresh install pinned by the
/// owner's fingerprint agrees, and an unpinned install counts no anchor
/// admission at all.
#[test]
fn a_dishonest_host_never_wins_the_root() {
    for host_first in [true, false] {
        let host = hosted_host();
        let world = world_row(&host);
        let owner = fresh_install_with(&host, hosted());
        let new = fresh_install_with(&host, hosted());
        let new_request = own_request(&new.vault);
        let host_seed = RecoveryRootSeed::generate().unwrap();
        let host_machine = request_for(host.vault_id, EntityId::now(), &ed_key(225));
        let host_moves = |host: &Host| {
            let root = publish_root(host, &host_seed);
            anchor_on(host, &host_seed, &host_machine);
            anchor_on(host, &host_seed, &new_request);
            root
        };
        let early = host_first.then(|| host_moves(&host));
        sync(&host.vault, &owner.vault);
        let prepared = owner.vault.prepare_owner_root(&owner.owner).unwrap();
        let ours = prepared.seed().public(&host.vault_id).unwrap().id;
        let seed = kit_seed(host.vault_id, prepared.seed());
        owner
            .vault
            .activate_owner_root(&owner.owner, HERE, prepared, &BTreeSet::new())
            .unwrap();
        sync(&owner.vault, &host.vault);
        let theirs = early.unwrap_or_else(|| host_moves(&host));
        sync(&host.vault, &owner.vault);

        let view = owner.vault.owner_root_view(None, 16).unwrap();
        assert_eq!(view.pinned, Some(ours), "{host_first}");
        assert!(view.foreign.contains_key(&theirs), "{host_first}");
        for machine in [host_machine.machine, new_request.machine] {
            assert!(!trusted(&owner, machine), "{host_first}");
        }
        owner
            .vault
            .anchor_machine(
                &owner.owner,
                HERE,
                &seed,
                &new_request,
                Some(new_request.code()),
                None,
            )
            .unwrap();
        assert!(trusted(&owner, new_request.machine));
        assert!(!trusted(&owner, host_machine.machine));
        owner
            .vault
            .set_world_privacy_as(
                &owner.owner,
                ActSurface::ThisInstall,
                world,
                settings(ReadLocation::MyMachines),
                None,
            )
            .unwrap();
        owner.vault.ensure_world_key(&owner.owner, world).unwrap();
        let allowed = BTreeSet::from([
            WrapRecipient::RecoveryRoot(ours),
            WrapRecipient::Machine(owner.machine()),
            WrapRecipient::Machine(new_request.machine),
        ]);
        let wrapped: BTreeSet<_> = key_records(&owner.vault, world)
            .into_iter()
            .flat_map(|record| record.wraps.into_iter().map(|(to, _)| to))
            .collect();
        assert_eq!(wrapped, allowed, "{host_first}");

        sync(&owner.vault, &host.vault);
        let pinned = fresh_install_with(&host, hosted());
        pinned
            .vault
            .pin_owner_root(&pinned.owner, HERE, ours)
            .unwrap();
        assert!(trusted(&pinned, owner.machine()));
        assert!(trusted(&pinned, new_request.machine));
        assert!(!trusted(&pinned, host_machine.machine));
        let unpinned = fresh_install_with(&host, hosted());
        for machine in [owner.machine(), new_request.machine, host_machine.machine] {
            assert!(!trusted(&unpinned, machine), "{host_first}");
        }
    }
}
