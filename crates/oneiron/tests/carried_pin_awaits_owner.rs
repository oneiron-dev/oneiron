//! CARRIED-PIN (HOSTED-CARRIER-FIRST-PIN = D, the lead 14 Nov 22:3x; Engine
//! RULING 22:29): a pin request another install carries never moves this
//! install's pin, and never sets a first one. A root request names its
//! target install, and the target's owner-work pickup ran a `Pin` on the
//! carrier's word: the request carries one signature, the carrier's install
//! key, and the owner it names is the carrier's claim. Every live machine
//! profile of the vault carries owner acts, a hosted node among them. So the
//! vault's host could mint a recovery root of its own and pin an owner's
//! device that had never pinned one to it, and the device then trusted that
//! root's chain.
//!
//! Now the pickup records the requested root as the root this install
//! awaits, the request's own wait (FIX 5582), and the request stays pending.
//! The owner confirms it on the device, at the pin door (`pin_owner_root`),
//! with his own proof there. No request carries a signature from a key the
//! device already trusts as the owner's, so every carried pin waits; a pin
//! request for the root already pinned changes nothing and runs as before.
//!
//! Red on main:
//! `a_hosts_pin_request_leaves_a_never_pinned_device_unpinned_and_awaiting`
//! (the device's pickup pins it to the host's root). Guard, which passes on
//! main too: `the_owner_confirms_the_awaited_root_at_the_devices_pin_door`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test carried_pin_awaits_owner`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActSurface, AwaitedRoot, HostSlipIssuer, MachineOwnership, MachineRole, OwnerRootView,
    RecoveryRootId, RootChange,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::OwnerWorkDrain;
use oneiron::{EntityId, Vault, VaultConfig};

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// The vault's host: a hosted node, rooted, whose install carries the
/// owner's acts, as every live machine profile of the vault does.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    _issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    vault_id: [u8; 32],
}

fn host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("the hosted node's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let owner = proof(&vault, person);
    let vault_id = vault
        .authority_fold()
        .expect("the host's fold")
        .vault_id
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        _issuer: issuer,
        owner,
        vault_id,
    }
}

impl Host {
    /// A recovery root the host mints with a seed of its own, on its own
    /// install: its record, its anchor's mark of the host's machine, and the
    /// host's own pin.
    fn mint_own_root(&self) -> RecoveryRootId {
        let prepared = self
            .vault
            .prepare_owner_root(&self.owner)
            .expect("the host prepares a root");
        self.vault
            .activate_owner_root(&self.owner, prepared, &BTreeSet::new())
            .expect("the host activates its root")
            .root
    }

    /// Records a pin of `root` on `target`, carried by the host's install
    /// as the hosted console's act.
    fn request_pin(&self, target: EntityId, root: RecoveryRootId) {
        let receipt = self
            .vault
            .request_root_change(
                &self.owner,
                ActSurface::HostedConsole,
                target,
                RootChange::Pin { root },
            )
            .expect("the host records the pin request");
        assert!(
            receipt.request.is_some(),
            "the pin request is recorded for the device: {receipt:?}"
        );
    }
}

/// The owner's device: its own install, enrolled as his, never pinned. It
/// takes the vault's authority history from the host, as sync does.
struct Device {
    _dir: tempfile::TempDir,
    vault: Vault,
    machine: EntityId,
    held: BTreeSet<Vec<u8>>,
}

fn device(host: &Host) -> Device {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(host.vault_id)
        .expect("the device's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, key)
        .expect("the device's enrolment request");
    host.vault
        .enroll_machine(
            &host.owner,
            ActSurface::HostedConsole,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the device as his");
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the device");
    let mut device = Device {
        _dir: dir,
        vault,
        machine: request.machine,
        held: BTreeSet::new(),
    };
    device.take(host);
    device
}

impl Device {
    /// Imports the rows of the host's history this device does not hold yet.
    fn take(&mut self, host: &Host) {
        let new: Vec<Vec<u8>> = host
            .vault
            .export_signed_authority_history()
            .expect("the host's history")
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new)
            .expect("the device takes the rows");
        self.held.extend(new);
    }

    fn owner(&self) -> AuthenticatedOwner {
        let person = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("the owner on the device");
        proof(&self.vault, person)
    }

    fn pending_pins(&self) -> usize {
        self.vault
            .pending_root_requests(&self.owner())
            .expect("the device's pending root requests")
            .iter()
            .filter(|(_, change, _)| matches!(change, RootChange::Pin { .. }))
            .count()
    }

    /// Two syncs and pickups: the first may only commit the wait for a root
    /// whose record the device does not store yet, which lets the next sync
    /// store it.
    fn sync_and_pick_up(&mut self, host: &Host) -> Vec<OwnerWorkDrain> {
        let mut drains = Vec::new();
        for _ in 0..2 {
            self.take(host);
            drains.push(
                self.vault
                    .run_pending_owner_work(|| true)
                    .expect("the device's pickup"),
            );
        }
        self.take(host);
        drains
    }

    fn roots(&self) -> OwnerRootView {
        self.vault
            .owner_root_view(None, 16)
            .expect("the device's roots")
    }
}

/// A device that never pinned a root, a pin request the vault's host carries
/// for its own new root: the device's pickup records the root as awaited and
/// the request stays pending. The device keeps no pin.
#[test]
fn a_hosts_pin_request_leaves_a_never_pinned_device_unpinned_and_awaiting() {
    let host = host();
    let mut device = device(&host);
    assert_eq!(
        device.roots().pinned,
        None,
        "the device never pinned a root"
    );

    let root = host.mint_own_root();
    host.request_pin(device.machine, root);
    device.take(&host);
    assert_eq!(
        device.pending_pins(),
        1,
        "the device counts the host's pin request as one naming it"
    );

    let drains = device.sync_and_pick_up(&host);
    let roots = device.roots();
    assert_eq!(
        roots.pinned, None,
        "a carried pin request sets no first pin on the device (drains {drains:?})"
    );
    assert_eq!(
        roots.awaiting.map(|awaited| awaited.root),
        Some(root),
        "the device awaits the requested root for the owner to confirm (drains {drains:?})"
    );
    assert_eq!(
        device.pending_pins(),
        1,
        "the request stays pending until the owner confirms it on the device"
    );
}

/// The owner confirms the awaited root at the device's own pin door, with his
/// proof there: the device pins it. On main the pickup had pinned it already,
/// and the door pins it again.
#[test]
fn the_owner_confirms_the_awaited_root_at_the_devices_pin_door() {
    let host = host();
    let mut device = device(&host);
    let root = host.mint_own_root();
    host.request_pin(device.machine, root);
    device.sync_and_pick_up(&host);

    let owner = device.owner();
    device
        .vault
        .pin_owner_root(&owner, root)
        .expect("the owner confirms the root on the device");
    let roots = device.roots();
    assert_eq!(
        roots.pinned,
        Some(root),
        "the owner's confirm pins the root"
    );
    assert!(
        roots
            .awaiting
            .is_none_or(|AwaitedRoot { root: awaited, .. }| awaited == root),
        "no other root waits: {roots:?}"
    );
}
