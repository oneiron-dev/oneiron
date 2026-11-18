//! MACHINE-NAMES-CARRIER = B (Engine RULING Mon 16 Nov 03:13; FIX [DEVICE-DISPLAY-NAME]): the
//! owner's name for a machine and the name a machine reports for itself reach every machine of
//! his through the residence home. On each steady pass a machine sends the home the cells it
//! wrote (`residence.machine_names.exchange`) and takes every cell the home holds; of two cells
//! for one machine and kind the later `(written_at, writer)` wins, and a clear is a dated cell
//! without a name. Only a machine of the owner's its socket proved is served.
//!
//! Three nodes of one vault: the home, a phone and a laptop, each its own install enrolled as the
//! owner's (`carried_pin_awaits_owner.rs`'s fixture). A pass runs the two halves the RPC joins:
//! the machine's (a door) and the home's (`machine_names_residence_exchange`, which the server
//! arm calls with the socket's `PeerMachine`).
//!
//! Red at the base (`opus-fix-sync/machine-reported-name-hosts`): the test does not build, as no
//! exchange exists there (no door, no residence function).
//!
//! Run: RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features \
//!   --test machine_names_exchange
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole, PeerMachine};
use oneiron::consent::AuthenticatedOwner;
use oneiron::machine_names::{MachineListing, MachineNameCell, MachineNameSource};
use oneiron::store::GateDecisionId;
use oneiron::sync::residence::machine_names_residence_exchange;
use oneiron::test_doors::machine_names::{cells_to_send, take_answer};
use oneiron::test_support::bind_host_owner;
use oneiron::{EntityId, Vault, VaultConfig};

/// A fresh owner proof minted on `vault`'s own handle.
fn proof(vault: &Vault) -> AuthenticatedOwner {
    let person = vault
        .ensure_embedded_owner_actor()
        .expect("the owner on this node");
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// A device config whose host reports `name` for the machine.
fn reporting(name: &str) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.machine_reported_name = Some(name.to_owned());
    config
}

/// The vault's home: a hosted node, rooted, carrying the owner's acts.
struct Home {
    _dir: tempfile::TempDir,
    vault: Vault,
    _issuer: HostSlipIssuer,
    vault_id: [u8; 32],
}

fn home() -> Home {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), reporting("Basement server")).expect("the home's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("the hosted node's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let vault_id = vault
        .authority_fold()
        .expect("the home's fold")
        .vault_id
        .expect("a rooted vault");
    Home {
        _dir: dir,
        vault,
        _issuer: issuer,
        vault_id,
    }
}

impl Home {
    /// The home's own MACHINE row.
    fn machine(&self) -> EntityId {
        self.vault
            .machine_list(&proof(&self.vault))
            .expect("the home's list")
            .into_iter()
            .find(|listing| listing.this_install)
            .expect("the home serves its machine")
            .machine
    }
}

/// One of the owner's machines: its own install, enrolled as his, taking the vault's authority
/// history from the home as sync does.
struct Node {
    _dir: tempfile::TempDir,
    vault: Vault,
    machine: EntityId,
    key: [u8; 32],
    held: BTreeSet<Vec<u8>>,
}

fn node(home: &Home, reported: &str) -> Node {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), reporting(reported)).expect("the node's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(home.vault_id)
        .expect("the node's encryption key");
    let request = vault
        .machine_enrolment_request(home.vault_id, key)
        .expect("the node's enrolment request");
    home.vault
        .enroll_machine(
            &proof(&home.vault),
            ActSurface::HostedConsole,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the node as his");
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the node");
    let mut node = Node {
        _dir: dir,
        vault,
        machine: request.machine,
        key: request.machine_key,
        held: BTreeSet::new(),
    };
    node.take(home);
    node
}

impl Node {
    /// Imports the rows of the home's history this node does not hold yet.
    fn take(&mut self, home: &Home) {
        let new: Vec<Vec<u8>> = home
            .vault
            .export_signed_authority_history()
            .expect("the home's history")
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new)
            .expect("the node takes the rows");
        self.held.extend(new);
    }

    /// This node as its socket proves it to the home.
    fn proven(&self) -> PeerMachine {
        PeerMachine::Proven {
            machine: self.machine,
            key: self.key,
        }
    }

    /// One steady pass's exchange with the home.
    fn pass(&self, home: &Home) {
        let cells = cells_to_send(&self.vault)
            .expect("the node's cells")
            .expect("the node serves its machine");
        let answer = machine_names_residence_exchange(&home.vault, self.proven(), cells)
            .expect("the home answers a machine of the owner's");
        take_answer(&self.vault, answer).expect("the node takes the home's cells");
    }
}

/// The home and two of the owner's machines, each folding all three.
fn vault_of_three() -> (Home, Node, Node) {
    let home = home();
    let mut phone = node(&home, "Pixel 9");
    let laptop = node(&home, "ThinkPad X1");
    phone.take(&home);
    let fold = home.vault.authority_fold().expect("the home's fold");
    for (machine, key) in [(phone.machine, phone.key), (laptop.machine, laptop.key)] {
        assert!(
            fold.trusted_machine(machine).is_some(),
            "the fixture: the home trusts each node as the owner's"
        );
        assert_eq!(
            fold.machine_proof_key(machine),
            Some(key),
            "the fixture: each node proves its enrolment key at the home"
        );
    }
    (home, phone, laptop)
}

/// `machine` as `vault`'s list shows it.
fn shown(vault: &Vault, machine: EntityId) -> MachineListing {
    vault
        .machine_list(&proof(vault))
        .expect("the machine list")
        .into_iter()
        .find(|listing| listing.machine == machine)
        .expect("the machine is listed")
}

#[test]
fn a_rename_made_on_the_phone_reaches_the_home_and_the_laptop() {
    let (home, phone, laptop) = vault_of_three();
    phone
        .vault
        .set_machine_owner_name(&proof(&phone.vault), phone.machine, Some("Maya's phone"))
        .expect("the owner renames the phone on the phone");

    phone.pass(&home);
    let at_home = shown(&home.vault, phone.machine);
    assert_eq!(
        (at_home.name.as_str(), at_home.name_source),
        ("Maya's phone", MachineNameSource::Owner),
        "the home shows the name the owner gave on the phone"
    );
    assert_eq!(
        at_home.reported_name.as_deref(),
        Some("Pixel 9"),
        "the phone's own report reaches the home"
    );

    laptop.pass(&home);
    let at_laptop = shown(&laptop.vault, phone.machine);
    assert_eq!(
        (at_laptop.name.as_str(), at_laptop.name_source),
        ("Maya's phone", MachineNameSource::Owner),
        "the laptop shows the name the owner gave on the phone"
    );
    assert_eq!(at_laptop.reported_name.as_deref(), Some("Pixel 9"));
    assert_eq!(
        shown(&laptop.vault, home.machine())
            .reported_name
            .as_deref(),
        Some("Basement server"),
        "the home's own report reaches the laptop"
    );
}

#[test]
fn a_clear_made_on_the_laptop_after_the_phones_rename_wins_everywhere() {
    let (home, phone, laptop) = vault_of_three();
    phone
        .vault
        .set_machine_owner_name(&proof(&phone.vault), laptop.machine, Some("Work laptop"))
        .expect("the owner names the laptop on the phone");
    phone.pass(&home);
    laptop.pass(&home);
    assert_eq!(
        shown(&laptop.vault, laptop.machine).owner_name.as_deref(),
        Some("Work laptop"),
        "the laptop takes the phone's name for it"
    );

    laptop
        .vault
        .set_machine_owner_name(&proof(&laptop.vault), laptop.machine, None)
        .expect("the owner clears the laptop's name on the laptop");
    laptop.pass(&home);
    phone.pass(&home);
    for (place, vault) in [("home", &home.vault), ("phone", &phone.vault)] {
        let listing = shown(vault, laptop.machine);
        assert_eq!(listing.owner_name, None, "the clear reaches the {place}");
        assert_eq!(
            (listing.name.as_str(), listing.name_source),
            ("ThinkPad X1", MachineNameSource::Reported),
            "the {place} shows the laptop by its own report again"
        );
    }
}

#[test]
fn an_unproved_peer_is_refused_and_changes_nothing() {
    let (home, phone, _laptop) = vault_of_three();
    phone
        .vault
        .set_machine_owner_name(&proof(&phone.vault), phone.machine, Some("Maya's phone"))
        .expect("the owner renames the phone on the phone");
    let cells = cells_to_send(&phone.vault)
        .expect("the phone's cells")
        .expect("the phone serves its machine");

    assert!(
        machine_names_residence_exchange(&home.vault, PeerMachine::Unknown, cells.clone()).is_err(),
        "a socket that proved no machine is refused"
    );
    let unknown_key = PeerMachine::Proven {
        machine: phone.machine,
        key: [0x5a; 32],
    };
    assert!(
        machine_names_residence_exchange(&home.vault, unknown_key, cells).is_err(),
        "a key the home's fold does not name for the phone is refused"
    );
    let at_home = shown(&home.vault, phone.machine);
    assert_eq!(at_home.owner_name, None, "the home kept no cell");
    assert_eq!(at_home.reported_name, None, "the home kept no report");
}

#[test]
fn a_machine_cannot_write_another_machines_report_or_cell() {
    let (home, phone, laptop) = vault_of_three();
    let later = u64::MAX / 2;
    let forged = vec![
        MachineNameCell::Reported {
            machine: phone.machine,
            name: Some("Forged report".to_owned()),
            model: None,
            written_at: later,
        },
        MachineNameCell::Owner {
            machine: home.machine(),
            name: Some("Forged name".to_owned()),
            written_at: later,
            writer: phone.machine,
            receipt: "00".repeat(16),
        },
    ];
    machine_names_residence_exchange(&home.vault, laptop.proven(), forged)
        .expect("the home answers a machine of the owner's");
    assert_eq!(
        shown(&home.vault, phone.machine).reported_name,
        None,
        "only the phone reports for the phone"
    );
    assert_eq!(
        shown(&home.vault, home.machine()).owner_name,
        None,
        "only the cell's writer sends it"
    );
}
