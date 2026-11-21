//! Fable design pass 31, step L-S4 (section 1.5, write 3): a row's open entries ride the owner's
//! full window with the row, and a holder adds each one that first arrives to the row's open set,
//! so a row that waits on the machine that wrote it waits here too, and an input erased here
//! seals it (oracle case 50). Case 37: a link to a dependency source this vault erased seals its
//! row, whichever of the link and the erase comes first.
//!
//! * `a_row_its_sender_waited_on_is_sealed_where_the_input_was_erased_first` (case 50): the hub
//!   holds `row`, carried by its window, written from `input` by a DerivedFrom edge; `input` is a
//!   row the hub holds and the window does not carry, and it waits on a row not here yet, so
//!   `row` waits on it. The hub's owner erases `input`, which seals `row` there. The device
//!   replays `input`'s tombstone first, then takes the hub's update through the admission door:
//!   `row` reads to no one there, the owner included.
//! * `a_row_its_sender_waited_on_waits_here_until_the_inputs_tombstone_seals_it` (case 50, the
//!   other order): the device takes the update first. `row` waits there (a stranger does not read
//!   it), and the replayed tombstone then seals it.
//! * `a_dependent_of_a_waiting_source_is_sealed_by_the_sources_erase` and
//!   `a_dependency_on_a_source_erased_here_seals_its_dependent` (case 37): the dependency put
//!   judges the link it writes; a dependency on a waiting source waits until the source's erase
//!   seals it, and one written after that erase is sealed at once.
//!
//! The two case-50 tests run red at the stack top 506d5eadafc, whose hub writes no open carrier:
//! the device reads `row` to a stranger. The case-37 tests pin what the base already does
//! (L-S1's judge in the dependency put).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test read_lineage_travel`.

#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]

#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

use oneiron::deletion::TombstoneReason;
use oneiron::memory::SafeDeleteReason;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, WindowExport};
use oneiron::test_doors::claim_refinement_erase::apply_replayed_tombstone;
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::test_doors::read_lineage_floor::{
    floor_sealed, floor_waits, register_dependency_source,
};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, Vault,
};

use crate::sync_harness::{T0, TestNode, WINDOW};

/// A CLAIM about `owner` under `predicate`, stated by `owner`, whose birth names `inputs` as its
/// evidence, written in `vault` at [`T0`].
fn claim_born_from(
    vault: &Vault,
    owner: EntityId,
    inputs: &[EntityId],
    predicate: &str,
) -> EntityId {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(owner),
        rmpv::Value::from("learnt"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: an open CLAIM body");
    body.source = Some(ClaimSource::UserStated);
    let made_by = MadeBy {
        inputs: inputs
            .iter()
            .map(|row| MadeByInput {
                row: *row,
                role: MadeByInputRole::Input,
            })
            .collect(),
        process: MadeByProcess {
            actor: owner,
            class: MadeByClass::Stated,
            identity: "read_lineage_travel.fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "0".repeat(64),
        },
        at: T0,
        trigger: None,
    };
    let id = EntityId::now();
    put_claim_made_by(vault, id, &body, made_by).expect("FIXTURE: the CLAIM and its birth");
    id
}

/// The owner of `vault` deletes `row`.
fn erase(vault: &Vault, owner: EntityId, row: EntityId) {
    vault
        .memory(owner, EdgeActorClass::Human)
        .safe_delete(&row.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner deletes the row");
}

/// The embedded owner of `vault`, with a machine id minted, so its carriers name their machine.
fn owner_with_machine_id(vault: &Vault) -> EntityId {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    vault
        .local_session_key(owner)
        .expect("FIXTURE: mint the machine id");
    owner
}

/// A hub whose `row` waited on `input` when the hub's owner erased `input`, and a device that
/// holds nothing of the window yet.
struct Travel {
    hub: TestNode,
    device: TestNode,
    device_owner: EntityId,
    row: EntityId,
    input: EntityId,
}

fn sender_waited_then_erased() -> Travel {
    let mut hub = TestNode::new("hub", 2);
    let owner = owner_with_machine_id(&hub.vault);
    hub.open_window(WINDOW);
    let mut device = TestNode::new("device", 1);
    let device_owner = owner_with_machine_id(&device.vault);
    device.open_window(WINDOW);
    // A mailbox row bound to a policy, so the hub's writes judge their links.
    bound_row_read_by(&hub.vault, EntityId::now(), &[owner])
        .expect("FIXTURE: a bound mailbox row on the hub");
    let input = claim_born_from(&hub.vault, owner, &[EntityId::now()], "profile.input");
    let row = claim_born_from(&hub.vault, owner, &[], "profile.row");
    hub.vault
        .put_edge(&row, EdgeKind::DerivedFrom, &input, 1.0)
        .expect("FIXTURE: the row names its input");
    let raw = hub
        .vault
        .get_raw(&row)
        .expect("FIXTURE: read the hub's row")
        .expect("FIXTURE: the hub holds the row");
    hub.put_entity_in_window(WINDOW, &row, &raw);
    assert!(
        floor_waits(&hub.vault, row).expect("the hub's floor state"),
        "FIXTURE: the row waits on its input at the hub",
    );
    erase(&hub.vault, owner, input);
    assert!(
        floor_sealed(&hub.vault, row).expect("the hub's floor state"),
        "FIXTURE: the input's erase seals the row at the hub",
    );
    Travel {
        hub,
        device,
        device_owner,
        row,
        input,
    }
}

/// The hub's export door answers the device's version, and the device takes the answer through
/// the window admission door before it lands it, as a sync connection's next round does.
fn deliver(hub: &TestNode, device: &mut TestNode) {
    let key = WindowKey::new(WINDOW);
    let device_vv = device.doc(WINDOW).oplog_vv().encode();
    match window::export_window_updates_since(&hub.vault, &key, hub.doc(WINDOW), &device_vv)
        .expect("the hub's export door answers")
    {
        WindowExport::Update(update) => {
            window::validate_window_update_residence_with_vault(
                &device.vault,
                device.doc(WINDOW),
                &update,
                &key,
            )
            .expect("the device admits the hub's update");
            device
                .doc(WINDOW)
                .import(&update)
                .expect("the device lands the hub's update");
        }
        WindowExport::Replacement(snapshot) => {
            device.install_replacement(&snapshot);
        }
    }
}

/// Whether `node`'s window carries an open carrier of `row`, from any machine.
fn carries_open_entries(node: &TestNode, row: &EntityId) -> bool {
    let prefix = format!("open/{}/", row.to_hex());
    let mut carried = false;
    node.doc(WINDOW)
        .get_map("source_audiences")
        .for_each(|map_key, _| carried |= map_key.starts_with(&prefix));
    carried
}

/// `row` reads to no one on `node`, its owner included.
fn assert_sealed(node: &TestNode, owner: EntityId, row: EntityId, when: &str) {
    assert!(
        !reads(&node.vault, row, &[EntityId::now()]).expect("a stranger's read"),
        "a stranger reads a row whose sender waited on an input erased here ({when})",
    );
    assert!(
        !reads(&node.vault, row, &[owner]).expect("the owner's read"),
        "the owner reads a row whose sender waited on an input erased here ({when})",
    );
    assert!(
        floor_sealed(&node.vault, row).expect("the floor's state"),
        "the row is not sealed ({when})",
    );
}

#[test]
fn a_row_its_sender_waited_on_is_sealed_where_the_input_was_erased_first() {
    let Travel {
        hub,
        mut device,
        device_owner,
        row,
        input,
    } = sender_waited_then_erased();
    apply_replayed_tombstone(&device.vault, &input, TombstoneReason::UserDelete, T0)
        .expect("the hub's tombstone of the input replays on the device");
    deliver(&hub, &mut device);
    assert!(
        carries_open_entries(&hub, &row),
        "the hub's window carries no open entry of a row that waits on an input",
    );
    assert!(
        device
            .vault
            .get_raw(&row)
            .expect("the device's read")
            .is_some(),
        "FIXTURE: the device lands the row",
    );
    assert_sealed(&device, device_owner, row, "the tombstone came first");
}

#[test]
fn a_row_its_sender_waited_on_waits_here_until_the_inputs_tombstone_seals_it() {
    let Travel {
        hub,
        mut device,
        device_owner,
        row,
        input,
    } = sender_waited_then_erased();
    deliver(&hub, &mut device);
    assert!(
        carries_open_entries(&hub, &row),
        "the hub's window carries no open entry of a row that waits on an input",
    );
    assert!(
        device
            .vault
            .get_raw(&row)
            .expect("the device's read")
            .is_some(),
        "FIXTURE: the device lands the row",
    );
    assert!(
        !reads(&device.vault, row, &[EntityId::now()]).expect("a stranger's read"),
        "a stranger reads a row whose sender waits on an input not here",
    );
    assert!(
        floor_waits(&device.vault, row).expect("the floor's state"),
        "the row does not wait on the input its sender waits on",
    );
    apply_replayed_tombstone(&device.vault, &input, TombstoneReason::UserDelete, T0)
        .expect("the hub's tombstone of the input replays on the device");
    assert_sealed(&device, device_owner, row, "the row came first");
}

/// A vault with a mailbox row bound to a policy its owner reads, so its writes judge their
/// links, and that vault's owner.
fn judging_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
    let vault =
        Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("FIXTURE: open the vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    bound_row_read_by(&vault, EntityId::now(), &[owner]).expect("FIXTURE: the owner's mailbox");
    (dir, vault, owner)
}

#[test]
fn a_dependent_of_a_waiting_source_is_sealed_by_the_sources_erase() {
    let (_dir, vault, owner) = judging_vault();
    let source = claim_born_from(&vault, owner, &[EntityId::now()], "profile.source");
    let dependent = claim_born_from(&vault, owner, &[], "profile.dependent");
    register_dependency_source(&vault, dependent, source)
        .expect("the dependency put names the source");
    assert!(
        floor_waits(&vault, dependent).expect("the floor's state"),
        "precondition: a dependent of a waiting source waits",
    );
    erase(&vault, owner, source);
    assert!(
        !reads(&vault, dependent, &[owner]).expect("the owner's read"),
        "the owner reads a dependent whose waiting source was erased",
    );
    assert!(
        floor_sealed(&vault, dependent).expect("the floor's state"),
        "a dependent whose waiting source was erased is not sealed",
    );
}

#[test]
fn a_dependency_on_a_source_erased_here_seals_its_dependent() {
    let (_dir, vault, owner) = judging_vault();
    let source = claim_born_from(&vault, owner, &[EntityId::now()], "profile.source");
    let dependent = claim_born_from(&vault, owner, &[], "profile.dependent");
    erase(&vault, owner, source);
    register_dependency_source(&vault, dependent, source)
        .expect("the dependency put names the erased source");
    assert!(
        !reads(&vault, dependent, &[owner]).expect("the owner's read"),
        "the owner reads a dependent written from a source erased here",
    );
    assert!(
        floor_sealed(&vault, dependent).expect("the floor's state"),
        "a dependent written from a source erased here is not sealed",
    );
}
