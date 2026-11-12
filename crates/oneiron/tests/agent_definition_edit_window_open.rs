//! An owner's edit of an agent definition survives the next cold open of the
//! window that carries the row (FIX AGENT-DEF-DIAL-REVERTS-ON-RESTART, E2E
//! COORDINATION-08).
//!
//! The owner's versioned edit (`vault.agents.update`) wrote the row through a
//! raw apply that named no changed row to its write door. The row's window
//! kept the body it held before the edit, and no owed-mirror marker said the
//! window was behind. The window's next cold open (a server restart) then
//! landed the old body back over the edit, so the refusal dial read back as
//! it was before the edit.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test agent_definition_edit_window_open`.
#![cfg(all(feature = "sync", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentScope, RefusalDial, RefusalDomain, RefusalLevel,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::residence_window_for_blob;
use oneiron::sync::types::WindowKey;
use oneiron::{EntityId, Error, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use rmpv::Value as RmpValue;

/// 2026-03-15 00:00 UTC. The definition is learned then, so its row rides
/// the base window of March 2026.
const T0: u64 = 1_773_532_800;
/// The owner's edit, six seconds later, in the same window.
const T1: u64 = T0 + 6;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn dial(bond: RefusalLevel, logistics: RefusalLevel) -> RefusalDial {
    RefusalDial::new()
        .with(RefusalDomain::Bond, bond)
        .with(RefusalDomain::Logistics, logistics)
}

/// Version "1", as `vault.agents.create` stores it: a Base agent whose dial
/// is voice in both domains.
fn first_version() -> AgentDefinition {
    AgentDefinition::new(
        "dial_ends.agent",
        "dial ends fixture",
        "1",
        Some("Say what you object to.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
    .with_refusal(Some(dial(RefusalLevel::Voice, RefusalLevel::Voice)))
}

/// Version "2" of the stored `first`, as `vault.agents.update` builds it:
/// the owner moves the dial to its two ends, none and full.
fn second_version(first: &AgentDefinition) -> AgentDefinition {
    let mut edited = first.clone();
    edited.version = "2".to_owned();
    edited.refusal = Some(dial(RefusalLevel::None, RefusalLevel::Full));
    edited
}

/// Opens the vault at `dir` as the process that holds its writer lease, with
/// the embedded owner's proof.
fn open_as_owner(dir: &Path, keystore: &Arc<MemoryKeystore>) -> (Arc<Vault>, AuthenticatedOwner) {
    let vault = Vault::open_owned(dir, VaultConfig::device()).expect("owned vault");
    vault.install_device_keystore(Arc::<MemoryKeystore>::clone(keystore));
    vault.prepare_install_signing().expect("install signing");
    let person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (Arc::new(vault), owner)
}

/// The window the engine keeps `id`'s row in.
fn residence_window(vault: &Vault, id: &EntityId) -> WindowKey {
    let raw = vault
        .get_raw(id)
        .expect("read the row")
        .expect("the row is stored");
    residence_window_for_blob(&raw).expect("the row's window")
}

/// The owner creates version "1", and the row's window opens and takes its
/// body. Returns the agent's id, its stored version "1", the manager and the
/// window's key; the window stays loaded.
fn created_under_a_loaded_window(
    vault: &Arc<Vault>,
    owner: &AuthenticatedOwner,
) -> (EntityId, AgentDefinition, Arc<WindowManager>, WindowKey) {
    let id = EntityId::now();
    vault
        .create_agent_definition_as(owner, &id, &first_version(), at(T0), T0)
        .expect("the owner creates version 1");
    let first = vault
        .get_agent_definition(&id)
        .expect("read the definition")
        .expect("version 1 is stored");
    assert_eq!(first.version, "1");
    assert_eq!(
        first.refusal,
        Some(dial(RefusalLevel::Voice, RefusalLevel::Voice))
    );
    let key = residence_window(vault, &id);
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "owner",
    ));
    let window = manager.open_window(&key).expect("the window opens");
    assert!(
        window.doc.get_map("entities").get(&id.to_hex()).is_some(),
        "the definition's window carries its row"
    );
    drop(window);
    (id, first, manager, key)
}

/// The owner's versioned edit of `first` to version "2", read back before
/// any window opens again. Returns version "2".
fn edit_to_second_version(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    id: &EntityId,
    first: &AgentDefinition,
) -> AgentDefinition {
    let second = second_version(first);
    vault
        .update_agent_definition_at_version_as(owner, id, "1", &second, at(T1), T1)
        .expect("the owner edits version 1 to version 2");
    assert_eq!(
        vault.get_agent_definition(id).expect("read the definition"),
        Some(second.clone()),
        "the edit reads back before the window opens again"
    );
    second
}

#[test]
fn an_owner_edit_made_while_its_window_is_loaded_survives_the_windows_cold_open() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let keystore = Arc::new(MemoryKeystore::new());
    let (vault, owner) = open_as_owner(dir.path(), &keystore);
    let (id, first, manager, key) = created_under_a_loaded_window(&vault, &owner);

    let second = edit_to_second_version(&vault, &owner, &id, &first);
    assert!(manager.unload_window(&key).expect("the window unloads"));
    let _window = manager.open_window(&key).expect("the window opens cold");

    assert_eq!(
        vault
            .get_agent_definition(&id)
            .expect("read the definition"),
        Some(second),
        "the cold open keeps the owner's edit"
    );
}

#[test]
fn an_owner_edit_made_while_its_window_is_unloaded_survives_the_windows_cold_open() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let keystore = Arc::new(MemoryKeystore::new());
    let (vault, owner) = open_as_owner(dir.path(), &keystore);
    let (id, first, manager, key) = created_under_a_loaded_window(&vault, &owner);
    assert!(manager.unload_window(&key).expect("the window unloads"));

    let second = edit_to_second_version(&vault, &owner, &id, &first);
    let _window = manager.open_window(&key).expect("the window opens cold");

    assert_eq!(
        vault
            .get_agent_definition(&id)
            .expect("read the definition"),
        Some(second),
        "the cold open keeps the owner's edit"
    );
}

#[test]
fn an_owner_edit_survives_a_restart_and_keeps_its_revision_fence() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let keystore = Arc::new(MemoryKeystore::new());
    // A clean stop persists the loaded window; the block's end lets the
    // manager, the proof and the vault go.
    let (id, first, second, key) = {
        let (vault, owner) = open_as_owner(dir.path(), &keystore);
        let (id, first, manager, key) = created_under_a_loaded_window(&vault, &owner);
        let second = edit_to_second_version(&vault, &owner, &id, &first);
        assert!(manager.unload_window(&key).expect("the window unloads"));
        (id, first, second, key)
    };

    let (vault, owner) = open_as_owner(dir.path(), &keystore);
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "owner",
    ));
    let _window = manager
        .open_window(&key)
        .expect("the window opens cold after the restart");

    let stored = vault
        .get_agent_definition(&id)
        .expect("read the definition")
        .expect("the definition is stored");
    assert_eq!(stored.version, "2", "the restart keeps the owner's version");
    assert_eq!(
        stored.refusal,
        Some(dial(RefusalLevel::None, RefusalLevel::Full)),
        "the restart keeps the owner's dial"
    );
    assert_eq!(stored, second);

    // The revision fence still holds: an edit of version "1" is refused,
    // and the stored row stays at version "2".
    let mut stale = first;
    stale.version = "3".to_owned();
    let refused =
        vault.update_agent_definition_at_version_as(&owner, &id, "1", &stale, at(T1 + 6), T1 + 6);
    assert!(
        matches!(refused, Err(Error::ConcurrentWrite(_))),
        "an edit of a version the row has left is refused: {refused:?}"
    );
    assert_eq!(
        vault
            .get_agent_definition(&id)
            .expect("read the definition"),
        Some(second)
    );
}
