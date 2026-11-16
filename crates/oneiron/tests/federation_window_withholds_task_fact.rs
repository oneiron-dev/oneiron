//! A window bound for another vault withholds every TASK authority fact and
//! still carries the TASK it is about (FIX TASK-FACT-FROM-FEDERATION-PEER;
//! Fable pass 28, Appendix B).
//!
//! Another vault's admission refuses a peer's role-6 row, as the peer's
//! bytes, and fails the whole frame: a fact carries no proof of who made it
//! until it carries its carrier's signature (pass 28 R5). So the export keeps
//! every fact home, and a member's window with a TASK in it carries no row
//! that fails the frame there. The owner's own machines still receive the
//! fact.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test federation_window_withholds_task_fact`.
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::sync::Arc;

use loro::{LoroDoc, ValueOrContainer};
use oneiron::authority::{HostSlipIssuer, PeerMachine};
use oneiron::federation::{FederationGrantRole, FederationGrantScope};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, filtered_window_doc, filtered_window_doc_for_peer,
};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Result, TimeRange, Vault, VaultConfig};
use rmpv::Value;

/// March 2026, the window every row here is written in.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const T0: u64 = 1_773_532_800;
/// The shared vault the member grant is for.
const SHARED: u64 = 42;

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("encode fixture");
    bytes
}

fn has_entity(doc: &LoroDoc, id: EntityId) -> bool {
    matches!(
        doc.get_map("entities").get(&id.to_hex()),
        Some(ValueOrContainer::Value(_))
    )
}

/// The TASK rows scoped to `task`: the authority facts about it.
fn authority_facts(vault: &Vault, task: EntityId) -> Result<Vec<EntityId>> {
    let tasks = vault.entities_by_type(ENTITY_TYPE_TASK)?;
    Ok(vault
        .edges_in(&task)?
        .iter()
        .filter(|edge| edge.kind == EdgeKind::ScopedTo && tasks.contains(&edge.target))
        .map(|edge| edge.target)
        .collect())
}

struct Fixture {
    _issuer: HostSlipIssuer,
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    selector: SyncSelector,
    task: EntityId,
    fact: EntityId,
    // Last, so every vault handle closes before its directory goes.
    _dir: tempfile::TempDir,
}

/// A shared vault with a member grant, one TASK and its Owner fact. Both rows
/// come from the task door, as a real TASK does: a row landed by replay takes
/// no birth stamp, and a selector export withholds an unstamped row that is
/// not a CLAIM, so a replayed TASK would cross no window at all.
fn fixture() -> Result<Fixture> {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Arc::new(Vault::open_owned(dir.path(), VaultConfig::default())?);
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let task = vault
        .memory(owner_id, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            Value::from("review the shared roadmap"),
            None,
            Some(owner_id),
            Some(T0),
        ))
        .expect("the task door")
        .task_ref
        .expect("the TASK creation took effect");
    let facts = authority_facts(&vault, task)?;
    assert_eq!(
        facts.len(),
        1,
        "the task door writes exactly the Owner fact beside the TASK"
    );
    let fact = facts[0];
    for (name, row) in [("TASK", task), ("Owner fact", fact)] {
        assert!(
            vault.record_scope(&row)?.is_some(),
            "the {name} carries a birth stamp, which a selector export needs"
        );
    }
    let owner =
        vault.authenticate_owner(owner_id, "owen@example.com", true, GateDecisionId::now())?;
    let issuer = HostSlipIssuer::from_secret(b"task-fact-member-window")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.initialize_shared_vault(&owner, SHARED, None, &[], 1)?;
    let member = EntityId::now();
    let member_body = encode(&Value::Map(vec![(
        Value::from("name"),
        Value::from("yuki"),
    )]));
    vault
        .batch()
        .put(
            &member,
            ENTITY_TYPE_PERSON,
            TimeRange { start: T0, end: T0 },
            T0,
            &member_body,
        )
        .commit()?;
    let grant = stand_member_grant(&vault, member, SHARED, FederationGrantRole::Member)?;
    let selector = SyncSelector::new(grant, member, SyncSelectorWorld::Base, vec![], vec![]);
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "owen",
    ));
    Ok(Fixture {
        _issuer: issuer,
        vault,
        manager,
        selector,
        task,
        fact,
        _dir: dir,
    })
}

#[test]
fn a_member_window_withholds_task_authority_facts() -> Result<()> {
    let fixture = fixture()?;
    let key = WindowKey::new(WINDOW);
    let window = fixture.manager.open_window(&key)?;
    // The fact is in the window the export filters, so its absence below is
    // the export's doing, not a gap in the window itself.
    assert!(
        has_entity(&window.doc, fixture.fact),
        "the Owner fact is in the unfiltered window"
    );
    let doc = filtered_window_doc_for_peer(
        &fixture.vault,
        &window.doc,
        &key,
        FederationGrantScope::vault(SHARED),
        &fixture.selector,
        PeerMachine::Unknown,
    )?;
    assert!(
        has_entity(&doc, fixture.task),
        "the TASK still crosses to the member"
    );
    assert!(
        !has_entity(&doc, fixture.fact),
        "the TASK's Owner fact stays home"
    );
    Ok(())
}

#[test]
fn an_own_machine_window_keeps_task_authority_facts() -> Result<()> {
    let fixture = fixture()?;
    let key = WindowKey::new(WINDOW);
    let window = fixture.manager.open_window(&key)?;
    // The public wrapper selects OwnMachines.
    let doc = filtered_window_doc(
        &fixture.vault,
        &window.doc,
        &key,
        FederationGrantScope::vault(SHARED),
        &fixture.selector,
    )?;
    assert!(has_entity(&doc, fixture.task), "the TASK crosses");
    assert!(
        has_entity(&doc, fixture.fact),
        "the owner's own machine receives the TASK's Owner fact"
    );
    Ok(())
}
