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
use oneiron::habit::TaskRole;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::ImportTier;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::sync::types::WindowKey;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, filtered_window_doc, filtered_window_doc_for_peer,
};
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{
    EntityId, Result, TASK_AUTHORITY_FACT_SCHEMA_VERSION, TASK_AUTHORITY_FACT_SUBKIND,
    TaskAuthorityFactKind, TimeRange, Vault, VaultConfig,
};
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

/// An ordinary TASK row (role 1).
fn task_body() -> Vec<u8> {
    encode(&Value::Map(vec![(
        Value::from("role"),
        Value::from(TaskRole::Task.role_byte()),
    )]))
}

/// One strict-v1 authority fact body about `task_ref`.
fn authority_fact_body(
    task_ref: EntityId,
    kind: TaskAuthorityFactKind,
    actor: EntityId,
) -> Vec<u8> {
    encode(&Value::Map(vec![
        (
            Value::from("role"),
            Value::from(TaskRole::AuthorityFact.role_byte()),
        ),
        (
            Value::from("schema_version"),
            Value::from(TASK_AUTHORITY_FACT_SCHEMA_VERSION),
        ),
        (
            Value::from("subkind"),
            Value::from(TASK_AUTHORITY_FACT_SUBKIND),
        ),
        (Value::from("task_ref"), Value::from(task_ref.to_hex())),
        (Value::from("kind"), Value::from(kind.as_byte())),
        (Value::from("actor_ref"), Value::from(actor.to_hex())),
        (Value::from("occurred_at"), Value::from(T0)),
    ]))
}

/// Lands one TASK row as this vault's own machine wrote it: the own-device
/// replay door admits role 6 like any other TASK row.
fn land_own_task_row(vault: &Vault, id: EntityId, body: &[u8]) -> Result<()> {
    replay_entity(
        vault,
        ReplicatedEntity {
            id,
            entity_type: ENTITY_TYPE_TASK,
            occurred: TimeRange { start: T0, end: T0 },
            learned_at: T0,
            row_version: 0,
            body,
        },
        ImportTier::OwnDevice,
    )
}

fn has_entity(doc: &LoroDoc, id: EntityId) -> bool {
    matches!(
        doc.get_map("entities").get(&id.to_hex()),
        Some(ValueOrContainer::Value(_))
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    selector: SyncSelector,
    task: EntityId,
    fact: EntityId,
}

/// A shared vault with a member grant, one TASK and its Owner fact.
fn fixture() -> Result<Fixture> {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default())?);
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
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
    let task = EntityId::now();
    let fact = EntityId::now();
    land_own_task_row(&vault, task, &task_body())?;
    land_own_task_row(
        &vault,
        fact,
        &authority_fact_body(task, TaskAuthorityFactKind::Owner, owner_id),
    )?;
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "owen",
    ));
    Ok(Fixture {
        _dir: dir,
        _issuer: issuer,
        vault,
        manager,
        selector,
        task,
        fact,
    })
}

#[test]
fn a_member_window_withholds_task_authority_facts() -> Result<()> {
    let fixture = fixture()?;
    let key = WindowKey::new(WINDOW);
    let window = fixture.manager.open_window(&key)?;
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
