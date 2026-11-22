//! `vault.agent_health.calls` refuses the list when a call receipt did not
//! read (FIX-LIST l23274): the receipts it skipped may be the agent's, so
//! answering the rest would read as complete. With every receipt readable
//! the verb answers the agent's receipts, oldest first.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test agent_health_calls_drops_unread`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::memory::{MEMORY_CODE_INTERNAL, MemoryResult};
use oneiron::receipt::{CallOutcome, CallReceiptInput, CallTransport};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::call_receipt_damage::put_undecodable_call_receipt;
use oneiron::test_doors::coach::define_agent;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

/// The one byte MessagePack never uses: a row of it decodes as nothing.
const UNDECODABLE: &[u8] = &[0xc1; 8];

fn open_owned(dir: &tempfile::TempDir) -> Vault {
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("an owned vault");
    oneiron::test_support::provision_engine_machines(&vault);
    vault
}

fn record_agent_call(vault: &Vault, agent: EntityId) {
    vault
        .record_call_receipt(CallReceiptInput {
            transport: CallTransport::HttpFacade,
            verb: "vault.agent_health.calls".to_owned(),
            actor_ref: agent.to_hex(),
            actor_class: "agent".to_owned(),
            credential_ref: None,
            carrier_machine: None,
            outcome: CallOutcome::Ok,
            request_digest: "0".repeat(64),
            result_digest: None,
            inputs: None,
            attempt: None,
            served: Vec::new(),
        })
        .expect("a call receipt");
}

fn calls(vault: &Vault, owner: EntityId, agent: EntityId) -> MemoryResult<Value> {
    invoke(
        &vault.memory(owner, EdgeActorClass::Human),
        "vault.agent_health.calls",
        json!({ "agent_ref": agent.to_hex(), "since": 0 }),
    )
}

#[test]
fn an_unread_call_receipt_refuses_the_agents_list() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owned(&dir);
    let agent = define_agent(&vault).expect("an agent");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    record_agent_call(&vault, agent);
    put_undecodable_call_receipt(&vault, &EntityId::now(), UNDECODABLE).expect("a damaged row");

    let error = calls(&vault, owner, agent).expect_err("an unread receipt refuses the list");
    assert_eq!(error.code, MEMORY_CODE_INTERNAL, "{error:?}");
}

#[test]
fn readable_receipts_answer_oldest_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owned(&dir);
    let agent = define_agent(&vault).expect("an agent");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    record_agent_call(&vault, agent);

    let list = calls(&vault, owner, agent).expect("readable receipts answer");
    let list = list.as_array().expect("the answer is a list");
    assert_eq!(list.len(), 1, "{list:?}");
}
