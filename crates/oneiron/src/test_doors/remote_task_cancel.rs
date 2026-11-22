//! Doors for oneiron-server's `tests/remote_task_cancel.rs` (L8-29): a
//! connector send its connector took as a remote task, Deferred with the
//! task's handle as a `tools/call` answered with a task leaves it; the
//! send's ledger state; and the owner's Stop writer's step for the sends of
//! a try. Compiled only under `--cfg oneiron_test_support`; never API.

use serde_json::json;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::connector_key::ScopedCapabilityProvenance;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::outbound_consent::tool_call::{MutationIntent, ToolCallDescriptor, prepare_tool_call};
use crate::outbound_consent::{DataClass, ScopedMcpCallContext};
use crate::outbound_intent_ledger::{
    BudgetChargeMarker, BudgetClass, IntentLedgerRecord, IntentState, OutboundAuthorizationBinding,
    OutboundCallRequest, OutboundToolDescriptor, RemoteTaskHandle, RemoteTaskPoll, defer_record,
    force_sync, insert_pending_in_txn, read_intent_record_in_txn,
};

/// The grant id the fixture send's capability provenance names.
pub const FIXTURE_GRANT: [u8; 16] = [0x29; 16];

/// The fixture send's authorization binding.
const FIXTURE_BINDING: [u8; 32] = [0x29; 32];

/// What the remote task send is: its try, the connector and tool it called
/// at the endpoint its grant admitted, the task id the connector answered,
/// and how the host polls the task (`None`: its credential cannot be
/// presented again).
pub struct DeferredConnectorSend<'a> {
    pub attempt: AttemptId,
    pub server: &'a str,
    pub tool: &'a str,
    pub endpoint: &'a str,
    pub task_id: &'a str,
    pub poll: Option<RemoteTaskPoll>,
    pub now_ms: u64,
}

/// Writes `send` as a Pending connector send (a scoped MCP `tools/call`
/// with no arguments, frozen as the preparation door freezes one) and moves
/// it to Deferred with its task's handle, as the connector's task answer
/// does: a polled task gets its first poll. The send's intent id.
///
/// An endpoint-bound send carries the capability provenance and the
/// authorization binding its scoped admission minted (the ledger refuses
/// one without them). Here they name a grant [`FIXTURE_GRANT`] the vault
/// does not hold, so the poll's grant check refuses its `tasks/get`, while
/// the owner's stop, which goes out whether or not the grant still admits
/// the send, is sent.
///
/// # Errors
/// A call that does not freeze; ledger and storage faults.
pub fn defer_connector_send(vault: &Vault, send: DeferredConnectorSend<'_>) -> Result<[u8; 32]> {
    let grant = EntityId::from_bytes(FIXTURE_GRANT)?;
    let capability = ScopedCapabilityProvenance::mint(send.server, &grant).ok_or_else(|| {
        crate::Error::InvalidConfig("the fixture's server is no canonical scoped server".into())
    })?;
    let schema = json!({ "type": "object" });
    let prepared = prepare_tool_call(
        ScopedMcpCallContext {
            server: send.server.to_owned(),
            tool: send.tool.to_owned(),
            payload_data_class: DataClass::Personal,
            resolved_endpoint: send.endpoint.to_owned(),
        },
        ToolCallDescriptor {
            schema: &schema,
            destructive_hint: false,
            replay: OutboundToolDescriptor {
                read_only_hint: None,
                idempotency_supported_hint: None,
            },
        },
        &json!({}),
        MutationIntent::Preview,
    )?;
    let request = OutboundCallRequest::new(
        send.attempt,
        0,
        send.server,
        send.tool,
        prepared.frozen_bytes().to_vec(),
        send.now_ms,
    )
    .with_authorization_binding(OutboundAuthorizationBinding::new(FIXTURE_BINDING))
    .with_resolved_endpoint(send.endpoint)
    .with_capability_provenance(capability);
    let marker = BudgetChargeMarker {
        key_ref: None,
        budget_class: BudgetClass::Operation,
        matched_rows: Vec::new(),
        sends_debit: 0,
        accounted_at_ms: send.now_ms,
    };
    let record = IntentLedgerRecord::pending(request, false, marker).map_err(ledger_error)?;
    let mut wtxn = vault.store.env.write_txn()?;
    insert_pending_in_txn(vault, &mut wtxn, &record).map_err(ledger_error)?;
    wtxn.commit()?;
    force_sync(vault).map_err(ledger_error)?;
    defer_record(
        vault,
        record.id,
        RemoteTaskHandle {
            id: send.task_id.to_owned(),
            poll_after_secs: None,
            poll: send.poll,
        },
        send.now_ms,
    )
    .map_err(ledger_error)?;
    Ok(record.id)
}

/// Row `intent`'s ledger state; `None` when no row has that id.
///
/// # Errors
/// Ledger and storage faults.
pub fn intent_state(vault: &Vault, intent: &[u8; 32]) -> Result<Option<IntentState>> {
    let txn = vault.store.env.read_txn()?;
    Ok(read_intent_record_in_txn(vault, &txn, intent)
        .map_err(ledger_error)?
        .map(|record| record.state))
}

/// The owner's Stop writer's step for `attempt`'s sends (a held program's
/// release, or a parked try's stop), in a writer of its own at `now_secs`.
///
/// # Errors
/// Storage faults.
pub fn stop_try_sends(vault: &Vault, attempt: AttemptId, now_secs: u64) -> Result<()> {
    crate::dreamer_runner::stop_sends_in_own_writer(vault, attempt, now_secs)
}

/// A ledger fault as the engine's error.
fn ledger_error(error: crate::outbound_intent_ledger::IntentLedgerError) -> crate::Error {
    match error {
        crate::outbound_intent_ledger::IntentLedgerError::Engine(error) => error,
        other => crate::Error::InvalidConfig(other.to_string()),
    }
}
