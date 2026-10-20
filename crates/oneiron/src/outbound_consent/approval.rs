//! FIX 6424 part 3 (2b, Engine 10-20 21:0x rulings 1, 7 and 8): an owner's
//! approve-once press on one scoped-MCP connector call, a payment or webhook
//! tool a connector exposes included, approves exactly that call as it was
//! prepared.
//!
//! The call's Gate input carries a typed [`ApprovalTarget::ScopedMcp`]: its
//! server, tool and resolved endpoint, its nonce (the call's attempt id and
//! call sequence, fixed before the call is prepared and kept on its held
//! row, so a resume of the same call names them again, while a call its
//! host names no invocation for starts a fresh attempt), and the digest of
//! the exact bytes its preparation froze. The digest a hold names is the
//! Gate's own composer over that input; [`scoped_mcp_approve_once_digest`]
//! composes it for a prepared call. It rides the call's held reply, its
//! status read and the owner's ask as `approval_digest`. A hold before any
//! preparation (no grant, key, approved manifest or pinned protocol), and a
//! code consent wait's own code-bound press, name none.
//!
//! A held call's row keeps the prepared request its approvable hold asked
//! about ([`HeldConnectorAsk`]: the digest, the frozen bytes' digest and the
//! endpoint; ids and digests, no bytes), from its first approvable hold
//! (CALLS `FIX 6424 pre-ask prepared snapshot retention`, MCP half). Each
//! retry prepares the call again and is gated on its own bytes: the same
//! request names the same digest and the kept one stands; a changed target
//! or body is a new ask, which the row keeps in its place. The code-wait
//! digest, the grant checks and every grant-backed path never read any of
//! it. A press the call's admission spent is kept beside its ledger row for
//! its retry (`outbound_intent_ledger::pinned_approval`).

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::gate::{ApprovalTarget, ExternalEffectGateInput, ScopedMcpCallFacts};

use super::connector_call::PendingConnectorCall;
use super::tool_call::PreparedToolCall;

/// The Gate input of one scoped call by `principal_ref` under `grant_id`,
/// pinned to `prepared` as attempt `attempt_id`, call `call_seq`: the
/// unpinned input the code-wait digest also composes over, with the call's
/// typed target beside it. The one place a scoped call's pinned input is
/// built, for its gate and for the public helper alike.
pub(super) fn scoped_mcp_pinned_gate_input(
    principal_ref: &str,
    grant_id: EntityId,
    prepared: &PreparedToolCall,
    attempt_id: AttemptId,
    call_seq: u64,
) -> ExternalEffectGateInput {
    let call = prepared.call();
    let mut gate = super::execution::scoped_mcp_gate_input(principal_ref, grant_id, call);
    gate.provenance.approval_target = Some(ApprovalTarget::ScopedMcp(ScopedMcpCallFacts {
        server: call.server.clone(),
        tool: call.tool.clone(),
        resolved_endpoint: call.resolved_endpoint.clone(),
        attempt_id: *attempt_id.as_bytes(),
        call_seq,
        payload_digest: frozen_digest(prepared),
    }));
    gate
}

/// BLAKE3 of the bytes `prepared` froze.
fn frozen_digest(prepared: &PreparedToolCall) -> [u8; 32] {
    *blake3::hash(prepared.frozen_bytes()).as_bytes()
}

/// FIX 6424 part 3: the approve-once digest (64 lower-hex) an owner's press
/// on one scoped connector call names, by the Gate's own composer over the
/// input that call's gate reads: the prepared call, its principal, the
/// standing grant it runs under (the actor when the principal is not an
/// entity id), and its attempt and call sequence (a served call's are
/// `connector_call_invocation`'s, at sequence 0). A held call's reply and
/// status carry the same digest as `approval_digest`.
#[must_use]
pub fn scoped_mcp_approve_once_digest(
    prepared: &PreparedToolCall,
    principal_ref: &str,
    grant_id: EntityId,
    attempt_id: AttemptId,
    call_seq: u64,
) -> Option<String> {
    ApprovalTarget::held_digest(&scoped_mcp_pinned_gate_input(
        principal_ref,
        grant_id,
        prepared,
        attempt_id,
        call_seq,
    ))
}

/// The prepared request one approvable hold of a connector call asked the
/// owner to press for: ids and digests only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeldConnectorAsk {
    /// The approve-once digest the hold named, 64 lower-hex.
    pub(super) approval_digest: String,
    /// BLAKE3 of the bytes the call's preparation froze, 64 lower-hex.
    pub(super) payload_digest: String,
    /// The endpoint the call was prepared for.
    pub(super) endpoint: String,
}

impl HeldConnectorAsk {
    /// The ask a Gate hold of `prepared` named, when that decision named an
    /// approve-once digest (`approval_digest`); `None` for any other result.
    pub(super) fn of(approval_digest: Option<String>, prepared: &PreparedToolCall) -> Option<Self> {
        Some(Self {
            approval_digest: approval_digest?,
            payload_digest: bytes_to_hex_lower(&frozen_digest(prepared)),
            endpoint: prepared.call().resolved_endpoint.clone(),
        })
    }
}

/// Keeps `ask`, this pass's approvable hold, on the held row `row`: the
/// first one saves it, the same request keeps it, and a changed target or
/// body is a new ask the row keeps in its place. A hold that names none (an
/// administrative one) leaves the kept ask, which still names the call's
/// prepared request.
pub(super) fn retain_held_ask(row: &mut PendingConnectorCall, ask: Option<&HeldConnectorAsk>) {
    let Some(ask) = ask else {
        return;
    };
    if row.held_ask.as_ref() == Some(ask) {
        return;
    }
    if row.held_ask.is_some() {
        tracing::info!(
            reason = "connector_call_new_ask",
            attempt = %bytes_to_hex_lower(row.attempt_id.as_bytes()),
            call_seq = row.call_seq,
            "a held connector call was prepared again with another target or body: its hold is \
             a new ask"
        );
    }
    row.held_ask = Some(ask.clone());
}
