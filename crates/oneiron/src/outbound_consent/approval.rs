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
//! A held call's row keeps the prepared request its approvable holds asked
//! about ([`ConnectorCallApproval`], each a [`HeldConnectorAsk`]: the
//! digest, the frozen bytes' digest and the endpoint's digest; digests only,
//! no bytes, no address) (CALLS `FIX 6424 pre-ask prepared snapshot
//! retention`, MCP half): the CURRENT ask, the one its last pass held as
//! approvable, which its status and its owner question name (an
//! administrative or uncertain-only hold clears it), and the last approvable
//! one any pass named. Each retry prepares the call again and is gated on
//! its own bytes, rebuilt live: the same request names the same digest; a
//! changed target or body is a new ask, and a question already put is put
//! again, at the next version, naming it. That metadata reads tolerantly: a
//! value that does not decode reads as absent (today's path, no digest),
//! while the request itself decodes as strictly as before. The code-wait
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
/// owner to press for: digests only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeldConnectorAsk {
    /// The approve-once digest the hold named, 64 lower-hex.
    pub(super) approval_digest: String,
    /// BLAKE3 of the bytes the call's preparation froze, 64 lower-hex.
    pub(super) payload_digest: String,
    /// BLAKE3 of the endpoint the call was prepared for, 64 lower-hex.
    pub(super) endpoint_digest: String,
}

impl HeldConnectorAsk {
    /// The ask a Gate hold of `prepared` named, when that decision named an
    /// approve-once digest (`approval_digest`); `None` for any other result.
    pub(super) fn of(approval_digest: Option<String>, prepared: &PreparedToolCall) -> Option<Self> {
        Some(Self {
            approval_digest: approval_digest?,
            payload_digest: bytes_to_hex_lower(&frozen_digest(prepared)),
            endpoint_digest: bytes_to_hex_lower(
                blake3::hash(prepared.call().resolved_endpoint.as_bytes()).as_bytes(),
            ),
        })
    }
}

/// The approvable asks a held call's passes named: see the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConnectorCallApproval {
    /// The ask the call's last pass held as approvable: what its status and
    /// its owner question name. `None` once a pass held it otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) current: Option<HeldConnectorAsk>,
    /// The last approvable ask any pass named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last: Option<HeldConnectorAsk>,
    /// How many distinct approvable asks the call made: its owner
    /// question's version counts up with it.
    #[serde(default)]
    pub(super) revision: u32,
}

impl ConnectorCallApproval {
    /// The approve-once digest the call's current ask names, if any.
    pub(super) fn current_digest(approval: Option<&Self>) -> Option<&str> {
        approval?
            .current
            .as_ref()
            .map(|ask| ask.approval_digest.as_str())
    }
}

/// A held call's approval metadata as stored, or a value that does not
/// decode, which reads as absent.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredApproval {
    Read(ConnectorCallApproval),
    Unread(serde::de::IgnoredAny),
}

/// Reads a held call's approval metadata tolerantly: a value that does not
/// decode reads as absent, so the call keeps today's path and names no
/// digest. The request around it decodes as strictly as before.
pub(super) fn tolerant_approval<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ConnectorCallApproval>, D::Error> {
    Ok(match Option::<StoredApproval>::deserialize(deserializer)? {
        Some(StoredApproval::Read(approval)) => Some(approval),
        Some(StoredApproval::Unread(_unread)) | None => None,
    })
}

/// Keeps `ask`, this pass's hold's approvable ask (`None` for an
/// administrative or uncertain-only hold, which clears the current one), as
/// the held row `row`'s current ask. A new approvable ask (the first, or a
/// changed target or body) after the owner's question was put has it put
/// again, naming this one.
pub(super) fn retain_held_ask(row: &mut PendingConnectorCall, ask: Option<&HeldConnectorAsk>) {
    let Some(ask) = ask else {
        if let Some(approval) = row.approval.as_mut() {
            approval.current = None;
        }
        return;
    };
    let approval = row.approval.get_or_insert_default();
    approval.current = Some(ask.clone());
    if approval.last.as_ref() == Some(ask) {
        return;
    }
    if approval.last.is_some() {
        tracing::info!(
            reason = "connector_call_new_ask",
            attempt = %bytes_to_hex_lower(row.attempt_id.as_bytes()),
            call_seq = row.call_seq,
            "a held connector call was prepared again with another target or body: its hold is \
             a new ask"
        );
    }
    approval.last = Some(ask.clone());
    approval.revision = approval.revision.saturating_add(1);
    // The question already put names another ask, or none: put it again. A
    // code consent wait asks its own.
    if row.code_consent_wait.is_none() {
        row.owner_ask_seq = None;
    }
}
