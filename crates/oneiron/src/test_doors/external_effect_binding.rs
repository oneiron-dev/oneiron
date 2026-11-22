//! Doors for `tests/effect_binding_names_call.rs` (FIX
//! [GATE-EFFECT-BINDING-NO-CALL-IDENTITY]): the Gate binds a held scoped-MCP
//! call's decision to that one call, as its pinned target names it, so two
//! held calls of one tool that differ only in their attempt, call sequence
//! or arguments hold two pending receipts, each its own.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{
    ApprovalTarget, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor,
    GateProvenanceHandles, ScopedMcpCallFacts, check_external_effect_policy,
    resolve_policy_manifest,
};
use crate::outbound_consent::{DataClass, ScopedMcpCallContext};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::GateDecisionId;

/// What the Gate recorded for a run of held calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldCallBindings {
    /// The outcome of every record, in order. The vault holds no policy
    /// manifest, so the Gate holds every external effect: each is
    /// `"pending"`.
    pub outcomes: Vec<String>,
    /// The first call, recorded again (its retry), answers with its own
    /// pending row.
    pub retry_reuses_its_row: bool,
    /// The next call of the same attempt holds a pending row of its own.
    pub other_sequence_own_row: bool,
    /// The same call sequence of another attempt holds a pending row of its
    /// own.
    pub other_attempt_own_row: bool,
    /// The same call with other arguments (another frozen payload digest)
    /// holds a pending row of its own.
    pub other_arguments_own_row: bool,
    /// Two effects with no scoped call, one of them carrying another
    /// family's pinned target, share one pending row: only a scoped call's
    /// identity joins the binding.
    pub unscoped_target_shares_row: bool,
    /// Pending external-effect rows the ledger holds afterwards.
    pub pending_rows: usize,
}

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture entity id")
}

fn call() -> ScopedMcpCallContext {
    ScopedMcpCallContext {
        server: "files".to_owned(),
        tool: "read_file".to_owned(),
        payload_data_class: DataClass::Personal,
        resolved_endpoint: "https://files.internal.example".to_owned(),
    }
}

/// An effect of the principal's, shaped as the scoped-MCP chokepoint shapes
/// one (`outbound_consent::execution::scoped_mcp_gate_input`), carrying
/// `scoped` as its scoped call and `target` as its pinned target.
fn effect(
    scoped: Option<ScopedMcpCallContext>,
    target: Option<ApprovalTarget>,
) -> ExternalEffectGateInput {
    let principal = id(0x41);
    ExternalEffectGateInput {
        actor: GateActor {
            actor_class: "first_party".to_owned(),
            actor_ref: Some(principal.to_hex()),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(principal),
            approval_target: target,
            ..GateProvenanceHandles::default()
        },
        verb: "send".to_owned(),
        channel: "mcp:files".to_owned(),
        channel_identity_ref: None,
        counterparty: None,
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: scoped,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: false,
        has_permission: false,
        policy_risk: ExternalEffectPolicyRisk::Normal,
        send_autonomy: None,
    }
}

/// A scoped call pinned as attempt `attempt`, call `call_seq`, over the
/// frozen bytes whose digest is `payload`.
fn pinned_call(attempt: u8, call_seq: u64, payload: u8) -> ExternalEffectGateInput {
    let call = call();
    let target = ApprovalTarget::ScopedMcp(ScopedMcpCallFacts {
        server: call.server.clone(),
        tool: call.tool.clone(),
        resolved_endpoint: call.resolved_endpoint.clone(),
        attempt_id: [attempt; 16],
        call_seq,
        payload_digest: [payload; 32],
    });
    effect(Some(call), Some(target))
}

/// Removes every policy manifest, so the policy resolves fail-closed and the
/// Gate holds every external effect on its missing authority.
fn clear_policy_manifests(vault: &Vault) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        let mut ids = Vec::new();
        for row in vault
            .store
            .type_index
            .prefix_iter(wtxn, &[ENTITY_TYPE_POLICY_MANIFEST])?
        {
            let (key, _) = row?;
            let id = EntityId::from_bytes(
                key[1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("type index key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("type index key"))?;
            ids.push(id);
        }
        for id in ids {
            crate::batch::deindex_entity_for_test(vault, wtxn, &id)?;
        }
        Ok(())
    })
}

/// Records, in one writer, a scoped call (attempt 1, call 0, payload 1), its
/// retry, the attempt's next call, the same call of another attempt, the
/// same call with other arguments, and two effects with no scoped call (one
/// with no pinned target, one with another family's), and reads which of
/// them the Gate answered with a row of its own.
pub fn record_held_calls(vault: &Vault) -> Result<HeldCallBindings> {
    clear_policy_manifests(vault)?;
    let policy = {
        let rtxn = vault.store.env.read_txn()?;
        resolve_policy_manifest(&vault.store, &rtxn)?
    };
    if !policy.is_fail_closed() {
        return Err(Error::InvariantViolation(
            "the fixture vault still resolves a policy manifest",
        ));
    }
    let communication = ApprovalTarget::Communication {
        sender: Some(id(0x42)),
        target: "+15550100".to_owned(),
        recipients: Vec::new(),
        thread_ref: Some("thread-1".to_owned()),
        content_ref: Some("blob:message-1".to_owned()),
        send_ref: "send-1".to_owned(),
    };
    let effects = [
        pinned_call(1, 0, 1),
        pinned_call(1, 0, 1),
        pinned_call(1, 1, 1),
        pinned_call(2, 0, 1),
        pinned_call(1, 0, 2),
        effect(None, None),
        effect(None, Some(communication)),
    ];
    vault.with_write_txn(|wtxn| {
        let mut outcomes = Vec::new();
        let mut ids: Vec<GateDecisionId> = Vec::new();
        for effect in &effects {
            let (decision_id, decision, _charge) =
                check_external_effect_policy(&vault.store, wtxn, effect, &policy, true)?;
            outcomes.push(decision.outcome().as_str().to_owned());
            ids.push(decision_id);
        }
        let mut pending_rows = 0;
        vault
            .store
            .for_each_gate_decision_in_txn(&*wtxn, |record| {
                if record.content_kind == "external_effect" && record.outcome == "pending" {
                    pending_rows += 1;
                }
                Ok(())
            })?;
        Ok(HeldCallBindings {
            outcomes,
            retry_reuses_its_row: ids[1] == ids[0],
            other_sequence_own_row: ids[2] != ids[0],
            other_attempt_own_row: ids[3] != ids[0] && ids[3] != ids[2],
            other_arguments_own_row: ids[4] != ids[0] && ids[4] != ids[2] && ids[4] != ids[3],
            unscoped_target_shares_row: ids[6] == ids[5],
            pending_rows,
        })
    })
}
