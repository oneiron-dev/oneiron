//! The ordinary frozen dispatch held by its owner's connector tool setting.

use crate::Vault;
use crate::consent::{AuthenticatedOwner, ConsentReceipt, EffectDigest};
use crate::entity_id::EntityId;
use crate::gate::ExternalEffectGateInput;
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason,
    HumanDecisionRequest, ProviderPin,
};

use crate::outbound_intent_ledger::{
    AdmittedApproval, IntentId, IntentLedgerError, IntentLedgerRecord, IntentState,
    PinnedApprovalFamily, admitting_actor_in_txn, hash_frozen_payload, pinned_retry_approval,
    read_intent_record_in_txn,
};

pub(super) struct OrdinaryCandidate {
    pub(super) gate: ExternalEffectGateInput,
    pub(super) digest: EffectDigest,
    pub(super) actor: Option<EntityId>,
    pub(super) family: PinnedApprovalFamily,
}

/// Only the common adapter's positively reconstructed ordinary targets enter
/// this path. A raw payload or another family's request keeps its old path.
pub(super) fn candidate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &IntentLedgerRecord,
) -> Result<Option<OrdinaryCandidate>, IntentLedgerError> {
    if record.state != IntentState::Pending
        || record.capability_provenance().is_some()
        || record.resolved_endpoint.is_some()
        || record.authorization_binding.is_some()
        || hash_frozen_payload(record.payload()) != record.payload_hash
    {
        return Ok(None);
    }
    let Some(gate) = crate::outbound::connector_slate_effect_from_frozen_payload(
        record.payload(),
        &record.server,
        &record.tool,
    ) else {
        return Ok(None);
    };
    let Some(family) = gate
        .provenance
        .approval_target
        .as_ref()
        .and_then(|target| target.pinned_family())
    else {
        return Ok(None);
    };
    let actor = admitting_actor_in_txn(vault, txn, &record.id)?;
    if actor != gate.provenance.actor_entity_ref {
        return Ok(None);
    }
    let Some(digest) = crate::gate::external_effect_approval_digest(&gate) else {
        return Ok(None);
    };
    Ok(Some(OrdinaryCandidate {
        gate,
        digest,
        actor,
        family,
    }))
}

/// A kept ordinary press is a retry proof only for this ledger row's actual
/// frozen request and actor, and the same target the live Gate recomposes.
pub(super) fn retry_approval_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &IntentLedgerRecord,
    effect: &ExternalEffectGateInput,
) -> Result<Option<AdmittedApproval>, IntentLedgerError> {
    let Some(candidate) = candidate_in_txn(vault, txn, record)? else {
        return Ok(None);
    };
    if candidate.actor != effect.provenance.actor_entity_ref
        || candidate.gate.actor.actor_class != effect.actor.actor_class
        || candidate.gate.actor.actor_ref != effect.actor.actor_ref
        || candidate.gate.actor.delegation_grant_ref != effect.actor.delegation_grant_ref
        || crate::gate::external_effect_approval_digest(effect) != Some(candidate.digest)
    {
        return Ok(None);
    }
    Ok(
        pinned_retry_approval(vault, txn, record.id, effect).filter(|proof| {
            proof.intent_id() == record.id && proof.effect_digest() == candidate.digest
        }),
    )
}

impl Vault {
    /// Approves exactly the ordinary Pending dispatch named by `intent_id` and
    /// its current frozen `approval_digest`. The authenticated owner's press
    /// mints no standing grant, sends nothing and charges nothing. The next
    /// pass still meets its current Gate, key, charters and delivery checks.
    ///
    /// # Errors
    /// Owner revalidation, a stopped or unsupported intent, a changed current
    /// ask or tool setting, an already spent press, or storage errors.
    pub fn approve_outbound_intent_once(
        &self,
        owner: &AuthenticatedOwner,
        intent_id: &IntentId,
        approval_digest: &str,
    ) -> Result<ConsentReceipt, IntentLedgerError> {
        self.try_with_write_txn(|wtxn| {
            owner.revalidate_in_txn(self, wtxn)?;
            let record = read_intent_record_in_txn(self, wtxn, intent_id)?
                .filter(|record| record.state == IntentState::Pending)
                .ok_or(IntentLedgerError::InvalidInput(
                    "outbound intent is not pending",
                ))?;
            if super::connector_slate::setting_in_txn(self, wtxn, &record)?
                != crate::connector_key::SlateDisposition::AlwaysAsk
            {
                return Err(IntentLedgerError::InvalidInput(
                    "outbound intent no longer asks",
                ));
            }
            let candidate = candidate_in_txn(self, wtxn, &record)?.ok_or(
                IntentLedgerError::InvalidInput("outbound intent names no ordinary ask"),
            )?;
            if candidate.digest.to_hex() != approval_digest {
                return Err(IntentLedgerError::InvalidInput(
                    "outbound intent's ask moved",
                ));
            }
            Ok(self.approve_once_in_txn(wtxn, owner, candidate.digest)?)
        })
    }
}

/// Versioned native queue identity; the host renders the structured question.
const ASK_QUEUE: &str = "outbound.intent.approval";
const ASK_QUEUE_VERSION: &str = "v1";
const ASK_VERSION: u32 = 1;
const ASK_DOMAIN: &[u8] = b"oneiron:outbound-intent-approval-ask:v1";

/// Keeps the exact ordinary question in the caller's writer. Its identity
/// depends on the ledger row and reviewed digest, not rendered wording. An
/// answered question stays answered; a bare admission invents no principal.
pub(super) fn queue_owner_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &IntentLedgerRecord,
) -> Result<Option<u64>, IntentLedgerError> {
    let Some(record) = read_intent_record_in_txn(vault, txn, &record.id)?
        .filter(|record| record.state == IntentState::Pending)
    else {
        return Ok(None);
    };
    let Some(candidate) = candidate_in_txn(vault, txn, &record)? else {
        return Ok(None);
    };
    let Some(principal) = candidate.actor else {
        return Ok(None);
    };
    let correlation = EntityId::derive(ASK_DOMAIN, &[&record.id, candidate.digest.as_bytes()])?;
    let mut question = DecisionQuestion {
        id: correlation,
        version: ASK_VERSION,
        text: String::new(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    };
    let to = AskTo::owner();
    let evidence = [correlation];
    if let Some(ask) = vault.decision_ask_for_in_txn(
        txn,
        &question,
        principal,
        &evidence,
        &to,
        Some(correlation),
    )? {
        if ask.withdrawn_at.is_none() {
            return Ok(Some(ask.seq));
        }
    }
    // Native identifiers only, not a hard-coded prose prompt or a request body.
    let state = serde_json::json!({
        "intent_id": crate::entity_id::bytes_to_hex_lower(&record.id),
        "server": record.server,
        "tool": record.tool,
        "approval_digest": candidate.digest.to_hex(),
    });
    question.text = state.to_string();
    Ok(Some(vault.queue_decision_ask_in_txn(
        txn,
        &HumanDecisionRequest {
            question,
            principal,
            evidence: evidence.to_vec(),
            reason: HumanAskReason::OwnerSelected,
            prior: None,
            prior_provider: None,
            queue_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: ASK_QUEUE.to_owned(),
                version: ASK_QUEUE_VERSION.to_owned(),
            },
            to,
            correlation: Some(correlation),
        },
        Some(&state),
    )?))
}
