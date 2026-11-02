//! An ask about one consent effect, kept (FIX 2975; DEC-0006: "A reason typed by the
//! authenticated owner is his act: it drafts the standing grant for the class it names,
//! with a one-line notice and one-tap undo ... unsure, ask with the nearest reason
//! pre-filled"). Queued, it carries the owner's nearest reason on record, read through
//! consent's own reason rows. Answered by the owner with a reason, it drafts the standing
//! grant of its bound, Proposed: the draft grants nothing until the owner confirms it, and
//! the confirm lands through consent's reason door, which mints the grant with its rule
//! row and its undo.

use super::{ASKS, DecisionAsk, DecisionAsks};
use crate::consent::{
    AuthenticatedOwner, OwnerReasonConfirm, OwnerReasonConfirmation, OwnerReasonVerdict,
    ReasonMatchConfidence,
};
use crate::llm::decision::AskRole;
use crate::llm::decision::ladder::{AskConsent, HumanDecisionRequest};
use crate::llm::decision::types::invalid;
use crate::{Result, Vault};
use serde::{Deserialize, Serialize};

/// The standing grant an owner's reason drafted from an ask about one consent effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AskGrantDraft {
    /// Drafted from the reason, by the bound's digest: it grants nothing until the owner
    /// confirms it.
    Proposed { grant_ref: String },
    /// The owner confirmed it: the standing grant is live, under the rule row the reason
    /// landed as.
    Confirmed {
        grant_ref: String,
        /// The confirm's consent receipt, by decision id hex.
        receipt: String,
        /// The reason's rule row, by decision id hex: the one-tap undo names it.
        rule: String,
    },
}

/// The draft an answer to `ask` by `role` with `reason` leaves: a Proposed grant of the
/// ask's bound when the owner gave a reason on an ask about a consent effect; none
/// otherwise, and none for a bound that no longer builds.
pub(super) fn drafted(
    ask: &DecisionAsk,
    reason: Option<&str>,
    role: &AskRole,
) -> Option<AskGrantDraft> {
    if reason.is_none() || *role != AskRole::Owner {
        return None;
    }
    let bound = ask.consent.as_ref()?.grant_bound().ok()?;
    Some(AskGrantDraft::Proposed {
        grant_ref: bound.digest().to_hex(),
    })
}

impl Vault {
    /// [`Self::queue_decision_ask_with_state`] for an ask about one consent effect: the ask
    /// keeps `consent`, and the owner's nearest reason on record for that effect, read as
    /// an unsure judgment reads it (it never answers the ask). A read that fails pre-fills
    /// nothing and still queues the ask.
    ///
    /// # Errors
    ///
    /// A consent whose effect or bound does not build, or the queue's own.
    pub fn queue_decision_ask_with_consent(
        &self,
        request: &HumanDecisionRequest,
        state: Option<&serde_json::Value>,
        consent: &AskConsent,
    ) -> Result<u64> {
        let (effect, _) = consent.validate()?;
        let prefill = match self.evaluate_owner_reason(&effect, ReasonMatchConfidence::Unsure) {
            Ok(OwnerReasonVerdict::Ask { prefill }) => prefill,
            Ok(OwnerReasonVerdict::Auto { .. }) | Err(_) => None,
        };
        self.with_write_txn_grouped(|txn| {
            let consent = Some((consent, prefill));
            self.queue_decision_ask_with_consent_in_txn(txn, request, state, consent)
        })
    }

    /// The owner's confirm of the standing grant his reason drafted on ask `seq`, as
    /// `owner`: consent's reason door mints it, with its rule row, `notice_text` (the
    /// host's words) and its undo, and the draft reads confirmed, in one writer. Only a
    /// Proposed draft confirms.
    ///
    /// # Errors
    ///
    /// No such ask, no Proposed draft on it, a draft that no longer matches its ask, an
    /// owner proof that no longer holds, consent's own refusal, or a store failure.
    pub fn confirm_decision_ask_grant(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        notice_text: &str,
    ) -> Result<(DecisionAsk, OwnerReasonConfirmation)> {
        self.recheck_owner(owner)?;
        self.with_write_txn_grouped(|txn| {
            let mut held = ASKS
                .get(&self.store, &*txn, &seq)?
                .ok_or_else(|| invalid("no such decision ask"))?;
            let (Some(consent), Some(answer)) = (&held.consent, &held.answer) else {
                return Err(invalid("the decision ask drafted no standing grant"));
            };
            let (Some(AskGrantDraft::Proposed { grant_ref }), Some(reason)) =
                (&answer.grant, &answer.reason)
            else {
                return Err(invalid("the decision ask holds no Proposed grant draft"));
            };
            let (effect, bound) = consent.validate()?;
            if bound.digest().to_hex() != *grant_ref {
                return Err(invalid("the grant draft no longer matches its ask"));
            }
            let grant_ref = grant_ref.clone();
            let confirmation = self.confirm_owner_reason_in_txn(
                txn,
                owner,
                &effect,
                &bound,
                OwnerReasonConfirm {
                    reason: Some(reason.as_str()),
                    notice_text,
                },
            )?;
            let confirmed = AskGrantDraft::Confirmed {
                grant_ref,
                receipt: confirmation.receipt.decision_id().to_hex(),
                rule: confirmation
                    .undo
                    .as_ref()
                    .map_or_else(String::new, |undo| undo.rule_decision_id.to_hex()),
            };
            if let Some(answer) = held.answer.as_mut() {
                answer.grant = Some(confirmed);
            }
            ASKS.put(&self.store, txn, &seq, &held)?;
            Ok((held, confirmation))
        })
    }
}

impl DecisionAsks {
    /// Confirms the standing grant the owner's reason drafted on one ask (see
    /// [`Vault::confirm_decision_ask_grant`]).
    ///
    /// # Errors
    ///
    /// As [`Vault::confirm_decision_ask_grant`].
    pub fn confirm_grant(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        notice_text: &str,
    ) -> Result<(DecisionAsk, OwnerReasonConfirmation)> {
        self.vault
            .confirm_decision_ask_grant(owner, seq, notice_text)
    }
}
