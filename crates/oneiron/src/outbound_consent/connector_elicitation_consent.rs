//! The owner's consent on an answer to a connector's question under `always
//! ask` (FIX 8808): DEC-0006's three outcomes, through the consent doors.
//!
//! The decisive ask offers approve once, approve and stop asking, and deny.
//! The call's row keeps what the ask is about beside its round: the frozen
//! answer's digest, the scope a stop-asking press remembers, and the once
//! digest an approval binds. The owner's authenticated press mints at the
//! owner answer route, in one writer with that row: approve once marks the
//! once digest, stop asking adds a standing grant on the scope (with no
//! expiry) beside the once mark, and deny records the refusal. The waiter
//! reads the press from the row, never a raw choice, and the send spends the
//! once mark. A later answer the standing grant covers goes without asking,
//! its use receipted.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ComposedEffect, ConsentDecision,
    EffectDigest, EffectFacts, GrantBound, StandingConsentGrant, UndoFidelity,
    approve_once_authorization_in_txn, evaluate_consent, spend_approve_once_in_txn,
};
use crate::entity_id::EntityId;
use crate::genui::{CONSENT_ACTION_APPROVE_ONCE, ConsentConfirmOutcome};
use crate::llm::decision::{AnswerContract, DecisionAnswer};

use super::connector_call::PENDING_CALLS;
use super::connector_elicitation_asks::{
    ConnectorElicitationAnswer, ELICITATION_ASK_QUEUE, elicitation_ask_correlation,
};
use super::execution::{ConnectorElicitationBinding, ElicitationAnswerVerdict};

/// The action class a stop-asking press remembers (FIX 8808).
const CONNECTOR_ELICITATION_ANSWER_ACTION: &str = "outbound.connector_elicitation_answer";

/// The derivation domain of the once digest an owner's press binds.
const CONNECTOR_ELICITATION_CONSENT_DOMAIN: &[u8] =
    b"oneiron:connector-elicitation-owner-consent:v1";

/// The option ids the decisive ask offers, by outcome.
const OPTION_STOP_ASKING: &str = "approve_and_stop_asking";
const OPTION_DENY: &str = "deny";

/// The option id the decisive ask offers for `outcome`.
const fn option_id(outcome: ConsentConfirmOutcome) -> &'static str {
    match outcome {
        ConsentConfirmOutcome::ApproveOnce => CONSENT_ACTION_APPROVE_ONCE,
        ConsentConfirmOutcome::ApproveAndStopAsking => OPTION_STOP_ASKING,
        ConsentConfirmOutcome::Deny => OPTION_DENY,
    }
}

/// The outcome an option id of the decisive ask names, if any.
fn outcome_of(option: &str) -> Option<ConsentConfirmOutcome> {
    ConsentConfirmOutcome::trio()
        .into_iter()
        .find(|outcome| option_id(*outcome) == option)
}

/// The decisive ask's contract: the three outcomes, in offer order.
pub(super) fn consent_contract() -> AnswerContract {
    AnswerContract::Choice {
        options: ConsentConfirmOutcome::trio()
            .into_iter()
            .map(|outcome| option_id(outcome).to_owned())
            .collect(),
    }
}

/// What a stop-asking press remembers (FIX 8808): the calling principal, the
/// governing key, the server, tool and endpoint, and the original call's
/// grant. No expiry; the owner revokes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConnectorElicitationGrantScope {
    principal_ref: String,
    key_ref: EntityId,
    server: String,
    tool: String,
    endpoint: String,
    grant_id: EntityId,
}

impl ConnectorElicitationGrantScope {
    fn of(binding: &ConnectorElicitationBinding) -> Self {
        Self {
            principal_ref: binding.principal_ref.clone(),
            key_ref: binding.key_ref,
            server: binding.server.clone(),
            tool: binding.tool.clone(),
            endpoint: binding.endpoint.clone(),
            grant_id: binding.grant_id,
        }
    }

    /// The action bound the scope is: the principal runs answers of this
    /// class to the governing key, on its server, tool, endpoint and grant.
    fn bound(&self) -> crate::Result<GrantBound> {
        GrantBound::action(
            ActorBound::new(self.principal_ref.as_str())?,
            ActionClass::new(CONNECTOR_ELICITATION_ANSWER_ACTION)?,
            ActionEnvelope::new([
                format!("server:{}", self.server),
                format!("tool:{}", self.tool),
                format!("endpoint:{}", self.endpoint),
                format!("grant:{}", self.grant_id.to_hex()),
            ])?
            .with_target(format!("connector_key:{}", self.key_ref.to_hex()))?
            .with_receipt_required(true),
        )
    }

    /// The once digest of the frozen answer `digest` to round `generation`
    /// of the question `handle`, under this scope.
    fn once_digest(&self, handle: &str, generation: u64, digest: &[u8; 32]) -> [u8; 32] {
        let generation = generation.to_be_bytes();
        let fields: [&[u8]; 9] = [
            self.principal_ref.as_bytes(),
            self.key_ref.as_bytes(),
            self.server.as_bytes(),
            self.tool.as_bytes(),
            self.endpoint.as_bytes(),
            self.grant_id.as_bytes(),
            handle.as_bytes(),
            &generation,
            digest,
        ];
        let mut hasher = blake3::Hasher::new();
        hasher.update(CONNECTOR_ELICITATION_CONSENT_DOMAIN);
        for field in fields {
            hasher.update(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(field);
        }
        *hasher.finalize().as_bytes()
    }
}

/// The owner's consent ask on one round's frozen answer, kept on the call's
/// row beside the round (FIX 8808), and the owner's press on it once there
/// is one. Digests and ids only, never the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ElicitationOwnerConsent {
    /// The decisive ask's correlation: the round and the frozen answer.
    correlation: EntityId,
    scope: ConnectorElicitationGrantScope,
    once_digest: [u8; 32],
    /// The owner's authenticated press, once there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pressed: Option<ConsentConfirmOutcome>,
    /// The standing grant a stop-asking press minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant_ref: Option<String>,
}

/// The registry ref of the standing grant that covers `bound` now, by the one
/// evaluator; `None` when none does. An answer reaches a foreign server and
/// no undo brings it back, so only a grant covers it.
fn covering_grant(
    bound: &GrantBound,
    grants: &[StandingConsentGrant],
) -> crate::Result<Option<String>> {
    let facts = EffectFacts::new(CONNECTOR_ELICITATION_ANSWER_ACTION)?
        .with_external_observers(true)
        .with_undo_fidelity(UndoFidelity::None);
    let effect = ComposedEffect::new(facts).with_action_requirement(bound.clone())?;
    if evaluate_consent(&effect, None, grants) != ConsentDecision::Auto {
        return Ok(None);
    }
    Ok(grants
        .iter()
        .find(|grant| grant.bound().contains(bound))
        .map(|grant| grant.bound().digest().to_hex()))
}

impl Vault {
    /// Keeps on the call `call_ref`'s row what the owner's consent ask on
    /// `answer` is about (FIX 8808), before the ask is queued, so the press
    /// finds it; an ask already kept for the same answer keeps its press.
    /// A row with no such unanswered round keeps what it has.
    pub(super) fn keep_elicitation_owner_consent(
        &self,
        call_ref: &EntityId,
        binding: &ConnectorElicitationBinding,
        answer: &ConnectorElicitationAnswer<'_>,
        correlation: EntityId,
    ) -> crate::Result<()> {
        let scope = ConnectorElicitationGrantScope::of(binding);
        let once_digest = scope.once_digest(answer.handle, answer.generation, &answer.digest);
        self.with_write_txn_grouped(|txn| {
            let Some(mut row) = PENDING_CALLS.get(&self.store, txn, call_ref)? else {
                return Ok(());
            };
            if row.settled.is_some() {
                return Ok(());
            }
            let Some(input) = row
                .input
                .as_mut()
                .filter(|input| input.handle == answer.handle)
            else {
                return Ok(());
            };
            if input
                .owner_consent
                .as_ref()
                .is_some_and(|kept| kept.correlation == correlation)
            {
                return Ok(());
            }
            input.owner_consent = Some(ElicitationOwnerConsent {
                correlation,
                scope,
                once_digest,
                pressed: None,
                grant_ref: None,
            });
            PENDING_CALLS.put(&self.store, txn, call_ref, &row)?;
            Ok(())
        })
    }

    /// The owner's authenticated press on decision ask `seq` (FIX 8808),
    /// before its answer lands: on a connector elicitation's decisive ask,
    /// `answer` mints through the consent doors in one writer with the
    /// call's row. Approve once marks the answer's once digest; approve and
    /// stop asking adds the standing grant its scope names, with no expiry,
    /// beside the once mark; deny records the refusal. A stop-asking press
    /// whose scope the consent bound does not admit approves once, its
    /// grant not kept and logged. Any other ask, a linked part, an ask no
    /// longer open, an answer that names no outcome, or one already
    /// pressed is left alone, so its answer goes on as before.
    ///
    /// # Errors
    ///
    /// A proof that is not the owner's, and storage errors; nothing is
    /// pressed then.
    pub fn press_connector_elicitation_consent(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        answer: &DecisionAnswer,
    ) -> crate::Result<()> {
        let DecisionAnswer::Choice(option) = answer else {
            return Ok(());
        };
        let Some(outcome) = outcome_of(option) else {
            return Ok(());
        };
        let Some(ask) = self.decision_ask(seq)? else {
            return Ok(());
        };
        if ask.queue_pin.model != ELICITATION_ASK_QUEUE
            || ask.question.contract != consent_contract()
            || !ask.is_open()
        {
            return Ok(());
        }
        let Some(correlation) = ask.correlation else {
            return Ok(());
        };
        self.with_write_txn_grouped(|txn| {
            let found = PENDING_CALLS
                .scan(&self.store, txn)?
                .into_iter()
                .find(|(_, row)| {
                    row.settled.is_none()
                        && row
                            .input
                            .as_ref()
                            .and_then(|input| input.owner_consent.as_ref())
                            .is_some_and(|consent| consent.correlation == correlation)
                });
            let Some((call_ref, mut row)) = found else {
                return Ok(());
            };
            let Some(consent) = row
                .input
                .as_mut()
                .and_then(|input| input.owner_consent.as_mut())
            else {
                return Ok(());
            };
            if consent.pressed.is_some() {
                return Ok(());
            }
            let once = EffectDigest::from_bytes(consent.once_digest);
            match outcome {
                ConsentConfirmOutcome::ApproveOnce => {
                    self.approve_once_in_txn(txn, owner, once)?;
                }
                ConsentConfirmOutcome::ApproveAndStopAsking => {
                    // A scope the consent bound does not admit keeps no
                    // standing grant; the approval still goes, once.
                    match consent.scope.bound() {
                        Ok(bound) => {
                            let minted = self.create_standing_grant_in_txn(txn, owner, bound)?;
                            consent.grant_ref = minted.grant_ref();
                        }
                        Err(error) => tracing::warn!(
                            %error,
                            "connector elicitation stop asking not kept; approved once"
                        ),
                    }
                    self.approve_once_in_txn(txn, owner, once)?;
                }
                ConsentConfirmOutcome::Deny => {
                    self.deny_consent_in_txn(txn, owner, once)?;
                }
            }
            consent.pressed = Some(outcome);
            PENDING_CALLS.put(&self.store, txn, &call_ref, &row)?;
            Ok(())
        })
    }

    /// The owner's authenticated press on the consent ask about the frozen
    /// answer `digest` to round `generation` of the question `handle` on the
    /// call `call_ref` (FIX 8808), as its row keeps it; `None` until the
    /// owner pressed one.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn connector_elicitation_consent(
        &self,
        call_ref: &EntityId,
        handle: &str,
        generation: u64,
        digest: &[u8; 32],
    ) -> crate::Result<Option<ConsentConfirmOutcome>> {
        let correlation = elicitation_ask_correlation(handle, generation, digest)?;
        let txn = self.store.env.read_txn()?;
        Ok(PENDING_CALLS
            .get(&self.store, &txn, call_ref)?
            .and_then(|row| row.input)
            .and_then(|input| input.owner_consent)
            .filter(|consent| consent.correlation == correlation)
            .and_then(|consent| consent.pressed))
    }

    /// Spends the once mark the owner's approving press left on the frozen
    /// answer `digest` to round `generation` of the question `handle` on the
    /// call `call_ref` (FIX 8808), as that answer goes; `true` when it spent
    /// it. No approving press, or no mark, spends nothing.
    ///
    /// # Errors
    ///
    /// A mark already spent; storage errors.
    pub fn consume_connector_elicitation_consent(
        &self,
        call_ref: &EntityId,
        handle: &str,
        generation: u64,
        digest: &[u8; 32],
    ) -> crate::Result<bool> {
        let correlation = elicitation_ask_correlation(handle, generation, digest)?;
        self.with_write_txn_grouped(|txn| {
            let Some(consent) = PENDING_CALLS
                .get(&self.store, txn, call_ref)?
                .and_then(|row| row.input)
                .and_then(|input| input.owner_consent)
                .filter(|consent| consent.correlation == correlation)
            else {
                return Ok(false);
            };
            if consent
                .pressed
                .is_none_or(|pressed| pressed == ConsentConfirmOutcome::Deny)
            {
                return Ok(false);
            }
            let once = EffectDigest::from_bytes(consent.once_digest);
            let Some(authorization) = approve_once_authorization_in_txn(&self.store, txn, &once)?
            else {
                return Ok(false);
            };
            spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            Ok(true)
        })
    }

    /// The verdict on `answer` under `always ask`, once the original grant
    /// and key admitted it (FIX 8808): it goes when a standing grant the
    /// owner's stop-asking press minted covers it, else it asks the owner.
    /// A coverage read that fails asks, as before.
    pub(super) fn always_ask_elicitation_verdict(
        &self,
        binding: &ConnectorElicitationBinding,
        answer: &ConnectorElicitationAnswer<'_>,
    ) -> ElicitationAnswerVerdict {
        match self.elicitation_answer_covered(binding, answer) {
            Ok(true) => ElicitationAnswerVerdict::Send,
            Ok(false) => ElicitationAnswerVerdict::AskOwner,
            Err(error) => {
                tracing::warn!(%error, "connector elicitation standing consent not read");
                ElicitationAnswerVerdict::AskOwner
            }
        }
    }

    /// Whether a standing grant the owner's stop-asking press minted covers
    /// `answer` under `binding` now (FIX 8808); the use is receipted in the
    /// writer that found it. A scope the consent bound does not admit is
    /// covered by nothing.
    fn elicitation_answer_covered(
        &self,
        binding: &ConnectorElicitationBinding,
        answer: &ConnectorElicitationAnswer<'_>,
    ) -> crate::Result<bool> {
        let scope = ConnectorElicitationGrantScope::of(binding);
        let Ok(bound) = scope.bound() else {
            return Ok(false);
        };
        let once = EffectDigest::from_bytes(scope.once_digest(
            answer.handle,
            answer.generation,
            &answer.digest,
        ));
        self.with_write_txn_grouped(|txn| {
            let grants = self.active_standing_consent_grants_in_txn(txn)?;
            let Some(grant_ref) = covering_grant(&bound, &grants)? else {
                return Ok(false);
            };
            self.record_standing_grant_use_in_txn(txn, &grant_ref, once)?;
            Ok(true)
        })
    }
}
