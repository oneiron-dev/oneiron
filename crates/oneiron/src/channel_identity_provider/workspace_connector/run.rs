//! One workspace call's send (FIX 4862; L3-17): its requests reach the
//! broker before the grant is read, one custody door releases the grant for
//! the effect and its readback, and a write's Gate records stand on each side
//! of its send, each in one transaction with the write's claim on its
//! invocation.

use std::sync::Arc;

use serde_json::{Value, json};

use super::invocation::WorkspaceWriteClaim;
use super::receipt::{
    EffectResult, SEND_DELIVERED, SEND_NOT_SENT, SEND_UNCERTAIN, WorkspaceEffect,
};
use super::token;
use super::wire::{WorkspaceBrokerHost, WorkspaceWireOutcome};
use super::{WorkspaceApi, WorkspacePlan, WorkspaceTool};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::GateDecisionId;
use crate::vault::Vault;

/// The request did not reach the credential broker; nothing was sent.
const BROKER_UNREACHED: &str = "broker_unreached";
/// The custody door refused the grant; nothing was sent.
const CREDENTIAL_REFUSED: &str = "credential_refused";
/// The grant gave no usable access token (a refused refresh, say); nothing
/// was sent.
const CREDENTIAL_UNUSABLE: &str = "credential_unusable";
/// A write's readback did not run: the write did not succeed.
const READBACK_NOT_RUN: &str = "readback_not_run";

/// What one call came to.
pub(super) enum WorkspaceAnswer {
    /// The provider answered the effect: the tool's output, an error when
    /// its status was not a success.
    Answered { output: Value, is_error: bool },
    /// Nothing was sent: the reason code.
    NotSent(String),
    /// The effect may have reached the provider, and no answer came back:
    /// the reason code.
    Uncertain(String),
}

/// One call's send, for one caller, over the host's broker leg and the
/// checked connection's stored grant.
pub(super) struct WorkspaceRun<'a> {
    pub(super) vault: &'a Vault,
    pub(super) host: Arc<dyn WorkspaceBrokerHost>,
    pub(super) module: &'static dyn WorkspaceApi,
    /// The custody name of the checked connection's grant.
    pub(super) credential: String,
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    /// A write's claim on its caller's invocation, when the caller carries
    /// one.
    pub(super) claim: Option<WorkspaceWriteClaim>,
}

impl WorkspaceRun<'_> {
    /// Sends `plan`'s requests for a call of `tool`. The effect reaches the
    /// broker first; a write then commits its intent record and its claim.
    /// One door releases the grant: its access token goes with the effect,
    /// and, when the effect succeeded, with its readback, which connects only
    /// then. A write appends its outcome record and settles its claim last.
    /// A claim whose invocation's row already answers the write (a replay
    /// that raced this call) answers that, and nothing is sent.
    ///
    /// # Errors
    ///
    /// Storage faults writing a Gate record. Every other stop is the answer's.
    pub(super) fn send(
        &self,
        tool: &WorkspaceTool,
        plan: WorkspacePlan,
    ) -> Result<WorkspaceAnswer> {
        let connection = self.module.connection();
        let effect = match self.host.prepare(&plan.effect, &EntityId::now().to_hex()) {
            Ok(prepared) => prepared,
            Err(reason) => {
                tracing::warn!(
                    %reason,
                    connector = self.module.catalog_name(),
                    tool = tool.name,
                    "a workspace request did not reach the credential broker"
                );
                return Ok(WorkspaceAnswer::NotSent(connection.code(BROKER_UNREACHED)));
            }
        };
        let client = token::refresh_client()?;
        let receipt = tool.writes.then(|| WorkspaceEffect {
            actor: self.actor,
            actor_class: self.actor_class,
            module: self.module,
            tool: tool.name,
            target: &plan.target,
            request: plan.effect.digest(),
            credential: &self.credential,
        });
        let intent = match &receipt {
            Some(write) => match self.intent(write)? {
                Ok(intent) => Some(intent),
                Err(answer) => return Ok(answer),
            },
            None => None,
        };
        let mut effect = Some(effect);
        let mut effect_outcome = None;
        let mut readback_outcome = None;
        let mut token_unusable = false;
        let mut successor = None;
        let door = self.vault.inject_secret_at_door(
            &self.credential,
            connection.effector,
            &mut |value: &[u8]| {
                let Some(prepared) = effect.take() else {
                    return Ok(());
                };
                let access_token = match token::access_token(&client, connection.token, value) {
                    Ok(access) => {
                        successor = access.successor;
                        access.access_token
                    }
                    Err(error) => {
                        token_unusable = true;
                        return Err(error);
                    }
                };
                let outcome = prepared.present(access_token.as_bytes());
                if let (Some(_), Some(readback)) = (outcome.success(), plan.readback.as_ref()) {
                    readback_outcome = Some(
                        match self.host.prepare(readback, &EntityId::now().to_hex()) {
                            Ok(prepared) => prepared.present(access_token.as_bytes()),
                            Err(reason) => WorkspaceWireOutcome::NotSent(reason),
                        },
                    );
                }
                effect_outcome = Some(outcome);
                Ok(())
            },
        );
        if let Ok(injected) = &door {
            self.vault
                .keep_provider_refreshed_grant(injected, successor);
        }
        let generation = door.as_ref().ok().map(|injected| injected.value_generation);
        // The provider's answer outranks a later door error: once the effect
        // was presented, what the provider said is the fact.
        let outcome = match (effect_outcome, door) {
            (Some(outcome), _) => outcome,
            (None, door) => {
                if let Err(error) = door {
                    tracing::warn!(
                        %error,
                        connector = self.module.catalog_name(),
                        tool = tool.name,
                        "the workspace grant was not presented"
                    );
                }
                let reason = if token_unusable {
                    CREDENTIAL_UNUSABLE
                } else {
                    CREDENTIAL_REFUSED
                };
                WorkspaceWireOutcome::NotSent(connection.code(reason))
            }
        };
        let receipts = match (&receipt, intent) {
            (Some(write), Some(intent)) => {
                let result = effect_result(&outcome, readback_outcome.as_ref(), generation);
                Some((intent, self.outcome(write, intent, &result)?))
            }
            _ => None,
        };
        Ok(self.answer(tool, &plan, outcome, readback_outcome, receipts))
    }

    /// Commits `write`'s intent record and, in the same transaction, its
    /// claim on the caller's invocation. The intent's id, or, when the
    /// invocation's row already answers the write, that answer, and no
    /// record.
    fn intent(
        &self,
        write: &WorkspaceEffect<'_>,
    ) -> Result<std::result::Result<GateDecisionId, WorkspaceAnswer>> {
        self.vault.with_write_txn_grouped(|txn| {
            if let Some(claim) = &self.claim
                && let Some(answer) = claim.answer_in_txn(&self.vault.store, txn)?
            {
                return Ok(Err(answer));
            }
            let intent = write.intent_in_txn(self.vault, txn)?;
            if let Some(claim) = &self.claim {
                claim.claim_in_txn(&self.vault.store, txn, intent)?;
            }
            Ok(Ok(intent))
        })
    }

    /// Appends `write`'s outcome record, linked to `intent`, and in the same
    /// transaction settles its claim with what the send came to.
    fn outcome(
        &self,
        write: &WorkspaceEffect<'_>,
        intent: GateDecisionId,
        result: &EffectResult,
    ) -> Result<GateDecisionId> {
        self.vault.with_write_txn_grouped(|txn| {
            let outcome = write.outcome_in_txn(self.vault, txn, intent, result)?;
            if let Some(claim) = &self.claim {
                claim.settle_in_txn(&self.vault.store, txn, intent, &result.send, outcome)?;
            }
            Ok(outcome)
        })
    }

    /// The call's answer. A read answers the provider's reply as it stands.
    /// A write answers the reply beside its readback (or why there is none)
    /// and its two Gate records' ids. A refused status answers as a tool
    /// error.
    fn answer(
        &self,
        tool: &WorkspaceTool,
        plan: &WorkspacePlan,
        outcome: WorkspaceWireOutcome,
        readback: Option<WorkspaceWireOutcome>,
        receipts: Option<(GateDecisionId, GateDecisionId)>,
    ) -> WorkspaceAnswer {
        let connection = self.module.connection();
        let field = self.module.target().field;
        let receipts = receipts.map(
            |(intent, outcome)| json!({ "intent": intent.to_hex(), "outcome": outcome.to_hex() }),
        );
        let reply = match outcome {
            WorkspaceWireOutcome::NotSent(reason) => return WorkspaceAnswer::NotSent(reason),
            WorkspaceWireOutcome::Uncertain(reason) => return WorkspaceAnswer::Uncertain(reason),
            WorkspaceWireOutcome::Answered { status, body } if !(200..300).contains(&status) => {
                let mut output = json!({ "status": status, "error": body });
                output[field] = Value::from(plan.target.as_str());
                if let Some(receipts) = receipts {
                    output["receipts"] = receipts;
                }
                return WorkspaceAnswer::Answered {
                    output,
                    is_error: true,
                };
            }
            WorkspaceWireOutcome::Answered { body, .. } => body,
        };
        if !tool.writes {
            return WorkspaceAnswer::Answered {
                output: reply,
                is_error: false,
            };
        }
        let mut output = json!({ "reply": reply });
        output[field] = Value::from(plan.target.as_str());
        match readback {
            Some(WorkspaceWireOutcome::Answered { status, body })
                if (200..300).contains(&status) =>
            {
                output["readback"] = body;
            }
            Some(WorkspaceWireOutcome::Answered { status, .. }) => {
                output["readbackError"] =
                    Value::from(connection.code(&format!("readback_status_{status}")));
            }
            Some(
                WorkspaceWireOutcome::NotSent(reason) | WorkspaceWireOutcome::Uncertain(reason),
            ) => {
                output["readbackError"] = Value::from(reason);
            }
            None => output["readbackError"] = Value::from(connection.code(READBACK_NOT_RUN)),
        }
        if let Some(receipts) = receipts {
            output["receipts"] = receipts;
        }
        WorkspaceAnswer::Answered {
            output,
            is_error: false,
        }
    }
}

/// What a write's outcome record says of its send.
fn effect_result(
    outcome: &WorkspaceWireOutcome,
    readback: Option<&WorkspaceWireOutcome>,
    generation: Option<u32>,
) -> EffectResult {
    let (send, reply) = match outcome {
        WorkspaceWireOutcome::Answered { status, body } if (200..300).contains(status) => {
            (SEND_DELIVERED.to_owned(), Some(json_digest(body)))
        }
        WorkspaceWireOutcome::Answered { status, body } => {
            (format!("rejected_{status}"), Some(json_digest(body)))
        }
        WorkspaceWireOutcome::NotSent(_) => (SEND_NOT_SENT.to_owned(), None),
        WorkspaceWireOutcome::Uncertain(_) => (SEND_UNCERTAIN.to_owned(), None),
    };
    EffectResult {
        send,
        generation,
        reply,
        readback: readback
            .and_then(WorkspaceWireOutcome::success)
            .map(json_digest),
    }
}

/// A JSON body's digest, lower hex, over its compact serialization.
fn json_digest(body: &Value) -> String {
    blake3::hash(body.to_string().as_bytes())
        .to_hex()
        .to_string()
}
