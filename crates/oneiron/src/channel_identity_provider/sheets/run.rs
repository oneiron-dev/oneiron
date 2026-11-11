//! One Sheets call's send (FIX 4862): its requests reach the broker before
//! the grant is read, one custody door releases the grant for the effect and
//! its readback, and a write's Gate records stand on each side of its send,
//! each in one transaction with the write's claim on its invocation.

use std::sync::Arc;

use serde_json::{Value, json};

use super::SHEETS_CONNECTOR_EFFECTOR;
use super::invocation::SheetsWriteClaim;
use super::receipt::{EffectResult, SEND_DELIVERED, SEND_NOT_SENT, SEND_UNCERTAIN, SheetsEffect};
use super::token;
use super::tools::SheetsCall;
use super::wire::{SheetsBrokerHost, SheetsWireOutcome, SheetsWireRequest};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::GateDecisionId;
use crate::vault::Vault;

/// The request did not reach the credential broker; nothing was sent.
const BROKER_UNREACHED: &str = "sheets_broker_unreached";
/// The custody door refused the grant; nothing was sent.
const CREDENTIAL_REFUSED: &str = "sheets_credential_refused";
/// The grant gave no usable access token (a refused refresh, say); nothing
/// was sent.
const CREDENTIAL_UNUSABLE: &str = "sheets_credential_unusable";
/// A write's readback did not run: the write did not succeed.
const READBACK_NOT_RUN: &str = "sheets_readback_not_run";

/// The requests one call sends: its effect, and after a write the read
/// that reads it back.
pub(super) struct SheetsRequests {
    pub(super) effect: SheetsWireRequest,
    readback: Option<SheetsWireRequest>,
}

impl SheetsRequests {
    /// The exact requests `call` sends, or the reason code its input does not
    /// fit a request.
    pub(super) fn of(call: &SheetsCall) -> std::result::Result<Self, &'static str> {
        Ok(match call {
            SheetsCall::SpreadsheetGet { spreadsheet_id } => Self {
                effect: SheetsWireRequest::spreadsheet_get(spreadsheet_id)?,
                readback: None,
            },
            SheetsCall::ValuesBatchGet(input) => {
                let ranges: Vec<&str> = input.ranges.iter().map(String::as_str).collect();
                Self {
                    effect: SheetsWireRequest::values_batch_get(
                        &input.spreadsheet_id,
                        &ranges,
                        input.value_render_option,
                        input.major_dimension,
                    )?,
                    readback: None,
                }
            }
            SheetsCall::ValuesBatchUpdate(input) => {
                let ranges: Vec<&str> = input
                    .data
                    .iter()
                    .map(|range| range.range.as_str())
                    .collect();
                Self {
                    effect: SheetsWireRequest::values_batch_update(input)?,
                    readback: Some(SheetsWireRequest::values_batch_get(
                        &input.spreadsheet_id,
                        &ranges,
                        input.response_value_render_option,
                        None,
                    )?),
                }
            }
            SheetsCall::StructuralBatchUpdate(input) => Self {
                effect: SheetsWireRequest::batch_update(input)?,
                readback: Some(SheetsWireRequest::spreadsheet_get(&input.spreadsheet_id)?),
            },
        })
    }
}

/// What one call came to.
pub(super) enum SheetsAnswer {
    /// Google answered the effect: the tool's output, an error when Google's
    /// status was not a success.
    Answered { output: Value, is_error: bool },
    /// Nothing was sent: the reason code.
    NotSent(String),
    /// The effect may have reached Google, and no answer came back: the
    /// reason code.
    Uncertain(String),
}

/// One call's send, for one caller, over the host's broker leg and the
/// checked connection's stored grant.
pub(super) struct SheetsRun<'a> {
    pub(super) vault: &'a Vault,
    pub(super) host: Arc<dyn SheetsBrokerHost>,
    /// The custody name of the checked connection's grant.
    pub(super) credential: String,
    pub(super) actor: EntityId,
    pub(super) actor_class: EdgeActorClass,
    /// A write's claim on its caller's invocation, when the caller carries
    /// one.
    pub(super) claim: Option<SheetsWriteClaim>,
}

impl SheetsRun<'_> {
    /// Sends `call`'s requests. The effect reaches the broker first; a write
    /// then commits its intent record and its claim. One door releases the
    /// grant: its access token goes with the effect, and, when the effect
    /// succeeded, with its readback, which connects only then. A write
    /// appends its outcome record and settles its claim last. A claim whose
    /// invocation's row already answers the write (a replay that raced this
    /// call) answers that, and nothing is sent.
    ///
    /// # Errors
    ///
    /// Storage faults writing a Gate record. Every other stop is the answer's.
    pub(super) fn send(&self, call: &SheetsCall, requests: SheetsRequests) -> Result<SheetsAnswer> {
        let tool = call.tool();
        let effect = match self
            .host
            .prepare(&requests.effect, &EntityId::now().to_hex())
        {
            Ok(prepared) => prepared,
            Err(reason) => {
                tracing::warn!(
                    %reason,
                    tool = tool.as_str(),
                    "a Sheets request did not reach the credential broker"
                );
                return Ok(SheetsAnswer::NotSent(BROKER_UNREACHED.to_owned()));
            }
        };
        let client = token::refresh_client()?;
        let receipt = tool.writes().then(|| SheetsEffect {
            actor: self.actor,
            actor_class: self.actor_class,
            tool,
            spreadsheet_id: call.spreadsheet_id(),
            request: requests.effect.digest(),
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
        let door = self.vault.inject_secret_at_door(
            &self.credential,
            SHEETS_CONNECTOR_EFFECTOR,
            &mut |value: &[u8]| {
                let Some(prepared) = effect.take() else {
                    return Ok(());
                };
                let access_token = match token::access_token(&client, value) {
                    Ok(access_token) => access_token,
                    Err(error) => {
                        token_unusable = true;
                        return Err(error);
                    }
                };
                let outcome = prepared.present(access_token.as_bytes());
                let readback = requests.readback.as_ref();
                if let (Some(_), Some(readback)) = (outcome.success(), readback) {
                    readback_outcome = Some(
                        match self.host.prepare(readback, &EntityId::now().to_hex()) {
                            Ok(prepared) => prepared.present(access_token.as_bytes()),
                            Err(reason) => SheetsWireOutcome::NotSent(reason),
                        },
                    );
                }
                effect_outcome = Some(outcome);
                Ok(())
            },
        );
        let generation = door.as_ref().ok().map(|injected| injected.value_generation);
        // Google's answer outranks a later door error: once the effect was
        // presented, what Google said is the fact.
        let outcome = match (effect_outcome, door) {
            (Some(outcome), _) => outcome,
            (None, door) => {
                if let Err(error) = door {
                    tracing::warn!(
                        %error,
                        tool = tool.as_str(),
                        "the Sheets grant was not presented"
                    );
                }
                let reason = if token_unusable {
                    CREDENTIAL_UNUSABLE
                } else {
                    CREDENTIAL_REFUSED
                };
                SheetsWireOutcome::NotSent(reason.to_owned())
            }
        };
        let receipts = match (&receipt, intent) {
            (Some(write), Some(intent)) => {
                let result = effect_result(&outcome, readback_outcome.as_ref(), generation);
                Some((intent, self.outcome(write, intent, &result)?))
            }
            _ => None,
        };
        Ok(answer(call, outcome, readback_outcome, receipts))
    }

    /// Commits `write`'s intent record and, in the same transaction, its
    /// claim on the caller's invocation. The intent's id, or, when the
    /// invocation's row already answers the write, that answer, and no
    /// record.
    fn intent(
        &self,
        write: &SheetsEffect<'_>,
    ) -> Result<std::result::Result<GateDecisionId, SheetsAnswer>> {
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
        write: &SheetsEffect<'_>,
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
}

/// What a write's outcome record says of its send.
fn effect_result(
    outcome: &SheetsWireOutcome,
    readback: Option<&SheetsWireOutcome>,
    generation: Option<u32>,
) -> EffectResult {
    let (send, reply) = match outcome {
        SheetsWireOutcome::Answered { status, body } if (200..300).contains(status) => {
            (SEND_DELIVERED.to_owned(), Some(json_digest(body)))
        }
        SheetsWireOutcome::Answered { status, body } => {
            (format!("rejected_{status}"), Some(json_digest(body)))
        }
        SheetsWireOutcome::NotSent(_) => (SEND_NOT_SENT.to_owned(), None),
        SheetsWireOutcome::Uncertain(_) => (SEND_UNCERTAIN.to_owned(), None),
    };
    EffectResult {
        send,
        generation,
        reply,
        readback: readback
            .and_then(SheetsWireOutcome::success)
            .map(json_digest),
    }
}

/// The call's answer. A read answers Google's reply as it stands. A write
/// answers Google's reply beside its readback (or why there is none) and
/// its two Gate records' ids. A refused status answers as a tool error.
fn answer(
    call: &SheetsCall,
    outcome: SheetsWireOutcome,
    readback: Option<SheetsWireOutcome>,
    receipts: Option<(GateDecisionId, GateDecisionId)>,
) -> SheetsAnswer {
    let receipts = receipts
        .map(|(intent, outcome)| json!({ "intent": intent.to_hex(), "outcome": outcome.to_hex() }));
    let reply = match outcome {
        SheetsWireOutcome::NotSent(reason) => return SheetsAnswer::NotSent(reason),
        SheetsWireOutcome::Uncertain(reason) => return SheetsAnswer::Uncertain(reason),
        SheetsWireOutcome::Answered { status, body } if !(200..300).contains(&status) => {
            let mut output = json!({
                "spreadsheetId": call.spreadsheet_id(),
                "status": status,
                "error": body
            });
            if let Some(receipts) = receipts {
                output["receipts"] = receipts;
            }
            return SheetsAnswer::Answered {
                output,
                is_error: true,
            };
        }
        SheetsWireOutcome::Answered { body, .. } => body,
    };
    if !call.tool().writes() {
        return SheetsAnswer::Answered {
            output: reply,
            is_error: false,
        };
    }
    let mut output = json!({ "spreadsheetId": call.spreadsheet_id(), "reply": reply });
    match readback {
        Some(SheetsWireOutcome::Answered { status, body }) if (200..300).contains(&status) => {
            output["readback"] = body;
        }
        Some(SheetsWireOutcome::Answered { status, .. }) => {
            output["readbackError"] = Value::from(format!("sheets_readback_status_{status}"));
        }
        Some(SheetsWireOutcome::NotSent(reason) | SheetsWireOutcome::Uncertain(reason)) => {
            output["readbackError"] = Value::from(reason);
        }
        None => output["readbackError"] = Value::from(READBACK_NOT_RUN),
    }
    if let Some(receipts) = receipts {
        output["receipts"] = receipts;
    }
    SheetsAnswer::Answered {
        output,
        is_error: false,
    }
}

/// A JSON body's digest, lower hex, over its compact serialization.
fn json_digest(body: &Value) -> String {
    blake3::hash(body.to_string().as_bytes())
        .to_hex()
        .to_string()
}
