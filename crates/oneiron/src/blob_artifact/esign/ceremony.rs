//! One public signing executor: turn, access, viewed, terminal, then action.
use super::{
    capability::{EsignCapability, binding},
    ledger::{append, state_in},
    model::*,
    principals::automated_signing_allowed,
};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SigningAction {
    Load,
    SaveField { field: String, value: FieldValue },
    Complete { consent: bool, next: Option<String> },
    Reject { reason: String },
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SigningPage {
    pub item_count: usize,
    pub title: String,
    pub recipient: String,
    pub fields: Vec<EsignField>,
    pub presentations: Vec<super::render::FieldPresentation>,
    pub values: BTreeMap<String, SignatureRow>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "outcome", content = "data", rename_all = "snake_case")]
pub enum SigningOutcome {
    Page(SigningPage),
    NotYourTurn,
    Terminal {
        status: DocumentStatus,
        item_count: usize,
    },
    AwaitingSeal,
    /// D6: the signing dial does not open this automated sign act, so the
    /// call is held for its role chain's answer, never dropped.
    HeldForOwner {
        held_at: u64,
    },
    ConsentRequired,
}

/// Who a signing call shows itself to be (OF-415). The capability proves
/// access to a recipient's turn, not who holds the link: only a vault
/// credential the call presents says that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningCaller {
    /// No credential: the capability alone, as a browser signer brings it.
    Bearer,
    /// A verified credential bound to a person.
    Person,
    /// A verified credential not shown to be a person: an agent, the
    /// system, or one that binds no actor class. Its sign act is automated
    /// whatever the recipient's flag says.
    Agent,
}

pub const ESIGN_SEAL_ATTEMPT_KIND: &str = "esign.seal";
pub(super) fn enqueue_seal(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    now: u64,
) -> Result<()> {
    // A held chain seals nothing; a decline or void on it still lands, and a
    // reseal after the owner's answer seals it.
    if super::ledger::held_in(vault, txn, document)? {
        return Ok(());
    }
    let state = state_in(vault, txn, document)?;
    if !state.ready_to_seal() {
        return Ok(());
    }
    let generation = if state.reseal_pending {
        super::ledger::events_in(vault, txn, document)?
            .iter()
            .rev()
            .find(|row| matches!(row.event, EsignEvent::ResealRequested { .. }))
            .ok_or_else(|| invalid("reseal request missing"))?
            .sequence
            + 1
    } else {
        0
    };
    crate::ports::JobQueue::port_job_enqueue(
        vault,
        txn,
        crate::attempt_queue::EnqueueAttempt {
            kind: ESIGN_SEAL_ATTEMPT_KIND.into(),
            payload: document.as_bytes().to_vec(),
            dedupe_key: Some(format!("{}:{generation}", document.to_hex())),
            run_id: None,
            now,
        },
    )?;
    Ok(())
}
/// Lands one recipient's Complete on `state`: the signed event, the notice
/// to each recipient it promotes, and the seal once the chain is ready.
#[allow(clippy::too_many_arguments)]
pub(super) fn sign(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    state: &EsignState,
    recipient: &str,
    next: &Option<String>,
    actor: EsignAuditActor,
    now: u64,
) -> Result<()> {
    let advanced = append(
        vault,
        txn,
        document,
        EsignEvent::Signed {
            recipient: recipient.to_owned(),
            next: next.clone(),
        },
        actor,
        now,
    )?;
    let promoted = advanced
        .recipients
        .iter()
        .filter(|(id, progress)| {
            progress.signing == SigningStatus::Ready
                && state.recipients[*id].signing != SigningStatus::Ready
        })
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    super::lifecycle::notify(
        vault,
        txn,
        document,
        &advanced,
        "pending",
        &promoted,
        super::lifecycle::NoticeTrigger {
            dispatch_ref: None,
            now,
        },
    )?;
    enqueue_seal(vault, txn, document, now)
}
impl Vault {
    /// No session or identity cookie. The capability proves access; explicit
    /// consent and the independently owner-controlled D6 dial authorize action.
    /// DATE values always come from the engine clock, never from `value`.
    pub fn execute_signing_action(
        &self,
        token: &EsignCapability,
        action: &SigningAction,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SigningOutcome> {
        self.execute_signing_action_as(token, action, SigningCaller::Bearer, ip, user_agent)
    }

    /// [`Self::execute_signing_action`] by a caller that showed who it is. An
    /// agent's Complete is an automated sign act: on a recipient the law
    /// keeps with a natural person it is refused, and elsewhere the D6 dial
    /// decides, holding what it does not open.
    pub fn execute_signing_action_as(
        &self,
        token: &EsignCapability,
        action: &SigningAction,
        caller: SigningCaller,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SigningOutcome> {
        let now = self.now_recorded_at();
        // Observe independently, including refused mutation attempts. A failed
        // observation transaction cannot turn a valid ceremony into a refusal.
        let _ = self.with_write_txn_grouped(|txn| {
            let cap = binding(self, txn, token)?;
            super::rate::observe(self, txn, &cap.document, &cap.recipient, now)
        });
        self.with_write_txn_grouped(|txn| {
            let cap = binding(self, txn, token)?;
            let document = EntityId::from_hex(&cap.document)?;
            // A reject narrows the document, so it lands even while an event
            // awaits its owner's answer; nothing else does.
            let rejecting = matches!(action, SigningAction::Reject { .. });
            let held = rejecting && super::ledger::held_in(self, txn, document)?;
            let mut state = if rejecting {
                super::ledger::restrictive_state_in(self, txn, document)?
            } else {
                state_in(self, txn, document)?
            };
            let recipient = state
                .document
                .recipients
                .iter()
                .find(|r| r.id == cap.recipient)
                .cloned()
                .ok_or_else(|| invalid("recipient removed"))?;
            let progress = state
                .recipients
                .get(&cap.recipient)
                .ok_or_else(|| invalid("recipient missing"))?;
            // Gate 1: a later sequential recipient is not even marked viewed.
            if progress.signing == SigningStatus::Waiting && state.status == DocumentStatus::Pending
            {
                return Ok(SigningOutcome::NotYourTurn);
            }
            // Gate 2: access authentication. A valid row is not authority after
            // revocation or its hard lifetime. No failure echoes the token.
            if cap.revoked_at.is_some() || now >= cap.hard_expires_at || now >= progress.expires_at
            {
                return Err(invalid("invalid capability"));
            }
            if state.status == DocumentStatus::Draft {
                return Err(invalid("document not sent"));
            }
            let actor = EsignAuditActor {
                actor: format!("recipient:{}", recipient.id),
                ip,
                user_agent,
            };
            // Gate 3: first-open is an event, idempotent on refresh.
            if progress.delivery != DeliveryStatus::Viewed && !held {
                state = append(
                    self,
                    txn,
                    document,
                    EsignEvent::Viewed {
                        recipient: recipient.id.clone(),
                    },
                    actor.clone(),
                    now,
                )?;
            }
            // Gate 4: terminal redirects never admit edits or sign actions.
            if matches!(
                state.status,
                DocumentStatus::Completed
                    | DocumentStatus::Rejected
                    | DocumentStatus::Voided
                    | DocumentStatus::Expired
            ) {
                return Ok(SigningOutcome::Terminal {
                    status: state.status,
                    item_count: state.document.items.len(),
                });
            }
            if state.rejection.is_some()
                || state.recipients[&recipient.id].signing == SigningStatus::Completed
            {
                return Ok(SigningOutcome::AwaitingSeal);
            }
            match action {
                SigningAction::Load => {}
                SigningAction::SaveField { field, value } => {
                    let definition = state
                        .document
                        .fields
                        .iter()
                        .find(|f| f.id == *field && f.recipient == recipient.id)
                        .ok_or_else(|| invalid("field not assigned to recipient"))?;
                    if let FieldValue::Signature { image_ref } = value {
                        let key = super::signature_image::image_binding_key(
                            document,
                            &recipient.id,
                            image_ref,
                        );
                        if !super::signature_image::BINDINGS.contains(&self.store, txn, &key)? {
                            return Err(invalid("signature image is not owned by this recipient"));
                        }
                    }
                    let value = if definition.meta == FieldMeta::Date {
                        let timestamp = i64::try_from(now).map_err(|_| invalid("date overflow"))?;
                        FieldValue::Text(
                            chrono::DateTime::from_timestamp(timestamp, 0)
                                .ok_or_else(|| invalid("date overflow"))?
                                .format("%Y-%m-%d")
                                .to_string(),
                        )
                    } else {
                        value.clone()
                    };
                    state = append(
                        self,
                        txn,
                        document,
                        EsignEvent::FieldSaved {
                            signature: SignatureRow {
                                field: field.clone(),
                                recipient: recipient.id.clone(),
                                value,
                                at: now,
                            },
                        },
                        actor,
                        now,
                    )?;
                }
                SigningAction::Complete { consent, next } => {
                    if !consent {
                        return Ok(SigningOutcome::ConsentRequired);
                    }
                    let automated = recipient.automated || caller == SigningCaller::Agent;
                    if automated && recipient.natural_person.is_some() {
                        return Err(invalid(
                            "a natural-person recipient signs in person, never through an agent",
                        ));
                    }
                    if automated
                        && !automated_signing_allowed(
                            self,
                            txn,
                            recipient.principal_ref.as_deref(),
                        )?
                    {
                        // D6 redirects the sign act up its role chain.
                        // Only a call that would land now is held.
                        state.clone().apply(
                            &EsignEvent::Signed {
                                recipient: recipient.id.clone(),
                                next: next.clone(),
                            },
                            now,
                        )?;
                        let held = super::escalation::hold(
                            self,
                            txn,
                            document,
                            &state.document.title,
                            &recipient,
                            next,
                            &actor,
                            now,
                        )?;
                        return Ok(SigningOutcome::HeldForOwner {
                            held_at: held.held_at,
                        });
                    }
                    sign(self, txn, document, &state, &recipient.id, next, actor, now)?;
                    return Ok(SigningOutcome::AwaitingSeal);
                }
                SigningAction::Reject { reason } => {
                    append(
                        self,
                        txn,
                        document,
                        EsignEvent::Declined {
                            recipient: recipient.id,
                            reason: reason.clone(),
                        },
                        actor,
                        now,
                    )?;
                    enqueue_seal(self, txn, document, now)?;
                    return Ok(SigningOutcome::AwaitingSeal);
                }
            }
            let presentations = state
                .document
                .fields
                .iter()
                .filter(|f| f.recipient == recipient.id)
                .map(|field| {
                    super::render::present_field(
                        field,
                        state.signatures.get(&field.id).map(|s| &s.value),
                    )
                    .map_err(|_| invalid("field cannot be presented"))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(SigningOutcome::Page(SigningPage {
                item_count: state.document.items.len(),
                presentations,
                title: state.document.title,
                recipient: recipient.id.clone(),
                fields: state
                    .document
                    .fields
                    .into_iter()
                    .filter(|f| f.recipient == recipient.id)
                    .collect(),
                values: state
                    .signatures
                    .into_iter()
                    .filter(|(_, v)| v.recipient == recipient.id)
                    .collect(),
            }))
        })
    }
}
