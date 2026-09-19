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
    HumanActionRequired,
    ConsentRequired,
}

pub const ESIGN_SEAL_ATTEMPT_KIND: &str = "esign.seal";
pub(super) fn enqueue_seal(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    now: u64,
) -> Result<()> {
    let state = state_in(vault, txn, document)?;
    if !state.ready_to_seal() {
        return Ok(());
    }
    let event_count = super::ledger::events_in(vault, txn, document)?.len();
    let generation = if state.reseal_pending {
        event_count as u64
    } else {
        0
    };
    crate::attempt_queue::AttemptQueue::new(vault).enqueue_in_txn(
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
        let now = crate::unix_seconds_now();
        // Commit accounting independently, including refused mutation attempts.
        self.with_write_txn(|txn| {
            let cap = binding(self, txn, token)?;
            super::rate::admit(self, txn, &cap.document, &cap.recipient, now)
        })?;
        self.with_write_txn(|txn| {
            let cap = binding(self, txn, token)?;
            let document = EntityId::from_hex(&cap.document)?;
            let mut state = state_in(self, txn, document)?;
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
            if progress.delivery != DeliveryStatus::Viewed {
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
                        if self.store.vault_meta.get(txn, &key)?.is_none() {
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
                        actor.clone(),
                        now,
                    )?;
                }
                SigningAction::Complete { consent, next } => {
                    if !consent {
                        return Ok(SigningOutcome::ConsentRequired);
                    }
                    if recipient.automated
                        && !automated_signing_allowed(
                            self,
                            txn,
                            recipient.principal_ref.as_deref(),
                        )?
                    {
                        return Ok(SigningOutcome::HumanActionRequired);
                    }
                    append(
                        self,
                        txn,
                        document,
                        EsignEvent::Signed {
                            recipient: recipient.id.clone(),
                            next: next.clone(),
                        },
                        actor.clone(),
                        now,
                    )?;
                    enqueue_seal(self, txn, document, now)?;
                    return Ok(SigningOutcome::AwaitingSeal);
                }
                SigningAction::Reject { reason } => {
                    append(
                        self,
                        txn,
                        document,
                        EsignEvent::Declined {
                            recipient: recipient.id.clone(),
                            reason: reason.clone(),
                        },
                        actor.clone(),
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
