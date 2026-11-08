//! One public signing executor: turn, access, viewed, terminal, then action.
use super::rate::{LimitCrossing, keep_limit_crossings};
use super::{
    capability::{EsignCapability, binding},
    field_admission::{EventFields, InspectedPages, inspect_event_pages},
    ledger::{append, append_inspected, state_in},
    model::*,
    principals::automated_signing_allowed,
};
use crate::limit_ask::EngineLimit;
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SigningAction {
    Load,
    SaveField { field: String, value: FieldValue },
    Complete { consent: bool, next: Option<String> },
    Reject { reason: String },
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SigningPage {
    pub item_count: usize,
    pub title: String,
    pub recipient: String,
    pub fields: Vec<EsignField>,
    pub presentations: Vec<super::render::FieldPresentation>,
    pub values: BTreeMap<String, SignatureRow>,
}
/// Receipt observations of the sealed bytes, in document item order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SigningSealedItem {
    pub sha256: String,
    pub active_content: super::sealer::SealActiveContentFacts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", content = "data", rename_all = "snake_case")]
pub enum SigningOutcome {
    Page(SigningPage),
    NotYourTurn,
    Terminal {
        status: DocumentStatus,
        item_count: usize,
        /// None when no sealing receipt is available to read.
        sealed_items: Option<Vec<SigningSealedItem>>,
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

impl SigningCaller {
    pub(super) fn authentication_method(self) -> EsignAuthenticationMethod {
        match self {
            Self::Bearer => EsignAuthenticationMethod::Bearer,
            Self::Person => EsignAuthenticationMethod::Person,
            Self::Agent => EsignAuthenticationMethod::Agent,
        }
    }
}

impl SigningAction {
    fn verb(&self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::SaveField { .. } => "save_field",
            Self::Complete { .. } => "complete",
            Self::Reject { .. } => "reject",
        }
    }
}

pub(super) fn signed_event(
    document: &EsignDocument,
    recipient: &str,
    next: &Option<String>,
    evidence: EsignSigningEvidence,
) -> EsignEvent {
    EsignEvent::Signed {
        recipient: recipient.to_owned(),
        next: next.clone(),
        evidence,
        items: document.items.clone(),
    }
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
        crate::store::attempt_inputs::EnqueueAttempt {
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
/// to each recipient it promotes, and the seal once the chain is ready. Its
/// fields are laid out on `inspected`, the recipient's PDFs as they were
/// inspected before this writer (FIX 9609).
#[allow(clippy::too_many_arguments)]
pub(super) fn sign(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    state: &EsignState,
    recipient: &str,
    next: &Option<String>,
    evidence: EsignSigningEvidence,
    actor: EsignAuditActor,
    now: u64,
    inspected: &InspectedPages,
) -> Result<()> {
    let advanced = append_inspected(
        vault,
        txn,
        document,
        signed_event(&state.document, recipient, next, evidence),
        actor,
        now,
        inspected,
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
/// The PDFs a signing act's writer lays fields on, inspected before it (FIX
/// 9609): none for an act that appends no field event, or that the writer's
/// own capability, ceiling, turn, status, consent or D6 gates refuse in this
/// read snapshot, so a refused call parses nothing.
fn inspect_act_pages(
    vault: &Vault,
    token: &EsignCapability,
    action: &SigningAction,
    caller: SigningCaller,
    now: u64,
    ceiling: &dyn Fn(&heed::RoTxn<'_>, EntityId) -> Result<bool>,
) -> InspectedPages {
    if !matches!(
        action,
        SigningAction::SaveField { .. } | SigningAction::Complete { consent: true, .. }
    ) {
        return InspectedPages::default();
    }
    inspect_event_pages(vault, |txn| {
        let cap = binding(vault, txn, token)?;
        super::lane_scope::ceiling_admits_in(ceiling, txn, &cap.document)?;
        let state = state_in(vault, txn, EntityId::from_hex(&cap.document)?)?;
        let (Some(recipient), Some(progress)) = (
            state
                .document
                .recipients
                .iter()
                .find(|r| r.id == cap.recipient),
            state.recipients.get(&cap.recipient),
        ) else {
            return Ok(None);
        };
        if state.status != DocumentStatus::Pending
            || state.rejection.is_some()
            || matches!(
                progress.signing,
                SigningStatus::Waiting | SigningStatus::Completed
            )
            || cap.revoked_at.is_some()
            || now >= cap.hard_expires_at
            || now >= progress.expires_at
        {
            return Ok(None);
        }
        let fields = match action {
            SigningAction::SaveField { field, .. } => {
                if !state
                    .document
                    .fields
                    .iter()
                    .any(|f| f.id == *field && f.recipient == recipient.id)
                {
                    return Ok(None);
                }
                EventFields::Saved(field.clone())
            }
            SigningAction::Complete { .. } => {
                let automated = recipient.automated || caller == SigningCaller::Agent;
                if automated
                    && (recipient.natural_person.is_some()
                        || !automated_signing_allowed(
                            vault,
                            txn,
                            recipient.principal_ref.as_deref(),
                        )?)
                {
                    return Ok(None);
                }
                EventFields::Signer(recipient.id.clone())
            }
            SigningAction::Load | SigningAction::Reject { .. } => return Ok(None),
        };
        Ok(Some((state, fields)))
    })
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
        self.execute_signing_action_as(token, action, SigningCaller::Bearer, None, ip, user_agent)
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
        verified_actor: Option<EntityId>,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SigningOutcome> {
        self.execute_signing_action_within(
            token,
            action,
            caller,
            verified_actor,
            ip,
            user_agent,
            &|_, _| Ok(true),
        )
    }

    /// [`Self::execute_signing_action_as`] under a narrowed caller's
    /// credential ceiling (FIX 6403): `ceiling` judges the document the
    /// capability binds as soon as the binding names it, in the observation
    /// writer and in the act's writer, before either reads or writes
    /// anything else. A document out of its reach answers as an invalid
    /// capability and is not observed. The capability, turn, access,
    /// consent and D6 gates stand as they are.
    pub(super) fn execute_signing_action_within(
        &self,
        token: &EsignCapability,
        action: &SigningAction,
        caller: SigningCaller,
        verified_actor: Option<EntityId>,
        ip: Option<String>,
        user_agent: Option<String>,
        ceiling: &dyn Fn(&heed::RoTxn<'_>, EntityId) -> Result<bool>,
    ) -> Result<SigningOutcome> {
        let now = self.now_recorded_at();
        // Observe independently, including refused mutation attempts. A failed
        // observation transaction cannot turn a valid ceremony into a refusal.
        let _ = self.with_write_txn_grouped(|txn| {
            let cap = binding(self, txn, token)?;
            super::lane_scope::ceiling_admits_in(ceiling, txn, &cap.document)?;
            super::rate::observe(
                self,
                txn,
                &cap.document,
                &cap.recipient,
                now,
                action.verb(),
                caller.authentication_method(),
                verified_actor,
            )
        });
        // FIX 9609: the PDFs this act lays fields on are inspected here,
        // before its writer, which lays the fields out on this inspection.
        let inspected = inspect_act_pages(self, token, action, caller, now, ceiling);
        self.with_write_txn_grouped(|txn| {
            let cap = binding(self, txn, token)?;
            super::lane_scope::ceiling_admits_in(ceiling, txn, &cap.document)?;
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
            // An owned snapshot: `state` is reassigned by the appends below.
            let progress = state
                .recipients
                .get(&cap.recipient)
                .cloned()
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
            // Gate 3: first-open is an event, idempotent on refresh. Viewed
            // is human-action-only evidence (FIX 7855): a known agent call
            // never marks viewed, while Bearer/Person acts still do. An
            // agent with a Gate-2-valid capability records AccessVerified
            // instead, so its field saves and sign acts land on verified
            // access without inventing Viewed.
            if !matches!(action, SigningAction::Load)
                && progress.delivery != DeliveryStatus::Viewed
                && !held
                && caller != SigningCaller::Agent
            {
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
            if caller == SigningCaller::Agent
                && !matches!(action, SigningAction::Load)
                && progress.access != AccessStatus::Verified
                && !held
            {
                state = append(
                    self,
                    txn,
                    document,
                    EsignEvent::AccessVerified {
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
                let sealed_items = super::seal::CANONICAL
                    .get(&self.store, txn, &document)
                    .ok()
                    .flatten()
                    .map(|manifest| {
                        manifest
                            .items
                            .into_iter()
                            .map(|item| SigningSealedItem {
                                sha256: crate::entity_id::bytes_to_hex_lower(&item.sha256),
                                active_content: item.active_content,
                            })
                            .collect()
                    });
                return Ok(SigningOutcome::Terminal {
                    status: state.status,
                    item_count: state.document.items.len(),
                    sealed_items,
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
                    let crossing = match (&definition.meta, &value) {
                        (FieldMeta::Email, FieldValue::Text(text)) => text_crossing(
                            self,
                            EngineLimit::EsignEmailFieldBytes,
                            text.len() as u64,
                        ),
                        (FieldMeta::Name | FieldMeta::Date, FieldValue::Text(text)) => {
                            text_crossing(self, EngineLimit::EsignNameFieldBytes, text.len() as u64)
                        }
                        _ => None,
                    };
                    state = append_inspected(
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
                        &inspected,
                    )?;
                    if let Some(crossing) = crossing {
                        keep_limit_crossings(
                            self,
                            txn,
                            &cap.document,
                            &cap.recipient,
                            &[crossing],
                            now,
                        )?;
                    }
                }
                SigningAction::Complete { consent, next } => {
                    if !consent {
                        return Ok(SigningOutcome::ConsentRequired);
                    }
                    let evidence = EsignSigningEvidence {
                        authentication_method: caller.authentication_method(),
                        disclosure_version: None,
                        consent: *consent,
                        intent: EsignSigningIntent::Direct,
                    };
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
                            &signed_event(&state.document, &recipient.id, next, evidence.clone()),
                            now,
                        )?;
                        let held = super::escalation::hold(
                            self,
                            txn,
                            document,
                            &state.document.title,
                            &recipient,
                            next,
                            evidence.clone(),
                            &actor,
                            now,
                        )?;
                        return Ok(SigningOutcome::HeldForOwner {
                            held_at: held.held_at,
                        });
                    }
                    sign(
                        self,
                        txn,
                        document,
                        &state,
                        &recipient.id,
                        next,
                        evidence,
                        actor,
                        now,
                        &inspected,
                    )?;
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
                    if let Some(crossing) = text_crossing(
                        self,
                        EngineLimit::EsignRejectReasonBytes,
                        reason.len() as u64,
                    ) {
                        keep_limit_crossings(
                            self,
                            txn,
                            &cap.document,
                            &cap.recipient,
                            &[crossing],
                            now,
                        )?;
                    }
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

fn text_crossing(vault: &Vault, row: EngineLimit, measured: u64) -> Option<LimitCrossing> {
    let bound = vault.limit_watch().bound(row);
    (measured > bound).then_some((row, bound, measured))
}
