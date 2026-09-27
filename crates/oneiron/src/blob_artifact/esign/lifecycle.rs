//! Pack-supplied lifecycle timing and atomic claim/edge-handoff sweeps.
use super::{
    ledger::{append, events_in, hash, state_in},
    model::*,
};
use crate::outbound::{OutboundDispatchOutcome, OutboundDispatchRequest};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignNoticeSwitches {
    pub invite: bool,
    pub pending: bool,
    pub completed: bool,
    pub rejection: bool,
    pub void: bool,
    pub expiry: bool,
}
impl Default for EsignNoticeSwitches {
    fn default() -> Self {
        Self {
            invite: true,
            pending: true,
            completed: true,
            rejection: true,
            void: true,
            expiry: true,
        }
    }
}

/// Rule values belong to the installing pack; the engine does not choose a
/// reminder ladder or a default expiry window. Seconds are measured from send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignLifecycleRules {
    pub expiry_after_seconds: u64,
    pub first_reminder_after_seconds: u64,
    pub repeat_reminder_every_seconds: u64,
    pub reminder_cap_seconds: u64,
    pub notices: EsignNoticeSwitches,
}
impl EsignLifecycleRules {
    pub(super) fn validate(&self) -> Result<()> {
        if self.expiry_after_seconds == 0
            || self.first_reminder_after_seconds == 0
            || self.repeat_reminder_every_seconds == 0
            || self.reminder_cap_seconds < self.first_reminder_after_seconds
            || self.reminder_cap_seconds > self.expiry_after_seconds
        {
            return Err(invalid("invalid lifecycle rules"));
        }
        Ok(())
    }
}
pub(super) fn rules_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
) -> Result<Option<EsignLifecycleRules>> {
    Ok(state_in(vault, txn, document)?.document.lifecycle)
}

/// Stage an edge-delivery intent inside the SAME writer transaction as its
/// triggering event. The edge resolves attachment refs and performs mail delivery.
/// A claim replay cannot create a second notice for the same transition/recipient.
pub(super) struct NoticeTrigger<'a> {
    pub(super) dispatch_ref: Option<&'a str>,
    pub(super) now: u64,
}

pub(super) fn notify(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    state: &EsignState,
    transition: &str,
    recipients: &[String],
    trigger: NoticeTrigger<'_>,
) -> Result<()> {
    let NoticeTrigger { dispatch_ref, now } = trigger;
    let switches = state
        .document
        .lifecycle
        .as_ref()
        .map_or_else(EsignNoticeSwitches::default, |r| r.notices.clone());
    let enabled = match transition {
        "invite" => switches.invite,
        "pending" => switches.pending,
        "completed" => switches.completed,
        "rejection" => switches.rejection,
        "void" => switches.void,
        "expiry" => switches.expiry,
        "reminder" => true,
        _ => return Err(invalid("unknown transition")),
    };
    if !enabled {
        return Ok(());
    }
    let (attachments, seal_generation) = if matches!(transition, "completed" | "rejection") {
        if !matches!(
            state.status,
            DocumentStatus::Completed | DocumentStatus::Rejected
        ) || state.sealed_sha256.is_empty()
        {
            return Err(invalid("terminal mail requires sealed output"));
        }
        let manifest = super::seal::CANONICAL
            .get_bytes(&vault.store, txn, &document)?
            .ok_or_else(|| invalid("sealed manifest missing"))?;
        let sealed: super::SealedDocument =
            serde_json::from_slice(&manifest).map_err(|_| invalid("sealed manifest schema"))?;
        if sealed.rejected != (transition == "rejection")
            || sealed.items.len() != state.sealed_sha256.len()
            || sealed
                .items
                .iter()
                .zip(&state.sealed_sha256)
                .any(|(item, sha)| item.sha256 != *sha)
        {
            return Err(invalid("sealed mail binding mismatch"));
        }
        (
            if transition == "completed" {
                sealed.items
            } else {
                Vec::new()
            },
            Some(sealed.attempt_ref),
        )
    } else {
        (Vec::new(), None)
    };

    let origin = if dispatch_ref.is_none() {
        let rows = events_in(vault, txn, document)?;
        let sender = rows
            .iter()
            .find(|r| matches!(r.event, EsignEvent::Sent))
            .or_else(|| rows.first())
            .ok_or_else(|| invalid("missing notice origin"))?;
        let trigger = rows.last().ok_or_else(|| invalid("missing notice event"))?;
        Some((
            sender.actor.actor.clone(),
            crate::entity_id::bytes_to_hex_lower(&hash(trigger)?),
        ))
    } else {
        None
    };
    for recipient in recipients {
        let row = state
            .document
            .recipients
            .iter()
            .find(|r| &r.id == recipient)
            .ok_or_else(|| invalid("notification recipient missing"))?;
        let payload = serde_json::to_vec(&serde_json::json!({
            "document": document.to_hex(), "recipient": recipient,
            "email": row.email, "transition": transition,
            "dispatch_ref": dispatch_ref, "sealed_items": attachments,
            "principal": origin.as_ref().map(|v| v.0.as_str()),
            "event_ref": origin.as_ref().map(|v| v.1.as_str()),
            "generation": seal_generation,
        }))
        .map_err(|_| invalid("delivery encoding"))?;
        crate::attempt_queue::AttemptQueue::new(vault).enqueue_in_txn(
            txn,
            crate::attempt_queue::EnqueueAttempt {
                kind: if dispatch_ref.is_some() {
                    "esign.delivery"
                } else {
                    "esign.notice"
                }
                .into(),
                payload,
                dedupe_key: Some(if let Some(generation) = &seal_generation {
                    format!(
                        "{}:{transition}:{recipient}:{generation}",
                        document.to_hex()
                    )
                } else if transition == "reminder" {
                    format!(
                        "{}:{transition}:{recipient}:{}",
                        document.to_hex(),
                        dispatch_ref.unwrap_or_default()
                    )
                } else {
                    format!("{}:{transition}:{recipient}", document.to_hex())
                }),
                run_id: None,
                now,
            },
        )?;
    }
    Ok(())
}

impl EsignState {
    /// The same eligibility law runs during claim folding and at cron admission.
    /// A replayed early, duplicate or post-cap reminder can never advance state.
    pub(super) fn next_reminder(&self, recipient: &str, now: u64) -> Result<Option<u32>> {
        let Some(rules) = &self.document.lifecycle else {
            return Ok(None);
        };
        let progress = self
            .recipients
            .get(recipient)
            .ok_or_else(|| invalid("unknown reminder recipient"))?;
        if self.status != DocumentStatus::Pending
            || self.rejection.is_some()
            || progress.signing != SigningStatus::Ready
            || now >= progress.expires_at
            || now >= self.document.expires_at
        {
            return Ok(None);
        }
        let sent = self
            .sent_at
            .ok_or_else(|| invalid("pending document has no send claim"))?;
        if now > sent.saturating_add(rules.reminder_cap_seconds) {
            return Ok(None);
        }
        let rung = u32::try_from(
            self.reminders
                .iter()
                .filter(|(id, _)| id == recipient)
                .count(),
        )
        .map_err(|_| invalid("reminder rung overflow"))?;
        let due = self.reminder_at.get(recipient).map_or_else(
            || sent.saturating_add(rules.first_reminder_after_seconds),
            |last| last.saturating_add(rules.repeat_reminder_every_seconds),
        );
        Ok((now >= due).then_some(rung))
    }
}
pub(super) fn reminder_due(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    recipient: &str,
    now: u64,
) -> Result<Option<u32>> {
    state_in(vault, txn, document)?.next_reminder(recipient, now)
}
impl Vault {
    /// Create a draft using pack data. A zero expiry means materialize the
    /// supplied window NOW, separately for the document and each recipient.
    pub fn create_esign_document_with_lifecycle(
        &self,
        document: EntityId,
        body: &EsignDocument,
        actor: EsignAuditActor,
        now: u64,
        rules: &EsignLifecycleRules,
    ) -> Result<()> {
        rules.validate()?;
        let mut body = body.clone();
        let expires = if body.expires_at == 0 || body.recipients.iter().any(|r| r.expires_at == 0) {
            now.checked_add(rules.expiry_after_seconds)
                .ok_or_else(|| invalid("expiry overflow"))?
        } else {
            0
        };
        if body.expires_at == 0 {
            body.expires_at = expires;
        }
        for recipient in &mut body.recipients {
            if recipient.expires_at == 0 {
                recipient.expires_at = body.expires_at.min(expires);
            }
        }
        body.lifecycle = Some(rules.clone());
        self.create_esign_document(document, &body, actor, now)
    }
    /// Sweep is caller-scheduled. Each expiry claim and its edge notification
    /// commit atomically; a repeated or racing sweep observes the terminal.
    pub fn sweep_esign_expiry(&self, documents: &[EntityId], now: u64) -> Result<usize> {
        if documents.len() > 100 {
            return Err(invalid("expiry sweep batch exceeds 100"));
        }
        self.with_write_txn(|txn| {
            let mut count = 0;
            for &document in documents {
                let state = state_in(self, txn, document)?;
                if let Some(recipient) = state.expiry_target(now) {
                    let state = append(
                        self,
                        txn,
                        document,
                        EsignEvent::Expired { recipient },
                        EsignAuditActor {
                            actor: "engine:expiry".into(),
                            ip: None,
                            user_agent: None,
                        },
                        now,
                    )?;
                    let recipients = state
                        .document
                        .recipients
                        .iter()
                        .map(|r| r.id.clone())
                        .collect::<Vec<_>>();
                    notify(
                        self,
                        txn,
                        document,
                        &state,
                        "expiry",
                        &recipients,
                        NoticeTrigger {
                            dispatch_ref: None,
                            now,
                        },
                    )?;
                    count += 1;
                }
            }
            Ok(count)
        })
    }
    /// Sweep due reminders through the existing OF-327 dispatch gate. A denied
    /// dispatch claims nothing; a successful sink appends esign.reminded and
    /// queues the exact recipient in one transaction. The caller supplies its
    /// authenticated actor, grants, window and unique intent/receipt identity.
    pub fn sweep_esign_reminders(
        &self,
        documents: &[EntityId],
        now: u64,
        mut request: impl FnMut(EntityId, &EsignRecipient, u32) -> OutboundDispatchRequest,
    ) -> std::result::Result<usize, crate::outbound::OutboundDispatchError> {
        if documents.len() > 100 {
            return Err(invalid("reminder sweep batch exceeds 100").into());
        }
        let mut sent = 0;
        for &document in documents {
            let candidates = {
                let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
                let state = state_in(self, &txn, document)?;
                let mut due = Vec::new();
                for r in state.document.recipients {
                    if let Some(rung) = reminder_due(self, &txn, document, &r.id, now)? {
                        due.push((r, rung));
                    }
                }
                due
            };
            for (recipient, rung) in candidates {
                let command = super::EsignOutboundCommand {
                    document: document.to_hex(),
                    recipient_count: {
                        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
                        state_in(self, &txn, document)?.document.recipients.len()
                    },
                    verb: super::EsignOutboundVerb::Remind,
                    reason: None,
                };
                let next_request = request(document, &recipient, rung);
                if next_request.occurred_at != now {
                    return Err(invalid("sweep clock differs from dispatch clock").into());
                }
                let result =
                    self.dispatch_esign_reminder(next_request, &command, &recipient.id, rung)?;
                if result.outcome == OutboundDispatchOutcome::DeliveredToChannel {
                    sent += 1;
                }
            }
        }
        Ok(sent)
    }
}
