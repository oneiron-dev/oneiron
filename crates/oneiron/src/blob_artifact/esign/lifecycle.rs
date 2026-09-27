//! Durable, transactionally claimed e-sign lifecycle notifications and expiry.
use super::{
    ledger::{append, state_in},
    model::*,
};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

pub(super) const INDEX: &[u8] = b"esign.lifecycle.v1/";
pub const ESIGN_DELIVERY_ATTEMPT_KIND: &str = "esign.delivery";

/// Pack policy defaults are frozen into each draft, not looked up at send time.
pub(super) fn materialize_expiry(doc: &mut EsignDocument, now: u64) -> Result<()> {
    if doc.expires_at == 0 {
        let at = chrono::DateTime::from_timestamp(
            i64::try_from(now).map_err(|_| invalid("expiry clock overflow"))?,
            0,
        )
        .ok_or_else(|| invalid("expiry clock overflow"))?;
        doc.expires_at = u64::try_from(
            at.checked_add_months(chrono::Months::new(3))
                .ok_or_else(|| invalid("expiry clock overflow"))?
                .timestamp(),
        )
        .map_err(|_| invalid("expiry clock overflow"))?;
    }
    for recipient in &mut doc.recipients {
        if recipient.expires_at == 0 {
            recipient.expires_at = doc.expires_at;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsignMailTransition {
    Invite,
    Pending,
    Completed,
    Rejection,
    Void,
    Expiry,
    Reminder,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignDeliveryPayload {
    pub document: String,
    pub recipient: String,
    pub transition: EsignMailTransition,
    /// The signed outbound intent or event sequence: stable provider idempotency seed.
    pub trigger: String,
}

pub(super) fn enqueue(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    recipient: &str,
    transition: EsignMailTransition,
    trigger: &str,
    now: u64,
) -> Result<()> {
    let payload = EsignDeliveryPayload {
        document: document.to_hex(),
        recipient: recipient.to_owned(),
        transition,
        trigger: trigger.to_owned(),
    };
    let bytes = serde_json::to_vec(&payload).map_err(|_| invalid("delivery encoding"))?;
    let dedupe_key = format!("esign:{}", blake3::hash(&bytes).to_hex());
    crate::attempt_queue::AttemptQueue::new(vault).enqueue_in_txn(
        txn,
        crate::attempt_queue::EnqueueAttempt {
            kind: ESIGN_DELIVERY_ATTEMPT_KIND.into(),
            payload: bytes,
            dedupe_key: Some(dedupe_key),
            run_id: None,
            now,
        },
    )?;
    Ok(())
}

pub(super) fn transition(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    previous: Option<&EsignState>,
    state: &EsignState,
    row: &EsignEventRow,
) -> Result<()> {
    let event = &row.event;
    let now = row.at;
    let sequence = row.sequence;
    let policy = &state.document.lifecycle;
    let choice = match event {
        EsignEvent::Signed { .. } if policy.pending => Some(EsignMailTransition::Pending),
        EsignEvent::Sealed {
            rejected: false, ..
        } if policy.completed && previous.is_some_and(|s| s.status == DocumentStatus::Pending) => {
            Some(EsignMailTransition::Completed)
        }
        EsignEvent::Sealed { rejected: true, .. }
            if policy.rejection
                && previous.is_some_and(|s| s.status == DocumentStatus::Pending) =>
        {
            Some(EsignMailTransition::Rejection)
        }
        EsignEvent::Voided { .. } if policy.voided => Some(EsignMailTransition::Void),
        EsignEvent::Expired | EsignEvent::RecipientExpired { .. } if policy.expired => {
            Some(EsignMailTransition::Expiry)
        }
        EsignEvent::ReminderClaimed { .. } if policy.reminder => {
            Some(EsignMailTransition::Reminder)
        }
        _ => None,
    };
    if let Some(kind) = choice {
        let trigger = format!("event:{sequence}");
        for recipient in &state.document.recipients {
            let status = &state.recipients[&recipient.id];
            let selected = match kind {
                EsignMailTransition::Pending => previous.is_some_and(|before| {
                    before.recipients[&recipient.id].signing == SigningStatus::Waiting
                        && status.signing == SigningStatus::Ready
                }),
                EsignMailTransition::Reminder => {
                    matches!(event, EsignEvent::ReminderClaimed { recipient: id, .. } if id == &recipient.id)
                }
                _ => true,
            };
            if selected {
                enqueue(vault, txn, document, &recipient.id, kind, &trigger, now)?;
            }
        }
    }
    Ok(())
}

/// A stage is active only in its own window; a missed 5-day sweep cannot
/// emit a stale 5-day mail in the 2-day window.
pub(super) fn reminder_due(
    policy: &EsignLifecyclePolicy,
    expiry: u64,
    stage: u8,
    now: u64,
) -> bool {
    let Some(&lead) = policy.reminder_lead_seconds.get(stage as usize) else {
        return false;
    };
    now >= expiry.saturating_sub(lead)
        && now < expiry
        && (stage == 1 || now < expiry.saturating_sub(policy.reminder_lead_seconds[1]))
}

fn sweep_one(vault: &Vault, document: EntityId, now: u64) -> Result<usize> {
    vault.with_write_txn(|txn| {
        if vault.get_blob_artifact_in_txn(txn, &document)?.is_none() {
            return Ok(0);
        }
        let state = state_in(vault, txn, document)?;
        if !matches!(
            state.status,
            DocumentStatus::Draft | DocumentStatus::Pending
        ) {
            return Ok(0);
        }
        let actor = EsignAuditActor {
            actor: "engine:lifecycle".into(),
            ip: None,
            user_agent: None,
        };
        if now >= state.document.expires_at {
            append(vault, txn, document, EsignEvent::Expired, actor, now)?;
            return Ok(1);
        }
        if let Some(recipient) = state.document.recipients.iter().find(|r| {
            matches!(r.role, RecipientRole::Signer | RecipientRole::Approver)
                && state.recipients[&r.id].signing != SigningStatus::Completed
                && now >= state.recipients[&r.id].expires_at
        }) {
            append(
                vault,
                txn,
                document,
                EsignEvent::RecipientExpired {
                    recipient: recipient.id.clone(),
                },
                actor,
                now,
            )?;
            return Ok(1);
        }
        if state.status != DocumentStatus::Pending || state.rejection.is_some() {
            return Ok(0);
        }
        let Some(sent) = state.sent_at else {
            return Ok(0);
        };
        let policy = &state.document.lifecycle;
        if !policy.reminder || now.saturating_sub(sent) >= policy.reminder_max_age_seconds {
            return Ok(0);
        }
        let mut claimed = 0;
        for recipient in &state.document.recipients {
            let progress = &state.recipients[&recipient.id];
            if progress.signing != SigningStatus::Ready {
                continue;
            }
            for stage in 0..2u8 {
                if !state
                    .reminder_claims
                    .contains(&(recipient.id.clone(), stage))
                    && reminder_due(policy, progress.expires_at, stage, now)
                {
                    append(
                        vault,
                        txn,
                        document,
                        EsignEvent::ReminderClaimed {
                            recipient: recipient.id.clone(),
                            stage,
                        },
                        actor.clone(),
                        now,
                    )?;
                    claimed += 1;
                }
            }
        }
        Ok(claimed)
    })
}
impl Vault {
    /// Cron entry point. Each claim and its mail attempt commit together; two
    /// sweepers serialize on the vault writer lock and never double-claim.
    pub fn sweep_esign_lifecycle(&self, now: u64) -> Result<usize> {
        let ids = {
            let txn = self.store.env.read_txn()?;
            let mut ids = Vec::new();
            for entry in self.store.vault_meta.prefix_iter(&txn, INDEX)? {
                let (key, _) = entry?;
                let bytes: [u8; 16] = key[INDEX.len()..]
                    .try_into()
                    .map_err(|_| invalid("lifecycle index"))?;
                ids.push(EntityId::from_bytes(bytes)?);
            }
            ids
        };
        let mut count = 0;
        for id in ids {
            count += sweep_one(self, id, now)?;
        }
        Ok(count)
    }
}
