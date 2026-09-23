//! Owner-tier reseal admission and bounded repair sweep.
use super::{
    ceremony::enqueue_seal,
    ledger::{append, events_in, state_in},
    model::*,
    principals::verify_owner,
};
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::{EntityId, Result, Vault};
impl Vault {
    pub fn request_esign_reseal(
        &self,
        owner: &AuthenticatedOwner,
        document: EntityId,
        grant_ref: &str,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<()> {
        let now = crate::unix_seconds_now();
        self.with_write_txn(|txn| {
            verify_owner(self, txn, owner)?;
            let required = GrantBound::action(
                ActorBound::new(owner.actor().to_hex())?,
                ActionClass::new("esign.reseal")?,
                ActionEnvelope::new([format!("document:{}", document.to_hex())])?,
            )?;
            let granted = self
                .active_standing_consent_grants_in_txn(txn)?
                .into_iter()
                .any(|g| g.bound().digest().to_hex() == grant_ref && g.bound().contains(&required));
            if !granted {
                return Err(invalid("live owner-tier reseal grant required"));
            }
            let state = state_in(self, txn, document)?;
            if state.reseal_pending {
                return Err(invalid("reseal already pending"));
            }
            append(
                self,
                txn,
                document,
                EsignEvent::ResealRequested {
                    owner: owner.actor().to_hex(),
                    authority: format!(
                        "grant:{grant_ref};owner_decision:{}",
                        owner.decision_id().to_hex()
                    ),
                },
                EsignAuditActor {
                    actor: owner.actor().to_hex(),
                    ip,
                    user_agent,
                },
                now,
            )?;
            enqueue_seal(self, txn, document, now)
        })
    }
    /// Backstop scan is caller-scheduled every fifteen minutes. Only seal-ready
    /// requests whose completion trigger is 15 minutes..6 hours old qualify.
    /// Voids and expiries can never become seal jobs.
    pub fn sweep_esign_seals(&self, documents: &[EntityId], now: u64) -> Result<usize> {
        if documents.len() > 100 {
            return Err(invalid("seal sweep batch exceeds 100"));
        }
        self.with_write_txn(|txn| {
            let mut queued = 0;
            for &document in documents {
                let state = state_in(self, txn, document)?;
                if !state.ready_to_seal() {
                    continue;
                }
                let rows = events_in(self, txn, document)?;
                let Some(trigger) = rows.iter().rev().find(|r| {
                    matches!(
                        r.event,
                        EsignEvent::Signed { .. }
                            | EsignEvent::Declined { .. }
                            | EsignEvent::Sent
                            | EsignEvent::ResealRequested { .. }
                    )
                }) else {
                    continue;
                };
                let age = now.saturating_sub(trigger.at);
                if (15 * 60..=6 * 60 * 60).contains(&age) {
                    enqueue_seal(self, txn, document, now)?;
                    queued += 1;
                }
            }
            Ok(queued)
        })
    }
}
