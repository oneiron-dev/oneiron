//! A lifecycle request a full budget window paces (FIX 8686). The Gate
//! allowed it, but every full row of its channel's connector key is a
//! count-bound window that refuses rather than suspends: nothing is applied,
//! no gate decision is recorded and nothing is charged. Its receipt says it
//! waits; its result names the instant the window opens, and a retry naming
//! the same request ref then is the same request. Also the result's hold
//! note, which names that wait or the press a hold waits for.

use super::*;

/// The outcome of a lifecycle request a full budget window paces.
const LIFECYCLE_PACED: &str = "paced";

impl ChannelIdentityLifecycleResult {
    /// FIX 6424 part 3: `; approve-once digest <hex> (request <ref>)` for a
    /// request the Gate held naming one; FIX 8686: `; budget window opens at
    /// <unix seconds> (request <ref>)` for one a full window paces; else
    /// nothing: what a landing that reports a hold in words appends after
    /// its own, unchanged.
    #[must_use]
    pub fn held_approval_note(&self) -> String {
        if let Some(until) = self.paced_until {
            return match self.request_ref {
                Some(request_ref) => format!(
                    "; budget window opens at {until} (request {})",
                    request_ref.to_hex()
                ),
                None => format!("; budget window opens at {until}"),
            };
        }
        match (self.approval_digest.as_deref(), self.request_ref) {
            (Some(digest), Some(request_ref)) => format!(
                "; approve-once digest {digest} (request {})",
                request_ref.to_hex()
            ),
            (Some(digest), None) => format!("; approve-once digest {digest}"),
            (None, _) => String::new(),
        }
    }
}

impl Vault {
    /// Receipts `request`, which a full budget window paces until
    /// `next_eligible_at`, in `wtxn`: no gate decision, the identity as it
    /// stands, and the window's reason. Nothing else is written.
    pub(super) fn paced_lifecycle_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        request: ChannelIdentityLifecycleRequest,
        snapshot: &ChannelIdentity,
        request_ref: Option<EntityId>,
        next_eligible_at: u64,
    ) -> Result<ChannelIdentityLifecycleResult> {
        let identity_id = request.intent.identity_id();
        let receipt = self.append_channel_identity_lifecycle_receipt_in_txn(
            wtxn,
            request.requested_at,
            LifecycleReceiptInput {
                identity_id,
                actor: request.actor,
                verb: request.intent.verb().as_str().to_owned(),
                intent_kind: request.intent.verb().intent_kind().to_owned(),
                outcome: LIFECYCLE_PACED.to_owned(),
                gate_decision_id: None,
                channel: snapshot.channel().to_owned(),
                address_or_handle: snapshot.address_or_handle().to_owned(),
                state: snapshot.state().as_str().to_owned(),
                fulfillment_mode: snapshot
                    .pending_fulfillment()
                    .map(|mode| mode.as_str().to_owned()),
                owner_visible_state: LIFECYCLE_PACED.to_owned(),
                outbound_closed: false,
                identity_retiring: false,
                quarantine_until: snapshot.quarantine_until(),
                approval_digest: None,
                request_ref,
            },
        )?;
        Ok(ChannelIdentityLifecycleResult {
            receipt_id: lifecycle_receipt_ref(receipt.receipt_id),
            gate_receipt_id: None,
            outcome: receipt.outcome,
            reason_codes: vec![crate::linear_sync::LINEAR_RATE_WINDOW_REASON.to_owned()],
            owner_visible_state: receipt.owner_visible_state,
            identity: Some(snapshot.clone()),
            outbound_closed: receipt.outbound_closed,
            identity_retiring: receipt.identity_retiring,
            approval_digest: None,
            request_ref,
            paced_until: Some(next_eligible_at),
        })
    }
}
