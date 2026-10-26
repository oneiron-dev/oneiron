//! Participation for issue signatures (OF-420, FIX 739). "Help improve
//! Oneiron" and the ED-08 publisher dial both decide whether a signature may
//! leave. While both are on, the vault keeps one standing channel grant for
//! the signature sender's own derived principal, so the ordinary gate admits
//! its sends by principal with no per-send ask; once either stops, the grant
//! is revoked. Under the outbound writer, admission and every live retry
//! also recheck the lane's custody and both switches. The bundle send's
//! one-time approval is never involved.

use super::super::store;
use super::wire::wire_signature;
use super::{
    DELIVERIES, ENDPOINTS, ReportDeliveryKey, ReportDeliveryOutcome, ReportPublisherEndpoint,
    SENDER, UNSUPPORTED_CHANNELS, publisher_of,
};
use crate::edit_distance::publisher::publisher_enabled_in_txn;
use crate::outbound::{PublisherSignatureAuthorization, connector_actor_id};
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, StandingOutboundGrantStatus,
    encode_standing_outbound_grant_body, standing_outbound_grant_ids_for_principal,
    standing_outbound_grant_in_txn,
};
use crate::{EntityId, Result, Vault};

/// Origin recorded on the participation grant: the owner's participation,
/// not an ask escalator.
const PARTICIPATION_COMPONENT: &str = "feedback_signature.participation";
const PARTICIPATION_ACTION: &str = "send";

impl Vault {
    /// "Help improve Oneiron" and the ED-08 publisher dial, read now.
    pub(super) fn signature_switches(&self) -> Result<(bool, bool)> {
        let txn = self.store.env.read_txn()?;
        Ok((
            self.config.failure_signals.exports(),
            publisher_enabled_in_txn(self, &txn)?,
        ))
    }

    /// Keeps the participation grant in step, once per run: one active
    /// channel grant for the signature sender while both switches are on and
    /// this host has a destination that takes signatures, and none
    /// otherwise. A grant a policy or destination change left behind is
    /// revoked and minted afresh. The bundle send's approval is untouched.
    pub(super) fn keep_signature_participation(
        &self,
        destination: Option<&ReportPublisherEndpoint>,
        now: u64,
    ) -> Result<()> {
        let (participation, publisher_dial) = self.signature_switches()?;
        let channel = destination
            .filter(|destination| {
                participation
                    && publisher_dial
                    && !UNSUPPORTED_CHANNELS.contains(&destination.channel.as_str())
            })
            .map(|destination| destination.channel.clone());
        let principal = connector_actor_id(SENDER)?.to_hex();
        self.with_write_txn_grouped(|txn| {
            let floor =
                crate::gate::resolve_policy_manifest(&self.store, txn)?.read_frontier_hash()?;
            let mut current = false;
            let mut stale = Vec::new();
            for id in standing_outbound_grant_ids_for_principal(&self.store, txn, &principal)? {
                let Some(grant) = standing_outbound_grant_in_txn(&self.store, txn, &id)? else {
                    continue;
                };
                if grant.origin_component_id != PARTICIPATION_COMPONENT
                    || grant.status != StandingOutboundGrantStatus::Active
                {
                    continue;
                }
                let fits = channel.as_ref().is_some_and(|channel| {
                    matches!(
                        &grant.scope,
                        StandingOutboundGrantScope::Channel { channel: scoped } if scoped == channel
                    )
                });
                if fits && !current && grant.is_active_under_policy(&floor) {
                    current = true;
                } else {
                    stale.push((id, grant));
                }
            }
            for (id, grant) in stale {
                let data = encode_standing_outbound_grant_body(&grant.revoked(now)?)?;
                self.apply_standing_outbound_grant_body(txn, &id, now, data)?;
            }
            if let Some(channel) = channel.as_ref().filter(|_| !current) {
                let grant = StandingOutboundGrant {
                    authority_scope: crate::federation::scope_codec::effect_preset(),
                    principal_ref: principal.clone(),
                    origin_component_id: PARTICIPATION_COMPONENT.to_owned(),
                    origin_action_id: PARTICIPATION_ACTION.to_owned(),
                    origin_receipt_ref: None,
                    scope: StandingOutboundGrantScope::Channel {
                        channel: channel.clone(),
                    },
                    status: StandingOutboundGrantStatus::Active,
                    created_at: now,
                    revoked_at: None,
                    last_used_at: None,
                    binding_diff_handle: participation_binding_handle(&principal),
                    read_frontier_hash: floor,
                };
                grant.validate()?;
                let data = encode_standing_outbound_grant_body(&grant)?;
                self.apply_standing_outbound_grant_body(txn, &EntityId::now(), now, data)?;
            }
            Ok(())
        })
    }

    /// Whether one frozen signature send may still leave, judged under the
    /// outbound writer: the issue still routes to that publisher, the lane
    /// froze exactly these bytes, destination and send and is not finished,
    /// the body is still an ED-08 signature byte for byte, the owner's
    /// binding still names that destination, and participation and the
    /// publisher dial are both on.
    pub(crate) fn report_signature_admissible_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        authorization: &PublisherSignatureAuthorization,
    ) -> Result<bool> {
        let key =
            ReportDeliveryKey::signature(&authorization.issue_ref, &authorization.publisher_ref);
        let row = key.row()?;
        let Some(issue) = store::read(self, txn, &row.0)? else {
            return Ok(false);
        };
        if publisher_of(&issue) != Some(key.publisher_ref.as_str()) {
            return Ok(false);
        }
        let Some(record) = DELIVERIES.get(&self.store, txn, &row)? else {
            return Ok(false);
        };
        let (Some(signature), Some(send)) = (&record.signature, &record.send) else {
            return Ok(false);
        };
        let destination = ReportPublisherEndpoint {
            channel: authorization.channel.clone(),
            endpoint: authorization.endpoint.clone(),
        };
        let bound = ENDPOINTS.get(&self.store, txn, &key.publisher_ref)?;
        Ok(!record
            .outcome
            .as_ref()
            .is_some_and(ReportDeliveryOutcome::is_final)
            && signature.digest == authorization.digest
            && blake3::hash(signature.body.as_bytes()).to_hex().as_str() == signature.digest
            && wire_signature(&signature.body, |model_id| {
                self.signature_stacks_in_txn(txn, model_id)
            })?
            .is_some()
            && send.send_ref == authorization.send_ref
            && send.destination == destination
            && bound.as_ref() == Some(&destination)
            && self.config.failure_signals.exports()
            && publisher_enabled_in_txn(self, txn)?)
    }
}

/// Content address of the participation decision behind the grant, under
/// its own domain tag so it can never be replayed as another grant's.
fn participation_binding_handle(principal: &str) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    for part in [
        b"oneiron.gate.standing_outbound_grant.feedback_signature.v1".as_slice(),
        principal.as_bytes(),
        PARTICIPATION_COMPONENT.as_bytes(),
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().as_bytes().to_vec()
}
