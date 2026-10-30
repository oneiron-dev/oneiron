//! Participation for issue signatures (OF-420, FIX 739). "Help improve
//! Oneiron" and the ED-08 publisher dial both decide whether a signature may
//! leave. While both are on, the vault keeps one standing channel grant for
//! the signature sender's own derived principal, so the ordinary gate admits
//! its sends by principal with no per-send ask; once either stops, the grant
//! is revoked. The grant is a standing consent Grant row the run derives
//! from the owner's two settings, stamped with the owner they belong to.
//! Under the outbound writer, admission and every live retry also recheck the
//! lane's custody and both switches. The bundle send's one-time approval is
//! never involved.

use super::super::store;
use super::wire::wire_signature;
use super::{
    DELIVERIES, ENDPOINTS, ReportDeliveryKey, ReportDeliveryOutcome, ReportPublisherEndpoint,
    SENDER, UNSUPPORTED_CHANNELS, publisher_of,
};
use crate::consent::{DerivedGrantOrigin, DerivedGrantSetting};
use crate::edit_distance::publisher::{publisher_dial_row_ref_in_txn, publisher_enabled_in_txn};
use crate::outbound::{PublisherSignatureAuthorization, connector_actor_id};
use crate::outbound_grant::{
    StandingOutboundGrantScope, standing_outbound_grants_for_principal_in_txn,
};
use crate::{EntityId, Result, Vault};

/// The setting the participation grant's receipt names when no vault row
/// holds the ED-08 publisher dial: its compiled default. "Help improve
/// Oneiron" is deployment configuration and has no row either.
const PUBLISHER_DIAL_COMPILED_REF: &str = "edit_distance.publisher.compiled_default";

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
    /// revoked and minted afresh, carrying out the owner's settings. The
    /// bundle send's approval is untouched.
    pub(super) fn keep_signature_participation(
        &self,
        destination: Option<&ReportPublisherEndpoint>,
    ) -> Result<()> {
        let (participation, publisher_dial) = self.signature_switches()?;
        let wanted = destination
            .filter(|destination| {
                participation
                    && publisher_dial
                    && !UNSUPPORTED_CHANNELS.contains(&destination.channel.as_str())
            })
            .map(|destination| StandingOutboundGrantScope::Channel {
                channel: destination.channel.clone(),
            });
        let principal = connector_actor_id(SENDER)?.to_hex();
        self.with_write_txn_grouped(|txn| {
            let floor =
                crate::gate::resolve_policy_manifest(&self.store, txn)?.read_frontier_hash()?;
            let mut current = false;
            let mut stale = Vec::new();
            for grant in
                standing_outbound_grants_for_principal_in_txn(&self.store, txn, &principal)?
            {
                if !grant.is_active()
                    || !matches!(grant.scope, StandingOutboundGrantScope::Channel { .. })
                {
                    continue;
                }
                if wanted.as_ref() == Some(&grant.scope)
                    && !current
                    && grant.is_active_under_policy(&floor)
                {
                    current = true;
                } else {
                    stale.push(grant);
                }
            }
            for grant in &stale {
                self.withdraw_standing_outbound_grant_in_txn(txn, None, grant)?;
            }
            if let Some(scope) = wanted.filter(|_| !current) {
                // The publisher dial's row is the owner's setting this grant
                // carries out; it names no setter, so the stamp takes the
                // vault's owner.
                let receipt_ref = publisher_dial_row_ref_in_txn(self, txn)?
                    .unwrap_or_else(|| PUBLISHER_DIAL_COMPILED_REF.to_owned());
                self.mint_derived_outbound_grant_in_txn(
                    txn,
                    DerivedGrantOrigin::SignatureParticipation,
                    &DerivedGrantSetting {
                        receipt_ref,
                        setter: None,
                    },
                    EntityId::now(),
                    &principal,
                    scope,
                )?;
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
