//! Real-signal snapshots written through the existing CID-5 claim family.
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{StalwartClient, invalid};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::identity_reputation::{
    EmailReputationWebhookSignal, IdentityAttestationTier, IdentityReputation,
    IdentityReputationSignal, IdentityReputationStatus, IdentitySendRateClamp, IdentityWarmupStage,
    PREDICATE_IDENTITY_REPUTATION_UPDATED_AT, is_identity_reputation_claim_predicate,
};
use crate::ports::EntityStoreRead;
use crate::{EntityId, Result, TimeRange, Vault};

/// There is intentionally no synthetic engagement or warmup-network source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeMailSignalSource {
    Postmaster,
    RealTraffic,
}

/// Cumulative counters for one identity from a host's verified report. Replies
/// and OOO responses are real inbound traffic, never generated warmup sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeMailReputationReport {
    pub observation_ref: String,
    pub evidence_ref: EntityId,
    pub source: NativeMailSignalSource,
    pub delivered: u64,
    pub bounces: u64,
    pub complaints: u64,
    pub spam_label_observations: u64,
    pub replies: u64,
    pub out_of_office: u64,
    /// Present only for an actual Postmaster report. Absence earns no
    /// attestation; a negative report never earns a graduation offer.
    pub postmaster_healthy: Option<bool>,
    pub observed_at: u64,
}

/// Traffic evidence needed to advance warmup, not a second rate clamp. CID-5's
/// existing caps and health thresholds remain the only send-rate calculation.
#[derive(Debug, Clone, Copy)]
pub struct NativeMailWarmupPolicy {
    pub warming_deliveries: u64,
    pub established_deliveries: u64,
    pub warming_responses: u64,
    pub established_responses: u64,
}

impl Default for NativeMailWarmupPolicy {
    fn default() -> Self {
        Self {
            warming_deliveries: 10,
            established_deliveries: 100,
            warming_responses: 1,
            established_responses: 5,
        }
    }
}

impl NativeMailWarmupPolicy {
    fn project(self, report: &NativeMailReputationReport) -> Result<IdentityReputation> {
        if self.warming_deliveries == 0
            || self.established_deliveries < self.warming_deliveries
            || self.warming_responses == 0
            || self.established_responses < self.warming_responses
            || report.observation_ref.trim().is_empty()
            || report.observation_ref.len() > 256
            || report.delivered == 0 && report.bounces == 0
            || report.complaints > report.delivered
            || report.replies.saturating_add(report.out_of_office) > report.delivered
            || report.source != NativeMailSignalSource::Postmaster
                && report.postmaster_healthy.is_some()
        {
            return Err(invalid(
                "invalid native mail real-signal report or warmup policy",
            ));
        }
        let mut reputation = IdentityReputation::new(IdentityWarmupStage::Cold, report.observed_at);
        reputation.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(
            EmailReputationWebhookSignal::new(
                report.delivered,
                report.complaints,
                report.bounces,
                false,
                report.observed_at,
            ),
        ))?;
        reputation.spam_label_observations = report.spam_label_observations;
        let responses = report.replies.saturating_add(report.out_of_office);
        reputation.attestation_tier = match report.postmaster_healthy {
            Some(true) => IdentityAttestationTier::A,
            Some(false) => IdentityAttestationTier::C,
            None if responses > 0 => IdentityAttestationTier::B,
            None => IdentityAttestationTier::Unknown,
        };
        reputation.warmup_stage = if reputation.status() != IdentityReputationStatus::Healthy {
            IdentityWarmupStage::Paused
        } else if report.delivered >= self.established_deliveries
            && (responses >= self.established_responses || report.postmaster_healthy == Some(true))
        {
            IdentityWarmupStage::Established
        } else if report.delivered >= self.warming_deliveries
            && (responses >= self.warming_responses || report.postmaster_healthy == Some(true))
        {
            IdentityWarmupStage::Warming
        } else {
            IdentityWarmupStage::Cold
        };
        reputation.validate()?;
        Ok(reputation)
    }
}

#[derive(Debug, Clone)]
pub struct NativeMailReputationUpdate {
    pub reputation: IdentityReputation,
    pub clamp: IdentitySendRateClamp,
    pub claim_refs: Vec<EntityId>,
}

impl StalwartClient {
    /// Atomically publish the report and replace this pack's previous CID-5
    /// heads. Reports are idempotent, evidence-linked and monotone in observed
    /// time. Other producers' heads are never silently overwritten.
    pub fn record_reputation(
        &self,
        vault: &Vault,
        identity_ref: EntityId,
        report: &NativeMailReputationReport,
        policy: NativeMailWarmupPolicy,
        requested_daily_cap: u64,
    ) -> Result<NativeMailReputationUpdate> {
        vault.require_builtin_channel_pack("native_mail")?;
        let reputation = policy.project(report)?;
        let evidence_json = serde_json::to_string(report)
            .map_err(|_| invalid("native mail report did not encode"))?;
        let evidence = Value::Map(vec![
            (
                Value::from("native_mail_observation"),
                Value::from(report.observation_ref.clone()),
            ),
            (
                Value::from("evidence_ref"),
                Value::from(report.evidence_ref.to_hex()),
            ),
            (Value::from("report"), Value::from(evidence_json)),
        ]);
        let mut bodies = reputation.claim_bodies(identity_ref)?;
        for body in &mut bodies {
            body.evidence = Some(evidence.clone());
            body.valid_from = Some(report.observed_at);
        }
        let mut txn = vault.store.env.write_txn()?;
        // Channel and mailbox are the identity's facts (OF-272); whether it
        // is delegated is custody, on the local row.
        let identity = vault
            .get_channel_identity_in_txn(&txn, &identity_ref)?
            .ok_or(crate::Error::EntityNotFound)?;
        let facts = crate::channel_identity::channel_identity_facts_in_txn(
            &vault.store,
            &txn,
            &identity_ref,
        )?
        .ok_or(crate::Error::EntityNotFound)?;
        if facts.channel != "email"
            || identity.is_delegated()
            || facts.address_or_handle != self.address_for_identity(identity_ref)
        {
            return Err(invalid(
                "native mail reputation names another instance's identity",
            ));
        }
        if vault
            .store
            .port_entity_record(&txn, &report.evidence_ref)?
            .is_none()
        {
            return Err(crate::Error::EntityNotFound);
        }
        let mut previous = Vec::new();
        for id in vault.claims_for_subject_in_txn(&txn, &identity_ref)? {
            let Some(body) = vault.get_claim_in_txn(&txn, &id)? else {
                continue;
            };
            let owned = body
                .evidence
                .as_ref()
                .and_then(Value::as_map)
                .is_some_and(|entries| {
                    entries
                        .iter()
                        .any(|(key, _)| key.as_str() == Some("native_mail_observation"))
                });
            if owned
                && is_identity_reputation_claim_predicate(&body.predicate)
                && body.lifecycle == ClaimLifecycleStatus::Active
                && !body.stale
            {
                let deletion =
                    crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &txn, &id)?;
                if deletion.deleted || deletion.stale {
                    continue;
                }
                if body.predicate == PREDICATE_IDENTITY_REPUTATION_UPDATED_AT
                    && body
                        .value
                        .as_u64()
                        .is_some_and(|time| time > report.observed_at)
                {
                    return Err(invalid(
                        "native mail reputation report is older than current evidence",
                    ));
                }
                previous.push((id, body));
            }
        }
        let mut claim_refs = Vec::new();
        for body in bodies {
            let id = EntityId::derive(
                b"oneiron.native_mail.reputation.v1",
                &[
                    identity_ref.as_bytes(),
                    report.observation_ref.as_bytes(),
                    body.predicate.as_bytes(),
                ],
            )?;
            let deletion =
                crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &txn, &id)?;
            if deletion.deleted || deletion.stale {
                return Err(invalid("native mail report was erased"));
            }
            if let Some(existing) = vault.get_claim_in_txn(&txn, &id)? {
                if existing != body {
                    return Err(invalid("native mail observation reference was reused"));
                }
            } else {
                vault.put_claim_in_txn(
                    &mut txn,
                    &id,
                    &body,
                    TimeRange {
                        start: report.observed_at,
                        end: report.observed_at,
                    },
                    report.observed_at,
                )?;
                for (old_id, old_body) in &previous {
                    if old_body.predicate == body.predicate {
                        // Do not close an owner's approval on a generated rotation
                        // proposal. Rotation remains an offer, never an action.
                        if old_body.approval == ClaimApprovalStatus::Approved
                            && body.approval == ClaimApprovalStatus::Proposed
                        {
                            continue;
                        }
                        vault.supersede_claim_in_txn(&mut txn, &id, old_id, report.observed_at)?;
                    }
                }
            }
            claim_refs.push(id);
        }
        txn.commit()?;
        vault.store.notify_proactivity_changes();
        Ok(NativeMailReputationUpdate {
            clamp: reputation.clamp_send_rate(identity_ref, requested_daily_cap),
            reputation,
            claim_refs,
        })
    }
}
