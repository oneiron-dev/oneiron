//! ChannelIdentity reputation claims and warmup delivery floors (OF-347 R4).
//!
//! This module is intentionally engine-level: provider adapters translate
//! native webhook payloads into the typed signal inputs here, and dispatch
//! callers consume the per-identity clamp result before scheduling sends.

use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::error::{Error, Result};
use crate::types::EntityId;

pub const IDENTITY_REPUTATION_SCHEMA_VERSION: u64 = 1;

pub const PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE: &str =
    "channel_identity.reputation.complaint_rate";
pub const PREDICATE_IDENTITY_REPUTATION_BOUNCE_RATE: &str =
    "channel_identity.reputation.bounce_rate";
pub const PREDICATE_IDENTITY_REPUTATION_SPAM_LABEL_OBSERVATIONS: &str =
    "channel_identity.reputation.spam_label_observations";
pub const PREDICATE_IDENTITY_REPUTATION_ATTESTATION_TIER: &str =
    "channel_identity.reputation.attestation_tier";
pub const PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE: &str =
    "channel_identity.reputation.warmup_stage";
pub const PREDICATE_IDENTITY_REPUTATION_UPDATED_AT: &str = "channel_identity.reputation.updated_at";
pub const PREDICATE_IDENTITY_REPUTATION_ROTATE_PROPOSAL: &str =
    "channel_identity.reputation.rotate_proposal";

pub const IDENTITY_REPUTATION_CLAIM_PREDICATES: [&str; 7] = [
    PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE,
    PREDICATE_IDENTITY_REPUTATION_BOUNCE_RATE,
    PREDICATE_IDENTITY_REPUTATION_SPAM_LABEL_OBSERVATIONS,
    PREDICATE_IDENTITY_REPUTATION_ATTESTATION_TIER,
    PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE,
    PREDICATE_IDENTITY_REPUTATION_UPDATED_AT,
    PREDICATE_IDENTITY_REPUTATION_ROTATE_PROPOSAL,
];

pub const WARMUP_COLD_DAILY_CAP: u64 = 25;
pub const WARMUP_WARMING_DAILY_CAP: u64 = 100;
pub const CONSTRAINED_REPUTATION_DAILY_CAP: u64 = 50;
pub const DEGRADED_REPUTATION_DAILY_CAP: u64 = 10;

const COMPLAINT_CONSTRAINED_THRESHOLD: f64 = 0.002;
const COMPLAINT_DEGRADED_THRESHOLD: f64 = 0.005;
const BOUNCE_CONSTRAINED_THRESHOLD: f64 = 0.02;
const BOUNCE_DEGRADED_THRESHOLD: f64 = 0.05;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityWarmupStage {
    Cold,
    Warming,
    Established,
    Paused,
}

impl IdentityWarmupStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warming => "warming",
            Self::Established => "established",
            Self::Paused => "paused",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "cold" => Some(Self::Cold),
            "warming" => Some(Self::Warming),
            "established" => Some(Self::Established),
            "paused" => Some(Self::Paused),
            _ => None,
        }
    }

    #[must_use]
    pub const fn daily_cap(self) -> u64 {
        match self {
            Self::Cold => WARMUP_COLD_DAILY_CAP,
            Self::Warming => WARMUP_WARMING_DAILY_CAP,
            Self::Established => u64::MAX,
            Self::Paused => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityAttestationTier {
    Unknown,
    A,
    B,
    C,
}

impl IdentityAttestationTier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::A => "a",
            Self::B => "b",
            Self::C => "c",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unknown" => Some(Self::Unknown),
            "a" => Some(Self::A),
            "b" => Some(Self::B),
            "c" => Some(Self::C),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityReputationStatus {
    Healthy,
    Constrained,
    Degraded,
}

impl IdentityReputationStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Constrained => "constrained",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IdentityReputation {
    pub complaint_rate: f64,
    pub bounce_rate: f64,
    pub spam_label_observations: u64,
    pub attestation_tier: IdentityAttestationTier,
    pub warmup_stage: IdentityWarmupStage,
    pub updated_at: u64,
}

impl IdentityReputation {
    pub fn new(warmup_stage: IdentityWarmupStage, updated_at: u64) -> Self {
        Self {
            complaint_rate: 0.0,
            bounce_rate: 0.0,
            spam_label_observations: 0,
            attestation_tier: IdentityAttestationTier::Unknown,
            warmup_stage,
            updated_at,
        }
    }

    pub fn apply_adapter_signal(&mut self, signal: IdentityReputationSignal) -> Result<()> {
        match signal {
            IdentityReputationSignal::EmailWebhook(webhook) => {
                webhook.validate()?;
                self.complaint_rate = rate(webhook.complaints, webhook.delivered);
                self.bounce_rate = rate(
                    webhook.bounces,
                    webhook.delivered.saturating_add(webhook.bounces),
                );
                if webhook.spam_label_observed {
                    self.spam_label_observations = self.spam_label_observations.saturating_add(1);
                }
                self.updated_at = self.updated_at.max(webhook.observed_at);
                self.validate()
            }
            IdentityReputationSignal::WarmupStage { stage, observed_at } => {
                self.warmup_stage = stage;
                self.updated_at = self.updated_at.max(observed_at);
                self.validate()
            }
            IdentityReputationSignal::AttestationTier { tier, observed_at } => {
                self.attestation_tier = tier;
                self.updated_at = self.updated_at.max(observed_at);
                self.validate()
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_rate(self.complaint_rate, "complaint_rate")?;
        validate_rate(self.bounce_rate, "bounce_rate")
    }

    #[must_use]
    pub fn status(&self) -> IdentityReputationStatus {
        if self.complaint_rate >= COMPLAINT_DEGRADED_THRESHOLD
            || self.bounce_rate >= BOUNCE_DEGRADED_THRESHOLD
            || self.spam_label_observations > 0
        {
            IdentityReputationStatus::Degraded
        } else if self.complaint_rate >= COMPLAINT_CONSTRAINED_THRESHOLD
            || self.bounce_rate >= BOUNCE_CONSTRAINED_THRESHOLD
            || self.attestation_tier == IdentityAttestationTier::C
        {
            IdentityReputationStatus::Constrained
        } else {
            IdentityReputationStatus::Healthy
        }
    }

    #[must_use]
    pub fn claim_bodies(&self, identity_ref: EntityId) -> Vec<ClaimBody> {
        IDENTITY_REPUTATION_CLAIM_PREDICATES
            .iter()
            .filter_map(|predicate| {
                if *predicate == PREDICATE_IDENTITY_REPUTATION_ROTATE_PROPOSAL {
                    return self.rotation_proposal_claim(identity_ref);
                }
                let mut claim = ClaimBody::new(
                    *predicate,
                    ClaimSubject::Entity(identity_ref),
                    self.claim_value(predicate)
                        .expect("predicate drawn from identity reputation family"),
                    1.0,
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                );
                claim.source = Some(ClaimSource::Observed);
                Some(claim)
            })
            .collect()
    }

    #[must_use]
    pub fn clamp_send_rate(
        &self,
        identity_ref: EntityId,
        requested_daily_cap: u64,
    ) -> IdentitySendRateClamp {
        let warmup_cap = self.warmup_stage.daily_cap();
        let status = self.status();
        let health_cap = match status {
            IdentityReputationStatus::Healthy => u64::MAX,
            IdentityReputationStatus::Constrained => CONSTRAINED_REPUTATION_DAILY_CAP,
            IdentityReputationStatus::Degraded => DEGRADED_REPUTATION_DAILY_CAP,
        };
        let effective_daily_cap = requested_daily_cap.min(warmup_cap).min(health_cap);

        IdentitySendRateClamp {
            identity_ref,
            requested_daily_cap,
            effective_daily_cap,
            warmup_cap,
            health_cap,
            status,
            rotate_proposal_required: status == IdentityReputationStatus::Degraded,
        }
    }

    #[must_use]
    pub fn rotation_proposal_claim(&self, identity_ref: EntityId) -> Option<ClaimBody> {
        if self.status() != IdentityReputationStatus::Degraded {
            return None;
        }
        let mut claim = ClaimBody::new(
            PREDICATE_IDENTITY_REPUTATION_ROTATE_PROPOSAL,
            ClaimSubject::Entity(identity_ref),
            self.rotation_proposal_value(),
            1.0,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        );
        claim.source = Some(ClaimSource::Generated);
        Some(claim)
    }

    fn claim_value(&self, predicate: &str) -> Option<Value> {
        match predicate {
            PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE => Some(Value::F64(self.complaint_rate)),
            PREDICATE_IDENTITY_REPUTATION_BOUNCE_RATE => Some(Value::F64(self.bounce_rate)),
            PREDICATE_IDENTITY_REPUTATION_SPAM_LABEL_OBSERVATIONS => {
                Some(Value::from(self.spam_label_observations))
            }
            PREDICATE_IDENTITY_REPUTATION_ATTESTATION_TIER => {
                Some(Value::from(self.attestation_tier.as_str()))
            }
            PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE => {
                Some(Value::from(self.warmup_stage.as_str()))
            }
            PREDICATE_IDENTITY_REPUTATION_UPDATED_AT => Some(Value::from(self.updated_at)),
            _ => None,
        }
    }

    fn rotation_proposal_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::from("schema_version"),
                Value::from(IDENTITY_REPUTATION_SCHEMA_VERSION),
            ),
            (Value::from("action"), Value::from("rotate")),
            (Value::from("auto_rotate"), Value::Boolean(false)),
            (Value::from("status"), Value::from(self.status().as_str())),
            (
                Value::from("complaint_rate"),
                Value::F64(self.complaint_rate),
            ),
            (Value::from("bounce_rate"), Value::F64(self.bounce_rate)),
            (
                Value::from("spam_label_observations"),
                Value::from(self.spam_label_observations),
            ),
            (
                Value::from("warmup_stage"),
                Value::from(self.warmup_stage.as_str()),
            ),
        ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityReputationSignal {
    EmailWebhook(EmailReputationWebhookSignal),
    WarmupStage {
        stage: IdentityWarmupStage,
        observed_at: u64,
    },
    AttestationTier {
        tier: IdentityAttestationTier,
        observed_at: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmailReputationWebhookSignal {
    pub delivered: u64,
    pub complaints: u64,
    pub bounces: u64,
    pub spam_label_observed: bool,
    pub observed_at: u64,
}

impl EmailReputationWebhookSignal {
    #[must_use]
    pub const fn new(
        delivered: u64,
        complaints: u64,
        bounces: u64,
        spam_label_observed: bool,
        observed_at: u64,
    ) -> Self {
        Self {
            delivered,
            complaints,
            bounces,
            spam_label_observed,
            observed_at,
        }
    }

    fn validate(self) -> Result<()> {
        if self.delivered == 0 && self.bounces == 0 {
            return Err(Error::InvalidClaimBody(
                "email reputation webhook must include delivered or bounced counts",
            ));
        }
        if self.complaints > self.delivered {
            return Err(Error::InvalidClaimBody(
                "email reputation complaints cannot exceed delivered count",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentitySendRateClamp {
    pub identity_ref: EntityId,
    pub requested_daily_cap: u64,
    pub effective_daily_cap: u64,
    pub warmup_cap: u64,
    pub health_cap: u64,
    pub status: IdentityReputationStatus,
    pub rotate_proposal_required: bool,
}

#[must_use]
pub fn is_identity_reputation_claim_predicate(predicate: &str) -> bool {
    IDENTITY_REPUTATION_CLAIM_PREDICATES.contains(&predicate)
}

pub(crate) fn validate_identity_reputation_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "identity reputation claim subject must be an entity",
        ));
    }
    if !is_identity_reputation_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "unknown identity reputation claim predicate",
        ));
    }

    match body.predicate.as_str() {
        PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE
        | PREDICATE_IDENTITY_REPUTATION_BOUNCE_RATE => {
            let rate = value_rate(&body.value)?;
            validate_rate(rate, "identity reputation rate")
        }
        PREDICATE_IDENTITY_REPUTATION_SPAM_LABEL_OBSERVATIONS => body
            .value
            .as_u64()
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "identity reputation spam_label_observations must be u64",
            )),
        PREDICATE_IDENTITY_REPUTATION_ATTESTATION_TIER => body
            .value
            .as_str()
            .and_then(IdentityAttestationTier::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "identity reputation attestation_tier must be unknown|a|b|c",
            )),
        PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE => body
            .value
            .as_str()
            .and_then(IdentityWarmupStage::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "identity reputation warmup_stage must be cold|warming|established|paused",
            )),
        PREDICATE_IDENTITY_REPUTATION_UPDATED_AT => {
            body.value
                .as_u64()
                .map(|_| ())
                .ok_or(Error::InvalidClaimBody(
                    "identity reputation updated_at must be u64",
                ))
        }
        PREDICATE_IDENTITY_REPUTATION_ROTATE_PROPOSAL => {
            validate_rotation_proposal_value(&body.value)?;
            if body.approval != ClaimApprovalStatus::Proposed {
                return Err(Error::InvalidClaimBody(
                    "identity reputation rotate proposal must use proposed approval",
                ));
            }
            Ok(())
        }
        _ => unreachable!("predicate membership checked above"),
    }
}

fn validate_rotation_proposal_value(value: &Value) -> Result<()> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody(
            "identity reputation rotate proposal value must be a map",
        ));
    };
    require_u64(entries, "schema_version").and_then(|version| {
        if version == IDENTITY_REPUTATION_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(Error::InvalidClaimBody(
                "identity reputation rotate proposal schema_version is unsupported",
            ))
        }
    })?;
    require_str(entries, "action").and_then(|action| {
        if action == "rotate" {
            Ok(())
        } else {
            Err(Error::InvalidClaimBody(
                "identity reputation rotate proposal action must be rotate",
            ))
        }
    })?;
    require_bool(entries, "auto_rotate").and_then(|auto_rotate| {
        if auto_rotate {
            Err(Error::InvalidClaimBody(
                "identity reputation rotate proposal must not auto-rotate",
            ))
        } else {
            Ok(())
        }
    })?;
    require_str(entries, "status").and_then(|status| {
        if status == IdentityReputationStatus::Degraded.as_str() {
            Ok(())
        } else {
            Err(Error::InvalidClaimBody(
                "identity reputation rotate proposal status must be degraded",
            ))
        }
    })?;
    validate_rate(require_f64(entries, "complaint_rate")?, "complaint_rate")?;
    validate_rate(require_f64(entries, "bounce_rate")?, "bounce_rate")?;
    require_u64(entries, "spam_label_observations")?;
    require_str(entries, "warmup_stage").and_then(|stage| {
        IdentityWarmupStage::parse(stage)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "identity reputation rotate proposal warmup_stage is invalid",
            ))
    })
}

fn rate(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn validate_rate(value: f64, field: &'static str) -> Result<()> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(Error::InvalidClaimBody(field))
    }
}

fn value_rate(value: &Value) -> Result<f64> {
    match value {
        Value::F32(value) => Ok(f64::from(*value)),
        Value::F64(value) => Ok(*value),
        Value::Integer(value) => {
            value
                .as_u64()
                .map(|value| value as f64)
                .ok_or(Error::InvalidClaimBody(
                    "identity reputation rate must be non-negative",
                ))
        }
        _ => Err(Error::InvalidClaimBody(
            "identity reputation rate must be numeric",
        )),
    }
}

fn require_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or(Error::InvalidClaimBody(
            "identity reputation proposal missing required field",
        ))
}

fn require_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    require_value(entries, key)?
        .as_u64()
        .ok_or(Error::InvalidClaimBody(
            "identity reputation proposal field must be u64",
        ))
}

fn require_f64(entries: &[(Value, Value)], key: &str) -> Result<f64> {
    value_rate(require_value(entries, key)?)
}

fn require_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    require_value(entries, key)?
        .as_str()
        .ok_or(Error::InvalidClaimBody(
            "identity reputation proposal field must be string",
        ))
}

fn require_bool(entries: &[(Value, Value)], key: &str) -> Result<bool> {
    match require_value(entries, key)? {
        Value::Boolean(value) => Ok(*value),
        _ => Err(Error::InvalidClaimBody(
            "identity reputation proposal field must be boolean",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("valid test entity")
    }

    #[test]
    fn email_webhook_signal_updates_health_claims() -> Result<()> {
        let identity_ref = entity(0xA1);
        let mut reputation = IdentityReputation::new(IdentityWarmupStage::Cold, 10);

        reputation.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(
            EmailReputationWebhookSignal::new(1_000, 3, 20, false, 20),
        ))?;

        assert_eq!(reputation.complaint_rate, 0.003);
        assert_eq!(reputation.bounce_rate, 20.0 / 1_020.0);
        assert_eq!(reputation.status(), IdentityReputationStatus::Constrained);

        for claim in reputation.claim_bodies(identity_ref) {
            validate_identity_reputation_claim_structure(&claim)?;
            assert_eq!(claim.subject, ClaimSubject::Entity(identity_ref));
        }
        Ok(())
    }

    #[test]
    fn warmup_and_health_clamps_are_per_identity() -> Result<()> {
        let healthy_identity = entity(0xA2);
        let degraded_identity = entity(0xA3);
        let healthy = IdentityReputation::new(IdentityWarmupStage::Cold, 10);
        let mut degraded = IdentityReputation::new(IdentityWarmupStage::Established, 10);
        degraded.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(
            EmailReputationWebhookSignal::new(1_000, 7, 10, false, 11),
        ))?;

        let healthy_clamp = healthy.clamp_send_rate(healthy_identity, 500);
        let degraded_clamp = degraded.clamp_send_rate(degraded_identity, 500);

        assert_eq!(healthy_clamp.identity_ref, healthy_identity);
        assert_eq!(healthy_clamp.effective_daily_cap, WARMUP_COLD_DAILY_CAP);
        assert!(!healthy_clamp.rotate_proposal_required);
        assert_eq!(degraded_clamp.identity_ref, degraded_identity);
        assert_eq!(
            degraded_clamp.effective_daily_cap,
            DEGRADED_REPUTATION_DAILY_CAP
        );
        assert!(degraded_clamp.rotate_proposal_required);
        Ok(())
    }

    #[test]
    fn complaint_spike_clamps_and_lands_rotate_proposal_only() -> Result<()> {
        let identity_ref = entity(0xA4);
        let mut reputation = IdentityReputation::new(IdentityWarmupStage::Established, 10);

        reputation.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(
            EmailReputationWebhookSignal::new(2_000, 18, 15, true, 11),
        ))?;

        let clamp = reputation.clamp_send_rate(identity_ref, 1_000);
        assert_eq!(clamp.status, IdentityReputationStatus::Degraded);
        assert_eq!(clamp.effective_daily_cap, DEGRADED_REPUTATION_DAILY_CAP);

        let proposal = reputation
            .rotation_proposal_claim(identity_ref)
            .expect("degraded identity proposes rotation");
        assert_eq!(proposal.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(proposal.source, Some(ClaimSource::Generated));
        validate_identity_reputation_claim_structure(&proposal)?;

        let Value::Map(entries) = &proposal.value else {
            panic!("proposal value is a map");
        };
        assert_eq!(require_str(entries, "action")?, "rotate");
        assert!(!require_bool(entries, "auto_rotate")?);
        Ok(())
    }

    #[test]
    fn malformed_reputation_claims_fail_closed() {
        let bad_rate = ClaimBody::new(
            PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE,
            ClaimSubject::Entity(entity(0xA5)),
            Value::F64(1.5),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        assert!(validate_identity_reputation_claim_structure(&bad_rate).is_err());

        let bad_proposal = ClaimBody::new(
            PREDICATE_IDENTITY_REPUTATION_ROTATE_PROPOSAL,
            ClaimSubject::Entity(entity(0xA6)),
            Value::Map(vec![
                (
                    Value::from("schema_version"),
                    Value::from(IDENTITY_REPUTATION_SCHEMA_VERSION),
                ),
                (Value::from("action"), Value::from("rotate")),
                (Value::from("auto_rotate"), Value::Boolean(true)),
                (
                    Value::from("status"),
                    Value::from(IdentityReputationStatus::Degraded.as_str()),
                ),
                (Value::from("complaint_rate"), Value::F64(0.01)),
                (Value::from("bounce_rate"), Value::F64(0.0)),
                (Value::from("spam_label_observations"), Value::from(0_u64)),
                (
                    Value::from("warmup_stage"),
                    Value::from(IdentityWarmupStage::Established.as_str()),
                ),
            ]),
            1.0,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        );
        assert!(validate_identity_reputation_claim_structure(&bad_proposal).is_err());
    }
}
