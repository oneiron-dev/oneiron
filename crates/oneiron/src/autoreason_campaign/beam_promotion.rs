//! One-shot, one-way promotion from held-out KEEP to a sealed BEAM referee.
//!
//! This module never contributes a scalar to campaign reward. Raw referee
//! numbers are consumed here and are not exposed in campaign report types.
use super::{CampaignComparisonReport, ExperimentVerdict};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::{Error, Result, Vault};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One-shot consumption marker and promotion receipt, keyed by the content-pinned
/// strategy's digest. Two byte shapes share this row over its lifetime (a raw
/// consumption sentinel, then the JSON receipt) and neither is ever decoded —
/// every access is a raw presence or byte-equality check — hence `Raw`.
const BEAM_ONCE: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTOREASON_BEAM_ONCE);

/// The current default (winning) authoring strategy pin and its receipt: a singleton row.
const BEAM_DEFAULT: SideTable<(), PromotionReceipt, LegacyJson> =
    SideTable::new(&side_table::AUTOREASON_BEAM_DEFAULT);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringStrategyPin {
    pub strategy_id: String,
    pub revision: String,
    pub config_sha256: String,
}
impl AuthoringStrategyPin {
    /// Pins the validated authoring behavior used to evaluate this strategy.
    /// Dataset, budget labels and verdict settings cannot mint a new sealed shot.
    /// Per-step reservation units are a behavioral admission axis, not a label.
    pub fn from_campaign(config: &super::CampaignConfig) -> super::CampaignResult<Self> {
        config.validate()?;
        // Declaration order is not authoring behavior; config validation accepts
        // the same three identities in any order.
        let mut arms = config.arms.clone();
        arms.sort_by_key(|row| match row.arm {
            super::CampaignArmId::SinglePass => 0,
            super::CampaignArmId::Tournament => 1,
            super::CampaignArmId::StrongCritic => 2,
        });
        let mut tournament = config.tournament;
        if tournament.uncertainty_tau == 0.0 {
            tournament.uncertainty_tau = 0.0;
        }
        let reserve_units_per_step = config.tournament_budget_axes()?.reserve_units_per_step;
        let bytes =
            serde_json::to_vec(&(&arms, &config.corpus, &tournament, reserve_units_per_step))
                .map_err(|_| super::CampaignError::ReportMismatch {
                    reason: "campaign configuration cannot be serialized",
                })?;
        Ok(Self {
            strategy_id: config.campaign_id.clone(),
            revision: format!("schema-{}", config.schema_version),
            config_sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    }

    pub(super) fn validate(&self) -> super::CampaignResult<()> {
        self.key()
            .map(|_| ())
            .map_err(|_| super::CampaignError::ReportMismatch {
                reason: "authoring strategy must be content-pinned",
            })
    }

    fn key(&self) -> Result<String> {
        if self.strategy_id.is_empty()
            || self.revision.is_empty()
            || self.config_sha256.len() != 64
            || !self.config_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(invalid("authoring strategy must be content-pinned"));
        }
        Ok(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(self).map_err(|_| invalid("strategy serialization"))?
            )
        ))
    }
}
/// Constructed only by the sealed referee adapter. No reward-path score accessor.
pub struct SealedRefereeMeasurement {
    won: bool,
    digest: String,
    referee_pin: String,
}
impl SealedRefereeMeasurement {
    pub fn from_referee_scores(candidate: f64, incumbent: f64, referee_pin: &str) -> Result<Self> {
        if !candidate.is_finite()
            || !incumbent.is_finite()
            || !(0.0..=1.0).contains(&candidate)
            || !(0.0..=1.0).contains(&incumbent)
            || !valid_referee_pin(referee_pin)
        {
            return Err(invalid(
                "content-pinned referee identity and valid scores required",
            ));
        }
        let digest = format!(
            "{:x}",
            Sha256::digest(format!("{referee_pin}:{candidate:?}:{incumbent:?}"))
        );
        Ok(Self {
            won: candidate > incumbent,
            digest,
            referee_pin: referee_pin.into(),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionReceipt {
    pub strategy: AuthoringStrategyPin,
    pub referee_pin: String,
    pub measurement_digest: String,
    pub became_default: bool,
    pub at: u64,
}
/// Marks the candidate spent BEFORE any external measurement. A crash or error
/// consumes the shot; concurrent and subsequent attempts refuse without a call.
pub fn measure_once(
    vault: &Vault,
    campaign: &CampaignComparisonReport,
    strategy: AuthoringStrategyPin,
    measure: impl FnOnce() -> Result<SealedRefereeMeasurement>,
) -> Result<PromotionReceipt> {
    campaign
        .validate()
        .map_err(|_| invalid("campaign comparison is invalid"))?;
    if campaign.verdict.verdict != ExperimentVerdict::Keep {
        return Err(invalid("only a KEEP winner can become a BEAM candidate"));
    }
    if strategy != campaign.tournament.held_out.authoring_strategy {
        return Err(invalid(
            "BEAM candidate differs from the campaign KEEP winner",
        ));
    }
    let key = strategy.key()?;
    vault.with_write_txn(|txn| {
        if BEAM_ONCE.contains(&vault.store, txn, &key)? {
            return Err(invalid("BEAM candidate measurement already consumed"));
        }
        BEAM_ONCE.put(
            &vault.store,
            txn,
            &key,
            &b"flagged:measurement-consumed".to_vec(),
        )?;
        Ok(())
    })?;
    let measured = measure()?;
    let receipt = PromotionReceipt {
        strategy,
        referee_pin: measured.referee_pin,
        measurement_digest: measured.digest,
        became_default: measured.won,
        at: crate::unix_seconds_now(),
    };
    let bytes = BEAM_DEFAULT.encode_value(&receipt)?;
    vault.with_write_txn(|txn| {
        BEAM_ONCE.put(&vault.store, txn, &key, &bytes)?;
        if receipt.became_default {
            BEAM_DEFAULT.put(&vault.store, txn, &(), &receipt)?;
        }
        Ok(())
    })?;
    Ok(receipt)
}
pub fn default_strategy(vault: &Vault) -> Result<Option<AuthoringStrategyPin>> {
    let txn = vault.store.env.read_txn()?;
    let Some(receipt) = BEAM_DEFAULT.get(&vault.store, &txn, &())? else {
        return Ok(None);
    };
    let key = receipt.strategy.key()?;
    let bytes = BEAM_DEFAULT.encode_value(&receipt)?;
    if !receipt.became_default
        || !valid_referee_pin(&receipt.referee_pin)
        || BEAM_ONCE.get(&vault.store, &txn, &key)? != Some(bytes)
    {
        return Err(invalid("unreceipted authoring default"));
    }
    Ok(Some(receipt.strategy))
}
fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

fn valid_referee_pin(pin: &str) -> bool {
    pin.split_once("@sha256:")
        .is_some_and(|(identity, digest)| {
            !identity.is_empty()
                && identity.len() <= 256
                && identity
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_/.:".contains(&b))
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
