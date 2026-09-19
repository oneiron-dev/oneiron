//! One-shot, one-way promotion from held-out KEEP to a sealed BEAM referee.
//!
//! This module never contributes a scalar to campaign reward. Raw referee
//! numbers are consumed here and are not exposed in campaign report types.
use super::{CampaignComparisonReport, ExperimentVerdict};
use crate::dreamer_runner::{DreamerClaimAuthoringAdmission, DreamerTournamentAdmission};
use crate::{Error, Result, Vault};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const DEFAULT_KEY: &[u8] = b"authoring/default-beam-winner";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringStrategyPin {
    pub strategy_id: String,
    pub revision: String,
    pub config_sha256: String,
}
impl AuthoringStrategyPin {
    fn key(&self) -> Result<Vec<u8>> {
        if self.strategy_id.is_empty()
            || self.revision.is_empty()
            || self.config_sha256.len() != 64
            || !self.config_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(invalid("authoring strategy must be content-pinned"));
        }
        Ok(format!(
            "authoring/beam-once/{:x}",
            Sha256::digest(
                serde_json::to_vec(self).map_err(|_| invalid("strategy serialization"))?
            )
        )
        .into_bytes())
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
            || !referee_pin.starts_with("CompanionMem@")
            || referee_pin.trim_end_matches('@') == "CompanionMem"
        {
            return Err(invalid(
                "sealed CompanionMem referee pin and valid scores required",
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
    let key = strategy.key()?;
    vault.with_write_txn(|txn| {
        if vault.store.vault_meta.get(txn, &key)?.is_some() {
            return Err(invalid("BEAM candidate measurement already consumed"));
        }
        vault
            .store
            .vault_meta
            .put(txn, &key, b"flagged:measurement-consumed")?;
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
    let bytes =
        serde_json::to_vec(&receipt).map_err(|_| invalid("promotion receipt serialization"))?;
    vault.with_write_txn(|txn| {
        vault.store.vault_meta.put(txn, &key, &bytes)?;
        if receipt.became_default {
            vault.store.vault_meta.put(txn, DEFAULT_KEY, &bytes)?;
        }
        Ok(())
    })?;
    Ok(receipt)
}
/// Resolves the host's default while retaining all class, uncertainty and batch
/// admission checks on the supplied tournament metadata.
pub fn default_admission(
    vault: &Vault,
    tournament: DreamerTournamentAdmission,
) -> Result<DreamerClaimAuthoringAdmission> {
    Ok(if default_strategy(vault)?.is_some() {
        DreamerClaimAuthoringAdmission::Tournament(tournament)
    } else {
        DreamerClaimAuthoringAdmission::SinglePass
    })
}
pub fn default_strategy(vault: &Vault) -> Result<Option<AuthoringStrategyPin>> {
    let txn = vault.store.env.read_txn()?;
    let Some(bytes) = vault.store.vault_meta.get(&txn, DEFAULT_KEY)? else {
        return Ok(None);
    };
    let receipt: PromotionReceipt =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid default authoring receipt"))?;
    let key = receipt.strategy.key()?;
    if !receipt.became_default || vault.store.vault_meta.get(&txn, &key)? != Some(bytes) {
        return Err(invalid("unreceipted authoring default"));
    }
    Ok(Some(receipt.strategy))
}
fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}
