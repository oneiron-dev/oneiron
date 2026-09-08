//! Consumer allowance states, warning levels, and top-up request types.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::codec::UsageError;
use super::keys::{
    MAX_DIMENSION_LEN, MAX_IDEMPOTENCY_KEY_LEN, validate_consumer_top_up_storage_keys,
    validate_dimension, validate_non_negative_finite,
};
use super::model::{UsageCounter, UsageMode, normalize_money};

pub(super) const ALLOWANCE_NOTICE_THRESHOLD_RATIO: f64 = 0.80;

const ALLOWANCE_CRITICAL_THRESHOLD_RATIO: f64 = 0.95;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerAllowanceWarningLevel {
    #[default]
    None,
    Notice,
    Critical,
    Exhausted,
}

impl ConsumerAllowanceWarningLevel {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Notice => "notice",
            Self::Critical => "critical",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerAllowanceWarning {
    /// Machine-readable warning level for the current allowance burn-down.
    pub level: ConsumerAllowanceWarningLevel,
    /// Whether the warning threshold has been reached.
    pub triggered: bool,
    /// Threshold ratio that selected this warning level.
    pub threshold_ratio: f64,
    /// Current usage divided by allowance. Null when no allowance exists.
    pub used_ratio: Option<f64>,
    /// Human-readable warning message for UI and API clients.
    pub message: String,
}

impl ConsumerAllowanceWarning {
    pub(super) fn for_usage(used_credit_units: f64, allowance_credit_units: f64) -> Self {
        if allowance_credit_units <= 0.0 {
            return Self::exhausted(None);
        }

        let raw_used_ratio = used_credit_units / allowance_credit_units;
        let used_ratio = normalize_money(raw_used_ratio);
        if raw_used_ratio >= 1.0 {
            Self::exhausted(Some(used_ratio))
        } else if raw_used_ratio >= ALLOWANCE_CRITICAL_THRESHOLD_RATIO {
            Self {
                level: ConsumerAllowanceWarningLevel::Critical,
                triggered: true,
                threshold_ratio: ALLOWANCE_CRITICAL_THRESHOLD_RATIO,
                used_ratio: Some(used_ratio),
                message: "consumer allowance is at or above the critical threshold".to_owned(),
            }
        } else if raw_used_ratio >= ALLOWANCE_NOTICE_THRESHOLD_RATIO {
            Self {
                level: ConsumerAllowanceWarningLevel::Notice,
                triggered: true,
                threshold_ratio: ALLOWANCE_NOTICE_THRESHOLD_RATIO,
                used_ratio: Some(used_ratio),
                message: "consumer allowance is at or above the notice threshold".to_owned(),
            }
        } else {
            Self::none(Some(used_ratio))
        }
    }

    pub(super) fn none(used_ratio: Option<f64>) -> Self {
        Self {
            level: ConsumerAllowanceWarningLevel::None,
            triggered: false,
            threshold_ratio: ALLOWANCE_NOTICE_THRESHOLD_RATIO,
            used_ratio,
            message: "consumer allowance is within the available balance".to_owned(),
        }
    }

    pub(super) fn exhausted(used_ratio: Option<f64>) -> Self {
        Self {
            level: ConsumerAllowanceWarningLevel::Exhausted,
            triggered: true,
            threshold_ratio: 1.0,
            used_ratio,
            message: "consumer allowance is exhausted".to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerAllowanceState {
    /// Total credited allowance available to the tenant.
    pub allowance_credit_units: f64,
    /// Tenant-wide credit units consumed against this allowance.
    pub used_credit_units: f64,
    /// Remaining tenant allowance after subtracting tenant-wide usage.
    pub remaining_credit_units: f64,
    /// Last top-up timestamp for this tenant, if any.
    pub updated_at: Option<u64>,
    /// Explicit threshold warning for the current allowance state.
    pub warning: ConsumerAllowanceWarning,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerUsageState {
    /// Tenant whose usage and allowance are represented.
    pub tenant_id: String,
    /// Optional vault scope for this usage state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    /// Server usage mode that determines whether usage events debit credits.
    pub mode: UsageMode,
    /// Aggregate usage counters for the selected scope.
    pub counters: UsageCounter,
    /// Tenant-wide allowance, remaining balance, and explicit warning state.
    pub allowance: ConsumerAllowanceState,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerUsageDetails {
    /// Summary usage and allowance state for the selected scope.
    pub usage: ConsumerUsageState,
    /// Per-agent usage counters for the selected scope.
    pub agents: BTreeMap<String, UsageCounter>,
    /// Per-model usage counters for the selected scope.
    pub models: BTreeMap<String, UsageCounter>,
    /// Per-service usage counters for the selected scope.
    pub services: BTreeMap<String, UsageCounter>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerTopUpRequest {
    /// Tenant whose allowance should be credited.
    pub tenant_id: String,
    /// Idempotency key that records this top-up once per tenant.
    pub idempotency_key: String,
    /// Credit units to add to the tenant allowance.
    pub credit_units: f64,
}

impl ConsumerTopUpRequest {
    pub(super) fn validate(&self) -> Result<(), UsageError> {
        validate_dimension("tenantId", &self.tenant_id, MAX_DIMENSION_LEN)?;
        validate_dimension(
            "idempotencyKey",
            &self.idempotency_key,
            MAX_IDEMPOTENCY_KEY_LEN,
        )?;
        validate_consumer_top_up_storage_keys(&self.tenant_id, &self.idempotency_key)?;
        validate_non_negative_finite("creditUnits", self.credit_units)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerTopUp {
    /// Tenant credited by this top-up.
    pub tenant_id: String,
    /// Idempotency key that identifies this top-up.
    pub idempotency_key: String,
    /// Credit units added by this top-up.
    pub credit_units: f64,
    /// USD value represented by the credited units.
    pub amount_usd: f64,
    /// Server timestamp when this top-up was first recorded.
    pub recorded_at: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerTopUpState {
    /// True when this request created a new top-up.
    pub recorded: bool,
    /// True when the idempotency key had already been recorded.
    pub replayed: bool,
    /// Top-up state associated with the idempotency key.
    pub top_up: ConsumerTopUp,
    /// Usage and allowance state after applying or replaying the top-up.
    pub usage: ConsumerUsageState,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ConsumerAllowanceRecord {
    pub(super) credit_units: f64,
    pub(super) updated_at: Option<u64>,
}
