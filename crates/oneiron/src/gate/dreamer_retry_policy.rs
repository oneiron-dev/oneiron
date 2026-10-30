//! A Dreamer Retry park's pause as a policy value (FIX 8716): the vault's
//! `dreamer_retry_park_seconds` row, else the shipped one.

use super::policy_values::{PolicyEvaluationScope, PolicyValue, PolicyValueKey};

/// The shipped pause before a later wake pass resumes a Dreamer Retry park
/// as the same try (Engine 10-21, FIX 8716).
fn shipped_default_dreamer_retry_park_seconds() -> u64 {
    let defaults: serde_json::Value =
        serde_json::from_str(include_str!("policy_value_defaults.json"))
            .expect("valid shipped policy defaults");
    defaults
        .as_array()
        .expect("shipped policy rows")
        .iter()
        .find(|row| row["key"] == "dreamer_retry_park_seconds" && row["scope"]["level"] == "vault")
        .and_then(|row| row["value"].as_u64())
        .filter(|value| *value > 0)
        .expect("shipped Dreamer retry park pause")
}

impl super::resolution::PolicyManifestResolution {
    /// How long a Dreamer Retry park waits before a later wake pass resumes
    /// it as the same try, in store-clock seconds (FIX 8716): the vault's
    /// row, else the shipped one. A fail-closed manifest reads the shipped
    /// row, since a pause grants nothing.
    pub(crate) fn dreamer_retry_park_seconds(&self) -> u64 {
        let fallback = shipped_default_dreamer_retry_park_seconds();
        match self
            .resolved_policy_value(
                PolicyValueKey::DreamerRetryParkSeconds,
                &PolicyEvaluationScope::default(),
                PolicyValue::DreamerRetryParkSeconds(fallback),
            )
            .value
        {
            PolicyValue::DreamerRetryParkSeconds(seconds) => seconds,
            _ => unreachable!("typed policy key"),
        }
    }
}
