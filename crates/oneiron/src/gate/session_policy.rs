//! A sitting's close policy (FIX 8600): the vault's own
//! `session_idle_floor_seconds` and `session_lifetime_ceiling_seconds` rows,
//! else the shipped ones — 1,200 and 43,200 seconds, the durations sittings
//! closed by before the rows existed. Vault scope only, until trusted
//! session axes exist.

use super::policy_values::{PolicyEvaluationScope, PolicyValue, PolicyValueKey};

/// The shipped vault-scope row for `key`, a positive count of seconds.
fn shipped_session_seconds(key: PolicyValueKey) -> u64 {
    let defaults: serde_json::Value =
        serde_json::from_str(include_str!("policy_value_defaults.json"))
            .expect("valid shipped policy defaults");
    defaults
        .as_array()
        .expect("shipped policy rows")
        .iter()
        .find(|row| row["key"] == key.as_str() && row["scope"]["level"] == "vault")
        .and_then(|row| row["value"].as_u64())
        .filter(|value| *value > 0)
        .expect("shipped sitting policy row")
}

impl super::resolution::PolicyManifestResolution {
    /// How long a sitting may go without activity before it closes, in
    /// store-clock seconds: the vault's row, else the shipped one. A
    /// fail-closed manifest reads the shipped row, the duration sittings
    /// closed by before the row existed.
    pub(crate) fn session_idle_floor_seconds(&self) -> u64 {
        let key = PolicyValueKey::SessionIdleFloorSeconds;
        let fallback = PolicyValue::SessionIdleFloorSeconds(shipped_session_seconds(key));
        match self
            .resolved_policy_value(key, &PolicyEvaluationScope::default(), fallback)
            .value
        {
            PolicyValue::SessionIdleFloorSeconds(seconds) => seconds,
            _ => unreachable!("typed policy key"),
        }
    }

    /// The hard wall-clock ceiling on one sitting's life whatever its
    /// activity (H-S4), in store-clock seconds: the vault's row, else the
    /// shipped one, which a fail-closed manifest also reads.
    pub(crate) fn session_lifetime_ceiling_seconds(&self) -> u64 {
        let key = PolicyValueKey::SessionLifetimeCeilingSeconds;
        let fallback = PolicyValue::SessionLifetimeCeilingSeconds(shipped_session_seconds(key));
        match self
            .resolved_policy_value(key, &PolicyEvaluationScope::default(), fallback)
            .value
        {
            PolicyValue::SessionLifetimeCeilingSeconds(seconds) => seconds,
            _ => unreachable!("typed policy key"),
        }
    }
}
