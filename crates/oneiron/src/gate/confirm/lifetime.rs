//! A locally attached critical confirmation's lifetime as a policy value (FIX
//! 8760): the vault-scope `critical_confirm_lifetime_seconds` row, else the
//! shipped 300 seconds. The gate reads it once, when it attaches the confirm,
//! and freezes the deadline on the pending row; the binding, its signed
//! authority action, the listing, the expiry sweep and an answer all read
//! that stored deadline, so a later policy edit never moves an issued one.

use crate::gate::policy_values::{PolicyEvaluationScope, PolicyValue, PolicyValueKey};

const KEY: PolicyValueKey = PolicyValueKey::CriticalConfirmLifetimeSeconds;

/// The shipped vault-scope lifetime, read from the seeded data.
fn shipped_lifetime_seconds() -> u64 {
    let defaults: serde_json::Value =
        serde_json::from_str(include_str!("../policy_value_defaults.json"))
            .expect("valid shipped policy defaults");
    defaults
        .as_array()
        .expect("shipped policy rows")
        .iter()
        .find(|row| row["key"] == KEY.as_str() && row["scope"]["level"] == "vault")
        .and_then(|row| row["value"].as_u64())
        .filter(|seconds| *seconds > 0)
        .expect("shipped critical confirm lifetime row")
}

impl crate::gate::resolution::PolicyManifestResolution {
    /// How long a critical write's locally attached confirm waits before a
    /// timeout demotes it, in seconds: the vault's row, else the shipped one.
    /// A fail-closed manifest reads the shipped row.
    pub(crate) fn critical_confirm_lifetime_seconds(&self) -> u64 {
        match self
            .resolved_policy_value(
                KEY,
                &PolicyEvaluationScope::default(),
                PolicyValue::CriticalConfirmLifetimeSeconds(shipped_lifetime_seconds()),
            )
            .value
        {
            PolicyValue::CriticalConfirmLifetimeSeconds(seconds) => seconds,
            _ => unreachable!("typed policy key"),
        }
    }
}
