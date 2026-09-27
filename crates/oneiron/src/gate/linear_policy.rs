//! Narrowable host policy rows stored in the trusted Gate manifest.
//! Execution cadence and transport ceilings are deployment policy, not an
//! engine timer. The server owns the timer; the vault owns the policy floor.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinearPermission {
    Conditional,
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinearPolicyRisk {
    Normal,
    HoldToProposal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinearPolicyPrecedence {
    NestedNarrowing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinearMissedTick {
    Skip,
    Delay,
}

/// Resolved `linear_host_policy` manifest row. Overrides can only narrow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinearHostPolicy {
    pub precedence: LinearPolicyPrecedence,
    pub interval_secs: u64,
    pub missed_tick: LinearMissedTick,
    pub page_size: u32,
    pub timeout_secs: u64,
    pub max_response_bytes: u64,
    pub permission: LinearPermission,
    pub risk: LinearPolicyRisk,
}
impl LinearHostPolicy {
    #[must_use]
    pub const fn shipped_default() -> Self {
        Self {
            precedence: LinearPolicyPrecedence::NestedNarrowing,
            interval_secs: 60,
            missed_tick: LinearMissedTick::Skip,
            page_size: 50,
            timeout_secs: 15,
            max_response_bytes: 4 * 1024 * 1024,
            permission: LinearPermission::Conditional,
            risk: LinearPolicyRisk::Normal,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.interval_secs == 0
            || self.interval_secs > 86_400
            || self.page_size == 0
            || self.page_size > 500
            || self.timeout_secs == 0
            || self.timeout_secs > 120
            || self.max_response_bytes == 0
            || self.max_response_bytes > 64 * 1024 * 1024
        {
            return Err(Error::InvalidConfig(
                "invalid Linear host policy bounds".into(),
            ));
        }
        Ok(())
    }
    /// A later host policy or nested manifest cannot widen the parent floor.
    pub fn narrow(&self, child: &Self) -> Result<Self> {
        self.validate()?;
        child.validate()?;
        if child.interval_secs < self.interval_secs
            || self.missed_tick == LinearMissedTick::Skip
                && child.missed_tick != LinearMissedTick::Skip
            || child.page_size > self.page_size
            || child.timeout_secs > self.timeout_secs
            || child.max_response_bytes > self.max_response_bytes
            || self.permission == LinearPermission::Denied
                && child.permission != LinearPermission::Denied
            || self.risk == LinearPolicyRisk::HoldToProposal
                && child.risk != LinearPolicyRisk::HoldToProposal
        {
            return Err(Error::InvalidConfig(
                "Linear host override widens policy".into(),
            ));
        }
        Ok(child.clone())
    }
    /// Restrictive fold of two trusted vault manifests (no last-writer wins).
    #[must_use]
    pub fn restrict(&self, other: &Self) -> Self {
        Self {
            precedence: LinearPolicyPrecedence::NestedNarrowing,
            interval_secs: self.interval_secs.max(other.interval_secs),
            missed_tick: if self.missed_tick == LinearMissedTick::Skip
                || other.missed_tick == LinearMissedTick::Skip
            {
                LinearMissedTick::Skip
            } else {
                LinearMissedTick::Delay
            },
            page_size: self.page_size.min(other.page_size),
            timeout_secs: self.timeout_secs.min(other.timeout_secs),
            max_response_bytes: self.max_response_bytes.min(other.max_response_bytes),
            permission: if self.permission == LinearPermission::Denied
                || other.permission == LinearPermission::Denied
            {
                LinearPermission::Denied
            } else {
                LinearPermission::Conditional
            },
            risk: if self.risk == LinearPolicyRisk::HoldToProposal
                || other.risk == LinearPolicyRisk::HoldToProposal
            {
                LinearPolicyRisk::HoldToProposal
            } else {
                LinearPolicyRisk::Normal
            },
        }
    }
    pub(crate) fn decode(value: &rmpv::Value) -> Option<Self> {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, value).ok()?;
        let policy: Self = rmp_serde::from_slice(&bytes).ok()?;
        policy.validate().ok()?;
        Some(policy)
    }
    #[must_use]
    pub(crate) fn as_value(&self) -> rmpv::Value {
        rmpv::Value::Map(
            vec![
                ("precedence", rmpv::Value::from("nested_narrowing")),
                ("interval_secs", rmpv::Value::from(self.interval_secs)),
                (
                    "missed_tick",
                    rmpv::Value::from(match self.missed_tick {
                        LinearMissedTick::Skip => "skip",
                        LinearMissedTick::Delay => "delay",
                    }),
                ),
                ("page_size", rmpv::Value::from(self.page_size)),
                ("timeout_secs", rmpv::Value::from(self.timeout_secs)),
                (
                    "max_response_bytes",
                    rmpv::Value::from(self.max_response_bytes),
                ),
                (
                    "permission",
                    rmpv::Value::from(match self.permission {
                        LinearPermission::Conditional => "conditional",
                        LinearPermission::Denied => "denied",
                    }),
                ),
                (
                    "risk",
                    rmpv::Value::from(match self.risk {
                        LinearPolicyRisk::Normal => "normal",
                        LinearPolicyRisk::HoldToProposal => "hold_to_proposal",
                    }),
                ),
            ]
            .into_iter()
            .map(|(key, value)| (rmpv::Value::from(key), value))
            .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Vault, VaultConfig};

    #[test]
    fn trusted_manifest_row_changes_host_policy_and_override_cannot_widen_it() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        assert_eq!(
            vault.linear_host_policy().unwrap(),
            LinearHostPolicy::shipped_default()
        );
        let mut raw = crate::gate::default_policy_manifest();
        let mut cursor = std::io::Cursor::new(&raw);
        let mut manifest = rmpv::decode::read_value(&mut cursor).unwrap();
        let rmpv::Value::Map(entries) = &mut manifest else {
            panic!("manifest map")
        };
        let (_, row) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("linear_host_policy"))
            .unwrap();
        let mut stricter = LinearHostPolicy::shipped_default();
        stricter.interval_secs = 120;
        stricter.page_size = 20;
        stricter.timeout_secs = 8;
        stricter.max_response_bytes = 1024;
        stricter.risk = LinearPolicyRisk::HoldToProposal;
        *row = stricter.as_value();
        raw.clear();
        rmpv::encode::write_value(&mut raw, &manifest).unwrap();
        crate::test_util::put_policy_manifest_bytes(
            &vault,
            crate::gate::default_policy_manifest_id().unwrap(),
            &raw,
        )
        .unwrap();
        let resolved = vault.linear_host_policy().unwrap();
        assert_eq!(resolved, stricter);
        let mut child = stricter.clone();
        child.interval_secs = 240;
        child.page_size = 10;
        child.timeout_secs = 4;
        child.max_response_bytes = 512;
        assert_eq!(resolved.narrow(&child).unwrap(), child);
        let mut widened = child;
        widened.page_size = 21;
        assert!(resolved.narrow(&widened).is_err());
        let mut widened = stricter.clone();
        widened.risk = LinearPolicyRisk::Normal;
        assert!(resolved.narrow(&widened).is_err());
        let mut widened = stricter;
        widened.missed_tick = LinearMissedTick::Delay;
        assert!(resolved.narrow(&widened).is_err());
    }
}
