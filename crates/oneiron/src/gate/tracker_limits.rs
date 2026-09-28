//! Policy-manifest operating budgets for retained live-query provenance.

use crate::{EntityId, Error, Result, Vault};
use rmpv::Value;
use std::collections::BTreeMap;

/// Shipped operating defaults; the policy may narrow or raise them within
/// the separate hard allocation ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveQueryTrackerLimits {
    pub max_events: usize,
    pub max_bytes: usize,
    pub receipt_grace_ticks: usize,
}
impl Default for LiveQueryTrackerLimits {
    fn default() -> Self {
        Self {
            max_events: 1024,
            max_bytes: 64 * 1024,
            receipt_grace_ticks: 2,
        }
    }
}
impl LiveQueryTrackerLimits {
    const HARD_MAX_EVENTS: usize = 8192;
    const HARD_MAX_BYTES: usize = 1024 * 1024;
    const HARD_MAX_GRACE_TICKS: usize = 32;
    fn restrict(self, other: Self) -> Self {
        Self {
            max_events: self.max_events.min(other.max_events),
            max_bytes: self.max_bytes.min(other.max_bytes),
            receipt_grace_ticks: self.receipt_grace_ticks.min(other.receipt_grace_ticks),
        }
    }
    fn decode(entries: &[(Value, Value)]) -> Option<Self> {
        if !(2..=3).contains(&entries.len()) {
            return None;
        }
        let mut events = None;
        let mut bytes = None;
        let mut grace = None;
        for (key, value) in entries {
            let value = usize::try_from(value.as_u64()?).ok()?;
            match key.as_str()? {
                "max_events" if events.replace(value).is_none() => {}
                "max_bytes" if bytes.replace(value).is_none() => {}
                "receipt_grace_ticks" if grace.replace(value).is_none() => {}
                _ => return None,
            }
        }
        let value = Self {
            max_events: events?,
            max_bytes: bytes?,
            receipt_grace_ticks: grace.unwrap_or(Self::default().receipt_grace_ticks),
        };
        (value.max_events > 0
            && value.max_events <= Self::HARD_MAX_EVENTS
            && value.max_bytes > 0
            && value.max_bytes <= Self::HARD_MAX_BYTES
            && value.receipt_grace_ticks > 0
            && value.receipt_grace_ticks <= Self::HARD_MAX_GRACE_TICKS)
            .then_some(value)
    }
}

/// One trusted pack's vault parent plus exact holder children. Children can
/// only narrow their parent, and all trusted packs compose restrictively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyTrackerLimits {
    vault: LiveQueryTrackerLimits,
    holders: BTreeMap<EntityId, LiveQueryTrackerLimits>,
}
impl PolicyTrackerLimits {
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        let mut vault = None;
        let mut holders = BTreeMap::new();
        let mut saw_holders = false;
        for (key, value) in entries {
            match key.as_str()? {
                "vault" if vault.is_none() => {
                    let Value::Map(fields) = value else {
                        return None;
                    };
                    vault = Some(LiveQueryTrackerLimits::decode(fields)?);
                }
                "holders" if !saw_holders => {
                    saw_holders = true;
                    let Value::Array(rows) = value else {
                        return None;
                    };
                    if rows.len() > 1024 {
                        return None;
                    }
                    for row in rows {
                        let Value::Map(fields) = row else {
                            return None;
                        };
                        if !(3..=4).contains(&fields.len()) {
                            return None;
                        }
                        let mut holder = None;
                        let mut limits = Vec::new();
                        for (field, value) in fields {
                            if field.as_str() == Some("holder_ref") {
                                let hex = value.as_str()?;
                                let id = EntityId::from_hex(hex).ok()?;
                                if id.to_hex() != hex || holder.replace(id).is_some() {
                                    return None;
                                }
                            } else {
                                limits.push((field.clone(), value.clone()));
                            }
                        }
                        if holders
                            .insert(holder?, LiveQueryTrackerLimits::decode(&limits)?)
                            .is_some()
                        {
                            return None;
                        }
                    }
                }
                _ => return None,
            }
        }
        Some(Self {
            vault: vault?,
            holders,
        })
    }
    pub(crate) fn restrict(&mut self, other: Self) {
        self.vault = self.vault.restrict(other.vault);
        for (holder, limits) in other.holders {
            self.holders
                .entry(holder)
                .and_modify(|old| *old = old.restrict(limits))
                .or_insert(limits);
        }
    }
    pub(crate) fn resolve(&self, holder: Option<EntityId>) -> LiveQueryTrackerLimits {
        holder
            .and_then(|id| self.holders.get(&id))
            .map_or(self.vault, |child| self.vault.restrict(*child))
    }
}

impl Vault {
    /// Resolves the live policy on session admission, never from wire fields.
    /// Unknown/malformed loaded policy refuses service instead of relaxing a cap.
    pub fn policy_livequery_tracker_limits(
        &self,
        holder_ref: Option<&str>,
    ) -> Result<LiveQueryTrackerLimits> {
        let txn = self.store.env.read_txn()?;
        let resolution = super::resolution::resolve_policy_manifest(&self.store, &txn)?;
        if resolution.diagnostics.loaded_manifest_forces_fail_closed() {
            return Err(Error::InvalidConfig(
                "livequery tracker policy is fail-closed".into(),
            ));
        }
        let holder = holder_ref.map(EntityId::from_hex).transpose()?;
        Ok(resolution
            .livequery_tracker_limits
            .as_ref()
            .map_or_else(LiveQueryTrackerLimits::default, |limits| {
                limits.resolve(holder)
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn holder_cannot_widen_vault_and_trusted_packs_restrict() {
        let id = EntityId::from_bytes([0xAE; 16]).unwrap();
        let value = Value::Map(vec![
            (
                Value::from("vault"),
                Value::Map(vec![
                    (Value::from("max_events"), Value::from(500)),
                    (Value::from("max_bytes"), Value::from(32_000)),
                ]),
            ),
            (
                Value::from("holders"),
                Value::Array(vec![Value::Map(vec![
                    (Value::from("holder_ref"), Value::from(id.to_hex())),
                    (Value::from("max_events"), Value::from(700)),
                    (Value::from("max_bytes"), Value::from(4_000)),
                ])]),
            ),
        ]);
        let mut policy = PolicyTrackerLimits::decode(&value).unwrap();
        assert_eq!(
            policy.resolve(Some(id)),
            LiveQueryTrackerLimits {
                max_events: 500,
                max_bytes: 4_000,
                receipt_grace_ticks: 2
            }
        );
        let narrower = Value::Map(vec![(
            Value::from("vault"),
            Value::Map(vec![
                (Value::from("max_events"), Value::from(300)),
                (Value::from("max_bytes"), Value::from(16_000)),
            ]),
        )]);
        policy.restrict(PolicyTrackerLimits::decode(&narrower).unwrap());
        assert_eq!(
            policy.resolve(Some(id)),
            LiveQueryTrackerLimits {
                max_events: 300,
                max_bytes: 4_000,
                receipt_grace_ticks: 2
            }
        );
        assert_eq!(
            policy.resolve(None),
            LiveQueryTrackerLimits {
                max_events: 300,
                max_bytes: 16_000,
                receipt_grace_ticks: 2
            }
        );
        assert!(
            PolicyTrackerLimits::decode(&Value::Map(vec![(
                Value::from("vault"),
                Value::Map(vec![
                    (Value::from("max_events"), Value::from(0)),
                    (Value::from("max_bytes"), Value::from(16_000)),
                ])
            )]))
            .is_none()
        );
    }
}
