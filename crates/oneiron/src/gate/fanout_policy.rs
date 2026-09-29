//! Manifest-backed fan-out policy composition; no executable defaults.

use std::collections::BTreeSet;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::error::{Error, Result};
use crate::outbound_chokepoint::FanoutApprovalMode;
use crate::task_verb::{
    ConsultFanOutPolicy, ConsultFanOutRate, ConsultFanOutScope, TaskCreateRateLimit,
};

/// The precedence row is itself vault policy. The stricter option ignores
/// holder overrides; neither option permits a child to exceed the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FanoutPrecedence {
    NestedNarrowing,
    MostRestrictive,
}

impl FanoutPrecedence {
    pub(crate) fn stricter(self, other: Self) -> Self {
        if self == Self::MostRestrictive || other == Self::MostRestrictive {
            Self::MostRestrictive
        } else {
            Self::NestedNarrowing
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FanoutControls {
    pub(crate) mode: FanoutApprovalMode,
    pub(crate) peer_rate: Option<ConsultFanOutRate>,
    pub(crate) create_rate: TaskCreateRateLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FanoutScopedRow {
    pub(crate) row_ref: String,
    pub(crate) scope: ConsultFanOutScope,
    pub(crate) policy: ConsultFanOutPolicy,
    /// Present only on an owner-authenticated, locally authored holder override.
    pub(crate) holder_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FanoutPolicyTrace {
    pub(crate) level: &'static str,
    pub(crate) row_ref: String,
    pub(crate) role: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedFanoutPolicy {
    pub(crate) policy: ConsultFanOutPolicy,
    pub(crate) quota_trace: FanoutPolicyTrace,
}

pub(crate) const VAULT_ROW_REF: &str = "oneiron.default.fanout.v1";

fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Option<T> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).ok()?;
    rmp_serde::from_slice(&bytes).ok()
}

pub(crate) fn valid_rates(
    create_rate: TaskCreateRateLimit,
    peer_rate: Option<&ConsultFanOutRate>,
) -> bool {
    create_rate.limit > 0
        && create_rate.window_seconds > 0
        && peer_rate.is_none_or(|rate| rate.window_secs > 0 && rate.spike_at > 0)
}

pub(crate) fn parse_controls(value: &Value) -> Option<FanoutControls> {
    let controls: FanoutControls = decode(value)?;
    valid_rates(controls.create_rate, controls.peer_rate.as_ref()).then_some(controls)
}

pub(crate) fn parse_precedence(value: &Value) -> Option<FanoutPrecedence> {
    decode(value)
}

pub(crate) fn parse_scoped_rows(value: &Value) -> Option<Vec<FanoutScopedRow>> {
    let Value::Array(values) = value else {
        return None;
    };
    let mut rows = Vec::with_capacity(values.len());
    let mut refs = BTreeSet::new();
    for value in values {
        let row: FanoutScopedRow = decode(value)?;
        if row.row_ref.is_empty()
            || !refs.insert(row.row_ref.clone())
            || !row.scope.is_valid()
            || row.scope.level() == 0
            || !valid_rates(row.policy.create_rate, row.policy.peer_rate.as_ref())
            || row
                .holder_ref
                .as_deref()
                .is_some_and(|id| canonical_ref(id).is_none())
        {
            return None;
        }
        rows.push(row);
    }
    Some(rows)
}

fn canonical_ref(id: &str) -> Option<EntityId> {
    EntityId::from_hex(id)
        .ok()
        .filter(|parsed| parsed.to_hex() == id)
}

impl ConsultFanOutScope {
    pub(crate) fn level(&self) -> u8 {
        if self.thread_ref.is_some() {
            3
        } else if self.subproject_ref.is_some() {
            2
        } else if self.project_ref.is_some() {
            1
        } else {
            0
        }
    }
    pub(crate) fn is_valid(&self) -> bool {
        (self.subproject_ref.is_none() || self.project_ref.is_some())
            && (self.thread_ref.is_none() || self.subproject_ref.is_some())
            && [
                self.project_ref.as_deref(),
                self.subproject_ref.as_deref(),
                self.thread_ref.as_deref(),
            ]
            .into_iter()
            .flatten()
            .all(|id| canonical_ref(id).is_some())
    }
    fn includes(&self, row: &Self) -> bool {
        row.project_ref
            .as_ref()
            .is_none_or(|id| self.project_ref.as_ref() == Some(id))
            && row
                .subproject_ref
                .as_ref()
                .is_none_or(|id| self.subproject_ref.as_ref() == Some(id))
            && row
                .thread_ref
                .as_ref()
                .is_none_or(|id| self.thread_ref.as_ref() == Some(id))
    }
    fn level_name(&self) -> &'static str {
        match self.level() {
            0 => "vault",
            1 => "project",
            2 => "sub-project",
            _ => "thread",
        }
    }
}

fn stricter_mode(a: FanoutApprovalMode, b: FanoutApprovalMode) -> FanoutApprovalMode {
    use FanoutApprovalMode::{Auto, FullAccess, Manual};
    match (a, b) {
        (Manual, _) | (_, Manual) => Manual,
        (Auto, _) | (_, Auto) => Auto,
        (FullAccess, FullAccess) => FullAccess,
    }
}

fn narrow_rate(
    a: Option<ConsultFanOutRate>,
    b: Option<ConsultFanOutRate>,
) -> Option<ConsultFanOutRate> {
    match (a, b) {
        (None, other) | (other, None) => other,
        (Some(a), Some(b)) => Some(ConsultFanOutRate {
            window_secs: a.window_secs.max(b.window_secs),
            spike_at: a.spike_at.min(b.spike_at),
        }),
    }
}

fn narrow_quota(a: TaskCreateRateLimit, b: TaskCreateRateLimit) -> TaskCreateRateLimit {
    TaskCreateRateLimit {
        limit: a.limit.min(b.limit),
        window_seconds: a.window_seconds.max(b.window_seconds),
    }
}

pub(crate) fn narrow(a: &ConsultFanOutPolicy, b: &ConsultFanOutPolicy) -> ConsultFanOutPolicy {
    ConsultFanOutPolicy {
        approval_threshold: a.approval_threshold.min(b.approval_threshold),
        mode: stricter_mode(a.mode, b.mode),
        peer_rate: narrow_rate(a.peer_rate.clone(), b.peer_rate.clone()),
        create_rate: narrow_quota(a.create_rate, b.create_rate),
    }
}

pub(crate) fn resolve(
    threshold: u32,
    controls: &FanoutControls,
    precedence: FanoutPrecedence,
    rows: &[FanoutScopedRow],
    scope: &ConsultFanOutScope,
) -> Result<ResolvedFanoutPolicy> {
    if !scope.is_valid() {
        return Err(Error::InvalidConfig(
            "fan-out policy scope malformed".into(),
        ));
    }
    let vault = ConsultFanOutPolicy {
        approval_threshold: threshold,
        mode: controls.mode,
        peer_rate: controls.peer_rate.clone(),
        create_rate: controls.create_rate,
    };
    let mut effective = ResolvedFanoutPolicy {
        policy: vault.clone(),
        quota_trace: FanoutPolicyTrace {
            level: "vault",
            row_ref: VAULT_ROW_REF.into(),
            role: "owner",
        },
    };
    let mut matches: Vec<_> = rows
        .iter()
        .filter(|row| scope.includes(&row.scope))
        .collect();
    matches.sort_by(|a, b| {
        a.scope
            .level()
            .cmp(&b.scope.level())
            .then_with(|| a.row_ref.cmp(&b.row_ref))
    });
    for row in matches {
        let was = effective.policy.create_rate;
        effective.policy =
            if row.holder_ref.is_some() && precedence == FanoutPrecedence::NestedNarrowing {
                // An authenticated holder can loosen its parent, but the vault is
                // an unconditionally binding ceiling on every descendant.
                narrow(&vault, &row.policy)
            } else {
                narrow(&effective.policy, &row.policy)
            };
        if effective.policy.create_rate != was {
            effective.quota_trace = FanoutPolicyTrace {
                level: row.scope.level_name(),
                row_ref: row.row_ref.clone(),
                role: if row.holder_ref.is_some() {
                    "holder"
                } else {
                    "owner"
                },
            };
        }
    }
    Ok(effective)
}

pub(crate) fn merge_controls(a: &FanoutControls, b: &FanoutControls) -> FanoutControls {
    FanoutControls {
        mode: stricter_mode(a.mode, b.mode),
        peer_rate: narrow_rate(a.peer_rate.clone(), b.peer_rate.clone()),
        create_rate: narrow_quota(a.create_rate, b.create_rate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_controls_decode() {
        let bytes = crate::gate::default_policy_manifest().unwrap();
        let Value::Map(entries) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap() else {
            panic!("shipped manifest is a map")
        };
        let value = entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("consult_fanout_controls"))
            .unwrap()
            .1
            .clone();
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &value).unwrap();
        let result = rmp_serde::from_slice::<FanoutControls>(&encoded);
        assert!(result.is_ok(), "shipped controls: {:?}", result.err());
        assert!(crate::gate::decode::decode_policy_manifest(&bytes).is_some());
    }
    #[test]
    fn malformed_controls_precedence_and_scope_rows_fail_closed() {
        let data = crate::gate::default_policy_manifest().unwrap();
        let Value::Map(original) = rmpv::decode::read_value(&mut data.as_slice()).unwrap() else {
            panic!("default manifest map")
        };
        for (key, corrupt) in [
            (
                "consult_fanout_controls",
                Value::Map(vec![
                    (Value::from("mode"), Value::from("full-access")),
                    (Value::from("peer_rate"), Value::Nil),
                    (
                        Value::from("create_rate"),
                        Value::Map(vec![
                            (Value::from("limit"), Value::from(0_u64)),
                            (Value::from("window_seconds"), Value::from(60_u64)),
                        ]),
                    ),
                ]),
            ),
            ("consult_fanout_precedence", Value::from("last_writer_wins")),
            (
                "consult_fanout_scope_rows",
                Value::Array(vec![Value::Map(vec![
                    (Value::from("row_ref"), Value::from("unbound")),
                    (
                        Value::from("scope"),
                        Value::Map(vec![(
                            Value::from("subproject_ref"),
                            Value::from("not-parented"),
                        )]),
                    ),
                    (Value::from("policy"), Value::Nil),
                    (Value::from("holder_ref"), Value::Nil),
                ])]),
            ),
        ] {
            let mut rows = original.clone();
            rows.iter_mut()
                .find(|(name, _)| name.as_str() == Some(key))
                .expect("shipped row")
                .1 = corrupt;
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &Value::Map(rows)).unwrap();
            assert!(
                crate::gate::decode::decode_policy_manifest(&bytes).is_none(),
                "malformed {key} must not be an implicit policy default"
            );
        }
    }
}
