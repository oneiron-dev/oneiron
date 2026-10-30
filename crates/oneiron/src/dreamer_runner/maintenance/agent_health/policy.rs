//! The reviewer's policy (FIX 8075, agent-mind §3.8: "The recipe is a
//! skill"): the in-force `agent-health-review` skill revision and the typed
//! T1 seeds its `policy.json` carries.
//! Entry: `ReviewerPolicy::read_in_txn`, then `ReviewerPolicy::seed` per dial.
//! A revision's seed replaces only a dial's compiled seed: an owner's seed or
//! pin and a fit outrank it (agent-mind §3.7). A missing, unreadable or
//! invalid policy, or key, falls back to the compiled seed for that dial
//! alone, and the pass logs it; it never fails the pass.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    HEALTH_CARD_FLOOR, HEALTH_CHECK_FAILS, HEALTH_COST_MIN_RUNS, HEALTH_COST_SPIKE,
    HEALTH_DUP_MIN_COST, HEALTH_LOOP_REPEATS, HEALTH_REVIEW_WINDOW_HOURS, HEALTH_SILENT_MINUTES,
    HEALTH_WAIT_MINUTES, HEALTH_WAIT_SHARE, HEALTH_WIDEN_DENIALS,
};
use crate::edge::EdgeKind;
use crate::learning_setting::SettingSpec;
use crate::{EntityId, Error, Result, Vault};

/// The reviewer skill: its revision's `policy.json` seeds the T1 dials, and
/// an owner's outcome on a card scores that revision.
pub(crate) const AGENT_HEALTH_REVIEW_SKILL_ID: &str = "agent-health-review";

/// The package file that carries a revision's seeds: one number per dial key.
pub(crate) const REVIEWER_POLICY_FILE: &str = "policy.json";

/// The detector dials a revision may seed. The review switch, the owner copy
/// and the escalation TTL decide whether and to whom a card goes; a revision
/// never seeds them.
const POLICY_DIALS: [&SettingSpec; 11] = [
    &HEALTH_LOOP_REPEATS,
    &HEALTH_CHECK_FAILS,
    &HEALTH_WAIT_SHARE,
    &HEALTH_WAIT_MINUTES,
    &HEALTH_SILENT_MINUTES,
    &HEALTH_WIDEN_DENIALS,
    &HEALTH_COST_SPIKE,
    &HEALTH_CARD_FLOOR,
    &HEALTH_DUP_MIN_COST,
    &HEALTH_COST_MIN_RUNS,
    &HEALTH_REVIEW_WINDOW_HOURS,
];

/// Why the policy, or one key of it, left a dial on its compiled seed.
#[derive(Debug)]
pub(super) enum PolicyFallback {
    /// No revision is in force: none was seeded, or the newest revision is
    /// not live, shared, active and approved.
    NoRevision,
    /// The revision or its package could not be read.
    Unreadable,
    /// The revision's package holds no `policy.json`.
    NoPolicy,
    /// `policy.json` is not one JSON object.
    Invalid,
    /// A dial the file leaves out, or whose value is not a number inside the
    /// dial's bounds.
    Dial(&'static str),
    /// A key that names no detector dial. It seeds nothing.
    Unknown(String),
}

/// The in-force reviewer revision and the seeds its policy carries.
pub(super) struct ReviewerPolicy {
    revision: Option<EntityId>,
    seeds: BTreeMap<&'static str, f64>,
    fallbacks: Vec<PolicyFallback>,
}

impl ReviewerPolicy {
    /// The in-force revision's policy, decoded per key. Any failure to read
    /// it is a fallback, never an error.
    pub(super) fn read_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Self {
        let (revision, bytes) = match in_force_policy_in_txn(vault, txn) {
            Ok(Some(read)) => read,
            Ok(None) => return Self::compiled(None, PolicyFallback::NoRevision),
            Err(error) => {
                tracing::debug!(kind = ?error.kind(), "agent-health reviewer revision unreadable");
                return Self::compiled(None, PolicyFallback::Unreadable);
            }
        };
        let Some(bytes) = bytes else {
            return Self::compiled(Some(revision), PolicyFallback::NoPolicy);
        };
        let (seeds, fallbacks) = decode(&bytes);
        Self {
            revision: Some(revision),
            seeds,
            fallbacks,
        }
    }

    /// Every dial on its compiled seed, for `fallback`.
    fn compiled(revision: Option<EntityId>, fallback: PolicyFallback) -> Self {
        Self {
            revision,
            seeds: BTreeMap::new(),
            fallbacks: vec![fallback],
        }
    }

    /// `spec` with the revision's seed in place of its compiled one, and the
    /// revision. `None` when the revision seeds no valid value for it.
    pub(super) fn seed(&self, spec: &SettingSpec) -> Option<(SettingSpec, EntityId)> {
        let revision = self.revision?;
        let seed = *self.seeds.get(spec.key)?;
        Some((SettingSpec { seed, ..*spec }, revision))
    }

    /// The pass's record of each fallback: a revision's bad policy or key
    /// at warn, no revision in force at debug.
    pub(super) fn log_fallbacks(&self) {
        let revision = self.revision.map(|revision| revision.to_hex());
        for fallback in &self.fallbacks {
            match fallback {
                PolicyFallback::NoRevision => {
                    tracing::debug!("agent-health reviewer: no revision in force, compiled seeds");
                }
                PolicyFallback::Dial(dial) => tracing::warn!(
                    revision = ?revision,
                    dial,
                    "agent-health reviewer policy: the dial keeps its compiled seed"
                ),
                PolicyFallback::Unknown(key) => tracing::warn!(
                    revision = ?revision,
                    key = %key,
                    "agent-health reviewer policy: the key names no detector dial"
                ),
                PolicyFallback::Unreadable | PolicyFallback::NoPolicy | PolicyFallback::Invalid => {
                    tracing::warn!(
                        revision = ?revision,
                        fallback = ?fallback,
                        "agent-health reviewer policy fell back to the compiled seeds"
                    );
                }
            }
        }
    }
}

/// The reviewer's in-force revision and its `policy.json` bytes: from the
/// bootstrap `agent-health-review` skill, through admitted succession
/// (`Supersedes`, new to old) to its newest revision, when that revision is
/// live, shared, active and approved (the judge rubric's walk). `None` when
/// no such revision exists; the bytes are `None` when its package holds no
/// policy.
fn in_force_policy_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<(EntityId, Option<Vec<u8>>)>> {
    let mut head = EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[AGENT_HEALTH_REVIEW_SKILL_ID.as_bytes()],
    )?;
    let mut seen = BTreeSet::from([head]);
    loop {
        let newer = vault.filtered_edge_peers(
            txn,
            crate::ports::EdgeDirection::In,
            &head,
            EdgeKind::Supersedes,
            Some(crate::registry::ENTITY_TYPE_SKILL),
        )?;
        // Admitted succession is linear; the least id settles a fork in it.
        let Some(next) = newer.into_iter().filter(|id| !seen.contains(id)).min() else {
            break;
        };
        seen.insert(next);
        head = next;
    }
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &head)?.is_live() {
        return Ok(None);
    }
    let record = match vault.read_skill_record_in_txn(txn, &head) {
        Ok(record) => record,
        Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if record.skill_id != AGENT_HEALTH_REVIEW_SKILL_ID
        || crate::skill::resident_of(&record)?.is_some()
        || !crate::skill::skill_loadable(&record)
    {
        return Ok(None);
    }
    let policy = vault
        .runtime_skill_package_in_txn(txn, &head, &record)?
        .and_then(|package| {
            package
                .files
                .into_iter()
                .find(|file| file.path == REVIEWER_POLICY_FILE)
                .map(|file| file.content)
        });
    Ok(Some((head, policy)))
}

/// The seeds T1 reads from `bytes`, a revision's `policy.json`: each
/// detector dial's valid seed, by dial key. The skill gate compares these
/// for a reviewer revision, not the file's text (FIX 10878).
pub(crate) fn reviewer_policy_seeds(bytes: &[u8]) -> BTreeMap<&'static str, f64> {
    decode(bytes).0
}

/// The typed seeds `bytes` carry (`TripwireBounds::decode`'s shape): one
/// JSON object whose keys are detector dial keys, each a finite number
/// inside its dial's bounds. A dial left out or out of bounds, and a key
/// that names no dial, is a fallback of that key alone; bytes that are not
/// one object fall back whole.
fn decode(bytes: &[u8]) -> (BTreeMap<&'static str, f64>, Vec<PolicyFallback>) {
    let Ok(serde_json::Value::Object(entries)) = serde_json::from_slice::<serde_json::Value>(bytes)
    else {
        return (BTreeMap::new(), vec![PolicyFallback::Invalid]);
    };
    let mut fallbacks: Vec<PolicyFallback> = entries
        .keys()
        .filter(|key| !POLICY_DIALS.iter().any(|spec| spec.key == key.as_str()))
        .map(|key| PolicyFallback::Unknown(key.clone()))
        .collect();
    let mut seeds = BTreeMap::new();
    for spec in POLICY_DIALS {
        match entries.get(spec.key).and_then(serde_json::Value::as_f64) {
            Some(seed) if seed.is_finite() && (spec.min..=spec.max).contains(&seed) => {
                seeds.insert(spec.key, seed);
            }
            _ => fallbacks.push(PolicyFallback::Dial(spec.key)),
        }
    }
    (seeds, fallbacks)
}
