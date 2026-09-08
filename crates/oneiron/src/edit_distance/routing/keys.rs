//! Pinned ledger keys and receipt fields.

use serde::{Deserialize, Serialize};

use super::scope::RoutingScopeKey;
use crate::error::{Error, Result};
use crate::llm::LlmRole;

// ---------------------------------------------------------------------------
// Keyspace + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` prefix of the per-scope aggregates. The full key is this
/// prefix ‖ task class ‖ `0x00` ‖ model version — task class FIRST, because
/// the peer distribution behind every relative score is exactly one
/// task-class-prefixed scan.
pub(super) const AGGREGATE_KEY_PREFIX: &[u8] = b"edit_distance/routing_aggregate/v1\0";

/// `vault_meta` prefix of the run→generation binding, keyed by receipt id.
pub(super) const MEMBER_KEY_PREFIX: &[u8] = b"edit_distance/routing_member/v1\0";

/// `vault_meta` prefix of the per-task-class rollout rung.
pub(super) const RUNG_KEY_PREFIX: &[u8] = b"edit_distance/routing_rung/v1\0";

/// `vault_meta` key holding the model version new folds are stamped with —
/// the house pattern of a per-feature key const over `vault_meta`
/// (`inbox::INBOX_REVIEW_DIAL_KEY`), because `settings.rs` is UI customization
/// and this is not.
pub(super) const SERVING_MODEL_KEY: &[u8] = b"edit_distance/routing_serving_model/v1";

/// Only accepted schema version for any row this module stores.
pub(super) const ROW_VERSION: u8 = 1;

pub(super) const AGGREGATE_ROW_LABEL: &str = "routing aggregate row";

pub(super) const MEMBER_ROW_LABEL: &str = "routing membership row";

pub(super) const RUNG_ROW_LABEL: &str = "routing rollout rung row";

pub(super) const SERVING_MODEL_ROW_LABEL: &str = "routing serving model row";

/// Separator between a key's task class and its model version. Neither half
/// may contain it, which the key builder enforces rather than assumes.
const KEY_SEPARATOR: u8 = 0;

/// Longest accepted task class — the ED lane's scope bound, shared with
/// `edit_distance::attribution` so one scope string means one thing lane-wide.
const MAX_TASK_CLASS_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN;

/// The role whose model drafts the proposals this projection measures, and so
/// the role whose default names the generation serving an unconfigured vault.
pub(super) const DRAFTING_ROLE: LlmRole = LlmRole::Orchestrator;

pub(super) const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct StoredAggregate {
    pub(super) v: u8,
    /// Judged amendments folded in.
    pub(super) runs: u64,
    /// Total edit mass, in `f64` because a sum of thousands of `f32` masses is
    /// not the number any of them were.
    pub(super) d_norm_sum: f64,
    /// How many of `runs` were judged sound.
    pub(super) sound: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StoredModelVersion {
    pub(super) v: u8,
    pub(super) model_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StoredRung {
    pub(super) v: u8,
    pub(super) rung: String,
}

// ---------------------------------------------------------------------------
// Keys + rows
// ---------------------------------------------------------------------------

pub(super) fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}

pub(super) fn decode_row<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    label: &'static str,
) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(label))
}

pub(super) fn decoded_aggregate(raw: &[u8]) -> Result<StoredAggregate> {
    let row: StoredAggregate = decode_row(raw, AGGREGATE_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(AGGREGATE_ROW_LABEL));
    }
    Ok(row)
}

pub(super) fn meta_key(prefix: &[u8], handle: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + handle.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(handle);
    key
}

pub(super) fn key_tail(key: &[u8], prefix: &[u8], label: &'static str) -> Result<String> {
    let tail = key
        .get(prefix.len()..)
        .ok_or(Error::CorruptedIndex(label))?;
    String::from_utf8(tail.to_vec()).map_err(|_| Error::CorruptedIndex(label))
}

pub(super) fn task_class_prefix(task_class: &str) -> Result<Vec<u8>> {
    let mut prefix = meta_key(
        AGGREGATE_KEY_PREFIX,
        normalized_task_class(task_class)?.as_bytes(),
    );
    prefix.push(KEY_SEPARATOR);
    Ok(prefix)
}

pub(super) fn aggregate_key(scope: &RoutingScopeKey) -> Result<Vec<u8>> {
    if scope.model_version.is_empty() || scope.model_version.as_bytes().contains(&KEY_SEPARATOR) {
        return Err(invalid("a routing model version must be a usable key"));
    }
    let mut key = task_class_prefix(&scope.task_class)?;
    key.extend_from_slice(scope.model_version.as_bytes());
    Ok(key)
}

pub(super) fn scope_key_of(key: &[u8]) -> Result<RoutingScopeKey> {
    let tail = key
        .get(AGGREGATE_KEY_PREFIX.len()..)
        .ok_or(Error::CorruptedIndex(AGGREGATE_ROW_LABEL))?;
    let split = tail
        .iter()
        .position(|byte| *byte == KEY_SEPARATOR)
        .ok_or(Error::CorruptedIndex(AGGREGATE_ROW_LABEL))?;
    let decode = |bytes: &[u8]| {
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::CorruptedIndex(AGGREGATE_ROW_LABEL))
    };
    Ok(RoutingScopeKey {
        task_class: decode(&tail[..split])?,
        model_version: decode(&tail[split + 1..])?,
    })
}

/// The trimmed task class, or the reason it is not one — ED-03's scope rule,
/// so one scope string means one thing lane-wide.
pub(super) fn normalized_task_class(task_class: &str) -> Result<&str> {
    let trimmed = task_class.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_TASK_CLASS_LEN
        || trimmed.as_bytes().contains(&KEY_SEPARATOR)
    {
        return Err(invalid(
            "a routing task class must be non-empty, separator-free and within the consent-ref bound",
        ));
    }
    Ok(trimmed)
}
