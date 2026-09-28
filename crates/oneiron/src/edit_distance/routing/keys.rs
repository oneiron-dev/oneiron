//! Pinned ledger keys and receipt fields.

use serde::{Deserialize, Serialize};

use super::scope::RoutingScopeKey;
use crate::error::{Error, Result};
use crate::llm::LlmRole;
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Per-scope aggregates, keyed by task class then model version — task class
/// FIRST, because the peer distribution behind every relative score is
/// exactly one task-class-prefixed scan.
pub(super) const AGGREGATE: SideTable<AggregateKey, StoredAggregate, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_ROUTING_AGGREGATE);

/// Run→generation binding, keyed by receipt id.
pub(super) const MEMBER: SideTable<String, StoredModelVersion, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_ROUTING_MEMBER);

/// Per-task-class rollout rung.
pub(super) const RUNG: SideTable<String, StoredRung, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_ROUTING_RUNG);

/// The model version new folds are stamped with — the house pattern of a
/// per-feature table in the owning module (`INBOX_REVIEW_DIAL_KEY`), because
/// `settings.rs` is UI customization and this is not.
pub(super) const SERVING_MODEL: SideTable<(), ServingModelVersion, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_ROUTING_SERVING_MODEL);

/// `edit_distance/routing_aggregate/v1` row key: task class, then `0x00`, then
/// model version. Not a [`FixedSideKey`](crate::side_table::FixedSideKey) tuple: neither half has a
/// fixed width.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct AggregateKey {
    pub(super) task_class: String,
    pub(super) model_version: String,
}

impl SideKey for AggregateKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.task_class.as_bytes());
        out.push(KEY_SEPARATOR);
        out.extend_from_slice(self.model_version.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let split = bytes.iter().position(|&byte| byte == KEY_SEPARATOR)?;
        Some(Self {
            task_class: String::from_utf8(bytes[..split].to_vec()).ok()?,
            model_version: String::from_utf8(bytes[split + 1..].to_vec()).ok()?,
        })
    }
}

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

macro_rules! row_codec {
    ($ty:ty, $label:expr) => {
        impl RawValue for $ty {
            fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
                Ok(encode_row(self, $label)?)
            }

            fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
                let row: $ty = decode_row(bytes, $label)?;
                if row.v != ROW_VERSION {
                    return Err(CodecError::Value(Error::CorruptedIndex($label)));
                }
                Ok(row)
            }
        }
    };
}

row_codec!(StoredAggregate, AGGREGATE_ROW_LABEL);
// `StoredModelVersion` backs two tables with two distinct pinned error
// labels (`MEMBER_ROW_LABEL`, `SERVING_MODEL_ROW_LABEL`), so it cannot take
// the shared macro: `MEMBER`'s value binds the type directly, and
// `SERVING_MODEL` wraps it in `ServingModelVersion` below.
impl RawValue for StoredModelVersion {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_row(self, MEMBER_ROW_LABEL)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let row: Self = decode_row(bytes, MEMBER_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(CodecError::Value(Error::CorruptedIndex(MEMBER_ROW_LABEL)));
        }
        Ok(row)
    }
}

/// [`StoredModelVersion`] as stored in [`SERVING_MODEL`] — same shape, its own
/// pinned error label.
pub(super) struct ServingModelVersion(pub(super) StoredModelVersion);

impl RawValue for ServingModelVersion {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_row(&self.0, SERVING_MODEL_ROW_LABEL)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let row: StoredModelVersion = decode_row(bytes, SERVING_MODEL_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(CodecError::Value(Error::CorruptedIndex(
                SERVING_MODEL_ROW_LABEL,
            )));
        }
        Ok(Self(row))
    }
}

row_codec!(StoredRung, RUNG_ROW_LABEL);

/// The bytes after [`AGGREGATE`]'s prefix that scope every model version under
/// one task class — the peer-distribution scan's `key_prefix`.
pub(super) fn task_class_prefix(task_class: &str) -> Result<Vec<u8>> {
    let mut prefix = normalized_task_class(task_class)?.as_bytes().to_vec();
    prefix.push(KEY_SEPARATOR);
    Ok(prefix)
}

pub(super) fn aggregate_key(scope: &RoutingScopeKey) -> Result<AggregateKey> {
    if scope.model_version.is_empty() || scope.model_version.as_bytes().contains(&KEY_SEPARATOR) {
        return Err(invalid("a routing model version must be a usable key"));
    }
    Ok(AggregateKey {
        task_class: normalized_task_class(&scope.task_class)?.to_owned(),
        model_version: scope.model_version.clone(),
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
