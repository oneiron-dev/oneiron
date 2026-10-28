//! Pinned ledger keys and receipt fields.

use serde::{Deserialize, Serialize};

use super::scope::RoutingScopeKey;
use crate::error::{Error, Result};
use crate::learning::TypeRef;
use crate::llm::LlmRole;
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Per-head aggregates, keyed by task class, measurement version, task type,
/// then executor — the first three FIRST, because the peers behind every
/// relative score and every carried prior are exactly one prefixed scan, and
/// runs measured under another engine version or placed in another task type
/// are not peers (FIX 7822, 7826).
pub(super) const AGGREGATE: SideTable<AggregateKey, StoredAggregate, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_ROUTING_AGGREGATE);

/// Run→executor binding, keyed by receipt id: the stamp the folded
/// receipt's judgment carried, and the mark that it was folded once.
pub(super) const MEMBER: SideTable<String, StoredExecutor, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_ROUTING_MEMBER);

/// Per-task-class rollout rung.
pub(super) const RUNG: SideTable<String, StoredRung, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_ROUTING_RUNG);

/// The executor serving now — the house pattern of a per-feature table in
/// the owning module (`INBOX_REVIEW_DIAL_KEY`), because `settings.rs` is UI
/// customization and this is not. No fold reads it (FIX 9812).
pub(super) const SERVING_MODEL: SideTable<(), ServingExecutor, Raw> =
    SideTable::new(&side_table::EDIT_DISTANCE_ROUTING_SERVING_MODEL);

/// `edit_distance/routing_aggregate/v1` row key: task class, `0x00`,
/// measurement version, `0x00`, task type, `0x00`, executor. Not a
/// [`FixedSideKey`](crate::side_table::FixedSideKey) tuple: no part has a
/// fixed width.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct AggregateKey {
    pub(super) task_class: String,
    pub(super) measurement_version: String,
    /// The task type's `node@version` form, or [`NO_TYPE_REF`].
    pub(super) type_ref: String,
    /// The executor identity at revision, or the unknown-executor key.
    pub(super) executor: String,
}

impl SideKey for AggregateKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.task_class.as_bytes());
        out.push(KEY_SEPARATOR);
        out.extend_from_slice(self.measurement_version.as_bytes());
        out.push(KEY_SEPARATOR);
        out.extend_from_slice(self.type_ref.as_bytes());
        out.push(KEY_SEPARATOR);
        out.extend_from_slice(self.executor.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let mut parts = bytes.splitn(4, |&byte| byte == KEY_SEPARATOR);
        let mut part = || String::from_utf8(parts.next()?.to_vec()).ok();
        Some(Self {
            task_class: part()?,
            measurement_version: part()?,
            type_ref: part()?,
            executor: part()?,
        })
    }
}

/// Only accepted schema version for any row this module stores.
pub(super) const ROW_VERSION: u8 = 1;

pub(super) const AGGREGATE_ROW_LABEL: &str = "routing aggregate row";

pub(super) const MEMBER_ROW_LABEL: &str = "routing membership row";

pub(super) const RUNG_ROW_LABEL: &str = "routing rollout rung row";

pub(super) const SERVING_MODEL_ROW_LABEL: &str = "routing serving model row";

/// Separator between a key's parts. No part may contain it, which the key
/// builder enforces rather than assumes.
const KEY_SEPARATOR: u8 = 0;

/// The task-type part of a head whose runs no task placed. It holds no `@`,
/// so no `node@version` form can collide with it.
const NO_TYPE_REF: &str = "-";

/// Longest accepted task class — the ED lane's scope bound, shared with
/// `edit_distance::attribution` so one scope string means one thing lane-wide.
const MAX_TASK_CLASS_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN;

/// The role whose model drafts the proposals this projection measures, and so
/// the role whose default names the executor serving an unconfigured vault.
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
    /// The sound share of every run summed: a single-verdict run adds 0 or 1.
    /// An integer row written before split verdicts reads back as the same
    /// count.
    pub(super) sound: f64,
    /// The attributed share of every run summed — what the judge could
    /// label, with each `unclear` share held out. `None` on a row written
    /// before split verdicts, whose runs were each judged whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) judged: Option<f64>,
    /// Runs drafted on the judge's own model (ARCH-0056 §8): flagged, since
    /// judges favour their own model's work.
    pub(super) on_judge_model: u64,
    /// The newest folded judgment's stamp: which other executor's head a
    /// new head carries its prior from.
    pub(super) last_at: u64,
}

impl StoredAggregate {
    /// The attributed weight the outcome score divides by.
    #[expect(
        clippy::cast_precision_loss,
        reason = "run counts live far below f64's exact-integer range"
    )]
    pub(super) fn judged_weight(&self) -> f64 {
        self.judged.unwrap_or(self.runs as f64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StoredExecutor {
    pub(super) v: u8,
    pub(super) executor: String,
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
// `StoredExecutor` backs two tables with two distinct pinned error labels
// (`MEMBER_ROW_LABEL`, `SERVING_MODEL_ROW_LABEL`), so it cannot take the
// shared macro: `MEMBER`'s value binds the type directly, and
// `SERVING_MODEL` wraps it in `ServingExecutor` below.
impl RawValue for StoredExecutor {
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

/// [`StoredExecutor`] as stored in [`SERVING_MODEL`] — same shape, its own
/// pinned error label.
pub(super) struct ServingExecutor(pub(super) StoredExecutor);

impl RawValue for ServingExecutor {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_row(&self.0, SERVING_MODEL_ROW_LABEL)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let row: StoredExecutor = decode_row(bytes, SERVING_MODEL_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(CodecError::Value(Error::CorruptedIndex(
                SERVING_MODEL_ROW_LABEL,
            )));
        }
        Ok(Self(row))
    }
}

row_codec!(StoredRung, RUNG_ROW_LABEL);

/// The bytes after [`AGGREGATE`]'s prefix that scope every executor under
/// one task class, measurement version and task type — the peer scan's
/// `key_prefix`.
pub(super) fn peer_prefix(scope: &RoutingScopeKey) -> Result<Vec<u8>> {
    let mut prefix = normalized_task_class(&scope.task_class)?
        .as_bytes()
        .to_vec();
    prefix.push(KEY_SEPARATOR);
    prefix.extend_from_slice(usable_key_part(&scope.measurement_version)?.as_bytes());
    prefix.push(KEY_SEPARATOR);
    prefix.extend_from_slice(type_ref_part(scope.type_ref.as_ref())?.as_bytes());
    prefix.push(KEY_SEPARATOR);
    Ok(prefix)
}

pub(super) fn aggregate_key(scope: &RoutingScopeKey) -> Result<AggregateKey> {
    Ok(AggregateKey {
        task_class: normalized_task_class(&scope.task_class)?.to_owned(),
        measurement_version: usable_key_part(&scope.measurement_version)?.to_owned(),
        type_ref: type_ref_part(scope.type_ref.as_ref())?,
        executor: usable_key_part(&scope.executor)?.to_owned(),
    })
}

/// The scope a stored key names.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] when the task-type part is neither absent nor a
/// `node@version` form.
pub(super) fn routing_scope(key: &AggregateKey) -> Result<RoutingScopeKey> {
    let scope = RoutingScopeKey::new(key.executor.clone(), key.task_class.clone())
        .measured_under(key.measurement_version.clone());
    if key.type_ref == NO_TYPE_REF {
        return Ok(scope);
    }
    let (node_id, version) = key
        .type_ref
        .rsplit_once('@')
        .ok_or(Error::CorruptedIndex(AGGREGATE_ROW_LABEL))?;
    let tree_version = version
        .parse()
        .map_err(|_| Error::CorruptedIndex(AGGREGATE_ROW_LABEL))?;
    Ok(scope.typed(TypeRef {
        node_id: node_id.to_owned(),
        tree_version,
    }))
}

/// A task type as one part of an aggregate key: its `node@version` form, or
/// [`NO_TYPE_REF`] when no task placed the runs.
fn type_ref_part(type_ref: Option<&TypeRef>) -> Result<String> {
    match type_ref {
        Some(type_ref) => {
            type_ref.validate()?;
            Ok(type_ref.wire_form())
        }
        None => Ok(NO_TYPE_REF.to_owned()),
    }
}

/// A version or executor as one part of an aggregate key: non-empty and
/// separator-free.
fn usable_key_part(version: &str) -> Result<&str> {
    if version.is_empty() || version.as_bytes().contains(&KEY_SEPARATOR) {
        return Err(invalid("a routing version must be a usable key"));
    }
    Ok(version)
}

/// Run counts live far below `f64`'s exact-integer range, so this cast is the
/// identity every caller here means by it.
pub(super) fn runs_as_f64(runs: u64) -> f64 {
    runs as f64
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
