//! Owned body descriptor vocabulary and its digest wire representation.

use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// Where a body's bytes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyLocation {
    /// Under the owning family's LMDB rows; erased with the owner's rows.
    Inline,
    /// One per-vault file named by the digest; reclaimed only once no
    /// descriptor holds the digest.
    File,
}

/// A body's identity: its BLAKE3 digest, length and location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyRef {
    #[serde(with = "hex32")]
    pub blake3: [u8; 32],
    pub bytes: u64,
    pub location: BodyLocation,
}

/// Whether a body is whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyState {
    /// The producer has not finished, or stopped before the whole body was
    /// durable. `retained` is a durable partial a reader may see, labelled
    /// partial; `None` is a body with nothing safe to show.
    Incomplete { retained: Option<BodyRef> },
    /// The whole body is durable and its digest is final.
    Complete { body: BodyRef },
}

impl BodyState {
    /// The bytes this state holds, if any.
    #[must_use]
    pub const fn held(&self) -> Option<&BodyRef> {
        match self {
            Self::Incomplete { retained } => retained.as_ref(),
            Self::Complete { body } => Some(body),
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }
}

/// One body occurrence and the record that owns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedBody {
    /// The content-owning record (an entity, or a run's replay record): erase
    /// starts here.
    pub owner: EntityId,
    /// This body or version occurrence. Two occurrences of the same bytes may
    /// have different owners, births and grants.
    pub occurrence: EntityId,
    /// The occurrence whose taint and secret marks this body's bytes carry:
    /// `occurrence` itself, but the owner's own owner/path occurrence on a
    /// code-run raw hold (FIX 7364). It is metadata of this descriptor
    /// only: it grants nothing and proves no bytes landed at that
    /// occurrence.
    pub mark_occurrence: EntityId,
    pub state: BodyState,
    /// What a MESSAGE that holds a run's result keeps of where the body came
    /// from (FIX 365), so a read reopens it after the run's replay is gone.
    /// `None` on every other holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<RetainedResultProvenance>,
    /// Where a code-run output occurrence is (FIX 7365), set by the one
    /// factory every code-run holder publishes through. An erase of the
    /// run's actor classifies a body its replay row does not list, such as a
    /// raw put's, by this path. `None` on every other family's body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_run_output: Option<CodeRunOutputOrigin>,
}

impl OwnedBody {
    /// Whether `self` and `other` are the same descriptor for a
    /// re-publication (FIX 7365): every field but `code_run_output`, the
    /// occurrence that keeps the marks included. The owner and the
    /// occurrence already fix that origin, so a stored descriptor without
    /// it, or with it, stays as it is.
    #[must_use]
    pub(crate) fn eq_ignoring_origin(&self, other: &Self) -> bool {
        let Self {
            owner,
            occurrence,
            mark_occurrence,
            state,
            result,
            code_run_output: _,
        } = self;
        *owner == other.owner
            && *occurrence == other.occurrence
            && *mark_occurrence == other.mark_occurrence
            && *state == other.state
            && *result == other.result
    }
}

/// A code-run output occurrence's native output path (FIX 7365): the path
/// its occurrence id derives from, with its owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRunOutputOrigin {
    pub path: String,
}

/// A result hold's source: the producer run, its occurrence of the body and
/// its path there, and the rows the run's answers were served from (`None`
/// when the run kept no set, which is unknown, never public). It is no grant:
/// a reader is admitted again under the taint the body has now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedResultProvenance {
    pub run_id: EntityId,
    pub occurrence: EntityId,
    pub path: String,
    pub served_rows: Option<Vec<EntityId>>,
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(blake3::Hash::from_bytes(*bytes).to_hex().as_str())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        blake3::Hash::from_hex(value)
            .map(|hash| *hash.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
