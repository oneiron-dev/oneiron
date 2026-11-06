//! Core half of `store::reader_fold_receipt`: its store-layer items live in `oneiron_store::reader_fold_receipt` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::reader_fold_receipt::*;

use crate::side_table::{CodecError, RawValue};
use crate::store::result_manifest::ResultOccurrence;
use crate::{EntityId, Error, Result};
use serde::{Deserialize, Serialize};

/// One result occurrence as a receipt names it: its id, the run that holds
/// it, its path in that run's record and its body's handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OccurrenceRef {
    pub(crate) occurrence: EntityId,
    pub(crate) owner: EntityId,
    pub(crate) path: String,
    pub(crate) handle: String,
}

impl OccurrenceRef {
    pub(crate) fn new(owner: EntityId, path: &str, handle: &str) -> Result<Self> {
        Ok(Self {
            occurrence: ResultOccurrence::owned(owner, path)?.id(),
            owner,
            path: path.to_owned(),
            handle: handle.to_owned(),
        })
    }
}

/// The source a fold read: its occurrence and the range of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptSource {
    pub(crate) occurrence: OccurrenceRef,
    pub(crate) range: (u64, u64),
}

/// One reader job a fold named: its task, its finding (none for a job that
/// left none), its state, why it settled short, and its delegated primary range.
/// A scoped finding alone does not establish byte coverage of that range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptFinding {
    pub(crate) task: EntityId,
    pub(crate) occurrence: Option<OccurrenceRef>,
    pub(crate) state: String,
    pub(crate) reason: Option<String>,
    pub(crate) range: (u64, u64),
}

/// One summary of a fold's tree and the results it summarized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReceiptTree {
    pub(crate) summary: OccurrenceRef,
    pub(crate) inputs: Vec<OccurrenceRef>,
}

/// What a folded result rests on: the source it was read from and the
/// findings it was folded from. It is not
/// `EdgeProvenanceClaimBody.substrate_ref` (provenance/codec.rs), which
/// names the MODEL that produced a write; nothing here reaches that field or
/// its gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReaderSubstrateRef {
    pub(crate) source: OccurrenceRef,
    pub(crate) findings: Vec<OccurrenceRef>,
}

/// A fold's receipt: the folded result, the source and range it read, each
/// job it named, the byte ranges read, unread and read short, the children's
/// cutoff, the recipe it folded by, its summary tree, every occurrence whose
/// taint the folded body inherits, what it rests on, and, once a document
/// import restored it, which occurrences it names did not come back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReaderFoldReceipt {
    pub(crate) folded: OccurrenceRef,
    pub(crate) source: ReceiptSource,
    pub(crate) findings: Vec<ReceiptFinding>,
    pub(crate) read: Vec<(u64, u64)>,
    pub(crate) unread: Vec<(u64, u64)>,
    pub(crate) partial: Vec<ReceiptPartial>,
    pub(crate) cutoff_unix_ms: u64,
    pub(crate) recipe: Option<serde_json::Value>,
    pub(crate) tree: Vec<ReceiptTree>,
    pub(crate) taint: Vec<OccurrenceRef>,
    pub(crate) substrate_ref: ReaderSubstrateRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) unresolved: Vec<OccurrenceRef>,
}

impl ReaderFoldReceipt {
    /// What the folded result's card says of it: the ranges read, unread
    /// and read short, how many jobs it named, and, for an imported receipt
    /// some of whose occurrences did not come back, how many.
    pub(crate) fn card(&self) -> serde_json::Value {
        let mut card = serde_json::json!({
            "read": self.read,
            "unread": self.unread,
            "partial": self.partial,
            "children": self.findings.len(),
        });
        if !self.unresolved.is_empty() {
            card["unresolved"] = self.unresolved.len().into();
        }
        card
    }

    /// An imported receipt: it keeps every occurrence it names, and names
    /// as `unresolved` each one `resolves` finds nothing for (its source,
    /// findings, summary tree, taint and what it rests on), once each.
    pub(crate) fn mark_unresolved(
        &mut self,
        mut resolves: impl FnMut(&OccurrenceRef) -> Result<bool>,
    ) -> Result<()> {
        let named = std::iter::once(&self.source.occurrence)
            .chain(self.findings.iter().filter_map(|f| f.occurrence.as_ref()))
            .chain(
                self.tree
                    .iter()
                    .flat_map(|t| std::iter::once(&t.summary).chain(&t.inputs)),
            )
            .chain(&self.taint)
            .chain(std::iter::once(&self.substrate_ref.source))
            .chain(&self.substrate_ref.findings);
        let mut seen = std::collections::BTreeSet::new();
        let mut unresolved = Vec::new();
        for item in named {
            if seen.insert((item.owner, item.occurrence)) && !resolves(item)? {
                unresolved.push(item.clone());
            }
        }
        self.unresolved = unresolved;
        Ok(())
    }

    /// The receipt of a withheld folded occurrence as an export carries it:
    /// its marker and its refs, no range, reason or recipe.
    pub(crate) fn refs_only(&self) -> serde_json::Value {
        let refs = |items: &mut dyn Iterator<Item = &OccurrenceRef>| {
            items
                .map(|item| item.occurrence.to_hex())
                .collect::<Vec<_>>()
        };
        serde_json::json!({
            "folded": self.folded.occurrence.to_hex(),
            "source": self.source.occurrence.occurrence.to_hex(),
            "findings": refs(&mut self.findings.iter().filter_map(|f| f.occurrence.as_ref())),
            "taint": refs(&mut self.taint.iter()),
        })
    }
}

macro_rules! json_row {
    ($row:ty, $what:literal) => {
        impl RawValue for $row {
            fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
                serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex($what).into())
            }

            fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
                serde_json::from_slice(bytes).map_err(|_| Error::CorruptedIndex($what).into())
            }
        }
    };
}

json_row!(ReaderFoldReceipt, "code-run reader fold receipt");
