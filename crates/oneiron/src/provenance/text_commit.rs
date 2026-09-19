//! Durable per-commit text provenance. The operation log is the receipt ledger;
//! a fold fails closed when even one covered commit lacks a receipt.

use super::made_by::{MadeBy, MadeByClass};
use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Half-open Loro operation span belonging to one document commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextCommitReceipt {
    #[serde(with = "super::entity_ref_wire")]
    pub document: EntityId,
    pub peer: u64,
    pub start: i32,
    pub end: i32,
    pub made_by: MadeBy,
}

/// Rebuildable row provenance, not a per-type derived flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowProvenance {
    pub document: EntityId,
    pub commits: Vec<TextCommitReceipt>,
    pub inputs: BTreeSet<EntityId>,
    pub actors: BTreeSet<EntityId>,
    pub class: MadeByClass,
}

impl RowProvenance {
    /// Call with the complete commit traversal, including absent receipts.
    /// Any gap, duplicate/overlapping span, or foreign document excludes the row.
    #[must_use]
    pub fn fold(
        document: EntityId,
        receipts: impl IntoIterator<Item = Option<TextCommitReceipt>>,
    ) -> Option<Self> {
        let mut commits = Vec::new();
        let mut inputs = BTreeSet::new();
        let mut actors = BTreeSet::new();
        let mut class = MadeByClass::Stated;
        for receipt in receipts {
            let receipt = receipt?;
            if receipt.document != document
                || receipt.start < 0
                || receipt.end <= receipt.start
                || receipt.made_by.process.identity.is_empty()
                || receipt.made_by.process.version.is_empty()
                || receipt.made_by.process.params_hash.is_empty()
                || [
                    &receipt.made_by.process.identity,
                    &receipt.made_by.process.version,
                    &receipt.made_by.process.params_hash,
                ]
                .iter()
                .any(|v| v.len() > 256)
                || receipt.made_by.inputs.len() > 1024
                || (receipt.made_by.trigger.is_some()
                    && (!commits.is_empty()
                        || !receipt
                            .made_by
                            .inputs
                            .iter()
                            .any(|input| input.role == super::made_by::MadeByInputRole::Prompt)))
            {
                return None;
            }
            if commits.iter().any(|other: &TextCommitReceipt| {
                other.peer == receipt.peer && other.start < receipt.end && receipt.start < other.end
            }) {
                return None;
            }
            inputs.extend(receipt.made_by.inputs.iter().map(|input| input.row));
            actors.insert(receipt.made_by.process.actor);
            if receipt.made_by.process.class == MadeByClass::Concluded {
                class = MadeByClass::Concluded;
            }
            commits.push(receipt);
        }
        if commits.is_empty() {
            return None;
        }
        Some(Self {
            document,
            commits,
            inputs,
            actors,
            class,
        })
    }
}
