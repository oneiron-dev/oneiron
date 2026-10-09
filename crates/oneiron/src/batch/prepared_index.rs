//! Index work a committing batch does before its write transaction opens
//! (RESEARCH-1115 Bend 2): the BM25 analysis of its text ops and the HNSW
//! neighbour search of its first fresh vector. The writer's critical section,
//! which a group commit shares with every other write in the group, then only
//! writes postings and edges. Anything not prepared here, or no longer
//! current when the transaction reaches it, is done in the transaction as
//! before.

use std::collections::{HashMap, VecDeque};

use super::BatchOp;
use crate::Vault;
use crate::bm25::AnalyzedText;
use crate::entity_id::EntityId;
use crate::hnsw::InsertPlan;

#[derive(Default)]
pub(super) struct PreparedIndexWork {
    /// One entry per text op of each id, in op order; `None` where the
    /// analysis failed and the transaction analyzes instead.
    pub(super) text: HashMap<EntityId, VecDeque<Option<AnalyzedText>>>,
    pub(super) vectors: HashMap<EntityId, VecDeque<InsertPlan>>,
}

impl PreparedIndexWork {
    pub(super) fn for_ops(vault: &Vault, ops: &[BatchOp]) -> Self {
        let mut prepared = Self::default();
        let mut first_vector = true;
        for op in ops {
            match op {
                BatchOp::Text { id, fields } => {
                    let analyzed = crate::bm25::analyze_text(&vault.analyzer, fields).ok();
                    prepared.text.entry(*id).or_default().push_back(analyzed);
                }
                // Only the batch's first vector can meet the graph it was
                // searched against: every later one follows a graph write.
                BatchOp::Vector { id, vector, .. } if first_vector => {
                    first_vector = false;
                    // A thread that already holds a read snapshot cannot open
                    // another; the insert then searches in the transaction.
                    if let Ok(rtxn) = vault.store.env.read_txn()
                        && let Some(plan) =
                            InsertPlan::search(&vault.store, &vault.config, &rtxn, id, vector)
                    {
                        prepared.vectors.entry(*id).or_default().push_back(plan);
                    }
                }
                _ => {}
            }
        }
        prepared
    }
}
