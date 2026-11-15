//! On-demand review explainers over the exact pending fork set. Outputs are never stored.

mod run;

pub use run::{
    ReviewExplainerError, ReviewExplainerExecution, ReviewExplainerRoute, explain_review_bundle,
};

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::forks::{ENTITY_DOC_FORK_SNAPSHOT, read_bundle};
use super::{EntityDoc, ForkRecord, invalid, storage};
use crate::error::Result;
use crate::{EntityId, Vault};

#[doc(hidden)]
use oneiron_records::entity_doc::review_explainer::one_line;
#[doc(hidden)]
pub use oneiron_records::entity_doc::review_explainer::{
    ReviewComplexity, ReviewDiagram, ReviewDiagramEdge, ReviewDiagramNode,
    ReviewExplainerCallReceipt, ReviewExplainerEscalation, ReviewExplainerReceipt,
    ReviewForkExplanation,
};

/// One retained fork and its opening-base and proposed text, read in one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewForkInput {
    pub record: ForkRecord,
    pub before: String,
    pub after: String,
    pub frontier: Vec<u8>,
}

/// Only forks still waiting for review belong in the explainer's input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewBundleInput {
    pub proposal: String,
    pub forks: Vec<ReviewForkInput>,
}

/// The model's text is mandatory; a diagram is supplementary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewExplainerOutput {
    pub summary: String,
    pub changes: Vec<ReviewForkExplanation>,
    pub diagram: Option<ReviewDiagram>,
}

impl ReviewExplainerOutput {
    pub fn complexity(&self) -> ReviewComplexity {
        self.changes
            .iter()
            .map(|change| change.complexity)
            .max()
            .unwrap_or(ReviewComplexity::Easy)
    }

    pub(super) fn validate(&self, input: &ReviewBundleInput) -> Result<()> {
        let expected: BTreeSet<_> = input
            .forks
            .iter()
            .map(|fork| fork.record.fork.as_str())
            .collect();
        let actual: BTreeSet<_> = self
            .changes
            .iter()
            .map(|change| change.fork.as_str())
            .collect();
        if !one_line(&self.summary)
            || actual != expected
            || actual.len() != self.changes.len()
            || self.changes.iter().any(|change| {
                !one_line(&change.line)
                    || change
                        .removed_public_names
                        .iter()
                        .any(|name| name.trim().is_empty())
                    || (!change.removed_public_names.is_empty()
                        && change.complexity != ReviewComplexity::VeryComplex)
            })
        {
            return Err(invalid(
                "explainer must cover each pending fork exactly once",
            ));
        }
        if let Some(diagram) = &self.diagram {
            let nodes: BTreeSet<_> = diagram.nodes.iter().map(|node| node.id.as_str()).collect();
            if nodes.is_empty()
                || nodes.len() != diagram.nodes.len()
                || diagram.nodes.iter().any(|node| {
                    node.id.trim().is_empty()
                        || node.label.trim().is_empty()
                        || node.forks.is_empty()
                        || node
                            .forks
                            .iter()
                            .any(|fork| !expected.contains(fork.as_str()))
                })
                || diagram.edges.iter().any(|edge| {
                    !nodes.contains(edge.from.as_str())
                        || !nodes.contains(edge.to.as_str())
                        || edge.label.trim().is_empty()
                })
            {
                return Err(invalid("explainer diagram contains unbound nodes or edges"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewBundleExplanation {
    pub explainer: ReviewExplainerOutput,
    pub receipt: ReviewExplainerReceipt,
}

impl Vault {
    /// Reads base and proposed text from retained forks, never from a later live head.
    /// The returned projection, like its generated explanation, is not a memory row.
    pub fn review_bundle_input(&self, proposal: &EntityId) -> Result<ReviewBundleInput> {
        let txn = self.store.env.read_txn()?;
        let bundle = read_bundle(&self.store, &txn, proposal)?;
        let mut forks = Vec::new();
        for record in bundle.pending() {
            storage::require_live(&self.store, &txn, &EntityId::from_hex(&record.entity)?)?;
            let bytes = ENTITY_DOC_FORK_SNAPSHOT
                .get(&self.store, &txn, &record.fork)?
                .ok_or(crate::Error::EntityNotFound)?;
            let doc = EntityDoc::from_snapshot(&bytes)?;
            forks.push(ReviewForkInput {
                record: record.clone(),
                before: doc.text_at(&record.base)?,
                after: doc.text(),
                frontier: doc.frontier(),
            });
        }
        if bundle.settled || forks.is_empty() {
            return Err(invalid("proposal has no pending review forks"));
        }
        Ok(ReviewBundleInput {
            proposal: bundle.proposal,
            forks,
        })
    }
}
