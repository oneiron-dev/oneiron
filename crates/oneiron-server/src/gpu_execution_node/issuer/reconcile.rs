//! The reconcile before dispatch (pass 33 section 8.5). Before its first reserve or submit to a
//! node since this issuer started, the issuer reads every key the node holds for it, ended keys
//! too, page by page. A key that has a dispatch row is left to `status`. A key without one is an
//! orphan: it goes to one hook, which row R4 fills with `JOB_ORPHAN` and its stop; until then
//! the hook logs the key. A reconcile that got no answer, or ended before its last page, leaves
//! the node unmarked, and no reserve or submit goes to it.
use std::collections::BTreeSet;
use std::sync::Mutex;

use oneiron::{EntityId, Vault};

use super::node_client::{JobNodeClient, NodeCallError};
use crate::gpu_execution_node::wire::{JobStatusAnswer, JobStatusRequest, KeyEntry};

/// What the issuer does with a key a node holds for it that it has no dispatch row for.
pub trait OrphanKeys: Send + Sync {
    /// `node` holds `entry`, which this issuer never dispatched or no longer knows.
    fn unknown_key(&self, node: EntityId, entry: &KeyEntry);
}

/// The hook until row R4's `JOB_ORPHAN` lands: it logs the key.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoggedOrphanKeys;

impl OrphanKeys for LoggedOrphanKeys {
    fn unknown_key(&self, node: EntityId, entry: &KeyEntry) {
        tracing::warn!(
            node = %node.to_hex(),
            key = %entry.key,
            state = ?entry.state,
            ended = entry.ended.is_some(),
            "vault_machine: a node holds a key this issuer has no dispatch row for"
        );
    }
}

/// Why a reconcile did not finish.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReconcileError {
    #[error(transparent)]
    Call(#[from] NodeCallError),
    /// The node answered something other than a page of keys.
    #[error("the machine did not list its keys: {answer}")]
    NotListed { answer: String },
    #[error("the issuer's store could not be read: {0}")]
    Store(String),
}

/// The nodes reconciled since this issuer started. It lives as long as the connector, so a
/// restarted issuer reconciles every node again.
#[derive(Debug, Default)]
pub struct Reconciled {
    nodes: Mutex<BTreeSet<EntityId>>,
}

impl Reconciled {
    /// Whether `node` was reconciled since this issuer started.
    #[must_use]
    pub fn is_marked(&self, node: EntityId) -> bool {
        self.nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&node)
    }

    /// Reconciles `node` unless it is marked: reads every page of its keys, hands each key with
    /// no dispatch row to `orphans`, and marks the node once the last page was read.
    ///
    /// # Errors
    ///
    /// [`ReconcileError`] when a page did not arrive; the node stays unmarked.
    pub fn ensure(
        &self,
        node: EntityId,
        vault: &Vault,
        client: &dyn JobNodeClient,
        orphans: &dyn OrphanKeys,
    ) -> Result<(), ReconcileError> {
        if self.is_marked(node) {
            return Ok(());
        }
        let mut after = None;
        loop {
            let page = match client.job_status(node, &JobStatusRequest::Keys { after })? {
                JobStatusAnswer::Keys(page) => page,
                other => {
                    return Err(ReconcileError::NotListed {
                        answer: super::status_answer_kind(&other).to_owned(),
                    });
                }
            };
            for entry in &page.entries {
                let dispatched = vault
                    .job_dispatch(&entry.key)
                    .map_err(|error| ReconcileError::Store(error.to_string()))?;
                if dispatched.is_none_or(|row| row.machine != node) {
                    orphans.unknown_key(node, entry);
                }
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        self.nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(node);
        Ok(())
    }
}
