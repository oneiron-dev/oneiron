//! The reconcile before dispatch (pass 33 section 8.5). Before its first reserve or submit to a
//! node since this issuer started, the issuer reads every key the node holds for it, ended keys
//! too, page by page. A key that has a dispatch row is left to `status`, except one the owner
//! wrote off, which goes to the hook as evidence. A key without one is an orphan: it goes to one
//! hook, which row R4 fills with `JOB_ORPHAN` and its stop (`super::orphans`), and the hook
//! hears when the node's whole listing was read. A reconcile that got no answer, or ended
//! before its last page, leaves the node unmarked, and no reserve or submit goes to it. A node
//! that names a cursor it named before, or more than [`RECONCILE_MAX_PAGES`] pages, is not
//! reconciled either: each call has its timeout, and these bound the whole reconcile.
use std::collections::{BTreeSet, HashSet};
use std::sync::Mutex;

use oneiron::job_dispatch::{DispatchClose, JobDispatch};
use oneiron::{EntityId, Vault};

use super::node_client::{JobNodeClient, NodeCallError};
use crate::gpu_execution_node::wire::{JobStatusAnswer, JobStatusRequest, KeyEntry};

/// The most pages of keys one reconcile reads from a node: a wire bound, like a page's own size
/// limit, so a node that never ends its list cannot hold a dispatch or the worker's step.
pub const RECONCILE_MAX_PAGES: usize = 4096;

/// What the issuer does with a key a node holds for it that it has no dispatch row for.
pub trait OrphanKeys: Send + Sync {
    /// `node` holds `entry`, which this issuer never dispatched or no longer knows.
    fn unknown_key(&self, node: EntityId, entry: &KeyEntry);

    /// `node`'s whole listing was read: every page, the last with no `next`.
    fn listing_complete(&self, node: EntityId) {
        let _ = node;
    }

    /// `node` holds `entry`, a key the owner wrote off (`row`, door 10). What it reports now is
    /// evidence only, never settled.
    fn written_off_key(&self, node: EntityId, row: &JobDispatch, entry: &KeyEntry) {
        let _ = (node, row, entry);
    }

    /// The housekeeping pass over the live orphans of every node: each is asked to stop again
    /// until its node answers its end.
    fn follow_live(&self) {}
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
    /// The node named, as the next page, a cursor it had named before.
    #[error("the machine repeated a cursor of its key list")]
    CursorRepeated,
    /// The node's list ran past [`RECONCILE_MAX_PAGES`] pages.
    #[error("the machine's key list ran past {RECONCILE_MAX_PAGES} pages")]
    TooManyPages,
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
        let mut cursors = HashSet::new();
        for _ in 0..RECONCILE_MAX_PAGES {
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
                match dispatched {
                    Some(row) if row.machine == node => {
                        if matches!(row.closed, Some(DispatchClose::WrittenOff { .. })) {
                            orphans.written_off_key(node, &row, entry);
                        }
                    }
                    _ => orphans.unknown_key(node, entry),
                }
            }
            match page.next {
                Some(next) if !cursors.insert(next.clone()) => {
                    return Err(ReconcileError::CursorRepeated);
                }
                Some(next) => after = Some(next),
                None => {
                    orphans.listing_complete(node);
                    self.nodes
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(node);
                    return Ok(());
                }
            }
        }
        Err(ReconcileError::TooManyPages)
    }
}
