//! `vault.code.merge_queue.export_green`'s request (FIX 6868, G2 PR3). It
//! names the queue, the owner's live checkout and the publication target.
//! It never names a revision, tree, frontier, verdict, pass or actor: the
//! engine resolves the queue's current sealed green itself. The answer is
//! the unchanged `vault.code.export` result.
use serde::{Deserialize, Serialize};

use crate::EntityId;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::merge_queue_doors::export_types::MergeQueueGreenExportRequest;
