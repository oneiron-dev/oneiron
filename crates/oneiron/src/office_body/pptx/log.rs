//! The deck log's entries as the body keeps them (FIX 4513): each operation
//! with the commit peer it ran under and its time, never its actor. The
//! peer's typed-body receipt names the actor while it stands, so the log a
//! reader gets, and the attribution index built from it, still show who made
//! each thing, and an erase leaves them naming no one.

use std::collections::BTreeMap;

use heed::RoTxn;
use loro::LoroDoc;
use oneiron_docedit::live::{DeckOp, StampedOp};
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::typed_body::{BodyActor, receipt_actor_in_txn};

/// One logged deck operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoggedOp {
    /// The peer of the commit that logged it, which keys its receipt.
    peer: u64,
    at: u64,
    op: DeckOp,
}

/// `stamped` as `doc`'s commit logs them: under the commit's own peer, which
/// the typed-body door set fresh for this call.
pub(super) fn logged(doc: &LoroDoc, stamped: &[StampedOp]) -> Vec<LoggedOp> {
    let peer = doc.peer_id();
    stamped
        .iter()
        .map(|stamped| LoggedOp {
            peer,
            at: stamped.at,
            op: stamped.op.clone(),
        })
        .collect()
}

/// `log` as docedit reads it: each operation stamped with the actor its
/// commit's receipt names on `artifact`'s body, or with no one
/// ([`BodyActor::Erased`]'s form) once that actor was erased or where the
/// commit has no receipt.
pub(super) fn stamped(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    log: &[LoggedOp],
) -> Result<Vec<StampedOp>> {
    let mut actors = BTreeMap::new();
    let mut out = Vec::with_capacity(log.len());
    for entry in log {
        let made_by = match actors.get(&entry.peer) {
            Some(made_by) => String::clone(made_by),
            None => {
                let made_by = receipt_actor_in_txn(store, txn, artifact, entry.peer)?
                    .map_or(BodyActor::Erased, BodyActor::Actor)
                    .to_hex();
                actors.insert(entry.peer, made_by.clone());
                made_by
            }
        };
        out.push(StampedOp {
            made_by,
            at: entry.at,
            op: entry.op.clone(),
        });
    }
    Ok(out)
}
