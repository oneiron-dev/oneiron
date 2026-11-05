//! Core half of `typed_body::body_actor`: its store-layer items live in `oneiron_store::typed_body::body_actor` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::typed_body::body_actor::*;

use super::{FORK_DOCS, FORKS, TypedForkState};
use crate::Vault;
/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the body rows.
pub(crate) use crate::deletion::names_no_actor;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::receipt_identity::ERASED_CALL_IDENTITY;
use serde::{Deserialize, Serialize};

impl TypedForkState {
    /// Makes the one who settled the fork no one when it is `actor`; whether
    /// it was.
    fn forget(&mut self, actor: EntityId) -> bool {
        match self {
            Self::Open => false,
            Self::Merged { by, .. } | Self::Discarded { by, .. } => by.forget(actor),
        }
    }
}

/// Erasing `actor` from the body forks (FIX 3520): an open fork it opened is
/// work a merge could still land, so it goes with its snapshot; a merged or
/// discarded fork keeps its row and names no one. An office fork's own
/// records go in the office scrubs. One-way, in the erase's own transaction.
/// An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a fork row that cannot be read.
pub(crate) fn erase_fork_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut forks = Vec::new();
    for (key, mut fork) in FORKS.scan(&vault.store, wtxn)? {
        let opened = fork.opener.forget(*actor);
        let settled = fork.state.forget(*actor);
        if opened || settled {
            forks.push((key, fork, opened));
        }
    }
    for (key, fork, opened) in forks {
        if opened && fork.state == TypedForkState::Open {
            FORKS.delete(&vault.store, wtxn, &key)?;
            FORK_DOCS.delete(&vault.store, wtxn, &key)?;
        } else {
            FORKS.put(&vault.store, wtxn, &key, &fork)?;
        }
    }
    Ok(())
}
