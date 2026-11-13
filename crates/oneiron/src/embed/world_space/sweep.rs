//! The sweep that moves a device's text vectors when a world's order starts or stops naming
//! its own text space (DEC-0005 #private-world-vectors; census L5-26).

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use super::super::space::{
    InputKind, delete_text_media_vector_in_space_in_txn, embedding_spaces_in_txn,
    media_vector_ids_in_txn,
};
use super::super::space_move::space_fill_kinds_in_txn;
use super::{WorldTextSpaces, space_runs_on_device};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Named, SideTable};

/// The map of each world's text space the vectors on this device last moved to match. Key: ().
const SWEPT: SideTable<(), SweptWorldTextSpaces, Named> =
    SideTable::new(&side_table::EMBEDDING_WORLD_TEXT_SPACES_SWEPT);

/// Each world that names a text space, with that space's id, in world order.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SweptWorldTextSpaces {
    spaces: Vec<(EntityId, String)>,
}

impl WorldTextSpaces {
    fn swept(&self) -> SweptWorldTextSpaces {
        SweptWorldTextSpaces {
            spaces: self
                .by_world
                .iter()
                .map(|(world, space)| (*world, space.id.clone()))
                .collect(),
        }
    }
}

/// The vectors one sweep dropped.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorldTextSpaceSweep {
    /// Vault-index vectors of rows a world's text space now takes.
    pub(crate) index_drops: usize,
    /// Text vectors in a device space that no longer takes their rows.
    pub(crate) space_drops: usize,
}

/// Moves this device's text vectors to match each world's text space, when the map differs
/// from the one they last matched (DEC-0005 #private-world-vectors). An order that names a
/// world's space drops the vault-index vector of every row the world carries, and queues the
/// row again: it stays pending for the world's space, and the vault's index takes it again
/// should the world inherit once more. An order that stops naming a space drops the world's
/// rows from it, and queues each row the vault's index now takes. A derived sweep rather than
/// a door hook, because an order edit that arrives by sync passes no door; a read when nothing
/// changed, and one writer when it did.
///
/// # Errors
///
/// Storage errors, or an authority log that does not fold.
pub(crate) fn sweep_world_text_spaces(vault: &Vault) -> Result<WorldTextSpaceSweep> {
    {
        let rtxn = vault.store.env.read_txn()?;
        let current = WorldTextSpaces::read_in(vault, &rtxn)?.swept();
        if SWEPT.get(&vault.store, &rtxn, &())?.unwrap_or_default() == current {
            return Ok(WorldTextSpaceSweep::default());
        }
    }
    vault.with_write_txn_grouped(|wtxn| sweep_in_txn(vault, wtxn))
}

fn sweep_in_txn(vault: &Vault, wtxn: &mut RwTxn<'_>) -> Result<WorldTextSpaceSweep> {
    let spaces = WorldTextSpaces::read_in(vault, wtxn)?;
    let current = spaces.swept();
    let previous = SWEPT.get(&vault.store, wtxn, &())?.unwrap_or_default();
    let mut sweep = WorldTextSpaceSweep::default();
    if previous == current {
        return Ok(sweep);
    }
    // A text row stays in a device space only while that space takes it: as its world's
    // space, or, for a row no such world carries, as the space a kind slot binds for text.
    for space in embedding_spaces_in_txn(&vault.store, wtxn)? {
        if !space_runs_on_device(&space.id) {
            continue;
        }
        let slot_text =
            space_fill_kinds_in_txn(&vault.store, wtxn, &space)?.contains(&InputKind::Text);
        for id in media_vector_ids_in_txn(&vault.store, wtxn, &space)? {
            let own = spaces.of_row(&vault.store, wtxn, &id)?;
            let takes = if own.is_empty() {
                slot_text
            } else {
                own.contains(space.id.as_str())
            };
            if takes || !delete_text_media_vector_in_space_in_txn(&vault.store, wtxn, &space, &id)?
            {
                continue;
            }
            sweep.space_drops += 1;
            if own.is_empty() {
                requeue_text_work_in_txn(vault, wtxn, &id)?;
            }
        }
    }
    // Only a world that names a space it did not name before can hold vault-index vectors
    // that must go; a map that only lost worlds skips the scan of the index.
    if current
        .spaces
        .iter()
        .any(|entry| !previous.spaces.contains(entry))
    {
        for id in crate::hnsw::collect_vector_ids(&vault.store, wtxn)? {
            if spaces.of_row(&vault.store, wtxn, &id)?.is_empty() {
                continue;
            }
            if crate::vault::entity_revision::drop_index_vector_in_txn(vault, wtxn, &id)? {
                sweep.index_drops += 1;
            }
            requeue_text_work_in_txn(vault, wtxn, &id)?;
        }
    }
    SWEPT.put(&vault.store, wtxn, &(), &current)?;
    Ok(sweep)
}

/// Queues `id`'s text work anew, as a repo row's requeue does: the vault's pending-text pass
/// leases it, or leaves it pending while a world's text space takes it.
fn requeue_text_work_in_txn(vault: &Vault, wtxn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    let Some(record) = vault.store.port_entity_record(wtxn, id)? else {
        return Ok(());
    };
    if !super::super::eligibility::is_embeddable_in_txn(
        vault,
        wtxn,
        id,
        record.entity_type,
        &record.body,
    )? {
        return Ok(());
    }
    if !vault.store.has_current_pending_embedding_in_txn(wtxn, id)? {
        vault.store.mark_pending_embedding(wtxn, id, &record.body)?;
    }
    super::super::clear_pending_embedding_lease_if_any(vault, wtxn, id)?;
    crate::sync::queue::delete_embed_job_in_txn(&vault.store, wtxn, id)?;
    crate::sync::queue::push_embed_job_in_txn(
        &vault.store,
        wtxn,
        id,
        super::super::EMBED_PRIORITY_BACKFILL,
    )
}
