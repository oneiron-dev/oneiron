//! A swapped-in space move, staged as `check_space_move` would leave it, for the undo-window
//! tests (restriction wave 16, C124): no probes run and no backfill fills.

use std::collections::BTreeSet;

use crate::Vault;
use crate::embed::{EmbeddingSpace, InputKind, SpaceMove, SpaceMoveState, SpaceRef};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// The move rows, bound here as `space_move.rs` binds them.
const EMBEDDING_MOVE: SideTable<String, SpaceMove, Named> =
    SideTable::new(&side_table::EMBEDDING_MOVE);

/// The width of the two staged spaces. No vector is stored, so it only has to validate.
const SPACE_DIMENSIONS: usize = 4;

/// One declared space of the staged move: it accepts `kind` and answers it, so the slot binds.
fn staged_space(id: &str, kind: InputKind) -> EmbeddingSpace {
    EmbeddingSpace {
        id: id.to_owned(),
        dimensions: SPACE_DIMENSIONS,
        accepts: BTreeSet::from([kind]),
        query_towers: BTreeSet::from([kind]),
        evidence: None,
    }
}

/// Declares `incumbent` and `candidate`, binds `kind`'s slot to the candidate, and stores the
/// move as swapped in at `swapped_at` (vault seconds), as a passing scheduled check would leave
/// it. The slot write and the `SwappedIn` row copy the swap in `conclude_space_move`: its slot
/// loop, its `SwappedIn { at, by_owner: false }` state, its row store, and its setup publish with
/// the committed hooks. The binding goes through the checked in-transaction door
/// (`bind_kind_slot_in_txn`), which writes the same slot row the swap's own setter writes. The
/// move's result note is not staged: retiring and undoing never read it.
///
/// # Errors
///
/// A malformed space id; storage errors.
#[cfg(oneiron_test_support)]
pub fn stage_swapped_in_space_move(
    vault: &Vault,
    incumbent: &str,
    candidate: &str,
    kind: InputKind,
    swapped_at: u64,
) -> Result<()> {
    let incumbent_space = staged_space(incumbent, kind);
    let candidate_space = staged_space(candidate, kind);
    let moving = SpaceMove {
        candidate: candidate.to_owned(),
        incumbent: SpaceRef::Declared(incumbent.to_owned()),
        kinds: BTreeSet::from([kind]),
        margin: None,
        started_at: swapped_at,
        state: SpaceMoveState::SwappedIn {
            at: swapped_at,
            by_owner: false,
        },
        last_check: None,
    };
    let setup = vault.with_write_txn(|wtxn| {
        crate::embed::declare_embedding_space_in_txn(&vault.store, wtxn, &incumbent_space)?;
        crate::embed::declare_embedding_space_in_txn(&vault.store, wtxn, &candidate_space)?;
        crate::embed::bind_kind_slot_in_txn(&vault.store, wtxn, kind, candidate)?;
        EMBEDDING_MOVE.put(&vault.store, wtxn, &moving.candidate, &moving)?;
        vault.publish_embedding_setup_in_txn(wtxn)
    })?;
    vault.embedding_setup_committed(setup);
    vault.embedding_move_ended();
    Ok(())
}
