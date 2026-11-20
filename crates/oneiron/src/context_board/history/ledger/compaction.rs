//! The board history's compaction marks: an owner's retained window (the
//! horizon a turn's read-back refuses before) and the turns a summary
//! folded, whose boards stop reconstructing.

use super::{BoardHistoryError, FOLDED, HORIZON, Result};
use crate::{EntityId, Vault};
use heed::RwTxn;

impl Vault {
    /// Advances the retained window monotonically. Anchors remain as compact
    /// tombstones so a pre-horizon request is distinguishable from an unknown
    /// turn. The Loro history is deliberately not shallow-compacted: citations
    /// and retained turns can still reference its earlier operations.
    pub fn advance_board_compaction_horizon(
        &self,
        owner: &EntityId,
        retained_from: u64,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        if let Some(current) = HORIZON.get(&self.store, &txn, owner)?
            && retained_from < current
        {
            return Err(BoardHistoryError::InvalidSelection(
                "compaction horizon cannot move backward",
            ));
        }
        HORIZON.put(&self.store, &mut txn, owner, &retained_from)?;
        txn.commit()?;
        Ok(())
    }

    /// The owner's retained board window as it stands: a turn anchored
    /// before it refuses with [`BoardHistoryError::BeyondCompactionHorizon`].
    /// `None` retains every anchored turn. A host driving the horizon reads
    /// this before advancing it, which never moves backward.
    pub fn board_compaction_horizon(&self, owner: &EntityId) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        Ok(HORIZON.get(&self.store, &txn, owner)?)
    }

    /// A production host that folded `turns` into a summary outside an
    /// epoch mint marks exactly those turns' boards folded, in one write:
    /// reconstructing one fails explicitly from here on, and every other
    /// turn's board stays whole. The epoch mint folds its own window in
    /// its transaction; this is the same mark for a host that lands its
    /// compaction elsewhere.
    pub fn fold_board_turns(&self, turns: impl IntoIterator<Item = EntityId>) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        fold_board_turns_in_txn(self, &mut txn, turns)?;
        txn.commit()?;
        Ok(())
    }
}

/// Compaction folded `turns` into a summary: exactly those turns' boards stop
/// reconstructing. Each turn is marked on its own, so folding one session
/// leaves the owner's boards in every other session whole. The mark is the
/// turn's, not its anchor's: a board recorded after the fold is folded too.
/// Runs inside the compaction's own transaction.
pub(crate) fn fold_board_turns_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    turns: impl IntoIterator<Item = EntityId>,
) -> crate::error::Result<()> {
    for turn in turns {
        FOLDED.put(&vault.store, txn, &turn, &())?;
    }
    Ok(())
}
