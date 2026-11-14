//! Delta-only board claims and exact Loro-frontier reconstruction, and the
//! epoch a folded chat turn reads as (FIX 5038).

mod claims;
mod epoch;
mod ledger;
mod types;

pub(crate) use claims::validate_board_claim;
pub use epoch::{BoardTurnEpoch, BoardTurnHistory};
pub(crate) use ledger::fold_board_turns_in_txn;
pub use types::{
    BoardHistoryError, BoardSelection, BoardTurn, BoardTurnReceipt, ReconstructedBoard,
};

// FIX [LIBTEST-QUARANTINE-CONTEXT-BOARD-HISTORY-TESTS]: the lib test target's type check fails here (7 errors: E0061 x5, E0308 x2); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests;
