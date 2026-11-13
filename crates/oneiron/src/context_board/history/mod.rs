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

#[cfg(test)]
mod tests;
