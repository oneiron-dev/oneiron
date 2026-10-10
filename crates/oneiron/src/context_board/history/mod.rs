//! Delta-only board claims and exact Loro-frontier reconstruction.

mod claims;
mod ledger;
mod types;

pub(crate) use claims::validate_board_claim;
pub(crate) use ledger::fold_board_turns_in_txn;
pub use types::{
    BoardHistoryError, BoardSelection, BoardTurn, BoardTurnReceipt, ReconstructedBoard,
};

#[cfg(test)]
mod tests;
