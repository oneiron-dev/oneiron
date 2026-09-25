//! Delta-only board claims and exact Loro-frontier reconstruction.

mod claims;
mod ledger;
mod types;

pub(crate) use claims::validate_board_claim;
pub use types::{
    BoardHistoryError, BoardSelection, BoardTurn, BoardTurnReceipt, ReconstructedBoard,
};

#[cfg(test)]
mod tests;
