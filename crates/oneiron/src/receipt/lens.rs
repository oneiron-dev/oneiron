//! The receipts of the pack lens lifecycle (OF-250): a proposal, and the
//! owner's selection or clearing of a lens slot.
//!
//! These project the lens records the proposal and slot doors already wrote
//! (`crate::lens`); they keep no store of their own. The proposal record is
//! the proposal's receipt, and the slot record is the owner's decision.
//! Selection and clearing also append that decision to the shared Gate ledger
//! in the slot's writer; clearing keeps its audit even after the slot is gone.

use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::receipt::lens::{
    LensActivationReceipt, LensApproval, LensProposalReceipt, LensSlotDecision,
};
