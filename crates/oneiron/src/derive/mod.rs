//! The derivation transaction (untangle slice 6.7, primitive C): an agent
//! lands what it derived as ONE batch, in one write, and the engine judges
//! each item on its own.
//!
//! The caller supplies the items and nothing about who it is: the engine
//! stamps the actor, the `Generated` source, the run and its recorded
//! lineage from the caller's live run ([`DerivationStamp`]), and marks every
//! row it lands `surface = vault.derive` with the batch's id. Each item
//! stages in a savepoint of the batch's write:
//! - a claim item goes through the shared claim gate as the caller, with
//!   the derivation floors (GATE-12, GATE-13, the checker) a Dreamer run
//!   meets; a held Auto write is tried again as Proposed;
//! - a refused item rolls back its savepoint and keeps a refusal receipt,
//!   and an item that names a refused item is refused in turn;
//! - a malformed batch aborts the whole write.
//!
//! The batch record ([`record`]) lists every item's outcome and the rows it
//! landed, so the batch can be read back and, from 6.7c, reverted.
//!
//! Every item kind is one arm of [`DerivationItem`] with a stager of its
//! own: a new kind adds an arm and touches no other (S69-C-ITEMS).

mod batch;
mod claim;
mod commit;
mod record;
mod supersede;
mod tables;

pub(crate) use batch::{
    DerivationBatch, DerivationItem, DerivationStamp, DerivedClaim, DerivedSupersede, ItemRef,
};
pub(crate) use commit::{DerivationReceipt, ItemOutcome, ItemReceipt};
pub(crate) use record::{
    DerivationBatchRecord, ItemRecord, batch_record_in_txn, batches_of_actor_in_txn,
};
pub(crate) use supersede::{SUPERSEDE_LIFECYCLE, SUPERSEDE_PROTECTED_SOURCE};

/// The provenance `surface` a derivation commit stamps on every row it
/// lands. The gate reads it as a derivation-class write.
pub(crate) const DERIVE_SURFACE: &str = "vault.derive";

/// The provenance key naming the batch a row landed in.
pub(crate) const DERIVE_BATCH_KEY: &str = "batch";

/// The refusal token of an item that names a refused item of its batch.
pub(crate) const DEPENDENCY_REFUSED: &str = "derive.dependency_refused";

/// The gate decision ledger's content kind for a derivation item's refusal
/// receipt.
pub(crate) const DERIVE_ITEM_CONTENT_KIND: &str = "vault.derive.item";
