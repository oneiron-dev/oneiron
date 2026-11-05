//! The typed-body commit receipts (KS7-2), under their body's entity tree. A
//! live receipt names its actor and, in its MadeBy, the process's actor: the
//! compartment keeps the receipt with both set to its own entity, and each
//! actor is an actor part. A restore writes the live receipt back only when
//! both open; otherwise it writes the erased form, the commit time alone, as
//! the erase does. The typed-body getter reads them.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::RoTxn;

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The field the receipt's actor fills.
pub const ACTOR: &str = "actor";

/// The field the MadeBy process's actor fills.
pub const PROCESS: &str = "made_by.process.actor";
