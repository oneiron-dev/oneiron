//! The checkpoint getter of blob artifact versions (KS7-2): each artifact's
//! head record and version records under the artifact's own entity tree.
//! These are metadata only: the bytes a version names sit in an ASSET, and
//! KS-2 seals every ASSET's bytes, inline or file (the entity getter hands
//! each ASSET row to it), so nothing here seals them twice. The version
//! highwater, claim and reference rows hold no payload and stay structure.
//! It also places the artifact's hosting rows (pointer, publish admission,
//! serving descriptor) under the artifact (FIX 10436).
//!
//! A version's MadeBy names its process's actor: the compartment keeps the
//! record with the artifact in that place, and the actor is an actor part.
//! The erased-producer form stays in the record with no actor part (FIX 9619).
//! A retired actor can be recovered only from its version's fully bound native
//! claim during authenticated restore, then scrubbed with that claim before
//! commit; otherwise the version stays out (FIX 6259).
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use crate::checkpoint_payload::rows;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The field the MadeBy process's actor fills.
pub const PROCESS: &str = "made_by.process.actor";
