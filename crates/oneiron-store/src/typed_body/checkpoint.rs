//! The checkpoint getter of typed bodies (KS7-2): each entity's body head,
//! head snapshot, forks, fork snapshots and commit receipts
//! ([`super::receipts::checkpoint`]), under its own entity tree. A body's
//! commit messages name no one (its receipts do), so its snapshots stay
//! exact. A fork's opener and settler are actor parts; an open fork whose
//! opener did not open goes on restore, as the erase deletes it, and its
//! snapshot holds only while its opener's tree opens. Office bodies keep
//! their documents here, not in a second snapshot. Nothing calls this until
//! KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use crate::typed_body::body_actor::BodyActor;
use crate::typed_body::receipts::checkpoint as receipts;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The field a fork's opener fills.
pub const OPENER: &str = "opener";

/// The field the actor who merged or discarded a fork fills.
pub const SETTLER: &str = "settler";
