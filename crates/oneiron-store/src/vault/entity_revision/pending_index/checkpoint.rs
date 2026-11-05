//! The checkpoint rows of the staged index inputs (KS7-2): the caller's
//! fields, vector and token waiting for idle publication, whole, under their
//! entity's tree. The revision getter (`storage::checkpoint`) reads them.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::RoTxn;

use crate::checkpoint_payload::rows;
use crate::revision_ref::RevisionRef;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
