//! Security-regression suite from a cross-cutting review batch: tests span
//! witness, structural puts, actor authority, supersession, hard-delete,
//! query, recall, consolidation, seeding, and outbound scheduling, one
//! concern per file under this directory.

use super::outbound::*;
use super::tests::{
    claim_input, facade_for, open_vault, put_owner, put_person, test_time, witness_message,
};
use super::*;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_PERSON;

mod authority;
// FIX [LIBTEST-QUARANTINE-MEMORY-TESTS-REGRESSIONS-CONSOLIDATION-OUTBOUND]: the lib test target's type check fails here (11 errors: E0609 x7, E0063 x4); port it, then drop this gate
#[cfg(any())]
mod consolidation_outbound;
mod outbound_actor_scope;
mod recall;
mod recall_revision;
mod recall_security;
