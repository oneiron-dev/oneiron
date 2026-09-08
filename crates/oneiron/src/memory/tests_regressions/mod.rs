//! Security-regression suite from a cross-cutting review batch: tests span
//! witness, structural puts, actor authority, supersession, hard-delete,
//! query, recall, consolidation, seeding, and outbound scheduling, one
//! concern per file under this directory.

use super::outbound::*;
use super::tests::{
    claim_input, facade_for, open_vault, put_person, short_id_part, test_time, witness_message,
};
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::outbound::OutboundDispatchError;
use crate::registry::ENTITY_TYPE_PERSON;

mod authority;
mod consolidation_outbound;
mod outbound_actor_scope;
mod recall;
mod retrieval_quality;
