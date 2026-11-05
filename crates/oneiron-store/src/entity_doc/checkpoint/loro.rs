//! The entity document's actor carriers in its Loro history (FIX 6072): its
//! birth's actor and every engine stamp's, with a receipted message's
//! receipt actors ([`super::message_receipts`], FIX 6479), split out and put
//! back through the shared projection
//! ([`crate::store::checkpoint_payload::loro`]). Every other operation of the
//! document's schema (its body text and its metadata map) names no one; an
//! operation outside that schema, or a message that is no engine stamp,
//! keeps its whole group under the vault-wide seal. A birth or stamp whose
//! actor did not open reads as no one, never as an actor some binding of its
//! peer names (Engine R2).
//!
//! A fork snapshot is a group of its own. A shallow one, as the live writer
//! keeps every one, stays under the vault-wide seal (Engine R3), and so does
//! a pending fork's: its record goes when its opener does not open, so its
//! snapshot is never kept without it (Engine and lead pick).

use ::loro::{ContainerID, ContainerType, JsonOp, JsonOpContent, LoroValue};

use crate::checkpoint_payload::loro::LoroActorCodec;
use crate::checkpoint_payload::loro::OpenedRow;
use crate::checkpoint_payload::loro::SHALLOW;
use crate::checkpoint_payload::loro::Split;
use crate::checkpoint_payload::loro::SplitRow;
use crate::checkpoint_payload::loro::SplitValue;
use crate::checkpoint_payload::rows;
use crate::entity_doc::document::BIRTH;
use crate::entity_doc::document::BODY;
use crate::entity_doc::document::META;
use crate::entity_doc::document::cut_stamp;
use crate::receipt_identity::ERASED_CALL_IDENTITY;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The path of a stamp's actor in its message.
pub const STAMP_ACTOR: &str = "actor";
/// The path of the birth's actor in its record.
pub const BIRTH_ACTOR: &str = "Birth.actor";

/// A commit message that is no engine stamp.
pub const NOT_A_STAMP: &str = "an entity document commit message that is no engine stamp";
/// A birth record that does not read, or does not spell its bytes back.
pub const BIRTH_UNREAD: &str = "an entity document birth that does not spell back";
/// An operation outside the entity document's body and metadata.
pub const OUTSIDE_SCHEMA: &str = "an entity document operation outside its body and metadata";
/// A pending fork's snapshot, whose record goes when its opener does not
/// open.
pub const PENDING_FORK: &str = "a pending fork's snapshot, whose record goes with its opener";

/// Whether `container` is the root container `name` of kind `kind`.
pub fn is_root(container: &ContainerID, name: &str, kind: ContainerType) -> bool {
    match container {
        ContainerID::Root {
            name: root,
            container_type,
        } => root.as_str() == name && *container_type == kind,
        ContainerID::Normal { .. } => false,
    }
}
