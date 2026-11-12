//! Moved from `crates/oneiron/src/outbound/connector_task.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_base::edge::EdgeKind;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::registry::ENTITY_TYPE_MACHINE;
use oneiron_base::registry::ENTITY_TYPE_TASK;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::CONNECTOR_ACTOR;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;
use oneiron_contracts::temporal::TimeRange;
use oneiron_delivery_vocabulary::delivery_window::types::DeliveryWindowApnsInterruptionLevel;
use oneiron_delivery_vocabulary::delivery_window::types::DeliveryWindowResolvedLevel;
use oneiron_store::write_envelope::task_body::TaskRole;
use serde::Deserialize;
use serde::Serialize;

/// What the owner's answer to an uncertain send's ask came to (FIX 4747).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UncertainSendAnswerOutcome {
    /// The TASK's executor sends it once more, under the same engine send id.
    ResendReleased,
    /// The TASK settles with the owner's word, unsent again.
    Declined,
    /// An earlier answer settled the ask, or the send settled without one:
    /// this answer changed nothing.
    AlreadySettled,
}
