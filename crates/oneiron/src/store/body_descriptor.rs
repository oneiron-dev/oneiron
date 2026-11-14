//! Owned body descriptor vocabulary and its digest wire representation.

use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::store::body_descriptor::{
    BodyLocation, BodyRef, BodyState, CodeRunOutputOrigin, OwnedBody, RetainedResultProvenance,
};
