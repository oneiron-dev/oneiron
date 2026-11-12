//! Core half of `origin::publish::inputs`: its store-layer items live in `oneiron_store::origin::publish::inputs` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::publish::inputs::*;

use super::types::{OriginPublishForce, OriginPublishReviewItem};
use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::origin::publish::inputs::{
    OriginPublishRequestInput, OriginPublishReviewView,
};
