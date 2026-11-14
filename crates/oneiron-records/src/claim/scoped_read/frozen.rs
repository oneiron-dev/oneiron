//! Moved from `crates/oneiron/src/claim/scoped_read/frozen.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::claim::scoped_read::*;
use crate::claim::*;
use oneiron_authority::federation::ScopeAxis;
use oneiron_authority::federation::ScopeId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;

/// [`FrozenReadLane::freeze`]'s refusal of a narrowed guest credential's lane.
pub const GUEST_LANE_NOT_SAVED: &str = "a narrowed guest credential's read lane is not saved";

/// Keeps each id `axis` names that `covered` holds (FIX 12285); whether it
/// cut one. An open or empty axis names no id and stays; one cut to no id
/// is bottom.
pub fn keep_covered_ids(axis: &mut ScopeAxis<ScopeId>, covered: &ScopeAxis<ScopeId>) -> bool {
    let ScopeAxis::Some(ids) = axis else {
        return false;
    };
    let named = ids.len();
    ids.retain(|id| covered.contains(id));
    if ids.len() == named {
        return false;
    }
    if ids.is_empty() {
        *axis = ScopeAxis::Bottom;
    }
    true
}
