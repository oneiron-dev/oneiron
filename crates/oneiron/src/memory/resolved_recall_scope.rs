//! The recall scope a device sends its home with a recall's search (FIX 2905):
//! the membership its own recall resolved, never a marker the home would
//! interpret again. The device resolves the actor's default worlds, the
//! named worlds, projects and facet, and the kinds; the home applies them
//! before its candidate cut, inside the caller's own reach. The scope
//! narrows relevance only: it grants nothing.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::resolved_recall_scope::{
    ResolvedRecallSelection, ResolvedRecallWorlds,
};

/// The bytes a forwarded search signs for its recall scope (FIX 2905), on
/// the device and at the home alike: a fixed tag for no scope, else each
/// axis in order, every list length-prefixed. One encoder, so the two ends
/// never bind different bytes.
#[must_use]
pub fn recall_scope_transcript(scope: Option<&ResolvedRecallSelection>) -> Vec<u8> {
    fn ids(out: &mut Vec<u8>, ids: &[EntityId]) {
        out.extend_from_slice(&(ids.len() as u64).to_be_bytes());
        for id in ids {
            out.extend_from_slice(id.as_bytes());
        }
    }
    let Some(scope) = scope else {
        return vec![0];
    };
    let mut out = vec![1];
    match &scope.worlds {
        None => out.push(0),
        Some(worlds) => {
            out.push(1);
            out.push(u8::from(worlds.include_base));
            ids(&mut out, &worlds.world_ids);
        }
    }
    ids(&mut out, &scope.project_ids);
    match &scope.conversation_ids {
        None => out.push(0),
        Some(conversations) => {
            out.push(1);
            ids(&mut out, conversations);
        }
    }
    match &scope.facet {
        None => out.push(0),
        Some(facet) => {
            out.push(1);
            out.extend_from_slice(facet.as_bytes());
        }
    }
    match &scope.kinds {
        None => out.push(0),
        Some(kinds) => {
            out.push(1);
            out.extend_from_slice(&(kinds.len() as u64).to_be_bytes());
            out.extend_from_slice(kinds);
        }
    }
    out
}
