//! The recall scope a device sends its home with a recall's search (FIX 2905):
//! the membership its own recall resolved, never a marker the home would
//! interpret again. The device resolves the actor's default worlds, the
//! named worlds, projects and facet, and the kinds; the home applies them
//! before its candidate cut, inside the caller's own reach. The scope
//! narrows relevance only: it grants nothing.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

/// One recall's resolved scope, as the device read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRecallSelection {
    /// The worlds read; `None` reads every world. An empty set reads none:
    /// it is a narrowing, not its absence.
    pub worlds: Option<ResolvedRecallWorlds>,
    /// The project audiences read, sorted and unique; empty reads every one.
    pub project_ids: Vec<EntityId>,
    /// The explicit/PERSON-authored conversations read, sorted and unique;
    /// `None` adds no narrowing, and an empty set reads none.
    pub conversation_ids: Option<Vec<EntityId>>,
    /// The facet a strict facet narrowing keeps.
    pub facet: Option<EntityId>,
    /// The registry kinds returned, sorted and unique; `None` is recall's
    /// default, every kind but the containers (`CONTAINER_KINDS`).
    pub kinds: Option<Vec<u8>>,
}

/// A resolved world set: base reality, and the named worlds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRecallWorlds {
    /// Whether base reality is read.
    pub include_base: bool,
    /// The world ids read, sorted and unique.
    pub world_ids: Vec<EntityId>,
}

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
