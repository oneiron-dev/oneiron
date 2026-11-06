//! Producer-captured native read anchors shared with lower row vocabulary.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::temporal::TimeRange;

/// One placed private-thread turn (FIX 11000): the thread `root` and the
/// `turn` in it. Content-free ids only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GateThreadAnchor {
    /// The thread root.
    pub root: EntityId,
    /// The turn placed in it.
    pub turn: EntityId,
}

/// Writer-captured anchors for one read context (FIX 11000 PARTLY).
///
/// Fields are private so only [`Self::complete`] and [`Self::incomplete`]
/// ever build one: `complete` carries the full Engine-required set
/// (subject-ancestry placed turns + reached roots/rooms + body and
/// prompt-source worlds, base explicit, sorted and deduped, and the candidate
/// header's own occurred range), while `incomplete` is the single empty value for every unknown, ambiguous,
/// cyclic, malformed, unsupported, or errored capture. A later kept path
/// must deny unless `is_complete` holds and `worlds` is nonempty; it must
/// never treat a partial set as complete, nor read an empty `worlds` as a
/// vacuous pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReadAnchors {
    /// True only when the Engine-required set is fully captured.
    #[serde(default)]
    complete: bool,
    /// Placed (root, turn) pairs under CONTENT.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    threads: Vec<GateThreadAnchor>,
    /// Reached thread roots under CURRENT.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reached: Vec<EntityId>,
    /// Reached rooms via subject ancestry; never the writer session room.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rooms: Vec<EntityId>,
    /// Body world plus prompt-source worlds; base stored explicitly, never
    /// empty when complete.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    worlds: Vec<EntityId>,
    /// The candidate header's own occurred start and end, never a put clock
    /// or a subject's time. Absent only in the incomplete empty value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    occurred: Option<[u64; 2]>,
}

impl GateReadAnchors {
    /// The complete Engine-required set, sorted and deduped by the caller.
    /// `worlds` must carry at least the base world.
    #[must_use]
    pub fn complete(
        threads: Vec<GateThreadAnchor>,
        reached: Vec<EntityId>,
        rooms: Vec<EntityId>,
        worlds: Vec<EntityId>,
        occurred: TimeRange,
    ) -> Self {
        debug_assert!(
            !worlds.is_empty(),
            "complete anchors carry at least the base world"
        );
        Self {
            complete: true,
            threads,
            reached,
            rooms,
            worlds,
            occurred: Some([occurred.start, occurred.end]),
        }
    }

    /// The single incomplete value: empty and never readable. Returned for
    /// every unknown, ambiguous, cyclic, malformed, unsupported, or errored
    /// capture, so no partial set can read as complete.
    #[must_use]
    pub fn incomplete() -> Self {
        Self {
            complete: false,
            threads: Vec::new(),
            reached: Vec::new(),
            rooms: Vec::new(),
            worlds: Vec::new(),
            occurred: None,
        }
    }

    /// Whether the writer captured nothing (incomplete and all empty),
    /// so the wire key omits and old bytes stay byte-identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.complete
            && self.threads.is_empty()
            && self.reached.is_empty()
            && self.rooms.is_empty()
            && self.worlds.is_empty()
            && self.occurred.is_none()
    }

    /// Whether the Engine-required set is fully captured. A kept path must
    /// still require nonempty `worlds`.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete && self.occurred.is_some()
    }

    /// Placed (root, turn) pairs under CONTENT.
    #[must_use]
    pub fn threads(&self) -> &[GateThreadAnchor] {
        &self.threads
    }

    /// Reached thread roots under CURRENT.
    #[must_use]
    pub fn reached(&self) -> &[EntityId] {
        &self.reached
    }

    /// Reached rooms via subject ancestry.
    #[must_use]
    pub fn rooms(&self) -> &[EntityId] {
        &self.rooms
    }

    /// Body world plus prompt-source worlds.
    #[must_use]
    pub fn worlds(&self) -> &[EntityId] {
        &self.worlds
    }

    /// The candidate header's own occurred range, kept verbatim.
    #[must_use]
    pub fn occurred(&self) -> Option<TimeRange> {
        self.occurred.map(|[start, end]| TimeRange { start, end })
    }
}
