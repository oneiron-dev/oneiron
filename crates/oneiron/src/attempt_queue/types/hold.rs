//! The pause a paused attempt row is held under (FIX 9579), kept on the row
//! itself rather than read back from its event history, which prunes.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

/// Why a paused row is paused. A person's pause wins over every engine
/// hold: it replaces the hold on the row, so no hold's release resumes it,
/// and only a resume clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AttemptPause {
    /// An intervention's pause by any actor other than an engine hold's.
    Person,
    /// OF-368: the TASK answers a comment thread that is unattached.
    Annotation {
        artifact_id: EntityId,
        thread_id: EntityId,
    },
    /// OF-541: the run reached its spend cap.
    Budget,
    /// OF-393: the cut waits on its launch approval.
    Fanout { launch_ref: EntityId },
}

impl AttemptPause {
    /// Whether an engine hold, not a person, paused the row.
    pub(crate) const fn is_engine_hold(self) -> bool {
        !matches!(self, Self::Person)
    }
}
