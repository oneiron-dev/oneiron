//! Moved from `crates/oneiron/src/browser_library.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::browser_library::admission::CallerUnavailable;
pub use crate::browser_library::admission::ProgramAdmissionFiling;
pub use crate::browser_library::admission::ProgramAdmissionOutcome;
pub use crate::browser_library::admission::ProgramAdmissionReceipt;
pub use crate::browser_library::admission::SourceUnavailable;
pub use crate::browser_library::evidence::FiledScope;
pub use crate::browser_library::evidence::SOLVED_CAPTURE_VERSION;
pub use crate::browser_library::evidence::SOLVED_GROUP_DOMAIN;
pub use crate::browser_library::evidence::SOLVED_RUN_DOMAIN;
pub use crate::browser_library::evidence::SOLVED_SCOPE_DOMAIN;
pub use crate::browser_library::evidence::SolvedRunScope;
pub use crate::browser_library::evidence::SolvedSource;
pub use crate::browser_library::evidence::WORKFLOW_FILING_DOMAIN;
pub use crate::browser_library::evidence::workflow_filing_id;
use oneiron_browser::RecentCounts;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
use serde::Deserialize;
use serde::Serialize;

/// How many of a lineage's newest outcomes its card counts as recent (CUA
/// E1 "recent", CALLS row; Engine 10-21 23:4x): each record keeps the last
/// [`RECENT_RUNS`] library runs, passed or missed, and repairs of its
/// lineage, the oldest dropped past them, and a successor starts from its
/// predecessor's. A count of outcomes, not a time window, so a program run
/// rarely keeps its record.
pub const RECENT_RUNS: usize = 20;

/// Whose word a library row records: an actor, or no one once that actor
/// was erased. It reads and writes as the actor's id, or as
/// [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryActor {
    Actor(EntityId),
    Erased,
}

impl LibraryActor {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }
}

impl Serialize for LibraryActor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Actor(id) => id.serialize(serializer),
            Self::Erased => serializer.serialize_str(ERASED_CALL_IDENTITY),
        }
    }
}

impl<'de> Deserialize<'de> for LibraryActor {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

/// What one outcome of a program's lineage was: a library run that met its
/// postcondition, one that did not, or a repair that filed a successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecentOutcome {
    Pass,
    Miss,
    Repair,
}

/// One outcome of a program's lineage, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentRun {
    pub outcome: RecentOutcome,
    pub at: u64,
}

/// A lineage's newest [`RECENT_RUNS`] outcomes, counted.
pub fn recent_counts(recent: &[RecentRun]) -> RecentCounts {
    let recent = &recent[recent.len().saturating_sub(RECENT_RUNS)..];
    let count = |outcome: RecentOutcome| {
        let counted = recent.iter().filter(|run| run.outcome == outcome).count();
        u32::try_from(counted).unwrap_or(u32::MAX)
    };
    RecentCounts {
        pass: count(RecentOutcome::Pass),
        miss: count(RecentOutcome::Miss),
        repair: count(RecentOutcome::Repair),
        of: u32::try_from(RECENT_RUNS).unwrap_or(u32::MAX),
    }
}
pub mod admission;
pub mod evidence;
