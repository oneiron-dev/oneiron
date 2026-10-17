//! Live tier-1 counting (OF-380). Each diagnostic an engine producer
//! captured counts once, under the class its detector names, the moment its
//! witness exists. A diagnostic names no affected agent, so its count is
//! unattributed rather than charged to the observing system or the owner.

use super::{
    AgentKind, AgentSurface, FailureClassV1, FailureSignalInput, FailureTaxonomy,
    VersionedComponent,
};
use crate::self_heal::{DiagnosticEvent, DiagnosticEventClass};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// Each diagnostic already counted, and the time it observed. Nightly scans
/// capture the same content-addressed diagnostic again; it counts once.
/// Key: id16 (diagnostic event id).
const COUNTED: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::FAILURE_SIGNALS_TIER1_COUNTED);

/// The agent name and version an unattributed count exports in clear.
pub(super) const UNATTRIBUTED: &str = "unattributed";

/// Each compiled T1 detector's tier-1 class (`None`: never counted) and
/// surface. An owner's consent refusal is the owner's choice, not an agent
/// failure; a storm of pending asks is. A detector absent here is a
/// model-graded window, counted by its family's event class.
const T1_DETECTORS: [(&str, Option<FailureClassV1>, AgentSurface); 5] = [
    ("consent.denied.v1", None, AgentSurface::Other),
    (
        "retrieval.miss.v1",
        Some(FailureClassV1::MemoryMiss),
        AgentSurface::Other,
    ),
    (
        "consolidation.error.v1",
        Some(FailureClassV1::TaskFailure),
        AgentSurface::Background,
    ),
    (
        "consent.storm.v1",
        Some(FailureClassV1::Other),
        AgentSurface::Other,
    ),
    (
        "predicate.drift.v1",
        Some(FailureClassV1::Other),
        AgentSurface::Other,
    ),
];

/// A model-graded window's class, from the event class its host family set.
const fn window_class(class: DiagnosticEventClass) -> Option<FailureClassV1> {
    match class {
        DiagnosticEventClass::ConsentDenied | DiagnosticEventClass::AgentBlocked => None,
        DiagnosticEventClass::RetrievalMiss => Some(FailureClassV1::MemoryMiss),
        DiagnosticEventClass::ConsolidationError | DiagnosticEventClass::DreamerRunDegenerate => {
            Some(FailureClassV1::TaskFailure)
        }
        DiagnosticEventClass::SilentConversationDegradation => {
            Some(FailureClassV1::SilentDegradation)
        }
        _ => Some(FailureClassV1::Other),
    }
}

/// The unattributed count one captured diagnostic records, or `None` when
/// its detector is not an agent failure.
pub(super) fn diagnostic_input(event: &DiagnosticEvent) -> Option<FailureSignalInput> {
    let (class, surface) = match T1_DETECTORS
        .iter()
        .find(|(id, _, _)| *id == event.detector_id)
    {
        Some((_, class, surface)) => (*class, *surface),
        None => (window_class(event.event_class), AgentSurface::Other),
    };
    Some(FailureSignalInput {
        taxonomy: FailureTaxonomy::V1(class?),
        agent_surface: surface,
        agent_kind: AgentKind::Unattributed,
        agent: VersionedComponent {
            name: UNATTRIBUTED.into(),
            version: UNATTRIBUTED.into(),
        },
        agent_ref: None,
    })
}

impl Vault {
    /// Counts a just-captured diagnostic unless it was counted before. The
    /// mark is taken first, so two passes cannot both count it, and released
    /// when the record does not land, so a later capture may count it. A
    /// witness that stopped verifying in between counts nothing.
    pub(super) fn count_tier1_diagnostic(
        &self,
        id: EntityId,
        input: FailureSignalInput,
        observed_at: u64,
    ) -> Result<()> {
        let fresh = self.with_write_txn_grouped(|txn| {
            if COUNTED.contains(&self.store, txn, &id)? {
                return Ok(false);
            }
            COUNTED.put(&self.store, txn, &id, &observed_at)?;
            Ok(true)
        })?;
        if !fresh {
            return Ok(());
        }
        let recorded = match self.tier1_observation(id)? {
            Some(observation) => self.record_failure_signal(&observation, input),
            None => Err(Error::InvalidConfig(
                "unregistered failure observation".into(),
            )),
        };
        let Err(error) = recorded else {
            return Ok(());
        };
        self.with_write_txn_grouped(|txn| COUNTED.delete(&self.store, txn, &id).map(|_| ()))?;
        match error {
            Error::InvalidConfig(_) => Ok(()),
            error => Err(error),
        }
    }
}
