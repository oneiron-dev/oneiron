//! The rows a live chat turn's call is read from (FIX 6935), ids only, for
//! its run's permits and metered settlement: the answering agent's
//! definition, each craft note it is shown, its retained log's summaries,
//! turns and messages, and the context board when the call carries it. The
//! person's own words are no stored row. A part that names no rows of its
//! own, as a caller's history line or a log not all pinned, leaves the whole
//! set unknown, never a partial list. Nothing reads the set to decide.
use oneiron::EntityId;
use oneiron::attempt_queue::ManifestEntry;
use oneiron::skill_optimize::union_source_rows;

/// What a turn's call has been read from so far; `None` once unknown.
pub(super) struct TurnSources(Option<Vec<EntityId>>);

impl TurnSources {
    /// The answering agent's definition, its instructions' row.
    pub(super) fn of_agent(agent: EntityId) -> Self {
        Self(Some(vec![agent]))
    }

    /// The rows one part of the call was read from: `None`, a part whose
    /// rows are unknown, leaves the set unknown.
    pub(super) fn add(&mut self, rows: Option<&[EntityId]>) {
        match (self.0.as_mut(), rows) {
            (Some(into), Some(rows)) => into.extend_from_slice(rows),
            _ => self.0 = None,
        }
    }

    /// The craft notes the call is shown, each by its claim.
    pub(super) fn craft(&mut self, entries: &[ManifestEntry]) {
        let claims: Option<Vec<EntityId>> = entries
            .iter()
            .map(|entry| EntityId::from_hex(&entry.reference).ok())
            .collect();
        self.add(claims.as_deref());
    }

    /// The set, sorted and deduplicated; `None` when unknown.
    pub(super) fn rows(self) -> Option<Vec<EntityId>> {
        union_source_rows([self.0])
    }
}
