//! The rows a context-pack response names: the rows it serves, and the rows
//! a keyed replay of it re-admits.

use super::CoreContextPackResponse;

impl CoreContextPackResponse {
    /// The rows this pack serves: its results, its neighbours and the
    /// evidence its L2 base names.
    pub(crate) fn served_rows(&self) -> oneiron::Result<Vec<oneiron::EntityId>> {
        let mut ids = self
            .results
            .iter()
            .chain(&self.neighbors)
            .map(|row| oneiron::EntityId::from_hex(&row.id))
            .collect::<oneiron::Result<Vec<_>>>()?;
        if let Some(base) = &self.l2_base {
            ids.extend_from_slice(base.evidence_ids());
        }
        Ok(ids)
    }

    /// The rows this pack names beyond its documents, each of which a keyed
    /// replay re-admits: every known contact it stamps and every capability
    /// it discovered.
    pub(crate) fn replay_admits(&self) -> Vec<oneiron::EntityId> {
        let contacts = self
            .interlocutors
            .iter()
            .flatten()
            .filter(|stamp| stamp.class == oneiron::interlocutor::InterlocutorClass::KnownContact)
            .filter_map(|stamp| oneiron::EntityId::from_hex(&stamp.speaker).ok());
        let capabilities = self.capabilities.iter().map(|hit| hit.id);
        contacts.chain(capabilities).collect()
    }

    /// The rows this answer was derived from, as the route lists them for
    /// the release of a drained retry (FIX 1435). They are the rows the
    /// pack serves, the rows a keyed replay of it re-admits, the
    /// CODE_ARTIFACT and units of each instruction file, every known
    /// contact its disclosure block stamps, and the reaction, message and
    /// reactor of each reaction signal.
    ///
    /// `None` when a returned record carries words read from rows the
    /// response does not keep: a MESSAGE's or TURN's reaction lines, which
    /// count reaction claims, or a TURN's text, which its messages hold.
    /// Its rows are then not all known. `None` too when a signal's id does
    /// not parse. A served row whose id does not parse is the error
    /// [`Self::served_rows`] returns.
    pub(crate) fn producer_rows(&self) -> oneiron::Result<Option<Vec<oneiron::EntityId>>> {
        let mut rows = self.served_rows()?;
        let composed_from_unlisted_rows = |entity: &super::CoreContextEntity| {
            let Some(fields) = entity.fields.as_ref() else {
                return false;
            };
            let reaction_lines = fields.contains_key(oneiron::reaction::REACTIONS_FIELD);
            match entity.entity_type {
                oneiron::registry::ENTITY_TYPE_TURN => reaction_lines || fields.contains_key("txt"),
                oneiron::registry::ENTITY_TYPE_MESSAGE => reaction_lines,
                _ => false,
            }
        };
        if self
            .results
            .iter()
            .chain(&self.neighbors)
            .any(composed_from_unlisted_rows)
        {
            return Ok(None);
        }
        rows.extend(self.replay_admits());
        for handle in &self.instruction_files {
            rows.push(handle.code_artifact_id);
            rows.extend_from_slice(&handle.units);
        }
        let stamps = self
            .disclosure
            .iter()
            .flat_map(|block| &block.interlocutors);
        rows.extend(
            stamps
                .filter(|stamp| {
                    stamp.class == oneiron::interlocutor::InterlocutorClass::KnownContact
                })
                .filter_map(|stamp| oneiron::EntityId::from_hex(&stamp.speaker).ok()),
        );
        for signal in &self.signals {
            for id in [&signal.reaction, &signal.message, &signal.by] {
                let Ok(id) = oneiron::EntityId::from_hex(id) else {
                    return Ok(None);
                };
                rows.push(id);
            }
        }
        rows.sort_unstable();
        rows.dedup();
        Ok(Some(rows))
    }
}
