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
}
