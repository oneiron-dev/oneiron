//! The form of an agent pack's selected-knowledge facet
//! (`knowledge/selected.json`): which of its two encodings a facet is in.
//! The agent definition codec (`agent_def::portable_knowledge`) writes and
//! reads the facet; the archive export and import name the form.

/// A selected-knowledge facet's form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnowledgeFormat {
    /// `[row, ...]`; typed ids are byte arrays. Read, never written.
    V1,
    /// `["oneiron.agent-knowledge.v2", row, ...]`; typed ids are lowercase
    /// hex text. A row is an object, so a leading string is only a marker.
    V2,
}

impl KnowledgeFormat {
    /// The form every new facet is written in.
    pub const CURRENT: Self = Self::V2;
}
