//! Moved from `crates/oneiron/src/note/files/source.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::note::files::source::FileHandle;
use serde::Deserialize;
use serde::Serialize;

/// What a Files source's notes derive their ids from, before the source's
/// id: never a host path, which a UTF-8 canonical folder always is.
pub const FILES_NAMESPACE: &str = "oneiron-files/";

/// This install's Files world: the WORLD every Files source of this install
/// lands in, and the machine it stays on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesWorld {
    pub world: EntityId,
    /// The install whose files the world holds: its one reader by default.
    pub machine: EntityId,
}

/// Where a Files source's files live (FIX 6942): the source's identity, the
/// world its notes are born in, the install it reads on, and what it never
/// reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesPlacement {
    /// The source's id: derived from its install, its world and its folder,
    /// so attaching the folder again finds the notes it landed.
    pub source: EntityId,
    pub world: EntityId,
    pub machine: EntityId,
    /// Patterns over each entry's name and its `/`-separated path under the
    /// folder (`*` within a name, `**` across folders, `?` one character):
    /// what the host never opens.
    pub exclude: Vec<String>,
}

/// The namespace a Files source's notes derive their ids from.
pub fn namespace(source: EntityId) -> String {
    format!("{FILES_NAMESPACE}{}", source.to_hex())
}
