//! Moved from `crates/oneiron/src/world_keys/bundle/carrier.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::ErrorKind;
use oneiron_contracts::entity_id::EntityId;
use serde::Serialize;
use serde::ser::SerializeStruct as _;

/// Where a readable world section stopped before it merged here (FIX 19525).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmergedStage {
    /// The section did not open with the world key held here.
    Open,
    /// The section opened, and its payload did not decode.
    Decode,
    /// One window of the section did not merge into its mirror here.
    Merge,
}

impl UnmergedStage {
    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::Open => {
                "the world's section did not open here: it is carried unchanged, the erased-actor \
                 cleanup did not run on it, and the owner repairs it"
            }
            Self::Decode => {
                "the world's section opened but did not decode here: it is carried unchanged, the \
                 erased-actor cleanup did not run on it, and the owner repairs it"
            }
            Self::Merge => {
                "a window of the world's section did not merge here: the section is carried \
                 unchanged, the erased-actor cleanup did not run on it, and the owner repairs it"
            }
        }
    }
}

/// A section of the latest generation that a publisher may read and carries
/// unchanged, because it did not open, decode or merge here (FIX 19525). No
/// unique history is dropped and no publication stops, but the erased-actor
/// cleanup that every merged section takes did not run on it: a repair case
/// for the owner. It names the world, the window when one window's merge
/// failed, the stage and the error's kind: never a section byte, a row or an
/// error message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmergedSection {
    pub world: EntityId,
    /// The label of the window whose merge failed; `None` when the section
    /// did not open or decode.
    pub window: Option<String>,
    pub stage: UnmergedStage,
    /// The kind of the error that stopped it.
    pub kind: ErrorKind,
}

impl Serialize for UnmergedSection {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("UnmergedSection", 5)?;
        out.serialize_field("world", &self.world)?;
        match &self.window {
            Some(window) => out.serialize_field("window", window)?,
            None => out.skip_field("window")?,
        }
        out.serialize_field("stage", &self.stage)?;
        out.serialize_field("kind", &self.kind)?;
        out.serialize_field("text", self.stage.text())?;
        out.end()
    }
}
