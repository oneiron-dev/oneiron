//! Moved from `crates/oneiron/src/off_record/lifecycle/types.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Current write-routing mode of an off-record session.
///
/// The mode says where NEW writes land. It never moves rows: flipping to
/// [`OffRecordMode::OnRecord`] seals the overlay so later writes go to base,
/// and the room's earlier turns stay overlay-only until promote or close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordMode {
    OffRecord,
    OnRecord,
    /// No transcript, derived memory, telemetry, or receipts are retained.
    /// Entry is explicit; this mode cannot be changed or promoted.
    Anonymous,
}

impl OffRecordMode {
    pub const fn write_target(self) -> oneiron_store::session_overlay::RouteTarget {
        match self {
            Self::OffRecord => oneiron_store::session_overlay::RouteTarget::Overlay,
            Self::OnRecord => oneiron_store::session_overlay::RouteTarget::Base,
            Self::Anonymous => oneiron_store::session_overlay::RouteTarget::Discard,
        }
    }
}

/// Backend class the disclosure-honesty line is relative to (OF-326
/// EF-316-style honesty caveat): evaporation is backend-relative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordBackendClass {
    /// Local inference: real evaporation — nothing leaves the device and
    /// nothing survives close.
    Local,
    /// Cloud or BYO-key inference: this engine persists nothing at close,
    /// but provider retention applies to what transited the provider API.
    RemoteProvider,
}

/// What a person did with the talk, as the room hears of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OffRecordNoticeAct {
    /// Saved the whole talk so far into their own vault.
    SavedTalk,
    /// Saved one turn into their own vault.
    SavedTurn,
    /// Saved a selected scratch artifact and its document into this vault.
    SavedArtifact,
    /// Put the stretch on record: later turns are saved as they land.
    SavingFromHere,
    /// Saving stopped: the person who put the stretch on record left its
    /// room, or lost this vault or their proof. Later turns stay off record.
    SavingStopped,
    /// Took an export file of the talk.
    Exported,
    /// An agent suggested a save. Nothing was saved.
    SaveSuggested,
    /// A holder of this vault's write grant declined the waiting save
    /// suggestions. Nothing was saved.
    SaveDeclined,
}
