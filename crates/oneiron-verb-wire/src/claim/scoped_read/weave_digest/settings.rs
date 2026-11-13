//! Moved from `crates/oneiron/src/claim/scoped_read/weave_digest/settings.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::claim::scoped_read::weave_digest::WeaveDigestCadence;
use crate::claim::scoped_read::weave_report::WeaveSectionKind;
use serde::Deserialize;
use serde::Serialize;

/// An Owner schedule's settings as the Coach may change them: its rhythm and
/// the order its sections lead in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestSettings {
    pub cadence: WeaveDigestCadence,
    /// The schedule's section kinds, in the order its digest lays them out.
    pub sections: Vec<WeaveSectionKind>,
}

/// Where a Coach change to the owner's digest settings stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WeaveDigestSettingChangeStatus {
    /// Proposed: it waits for the owner's answer, and silence changes nothing.
    Pending,
    /// The Coach applied it under a Grant that names digest settings.
    Applied,
    /// The owner accepted the proposal, as his own act.
    Accepted,
    /// The owner declined the proposal.
    Declined,
    /// The owner's own edit came first; nothing applied.
    Superseded,
    /// The owner's one tap restored the settings before it.
    Undone,
}

/// One Coach change to the owner's digest rhythm or section order, from his
/// own behaviour only (FIX 5495). Applied and accepted changes keep a
/// one-tap undo while the settings stay as the change left them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestSettingChange {
    /// The change, as 32 hex.
    pub change_ref: String,
    pub status: WeaveDigestSettingChangeStatus,
    /// The settings it was proposed against.
    pub before: WeaveDigestSettings,
    /// The settings it sets.
    pub after: WeaveDigestSettings,
    /// Why the Coach proposed it, from the owner's own behaviour.
    pub reason: String,
    /// The Coach that proposed it, as 32 hex.
    pub coach_ref: String,
    /// The Grant naming digest settings it applied under, as 32 hex; absent
    /// for a proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
    /// The settings generation it was proposed against.
    pub base_generation: u64,
    /// The generation its apply or accept wrote; its undo needs it current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_generation: Option<u64>,
    /// The generation its undo wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undone_generation: Option<u64>,
    /// When the Coach made it, in Unix seconds.
    pub created_at: u64,
    /// When it reached its status, in Unix seconds; absent while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<u64>,
    /// For a proposal, why a Grant of the Coach's that named these settings
    /// was passed over: `pact_standing_lapsed` when, on a shared vault, its
    /// pact membership alone had lapsed (FIX 7548). Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_omitted: Option<String>,
}

/// The owner's answer to one proposed change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestSettingAnswer {
    /// The change, as 32 hex.
    pub change_ref: String,
    /// `true` accepts it as the owner's own act; `false` declines it.
    pub accept: bool,
}

/// The owner's one-tap undo of an applied or accepted change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestSettingUndo {
    /// The change, as 32 hex.
    pub change_ref: String,
}

/// What the owner tells the Coach about his own digest. His next own edit of
/// the schedule retires it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestFeedback {
    /// The rhythm he wants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_cadence: Option<WeaveDigestCadence>,
    /// The section he wants first; it must already be one of the schedule's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lead_section: Option<WeaveSectionKind>,
    /// Keep the settings as they are: the Coach proposes nothing.
    #[serde(default)]
    pub keep_current: bool,
}
