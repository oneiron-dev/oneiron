//! CA-08 consultancy preset: the CONTRACT, never the copy.
//!
//! ONE-1775 owns the stage-ladder mechanism and deliberately spells no stage
//! name. This module is the other half of that split: it declares the typed
//! shape a consultancy preset has to arrive in, and validates one host-supplied
//! pack config against the ratified content invariants. It instantiates
//! `StageLadderDefinition` rather than restating it — no schema is copied
//! across the seam.
//!
//! Three laws shape the whole file.
//!
//! 1. **`load_campaign_preset` is the only production function.** It parses
//!    caller-supplied JSON, validates it, and returns owned data. It reads no
//!    path, writes no storage, queues no work, sends nothing, registers no
//!    kind, and allocates no entity byte.
//! 2. **No consultancy CONTENT lives in this crate.** Headings, SOW and
//!    one-pager bodies, and Mom-Test interview text are host-supplied pack
//!    config. The engine ships section KEYS, evidence SLOT names, and the
//!    validation that a config declares them — never a sentence a counterparty
//!    would read. The parse-plus-validate shape mirrors
//!    [`crate::channel_identity_manifest::parse_channel_identity_capability_matrix`];
//!    its compiled-in asset and `OnceLock` cache are deliberately NOT mirrored,
//!    because a built-in catalog is exactly the embedded content this module
//!    exists to keep out.
//! 3. **The preset is data for other owners' machinery.** The snooze dials feed
//!    CA-01's `campaign.member` paused form through CA-04's re-entry door; the
//!    no-show legs feed CA-04's recovery plan; deposit, audit, desk, and
//!    renewal fields are evidence HOOK declarations whose truth stays with the
//!    counterparty ledger, TASK_LIST, and commitment owners. Nothing here adds
//!    a scheduler, recurrence primitive, commitment type, or delivery action.
//!
//! The validated content invariants are the ratified ones: id
//! `CONSULTANCY_PRESET_ID` at version `CONSULTANCY_PRESET_VERSION`, the
//! eight-stage pipeline with `member (cold)` absent because membership is not
//! pipeline, `call_held` earned only by a calendar event OUTCOME, all six reply
//! codes routed exactly once, a 60–90 day positive-later snooze that restarts at
//! touch 1 and also wakes on a fresh trigger, same-day-reschedule → D+3 bump →
//! snooze no-show recovery, a 14-day audit, and a `P1M` desk month.

mod content;
mod loader;
mod shape;
mod validate;

pub use self::loader::load_campaign_preset;
pub use self::shape::{
    BriefSectionData, BriefTemplateData, BriefTemplateKind, BriefTemplateSet,
    CONSULTANCY_PRESET_ID, CONSULTANCY_PRESET_VERSION, CampaignPresetData, CampaignTemplateData,
    CommitmentRhythmData, LanePolicyData, QuestionBlockData, RhythmAnchor, RhythmCheckpointData,
    SnoozePolicyData,
};

#[cfg(test)]
mod tests;

// The flat presets.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/stage import header, and
// every presets-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::validate::is_external_hook;
#[cfg(test)]
use crate::campaign::claims::{StageEvidenceClass, StageKey};
#[cfg(test)]
use crate::campaign::stage::{
    NO_SHOW_BUMP_AFTER_SECS, ReplyCode, ReplyDisposition, StageLadderDefinition,
};
#[cfg(test)]
use crate::error::Error;
