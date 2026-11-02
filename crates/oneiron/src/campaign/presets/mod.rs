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
//! 1. **`load_campaign_preset` is the only loader.** It parses caller-supplied
//!    JSON, validates it, and returns owned data. It reads no path, writes no
//!    storage, queues no work, sends nothing, registers no kind, and allocates
//!    no entity byte. Beside it, `campaign_preset_defaults` reads the shipped
//!    policy dials and `resolve_reply_snooze_policy` reads a campaign's own
//!    stored pause; neither writes anything.
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
//! codes routed exactly once, a positive-later snooze whose default sits in its
//! own range and restarts at touch 1, and same-day-reschedule → D+3 bump →
//! snooze no-show recovery. The snooze range, the audit window and the desk
//! period are owner-editable dials: `defaults.json` ships the 60–90 day snooze
//! that wakes on a fresh trigger, a 14-day audit and a `P1M` desk month as
//! where a preset starts, and a preset that sets other values runs those
//! (FIX 9665).

mod content;
mod defaults;
mod loader;
mod shape;
mod validate;

pub use self::defaults::{
    CAMPAIGN_PRESET_DEFAULTS_JSON, CampaignPresetDefaults, campaign_preset_defaults,
    default_reply_snooze_policy, resolve_reply_snooze_policy,
};
pub use self::loader::load_campaign_preset;
pub use self::shape::{
    BriefSectionData, BriefTemplateData, BriefTemplateKind, BriefTemplateSet,
    CONSULTANCY_PRESET_ID, CONSULTANCY_PRESET_VERSION, CampaignPresetData, CampaignTemplateData,
    CommitmentRhythmData, LanePolicyData, QuestionBlockData, RhythmAnchor, RhythmCheckpointData,
    SnoozePolicyData,
};

pub(crate) use self::validate::validate_snooze_policy;

// The flat presets.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/stage import header, and
// every presets-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
