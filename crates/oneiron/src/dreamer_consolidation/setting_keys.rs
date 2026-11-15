//! The settings `dreamer_consolidation` keeps (DESIGN 15-setting-primitive, stages 1 and 2): each
//! row is one catalogue key, and the crate's build script lists it in the setting catalogue.

use super::excluded_conversations::{DreamerExcludedConversations, forget_newly_excluded};
use super::routing::{ConsolidationKeyRules, shipped_key_rules};
use super::selection::{
    SelectionScoring, SelectionTiming, shipped_selection_scoring, shipped_selection_timing,
};
use super::strength::ConsolidationStrengthPolicy;
use crate::federation::EngineControlClass;
use crate::setting::{Kind, SetBy};

crate::setting::setting_keys! {
    /// Which claim keys the consolidator may fold: per predicate, whether its text is normalised
    /// and which field of a structured value is its question. Absent, the shipped
    /// key_defaults.json decides.
    pub(crate) CONSOLIDATION_KEY_RULES: ConsolidationKeyRules = "dreamer.consolidation.key_rules" {
        kind: Kind::new(shipped_key_rules),
    };
    /// Conversations whose turns stay out of Dreamer consolidation. Words framed before a change
    /// forget the newly excluded conversations in the change's own commit.
    pub(crate) EXCLUDED_CONVERSATIONS: DreamerExcludedConversations =
        "dreamer.excluded_conversations" {
        kind: Kind::new(DreamerExcludedConversations::default),
        on_change: Some(forget_newly_excluded),
    };
    /// How selection scores and admits a consolidation candidate (the evidence minimum, the
    /// cosine threshold, the strength weights, the type priors and the scales) and how wide its
    /// extraction runs. A new value orders the selections made after it. Absent, the shipped
    /// selection_defaults.json decides.
    pub(crate) SELECTION_SCORING: SelectionScoring = "dreamer.consolidation.selection.scoring" {
        kind: Kind::new(shipped_selection_scoring),
    };
    /// How long a claim soaks before selection takes it, and the window its recency signal is
    /// measured over, in milliseconds. A holder of the maintenance cadence class moves it either
    /// way, as before: it moves no access, authority, money or identity, so its order is neutral.
    /// Absent, the shipped selection_defaults.json decides.
    pub(crate) SELECTION_TIMING: SelectionTiming = "dreamer.consolidation.selection.timing" {
        kind: Kind::new(shipped_selection_timing).neutral(),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
    };
    /// When a quiet claim may be archived: the strength it must score strictly below, and how long
    /// it stays without new independent evidence first. A holder of the maintenance cadence class
    /// moves it either way, as before, so its order is neutral. Absent, the shipped
    /// strength_defaults.json decides.
    pub(crate) STRENGTH_POLICY: ConsolidationStrengthPolicy =
        "dreamer.consolidation.strength.policy" {
        kind: Kind::new(ConsolidationStrengthPolicy::default).neutral(),
        set_by: SetBy::Class(EngineControlClass::MaintenanceCadence),
    };
}
