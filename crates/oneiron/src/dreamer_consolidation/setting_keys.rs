//! The settings `dreamer_consolidation` keeps (DESIGN 15-setting-primitive, stage 1): each row is
//! one catalogue key, and the crate's build script lists it in the setting catalogue.

use super::excluded_conversations::{DreamerExcludedConversations, forget_newly_excluded};
use super::routing::{ConsolidationKeyRules, shipped_key_rules};
use crate::setting::Kind;

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
}
