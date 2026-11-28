//! The settings `dreamer_consolidation` keeps (DESIGN 15-setting-primitive, stage 1): each row is
//! one catalogue key, and the crate's build script lists it in the setting catalogue.

use super::answer_schema::{answer_schema_off, answer_schema_on, rearm_answer_schema_on_change};
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
    /// Whether the Dreamer holds its claim extraction answer to the answer's JSON Schema on
    /// your own house server. On by default. A nightly check pauses it when nights with the
    /// schema score lower than nights without it, and says so in your morning report; turning
    /// it on here again re-arms it.
    pub(crate) ANSWER_SCHEMA: bool = "dreamer.extraction.answer_schema" {
        kind: Kind::new(answer_schema_on)
            .strictest(answer_schema_off)
            .lower(),
        on_change: Some(rearm_answer_schema_on_change),
        records_equal_owner_write: true,
    };
}
