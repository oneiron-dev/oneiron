//! The answer-schema line of the morning report (HOUSE-SCHEMA-SWITCH): one item per
//! answer-schema event no digest carried yet, each with its receipt id. Never the request or
//! reply text.

use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// The derived group the answer-schema line renders under.
pub const ANSWER_SCHEMA_GROUP: &str = "dreamer.answer_schema";

/// The line's view: Settings, where the owner turns the schema back on.
pub const ANSWER_SCHEMA_VIEW: &str = "vault.settings";

/// The answer-schema events no digest carried yet, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestAnswerSchema {
    pub items: Vec<DigestAnswerSchemaItem>,
    /// The newest event the line carries: the next line starts after it.
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub through: EntityId,
    pub view: String,
}

/// One answer-schema event, content-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestAnswerSchemaItem {
    /// The event's id: the ref the item renders with.
    pub event: String,
    /// `paused` or `rearmed`.
    pub kind: String,
    /// The exact line the owner reads.
    pub summary: String,
    pub at: u64,
}

impl DigestAnswerSchema {
    /// Whether the line makes a digest due on its own: it carries an event.
    #[must_use]
    pub fn arms(&self) -> bool {
        !self.items.is_empty()
    }

    /// Renders the line under a presentation's two templates: the group, then one item per event.
    pub fn render(
        &self,
        group_template: &str,
        item_template: &str,
        group: &str,
        rendered: &mut String,
    ) {
        rendered.push_str(&group_template.replace("{group}", group));
        for event in &self.items {
            rendered.push_str(
                &item_template
                    .replace("{summary}", &event.summary)
                    .replace("{ref}", &event.event),
            );
        }
    }
}
