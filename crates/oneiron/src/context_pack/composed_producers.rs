//! The rows a context pack's composed fields were read from (FIX 1435).

use std::collections::{HashMap, HashSet};

use crate::entity_id::EntityId;
use crate::reaction::REACTIONS_FIELD;

use super::ContextPack;

/// The rows each returned record's composed fields were read from, per
/// record (FIX 1435). A TURN's `txt` joins the words of its messages. A
/// MESSAGE's or TURN's reaction lines count reaction claims and name
/// reactors. Neither field is read from the record's own body, so the
/// record alone does not name its rows.
///
/// This is lineage only. It is not a read receipt and it grants no
/// authority. A record that has no entry here for a field it carries has
/// rows that are not known.
#[derive(Debug, Default)]
pub struct ComposedFieldProducers {
    /// Per TURN, the messages whose released words its `txt` joins.
    turn_messages: HashMap<EntityId, Vec<EntityId>>,
    /// Per MESSAGE or TURN, the reaction claims its lines count and the
    /// reactors they name.
    reaction_rows: HashMap<EntityId, Vec<EntityId>>,
}

impl ComposedFieldProducers {
    /// Records that `turn`'s `txt` joins the words of `messages`.
    pub(crate) fn record_turn_text(
        &mut self,
        turn: EntityId,
        messages: impl IntoIterator<Item = EntityId>,
    ) {
        self.turn_messages.entry(turn).or_default().extend(messages);
    }

    /// Records that `record`'s reaction lines are read from `rows`.
    pub(crate) fn record_reaction_lines(
        &mut self,
        record: EntityId,
        rows: impl IntoIterator<Item = EntityId>,
    ) {
        self.reaction_rows.entry(record).or_default().extend(rows);
    }

    /// The messages whose words `turn`'s `txt` joins, when this pack
    /// composed that field.
    #[must_use]
    pub fn turn_text(&self, turn: &EntityId) -> Option<&[EntityId]> {
        self.turn_messages.get(turn).map(Vec::as_slice)
    }

    /// The reaction claims and reactors `record`'s reaction lines are read
    /// from, when this pack attached those lines.
    #[must_use]
    pub fn reaction_lines(&self, record: &EntityId) -> Option<&[EntityId]> {
        self.reaction_rows.get(record).map(Vec::as_slice)
    }

    /// Keeps only the entries of records that `pack` still returns with the
    /// composed field. Call it after each cut and projection of the pack.
    pub fn retain_returned(&mut self, pack: &ContextPack) {
        let carrying = |field: &str| -> HashSet<EntityId> {
            pack.results
                .iter()
                .chain(&pack.neighbors)
                .filter(|entity| {
                    entity
                        .fields
                        .as_ref()
                        .is_some_and(|fields| fields.contains_key(field))
                })
                .map(|entity| entity.id)
                .collect()
        };
        let texts = carrying("txt");
        self.turn_messages.retain(|turn, _| texts.contains(turn));
        let lines = carrying(REACTIONS_FIELD);
        self.reaction_rows
            .retain(|record, _| lines.contains(record));
    }
}
