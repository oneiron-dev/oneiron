//! Visible text projection over a checked selected path or the current ChildOf writer.
//! Topology, lifetime and text are read through one vault snapshot.

use crate::conversation_dag::retained_path::{
    PreviewTopology, RetainedRow, RetainedTurn, SelectedPathSnapshot, retained_row,
};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::{EntityId, Vault};
use heed::RoTxn;
use serde_json::Value;

impl Vault {
    /// Latest visible message from the selected conversation, clipped to 50 Unicode scalars.
    /// No selected DAG state means the current ChildOf-only witness writer is used.
    pub fn conversation_last_message_snippet(
        &self,
        conversation: &EntityId,
    ) -> Result<Option<String>> {
        let txn = self.store.env.read_txn()?;
        let turns = match self.preview_turns_in(&txn, conversation)? {
            PreviewTurns::Path(turns) => turns,
            PreviewTurns::Learned(mut turns) => {
                turns.sort_by(|left, right| right.cmp(left));
                turns.into_iter().map(|(_, id)| id).collect()
            }
        };
        for turn in turns {
            let turn = RetainedTurn {
                row: retained_row(&self.store, &txn, &turn, ENTITY_TYPE_TURN)?,
                id: turn,
            };
            if let Some(text) = self.visible_turn_text(&txn, &turn)? {
                return Ok(Some(snippet(&text)));
            }
        }
        Ok(None)
    }

    /// The turns a preview looks at: the selected path, or with no selected
    /// DAG state the live ChildOf turns. Only ids and learned times: a caller
    /// reads each turn's body when it gets to it.
    pub(crate) fn preview_turns_in(
        &self,
        txn: &RoTxn<'_>,
        conversation: &EntityId,
    ) -> Result<PreviewTurns> {
        match SelectedPathSnapshot::read(self, txn, conversation)? {
            PreviewTopology::Selected(path) => {
                return Ok(PreviewTurns::Path(
                    path.turns.into_iter().rev().map(|turn| turn.id).collect(),
                ));
            }
            PreviewTopology::ChildOfOnly => {}
            PreviewTopology::ProvenEmpty => return Ok(PreviewTurns::Path(Vec::new())),
        }
        let mut turns = Vec::new();
        for edge in self.store.port_edges(
            txn,
            conversation,
            EdgeDirection::In,
            Some(EdgeKind::ChildOf),
            None,
        )? {
            let id = edge?.target;
            // ChildOf-only rooms can have other entity kinds on the same edge.
            if self
                .store
                .port_entity_record(txn, &id)?
                .is_none_or(|row| row.entity_type != ENTITY_TYPE_TURN)
            {
                continue;
            }
            if let RetainedRow::Live { learned_at, .. } =
                retained_row(&self.store, txn, &id, ENTITY_TYPE_TURN)?
            {
                turns.push((learned_at, id));
            }
        }
        Ok(PreviewTurns::Learned(turns))
    }

    /// The MESSAGE rows that are part of `turn`.
    pub(crate) fn turn_message_ids_in(
        &self,
        txn: &RoTxn<'_>,
        turn: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let mut ids = Vec::new();
        for edge in
            self.store
                .port_edges(txn, turn, EdgeDirection::In, Some(EdgeKind::PartOf), None)?
        {
            let id = edge?.target;
            if self
                .store
                .port_entity_record(txn, &id)?
                .is_some_and(|row| row.entity_type == ENTITY_TYPE_MESSAGE)
            {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    fn visible_turn_text(&self, txn: &RoTxn<'_>, turn: &RetainedTurn) -> Result<Option<String>> {
        let RetainedRow::Live { body, .. } = &turn.row else {
            return Ok(None);
        };
        if self.archive_tombstone_in_txn(txn, &turn.id)?.is_some() {
            return Ok(None);
        }
        let mut latest = LatestMessage::default();
        for id in self.turn_message_ids_in(txn, &turn.id)? {
            let RetainedRow::Live { body, .. } =
                retained_row(&self.store, txn, &id, ENTITY_TYPE_MESSAGE)?
            else {
                continue;
            };
            if self.archive_tombstone_in_txn(txn, &id)?.is_some() {
                continue;
            }
            #[cfg(feature = "sync")]
            let body = crate::entity_doc::resolve_record_body(&self.store, txn, &id, &body)?;
            latest.offer(id, &body);
        }
        if let Some(text) = latest.text() {
            return Ok(Some(text));
        }
        #[cfg(feature = "sync")]
        let resolved = crate::entity_doc::resolve_record_body(&self.store, txn, &turn.id, body)?;
        #[cfg(feature = "sync")]
        let body = resolved.as_slice();
        Ok(turn_text(body))
    }
}

/// The turns a preview looks at, and the order it prefers them in.
pub(crate) enum PreviewTurns {
    /// The selected path from its HEAD back, the order preferred.
    Path(Vec<EntityId>),
    /// The live ChildOf turns in index order, each with its learned time; the
    /// latest learned is preferred.
    Learned(Vec<(u64, EntityId)>),
}

/// The latest visible message of one turn, kept as its messages are offered
/// (id and live body): by its order inside the turn, then its id. Only the
/// winner's text is held.
#[derive(Debug, Default)]
pub(crate) struct LatestMessage(Option<(u64, EntityId, String)>);

impl LatestMessage {
    pub(crate) fn offer(&mut self, id: EntityId, body: &[u8]) {
        let Some(message) = rmp_serde::from_slice::<Value>(body).ok() else {
            return;
        };
        if message.get("is_visible").and_then(Value::as_bool) != Some(true) {
            return;
        }
        let Some(text) = message.get("content").and_then(Value::as_str) else {
            return;
        };
        let order = message.get("order").and_then(Value::as_u64).unwrap_or(0);
        if self
            .0
            .as_ref()
            .is_none_or(|(old_order, old_id, _)| (order, id) > (*old_order, *old_id))
        {
            self.0 = Some((order, id, text.to_owned()));
        }
    }

    pub(crate) fn text(self) -> Option<String> {
        self.0.map(|(_, _, text)| text)
    }
}

/// A turn's own text, the preview of a turn with no visible message.
pub(crate) fn turn_text(body: &[u8]) -> Option<String> {
    rmp_serde::from_slice::<Value>(body)
        .ok()
        .and_then(|body| body.get("txt").and_then(Value::as_str).map(str::to_owned))
}

pub(crate) fn snippet(source: &str) -> String {
    if source.chars().count() <= 50 {
        return source.to_owned();
    }
    source
        .chars()
        .take(49)
        .chain(std::iter::once('…'))
        .collect()
}
