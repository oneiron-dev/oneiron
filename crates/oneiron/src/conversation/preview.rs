//! Visible text projection over a checked selected path or the current ChildOf writer.
//! Topology, lifetime and text are read through one vault snapshot.

use crate::conversation_dag::retained_path::{
    PreviewTopology, RetainedRow, RetainedTurn, SelectedPathSnapshot, retained_row,
};
use crate::edge::EdgeKind;
use crate::error::{Error, RecordError, Result};
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
        let turns: Vec<EntityId> = match SelectedPathSnapshot::read(self, &txn, conversation)? {
            PreviewTopology::Selected(path) => {
                path.turns.into_iter().rev().map(|turn| turn.id).collect()
            }
            PreviewTopology::ChildOfOnly => {
                let mut turns = self.childof_turns_in(&txn, conversation)?;
                turns.sort_by(|left, right| right.cmp(left));
                turns.into_iter().map(|(_, id)| id).collect()
            }
            PreviewTopology::ProvenEmpty => Vec::new(),
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

    /// The live TURNs that are ChildOf `conversation`, in index order, each
    /// with its learned time: the turns a preview may look at.
    pub(crate) fn childof_turns_in(
        &self,
        txn: &RoTxn<'_>,
        conversation: &EntityId,
    ) -> Result<Vec<(u64, EntityId)>> {
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
        Ok(turns)
    }

    /// The order a reader's preview takes the turns it may read, each given
    /// as its learned time and id: the selected path from its HEAD back, or
    /// with no selected DAG state the latest learned first. The ChildOf-only
    /// proof looks at those turns alone, so a turn the reader may not read
    /// never decides it. `None` when the topology is unresolved: the preview
    /// shows nothing rather than a turn off the selected path.
    pub(crate) fn readable_preview_order(
        &self,
        conversation: &EntityId,
        mut readable: Vec<(u64, EntityId)>,
    ) -> Result<Option<Vec<EntityId>>> {
        readable.sort_by_key(|(_, id)| *id);
        let path: Option<Vec<EntityId>> = {
            let admits =
                |id: &EntityId| readable.binary_search_by_key(id, |(_, turn)| *turn).is_ok();
            let txn = self.store.env.read_txn()?;
            match SelectedPathSnapshot::read_admitting(self, &txn, conversation, &admits) {
                Ok(PreviewTopology::Selected(path)) => Some(
                    path.turns
                        .into_iter()
                        .rev()
                        .map(|turn| turn.id)
                        .filter(admits)
                        .collect(),
                ),
                Ok(PreviewTopology::ChildOfOnly) => None,
                Ok(PreviewTopology::ProvenEmpty) => Some(Vec::new()),
                Err(Error::Record(RecordError::InvalidConversationDag(reason))) => {
                    tracing::debug!(
                        conversation = %conversation.to_hex(),
                        reason,
                        "a conversation preview's topology is unresolved"
                    );
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        };
        Ok(Some(path.unwrap_or_else(|| {
            readable.sort_by(|left, right| right.cmp(left));
            readable.into_iter().map(|(_, id)| id).collect()
        })))
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
