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
        for turn in self.preview_turns_in(&txn, conversation)? {
            if let Some(text) = self.visible_turn_text(&txn, &turn)? {
                return Ok(Some(snippet(&text)));
            }
        }
        Ok(None)
    }

    /// The live turns a preview looks at, the one it prefers first: the
    /// selected path from its HEAD back, or with no selected DAG state the
    /// ChildOf turns from the latest learned.
    pub(crate) fn preview_turns_in(
        &self,
        txn: &RoTxn<'_>,
        conversation: &EntityId,
    ) -> Result<Vec<RetainedTurn>> {
        match SelectedPathSnapshot::read(self, txn, conversation)? {
            PreviewTopology::Selected(path) => return Ok(path.turns.into_iter().rev().collect()),
            PreviewTopology::ChildOfOnly => {}
            PreviewTopology::ProvenEmpty => return Ok(Vec::new()),
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
            let row = retained_row(&self.store, txn, &id, ENTITY_TYPE_TURN)?;
            if let RetainedRow::Live { learned_at, .. } = row {
                turns.push((learned_at, RetainedTurn { id, row }));
            }
        }
        turns.sort_by(|(left, a), (right, b)| (right, b.id).cmp(&(left, a.id)));
        Ok(turns.into_iter().map(|(_, turn)| turn).collect())
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
        let mut messages = Vec::new();
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
            messages.push((id, body));
        }
        if let Some(text) = latest_message_text(messages.iter().map(|(id, body)| (*id, &body[..])))
        {
            return Ok(Some(text));
        }
        #[cfg(feature = "sync")]
        let resolved = crate::entity_doc::resolve_record_body(&self.store, txn, &turn.id, body)?;
        #[cfg(feature = "sync")]
        let body = resolved.as_slice();
        Ok(turn_text(body))
    }
}

/// The text of the latest visible message among `messages` (id and live
/// body), by its order inside the turn and then its id.
pub(crate) fn latest_message_text<'b>(
    messages: impl IntoIterator<Item = (EntityId, &'b [u8])>,
) -> Option<String> {
    let mut latest: Option<(u64, EntityId, String)> = None;
    for (id, body) in messages {
        let Some(message) = rmp_serde::from_slice::<Value>(body).ok() else {
            continue;
        };
        if message.get("is_visible").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(text) = message.get("content").and_then(Value::as_str) else {
            continue;
        };
        let order = message.get("order").and_then(Value::as_u64).unwrap_or(0);
        if latest
            .as_ref()
            .is_none_or(|(old_order, old_id, _)| (order, id) > (*old_order, *old_id))
        {
            latest = Some((order, id, text.to_owned()));
        }
    }
    latest.map(|(_, _, text)| text)
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
