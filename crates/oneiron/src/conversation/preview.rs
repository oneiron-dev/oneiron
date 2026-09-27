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
        match SelectedPathSnapshot::read(self, &txn, conversation)? {
            PreviewTopology::Selected(path) => {
                for turn in path.turns.iter().rev() {
                    if let Some(text) = self.visible_turn_text(&txn, turn)? {
                        return Ok(Some(snippet(&text)));
                    }
                }
                return Ok(None);
            }
            PreviewTopology::ChildOfOnly => {}
            PreviewTopology::ProvenEmpty => return Ok(None),
        }
        let mut latest: Option<(u64, EntityId, String)> = None;
        for edge in self.store.port_edges(
            &txn,
            conversation,
            EdgeDirection::In,
            Some(EdgeKind::ChildOf),
            None,
        )? {
            let id = edge?.target;
            // ChildOf-only rooms can have other entity kinds on the same edge.
            if self
                .store
                .port_entity_record(&txn, &id)?
                .is_none_or(|row| row.entity_type != ENTITY_TYPE_TURN)
            {
                continue;
            }
            let row = retained_row(&self.store, &txn, &id, ENTITY_TYPE_TURN)?;
            let RetainedRow::Live { learned_at, .. } = row else {
                continue;
            };
            let turn = RetainedTurn { id, row };
            if let Some(text) = self.visible_turn_text(&txn, &turn)?
                && latest
                    .as_ref()
                    .is_none_or(|(at, old_id, _)| (learned_at, id) > (*at, *old_id))
            {
                latest = Some((learned_at, id, text));
            }
        }
        Ok(latest.map(|(_, _, text)| snippet(&text)))
    }

    fn visible_turn_text(&self, txn: &RoTxn<'_>, turn: &RetainedTurn) -> Result<Option<String>> {
        let RetainedRow::Live { body, .. } = &turn.row else {
            return Ok(None);
        };
        if self.archive_tombstone_in_txn(txn, &turn.id)?.is_some() {
            return Ok(None);
        }
        let mut latest: Option<(u64, EntityId, String)> = None;
        for edge in self.store.port_edges(
            txn,
            &turn.id,
            EdgeDirection::In,
            Some(EdgeKind::PartOf),
            None,
        )? {
            let id = edge?.target;
            if self
                .store
                .port_entity_record(txn, &id)?
                .is_none_or(|row| row.entity_type != ENTITY_TYPE_MESSAGE)
            {
                continue;
            }
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
            let Some(message) = rmp_serde::from_slice::<Value>(&body).ok() else {
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
        if let Some((_, _, text)) = latest {
            return Ok(Some(text));
        }
        #[cfg(feature = "sync")]
        let resolved = crate::entity_doc::resolve_record_body(&self.store, txn, &turn.id, body)?;
        #[cfg(feature = "sync")]
        let body = resolved.as_slice();
        Ok(rmp_serde::from_slice::<Value>(body)
            .ok()
            .and_then(|body| body.get("txt").and_then(Value::as_str).map(str::to_owned)))
    }
}

fn snippet(source: &str) -> String {
    if source.chars().count() <= 50 {
        return source.to_owned();
    }
    source
        .chars()
        .take(49)
        .chain(std::iter::once('…'))
        .collect()
}
