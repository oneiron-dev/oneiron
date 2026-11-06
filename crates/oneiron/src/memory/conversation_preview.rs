//! Conversation preview candidates and deterministic MESSAGE text selection.

use crate::EntityId;
use serde_json::Value;

/// The turns a reader's preview may look at, before the lane admits any.
pub(crate) enum PreviewCandidates {
    /// The checked selected path from its HEAD back, the order preferred.
    Path(Vec<EntityId>),
    /// With no selected HEAD, the live ChildOf turns in index order.
    ChildOf(Vec<EntityId>),
    /// The selected path is unresolved: no preview.
    Unresolved,
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
