//! The identity of a journal MESSAGE's result, without its content or preview.

use super::{MessageResultAttachment, MessageResultSource, ResultFacet, handle_digest};
use crate::store::result_manifest::ResultOccurrence;
use oneiron_base::message_body_fields::map_value;

impl MessageResultAttachment {
    /// Selects only visibility and the result's identity fields. Other values
    /// are stepped over as MessagePack bytes, never decoded or cloned.
    /// This is a reference, not a validated preview or a body-read admission.
    pub(crate) fn reference_from_message(body: &[u8]) -> Option<(MessageResultSource, String)> {
        if map_value(body, b"is_visible")? != [0xc3] {
            return None;
        }
        let metadata = map_value(body, b"metadata")?;
        let result = map_value(metadata, b"result")?;
        let source: MessageResultSource =
            rmp_serde::from_slice(map_value(result, b"source")?).ok()?;
        let handle: String = rmp_serde::from_slice(map_value(result, b"handle")?).ok()?;
        let kind: String = rmp_serde::from_slice(map_value(result, b"kind")?).ok()?;
        let more: Vec<ResultFacet> = rmp_serde::from_slice(map_value(result, b"more")?).ok()?;
        if handle_digest(&handle).is_none()
            || !matches!(kind.as_str(), "text" | "binary")
            || more != ResultFacet::ALL
            || ResultOccurrence::owned(source.run_id, &source.path)
                .ok()?
                .id()
                != source.occurrence
        {
            return None;
        }
        Some((source, handle))
    }
}
