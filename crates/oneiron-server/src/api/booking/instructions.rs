use oneiron::EntityId;
use oneiron::booking::EventTypeKey;
use oneiron::booking::agent_api::{
    BOOKING_AGENT_INSTRUCTIONS_MIME, BOOKING_AGENT_INSTRUCTIONS_VERSION, BookingAgentEndpoint,
    BookingAgentInstructionsBlock, BookingAgentOperation,
};
use oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION;

use super::constants::BOOKING_ROUTE_PREFIX;
use super::page_token::page_event_type_configs;
use crate::error::ApiError;
use crate::server::SyncServer;

// -------------------------------------------------------------------------
// Instructions document + embeddable fragment
// -------------------------------------------------------------------------

/// Builds the canonical instructions block for one resolved page.
///
/// Operations are emitted in [`BookingAgentOperation::CANONICAL`] order and
/// every path is relative and same-origin, so two nodes serving the same page
/// produce the same bytes.
pub(crate) fn booking_agent_instructions_block(
    server: &SyncServer,
    page_token: &str,
    page_ref: EntityId,
) -> Result<BookingAgentInstructionsBlock, ApiError> {
    // Configuration claims have no inherent order, so the block imposes one:
    // the same page must produce the same bytes on every node.
    let mut keys: Vec<String> = page_event_type_configs(&server.vault, page_ref)?
        .into_iter()
        .map(|config| config.key.0)
        .collect();
    keys.sort_unstable();
    keys.dedup();
    let event_types: Vec<EventTypeKey> = keys.into_iter().map(EventTypeKey).collect();

    // Every operation is a POST: each one carries a typed body, and none of
    // them is safe to cache or replay from a URL alone.
    let operations = BookingAgentOperation::CANONICAL
        .into_iter()
        .map(|operation| BookingAgentEndpoint {
            operation,
            method: "POST".to_owned(),
            path: format!("{BOOKING_ROUTE_PREFIX}/{page_token}/{}", operation.as_str()),
        })
        .collect();

    let block = BookingAgentInstructionsBlock {
        version: BOOKING_AGENT_INSTRUCTIONS_VERSION,
        page_token: page_token.to_owned(),
        event_types,
        operations,
        constraint_schema_version: CONSTRAINT_SCHEMA_VERSION,
    };
    block.validate().map_err(|defect| {
        tracing::error!(
            defect = defect.as_str(),
            "booking agent instructions defect"
        );
        ApiError::internal_server_error("booking agent instructions block is not canonical")
    })?;
    Ok(block)
}

/// The canonical JSON bytes of one instructions block.
///
/// This is the single serializer: the HTTP document and the embedded fragment
/// both come from here, so byte-equivalence is a property of the code rather
/// than of two implementations agreeing.
pub(crate) fn booking_agent_instructions_json(
    block: &BookingAgentInstructionsBlock,
) -> Result<String, ApiError> {
    serde_json::to_string(block)
        .map_err(|_| ApiError::internal_server_error("booking agent instructions do not serialize"))
}

/// Renders the embeddable, script-safe `<script type=...>` fragment.
///
/// ONE-1815 inserts this into its rendered page verbatim. It may style around
/// the fragment; it cannot mutate the versioned JSON contract inside it.
///
/// Script safety is structural. The JSON is escaped so that no `<`, `>`, or
/// `&` survives into the document, which makes `</script>` unrepresentable
/// inside the block, and U+2028/U+2029 are escaped so the block stays a single
/// JavaScript source line. Every escape is a legal JSON string escape, so the
/// decoded value is byte-identical to
/// [`booking_agent_instructions_json`] after re-serialization.
pub(crate) fn render_booking_agent_instructions_block(
    block: &BookingAgentInstructionsBlock,
) -> Result<String, ApiError> {
    let json = booking_agent_instructions_json(block)?;
    Ok(format!(
        "<script type=\"{BOOKING_AGENT_INSTRUCTIONS_MIME}\">{}</script>",
        script_safe_json(&json)
    ))
}

/// Escapes the four characters that could terminate or reshape the block.
fn script_safe_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for character in json.chars() {
        match character {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}
