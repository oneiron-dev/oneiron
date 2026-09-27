use super::*;

pub(crate) fn execute_mcp_read(
    server: &SyncServer,
    args: crate::mcp::McpReadToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    if let Some(entity_ref) = args.target.entity_ref.as_deref() {
        let id = parse_entity_id_param(entity_ref, "target.entity_ref").map_err(mcp_api_error)?;
        let read = scoped_read
            .get_entity_parts_with_receipt(&id, None)
            .map_err(|error| mcp_engine_error("mcp read failed", error))?;
        let item = read.value.map(|(entity_type, learned_at, body)| {
            projection::project_entity_parts(&id, entity_type, learned_at, &body, View::Full)
        });
        return Ok(json!({
            "content": [mcp_text_content(if item.is_some() { "entity found" } else { "entity not found" })],
            "structuredContent": {
                "tool": McpToolName::Read.as_str(),
                "target": { "entity_ref": entity_ref },
                "narrowing": read.receipt,
                "found": item.is_some(),
                "item": item,
            },
            "isError": false,
        }));
    }
    if let Some(short_ref) = args.target.short_ref.as_deref() {
        let (short_id, content_hash, mode) =
            parse_revision_short_ref(short_ref).map_err(mcp_api_error)?;
        let read = hydrate_short_id_response_with_mode(
            &scoped_read,
            short_id,
            content_hash,
            View::Full,
            mode,
            None,
        )
        .map_err(mcp_api_error)?;
        let item = read.value;
        return Ok(json!({
            "content": [mcp_text_content(if item.is_some() { "short ref found" } else { "short ref not found" })],
            "structuredContent": {
                "tool": McpToolName::Read.as_str(),
                "target": { "short_ref": short_ref },
                "narrowing": read.receipt,
                "found": item.is_some(),
                "item": item,
            },
            "isError": false,
        }));
    }
    Ok(json!({
        "content": [mcp_text_content("context pack reference accepted")],
        "structuredContent": {
            "tool": McpToolName::Read.as_str(),
            "target": { "context_pack": args.target.context_pack },
        },
        "isError": false,
    }))
}
