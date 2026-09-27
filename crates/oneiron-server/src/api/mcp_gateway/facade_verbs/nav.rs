use super::*;

pub(crate) fn execute_mcp_nav(
    server: &SyncServer,
    args: crate::mcp::McpNavToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    let limit = args.limit.unwrap_or(10).min(CORE_MAX_LIST_LIMIT as u32) as usize;
    match args.mode {
        crate::mcp::McpNavMode::Search => {
            let query = args.query.as_deref().ok_or_else(|| {
                McpGatewayError::new(
                    -32602,
                    "tool_args_invalid",
                    "oneiron.nav query is required for search mode",
                )
                .with_field("query")
            })?;
            let results = scoped_read
                .search_text(query, limit, None)
                .map_err(|error| mcp_engine_error("mcp nav search failed", error))?;
            let (items, narrowing) = project_nav_results(&scoped_read, results)?;
            Ok(json!({
                "content": [mcp_text_content(format!("{} result(s)", items.len()))],
                "structuredContent": {
                    "tool": McpToolName::Nav.as_str(),
                    "mode": "search",
                    "narrowing": narrowing,
                    "items": items,
                },
                "isError": false,
            }))
        }
        _ => Ok(json!({
            "content": [mcp_text_content("navigation mode accepted")],
            "structuredContent": {
                "tool": McpToolName::Nav.as_str(),
                "mode": format!("{:?}", args.mode).to_ascii_lowercase(),
                "status": "accepted",
            },
            "isError": false,
        })),
    }
}

pub(super) fn project_nav_results(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    results: oneiron::claim::ScopedReadResult<Vec<oneiron::ScoredEntity>>,
) -> Result<(Vec<Value>, oneiron::claim::ScopedReadReceipt), McpGatewayError> {
    let mut narrowing = results.receipt;
    let projected = scoped_read
        .get_entities_parts_with_modes_with_receipt(
            &results
                .value
                .iter()
                .map(|row| (row.id, oneiron::memory::ReadMode::Indexed))
                .collect::<Vec<_>>(),
            Some(&narrowing.applied.as_filter()),
        )
        .map_err(|error| mcp_engine_error("mcp nav projection failed", error))?;
    narrowing.restrict_with(&projected.receipt);
    let items = results
        .value
        .into_iter()
        .zip(projected.value)
        .filter_map(|(row, parts)| {
            let (kind, learned_at, body) = parts?;
            Some(projection::project_entity_parts(
                &row.id,
                kind,
                learned_at,
                &body,
                View::Summary,
            ))
        })
        .collect::<Vec<_>>();
    Ok((items, narrowing))
}
