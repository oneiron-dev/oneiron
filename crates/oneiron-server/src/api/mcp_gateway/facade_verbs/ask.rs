use super::*;

pub(crate) fn mcp_ask_result(args: McpAskToolArgs, actor: &McpResolvedActor) -> Value {
    json!({
        "content": [mcp_text_content("ask accepted")],
        "structuredContent": {
            "tool": McpToolName::Ask.as_str(),
            "status": "accepted",
            "query": args.query,
            "context_pack": args.context_pack,
            "effort": args.effort,
            "citation_mode": args.citation_mode,
            "actor": mcp_actor_result(actor),
        },
        "isError": false,
    })
}

pub(crate) fn mcp_routed_ask_result(args: McpRoutedAskToolArgs, actor: &McpResolvedActor) -> Value {
    json!({
        "content": [mcp_text_content("routed ask accepted")],
        "structuredContent": {
            "tool": McpToolName::RoutedAsk.as_str(),
            "status": "accepted",
            "query": args.query,
            "context_pack": args.context_pack,
            "route": args.route,
            "effort": args.effort,
            "citation_mode": args.citation_mode,
            "actor": mcp_actor_result(actor),
        },
        "isError": false,
    })
}
