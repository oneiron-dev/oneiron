//! `vault.questions.answers` on MCP (FIX 9175): its untagged reply counted as
//! the rows it holds. Without a cursor the reply is every answer as one bare
//! list, which the page window splits and continues from its retained copy.
//! With one it is a page: its `answers` are the rows, and its `next_cursor`
//! goes back inside the call's own `spec`, `id` and `page_size` as sent.

use serde_json::Value;

use super::McpGatewayError;
use crate::mcp::McpPageSource;
use oneiron::receipt::QuestionAnswersReply;

/// The MCP value and page source of one `vault.questions.answers` reply.
pub(super) fn mcp_question_answers_result(
    reply: QuestionAnswersReply,
) -> Result<(Value, McpPageSource), McpGatewayError> {
    let source = match &reply {
        QuestionAnswersReply::All(answers) => McpPageSource::complete(answers.len()),
        QuestionAnswersReply::Page(page) => McpPageSource::scoped_window(
            page.answers.len(),
            0,
            usize::from(page.next_cursor.is_some()),
            true,
        )
        .rows_at("answers")
        .resumed_within("next_cursor", "spec", "cursor"),
    };
    let value = serde_json::to_value(reply).map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            "typed agent result cannot be encoded",
        )
    })?;
    Ok((value, source))
}
