use super::*;

/// Dispatches `oneiron.calendar`.
///
/// Every arm goes through [`oneiron::Memory`] — the calendar dialect owns
/// no vault access of its own, so the actor binding, the scoped-read lane, and
/// the outbound gate are all the engine's, not a second server-side copy. The
/// invite arm in particular reaches the connector only via `schedule_outbound`;
/// there is no direct execution path in this file.
pub(crate) fn execute_mcp_calendar(
    server: &SyncServer,
    args: crate::mcp::McpCalendarToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let op = args.operation.op();
    let facade = server.vault.memory(actor.actor_ref, actor.actor_class);

    let mut structured = match args.operation {
        crate::mcp::McpCalendarOperation::Read { event_ref } => {
            let item = facade
                .calendar_read(&oneiron::CalendarReadRequest { event_ref })
                .map_err(mcp_facade_error)?;
            json!({ "found": item.is_some(), "item": item })
        }
        crate::mcp::McpCalendarOperation::Search {
            calendars,
            range,
            text,
            limit,
        } => {
            let items = facade
                .calendar_search(&oneiron::CalendarSearchRequest {
                    calendars: calendar_selectors(calendars),
                    range: range.map(|range| oneiron::CalendarRangeDto {
                        start: range.start,
                        end: range.end,
                    }),
                    text,
                    limit: limit.unwrap_or(CORE_MAX_LIST_LIMIT as u32),
                })
                .map_err(mcp_facade_error)?;
            json!({ "count": items.len(), "items": items })
        }
        crate::mcp::McpCalendarOperation::Freebusy { calendars, range } => {
            let intervals = facade
                .calendar_freebusy(
                    &calendar_selectors(calendars),
                    oneiron::TimeRange {
                        start: range.start,
                        end: range.end,
                    },
                )
                .map_err(mcp_facade_error)?;
            json!({ "count": intervals.len(), "intervals": intervals })
        }
        crate::mcp::McpCalendarOperation::Invite {
            method,
            uid,
            sequence,
            ics_blob_ref,
            recipient,
        } => {
            let receipt = facade
                .calendar_invite(&oneiron::CalendarInviteSurfaceInput {
                    method,
                    uid,
                    sequence,
                    ics_blob_ref,
                    recipient,
                })
                .map_err(mcp_facade_error)?;
            json!({ "receipt": receipt })
        }
    };

    if let Some(object) = structured.as_object_mut() {
        object.insert(
            "tool".to_owned(),
            Value::String(McpToolName::Calendar.as_str().to_owned()),
        );
        object.insert("op".to_owned(), Value::String(op.to_owned()));
        object.insert("actor".to_owned(), mcp_actor_result(actor));
    }
    Ok(json!({
        "content": [mcp_text_content(format!("calendar {op} completed"))],
        "structuredContent": structured,
        "isError": false,
    }))
}

fn calendar_selectors(
    selectors: Vec<crate::mcp::McpCalendarSelector>,
) -> Vec<oneiron::CalendarSel> {
    selectors
        .into_iter()
        .map(|selector| oneiron::CalendarSel {
            system: selector.system,
        })
        .collect()
}
