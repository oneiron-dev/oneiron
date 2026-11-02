//! The DAG append doors' wire conversions (FIX 9771): a request becomes
//! the engine's append of a TURN or of a MESSAGE of a TURN, and an append's
//! receipt becomes its 200 body, which names the stored record's own type.

use super::super::{
    CoreEntityWriteResponse, core_body_for_write, core_entity_timestamps, core_text_fields,
    core_write_text, encode_core_body, parse_entity_id_param, project_core_entity,
};
use super::types::parse_optional;
use super::{DagAddressMode, DagAppendRequest, DagAppendResponse};
use crate::auth::CoreAuth;
use crate::error::{ApiError, EnvelopedApiError};
use crate::projection::View;
use crate::server::SyncServer;
use axum::Json;
use oneiron::EntityId;
use oneiron::conversation_dag::{AddressMode, AppendRecord, QuoteSpan};
use oneiron::core_write::{
    CoreDagAddressMode, CoreDagQuoteInput, DagRecordAppendInput, DagRecordAppendReceipt,
};
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

pub(super) fn appended_response(
    server: &SyncServer,
    appended: oneiron::conversation_dag::AppendedRecord,
) -> Result<Json<DagAppendResponse>, EnvelopedApiError> {
    server.ai.turn_landed(
        server.vault(),
        oneiron::dreamer_wake::WakeTurnSubject::Vault,
    );
    project_appended(server, appended.into())
}

/// An append's 200 body: the stored record, a TURN or a MESSAGE as the
/// receipt names its type, HEAD after it, its parent, the TURN a MESSAGE is
/// part of and what it answers (FIX 9771). It lands nothing; the write that
/// made the record did.
pub(super) fn project_appended(
    server: &SyncServer,
    receipt: DagRecordAppendReceipt,
) -> Result<Json<DagAppendResponse>, EnvelopedApiError> {
    let id = parse_entity_id_param(&receipt.id, "id")?;
    let Json(item) = project_core_entity(&server.vault, &id, View::Full)?;
    Ok(Json(DagAppendResponse {
        entity: CoreEntityWriteResponse {
            id: receipt.id,
            entity_type: receipt.entity_type,
            item,
        },
        head: receipt.head,
        parent: receipt.parent,
        containing_turn: receipt.containing_turn,
        reply_target: receipt.reply_target,
    }))
}

pub(super) fn append_input(
    server: &SyncServer,
    conversation: EntityId,
    req: DagAppendRequest,
    auth: &CoreAuth,
) -> Result<AppendRecord, EnvelopedApiError> {
    let times = core_entity_timestamps(req.occurred_start, req.occurred_end, req.learned_at)?;
    let containing_turn = parse_optional(req.containing_turn.as_deref(), "containing_turn")?;
    let kind = if containing_turn.is_some() {
        ENTITY_TYPE_MESSAGE
    } else {
        ENTITY_TYPE_TURN
    };
    let body = core_body_for_write(
        kind,
        &req.body,
        super::super::announcement_authority(server, auth),
    );
    Ok(AppendRecord {
        conversation,
        reply_to: parse_optional(req.reply_to.as_deref(), "reply_to")?,
        quote: req
            .quote
            .as_ref()
            .map(|quote| {
                Ok::<_, ApiError>(QuoteSpan {
                    message: parse_entity_id_param(&quote.message, "quote.message")?,
                    start: quote.start,
                    end: quote.end,
                })
            })
            .transpose()?,
        address: match req.addr.unwrap_or(DagAddressMode::Broadcast) {
            DagAddressMode::Broadcast => AddressMode::Broadcast,
            DagAddressMode::Direct => AddressMode::Direct,
        },
        recipients: req
            .to
            .unwrap_or_default()
            .iter()
            .map(|id| parse_entity_id_param(id, "to"))
            .collect::<Result<Vec<_>, _>>()?,
        parent: parse_optional(req.parent.as_deref(), "parent")?,
        advance: req.advance,
        kind,
        containing_turn,
        occurred: times.occurred,
        learned_at: times.learned_at,
        body: encode_core_body(&body)?,
        text: core_text_fields(req.text.as_deref(), &body),
        session: parse_optional(req.session.as_deref(), "session")?,
        actor: req.actor.parse(server, auth)?,
        thread_audience: req
            .thread_audience
            .map(|ids| {
                ids.iter()
                    .map(|id| parse_entity_id_param(id, "thread_audience"))
                    .collect::<Result<std::collections::BTreeSet<_>, _>>()
            })
            .transpose()?,
    })
}

/// The append row's input: the request less its actor, which the route
/// asserts and the writer bylines.
pub(super) fn append_row(conversation: EntityId, req: DagAppendRequest) -> DagRecordAppendInput {
    DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: req.parent,
        reply_to: req.reply_to,
        containing_turn: req.containing_turn,
        addr: req.addr.map(|addr| match addr {
            DagAddressMode::Broadcast => CoreDagAddressMode::Broadcast,
            DagAddressMode::Direct => CoreDagAddressMode::Direct,
        }),
        to: req.to,
        advance: req.advance,
        body: req.body,
        text: core_write_text(req.text),
        occurred_start: req.occurred_start,
        occurred_end: req.occurred_end,
        learned_at: req.learned_at,
        session: req.session,
        quote: req.quote.map(|quote| CoreDagQuoteInput {
            message: quote.message,
            start: quote.start,
            end: quote.end,
        }),
        thread_audience: req.thread_audience,
    }
}
