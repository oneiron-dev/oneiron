//! Move native connector status and schema JSON through the core SDK codec.

use serde_json::Value;

use crate::code_run::ConnectorCallReply;
use crate::memory::MemoryResult;

use super::{ConnectorCallStatus, ConnectorSchemaReply, encode};

pub(super) fn schema(mut output: ConnectorSchemaReply) -> MemoryResult<Value> {
    let input_schema = output.input_schema.as_mut().map(Value::take);
    let mut encoded = encode(output)?;
    if let Some(input_schema) = input_schema {
        encoded["input_schema"] = input_schema;
    }
    Ok(encoded)
}

pub(super) fn status(mut output: ConnectorCallStatus) -> MemoryResult<Value> {
    let payload = match &mut output {
        ConnectorCallStatus::Settled { reply, .. }
        | ConnectorCallStatus::AwaitingInput { reply, .. } => take_reply(reply),
        ConnectorCallStatus::Pending { .. } => None,
    };
    let mut encoded = encode(output)?;
    if let Some(payload) = payload {
        restore_reply(&mut encoded["reply"], payload);
    }
    Ok(encoded)
}

enum ReplyPayload {
    Delivered {
        content: Value,
        structured_content: Option<Value>,
        rpc_error: Option<Value>,
    },
    Questions(Vec<Value>),
}

fn take_reply(reply: &mut ConnectorCallReply) -> Option<ReplyPayload> {
    match reply {
        ConnectorCallReply::Delivered {
            result: Some(result),
            ..
        } => Some(ReplyPayload::Delivered {
            content: result.content.take(),
            structured_content: result.structured_content.take(),
            rpc_error: result.rpc_error.take(),
        }),
        ConnectorCallReply::AwaitingInput { questions, .. } => Some(ReplyPayload::Questions(
            questions
                .iter_mut()
                .map(|question| question.requested_schema.take())
                .collect(),
        )),
        _ => None,
    }
}

fn restore_reply(encoded: &mut Value, payload: ReplyPayload) {
    match payload {
        ReplyPayload::Delivered {
            content,
            structured_content,
            rpc_error,
        } => {
            let result = &mut encoded["result"];
            result["content"] = content;
            if let Some(structured_content) = structured_content {
                result["structured_content"] = structured_content;
            }
            if let Some(rpc_error) = rpc_error {
                result["rpc_error"] = rpc_error;
            }
        }
        ReplyPayload::Questions(schemas) => {
            for (index, schema) in schemas.into_iter().enumerate() {
                encoded["questions"][index]["requested_schema"] = schema;
            }
        }
    }
}
