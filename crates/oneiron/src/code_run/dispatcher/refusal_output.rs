//! Released reason bodies captured from the actual accepted refusal call.

use std::collections::HashMap;

use super::HostSelfDispatcher;
use crate::Vault;
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadActorKey};
use crate::context_pack::{ContextEntity, FieldProfile};
use crate::error::Result;
use crate::task_verb::ConsultPayloadRef;

impl HostSelfDispatcher<'_> {
    pub(super) fn capture_task_refusal_output(
        &self,
        vault: &Vault,
        reader: Option<ScopedReadActorKey>,
        reason: ConsultPayloadRef,
    ) {
        let Some(reader) = reader else {
            return;
        };
        match released_reason_body(vault, reader, reason) {
            Ok(bytes) => *self.task_refusal_output.borrow_mut() = bytes,
            Err(error) => {
                tracing::warn!(error = %error, "accepted task refusal reason is unavailable");
            }
        }
    }

    pub(crate) fn take_task_refusal_output(&self) -> Option<Vec<u8>> {
        self.task_refusal_output.borrow_mut().take()
    }
}

fn released_reason_body(
    vault: &Vault,
    reader: ScopedReadActorKey,
    reason: ConsultPayloadRef,
) -> Result<Option<Vec<u8>>> {
    let lane = vault
        .scoped_read(reader)
        .with_claim_status(ClaimReadStatus::Recorded);
    let read = lane.read_projected(
        &[PointRead::id(reason.entity_ref())],
        None,
        |txn, rows| -> Result<Option<Vec<u8>>> {
            let Some(row) = rows.into_iter().next().flatten() else {
                return Ok(None);
            };
            if row.entity_type != reason.entity_type() {
                return Ok(None);
            }
            let Some(body) = row.body.as_deref() else {
                return Ok(None);
            };
            let fields = match reason {
                ConsultPayloadRef::Claim(_) => {
                    let Some(fields) = crate::context_pack::released_claim_fields(body) else {
                        return Ok(None);
                    };
                    fields
                }
                ConsultPayloadRef::Turn(turn) => {
                    let Some(served) = crate::vault::entity_revision::served_turn_text_in_txn(
                        vault,
                        &vault.store,
                        txn,
                        &turn,
                        crate::vault::ReadMode::Live,
                        true,
                    )?
                    else {
                        return Ok(None);
                    };
                    let messages =
                        served.released(|message| lane.is_entity_readable_in(txn, message))?;
                    let Some(text) = crate::embed::joined_turn_text(&messages) else {
                        return Ok(None);
                    };
                    HashMap::from([("txt".to_owned(), serde_json::Value::String(text))])
                }
            };
            let entity = ContextEntity {
                id: row.id,
                short_id: String::new(),
                content_hash: row.content_hash,
                source_revision_ref: None,
                entity_type: row.entity_type,
                score: 0.0,
                critical: false,
                fields: Some(fields),
                edges: None,
                vector: None,
            };
            let Some(projected) = crate::serialize::project_entity_json_row(
                &entity,
                &reason.short_ref(),
                FieldProfile::Full,
            ) else {
                return Ok(None);
            };
            serde_json::to_vec(&projected)
                .map(Some)
                .map_err(|error| crate::Error::InvalidConfig(error.to_string()))
        },
    )?;
    Ok(read.value)
}
