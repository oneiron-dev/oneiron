//! MESSAGE doors adapt typed calls to the existing witness and stream programs.
use super::*;
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadResult};
use crate::memory::{MemoryError, MemoryResult, WitnessMessage, WitnessReceipt, WitnessTurn};

impl MessageBirth {
    fn turn(
        &self,
        message: &str,
        content: String,
        register: Option<&str>,
    ) -> MemoryResult<WitnessTurn> {
        let mut metadata = self.metadata.clone();
        if let Some(register) = register {
            let fields = metadata
                .get_or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .ok_or_else(|| {
                    MemoryError::bad_request("a message register needs object metadata")
                })?;
            fields.insert("register".to_owned(), register.into());
        }
        Ok(WitnessTurn {
            conversation_ref: self.conversation_ref.clone(),
            turn_ref: self.turn_ref.clone(),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_owned()),
                author: self.author,
                message_type: self.message_type.clone(),
                content,
                metadata,
                is_visible: self.is_visible,
                order: self.order,
                quote: self.quote.clone(),
            }],
            occurred_at: self.occurred_at,
            assertions: self.assertions.clone(),
        })
    }
}

impl Memory<'_> {
    /// Atomic whole-message birth through the witness ceiling, not a text edit.
    pub fn messages_commit(&self, input: &CommitMessageRequest) -> MemoryResult<WitnessReceipt> {
        EntityId::from_hex(&input.message_id)?;
        let turn = input.birth.turn(
            &input.message_id,
            input.content.clone(),
            input.options.register.as_deref(),
        )?;
        crate::memory::caps::check_witness_turn(&turn)?;
        self.commit_message(&turn)
    }

    /// New streams carry birth axes; continuations take all axes from their MESSAGE.
    pub fn messages_begin_stream(
        &self,
        input: &BeginMessageStreamRequest,
    ) -> MemoryResult<MessageStreamHandle> {
        let message = EntityId::from_hex(&input.message_id)?;
        let mode = input.options.mode.map(Into::into);
        match &input.birth {
            Some(birth) => {
                // The engine checks supplied axes against an existing MESSAGE in its writer.
                let turn = birth.turn(
                    &input.message_id,
                    String::new(),
                    input.options.register.as_deref(),
                )?;
                self.begin_message_stream(&turn, mode).map_err(stream_error)
            }
            None => {
                if input.options.register.is_some() {
                    return Err(MemoryError::bad_request(
                        "a continuation keeps its MESSAGE's birth register",
                    ));
                }
                self.begin_message_continuation(&message, mode)
                    .map_err(stream_error)
            }
        }
    }

    pub fn messages_append_stream(&self, input: &AppendToStreamRequest) -> MemoryResult<()> {
        self.append_to_stream(input.handle, &input.delta)
            .map_err(stream_error)
    }

    pub fn messages_flush_stream(&self, input: &MessageStreamRequest) -> MemoryResult<()> {
        self.flush_stream(input.handle).map_err(stream_error)
    }

    pub fn messages_finalize_stream(
        &self,
        input: &MessageStreamRequest,
    ) -> MemoryResult<MessageStreamReceipt> {
        self.finalize_stream(input.handle).map_err(stream_error)
    }

    pub fn messages_cancel_stream(
        &self,
        input: &CancelStreamRequest,
    ) -> MemoryResult<MessageStreamReceipt> {
        self.cancel_stream(input.handle, input.reason.clone().into())
            .map_err(stream_error)
    }

    pub fn messages_stream_partial(
        &self,
        input: &MessageStreamRequest,
    ) -> MemoryResult<MessageStreamPartial> {
        self.message_stream_partial(input.handle)
            .map_err(stream_error)
    }

    /// Reads history and completion in the same snapshot that admits the MESSAGE.
    pub fn messages_durability(
        &self,
        input: &MessageDurabilityRequest,
    ) -> MemoryResult<ScopedReadResult<Option<MessageDurability>>> {
        let message = EntityId::from_hex(&input.message_id)?;
        let after = input
            .after_generation
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        let limit = crate::memory::caps::clamp_search_limit(input.limit.unwrap_or(100))
            .0
            .max(1);
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let result = lane.read_projected(&[PointRead::id(message)], None, |txn, rows| {
            let Some(row) = rows
                .into_iter()
                .next()
                .flatten()
                .filter(|row| row.body.is_some())
            else {
                return Ok::<_, MemoryError>(None);
            };
            if row.entity_type != crate::registry::ENTITY_TYPE_MESSAGE {
                return Ok(None);
            }
            let (receipts, next_after_generation) =
                storage::receipt_history(self.vault, txn, message, after, limit)?;
            #[cfg(feature = "sync")]
            let (document_exists, document_history) = {
                let raw = self
                    .vault
                    .get_raw_in(txn, &message)?
                    .ok_or(crate::Error::EntityNotFound)?;
                let body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
                let states = crate::entity_doc::record_body_history_in_txn(
                    &self.vault.store,
                    txn,
                    &message,
                    body,
                    limit,
                )?;
                let exists = states.is_some();
                let history = states
                    .unwrap_or_default()
                    .into_iter()
                    .map(|state| {
                        let body: serde_json::Value =
                            rmp_serde::from_slice(&state.body).map_err(|_| {
                                crate::Error::CorruptedIndex("message document history")
                            })?;
                        let content = body
                            .get("content")
                            .and_then(serde_json::Value::as_str)
                            .ok_or(crate::Error::CorruptedIndex("message history content"))?
                            .to_owned();
                        Ok::<_, MemoryError>(MessageDocumentState {
                            frontier: state.frontier,
                            content,
                        })
                    })
                    .collect::<MemoryResult<Vec<_>>>()?;
                (exists, history)
            };
            #[cfg(not(feature = "sync"))]
            let (document_exists, document_history) = (false, Vec::new());
            Ok(Some(MessageDurability {
                message_id: message.to_hex(),
                completion: message_completion_in_txn(self.vault, txn, &message)?,
                latest_receipt: storage::receipt(self.vault, txn, message)?,
                receipts,
                next_after_generation,
                document_exists,
                document_history,
            }))
        })?;
        if result.value.is_some() {
            self.produced_from([message]);
        }
        Ok(result)
    }
}

fn stream_error(error: MessageStreamError) -> MemoryError {
    use crate::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND};
    match error {
        MessageStreamError::Memory(error) => *error,
        MessageStreamError::Engine(error) => error.into(),
        MessageStreamError::WrongActor => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            error.to_string(),
            &["Use a stream opened by this credential's own actor."],
        ),
        MessageStreamError::StreamNotFound => MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            error.to_string(),
            &["Open a new stream and use its returned handle."],
        ),
        MessageStreamError::StreamAlreadyActive(_) => MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            error.to_string(),
            &["Finish the active stream before opening another."],
        ),
        MessageStreamError::InvalidRequest(_)
        | MessageStreamError::BufferOverflow
        | MessageStreamError::PresenceFrameTooLarge => MemoryError::bad_request(error.to_string()),
        _ => MemoryError::new(crate::memory::MEMORY_CODE_INTERNAL, error.to_string(), &[]),
    }
}
