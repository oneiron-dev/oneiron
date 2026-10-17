//! Begin, append and flush. The only pre-final durable row is the seed, which
//! checkpoints each accepted delta before that text is published.
use super::super::witness_message_envelope;
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::error::Error;
use crate::gate::{check_witness_message_ceiling, resolve_policy_manifest};
use crate::memory::support::verify_actor_binding_in_txn;
use crate::memory::{MemoryResult, WitnessReceipt, WitnessTurn, resolve_entity_ref};
use crate::write_envelope::WriteActor;

impl Memory<'_> {
    /// Whole-message atomic path: the existing witness ceiling, canonical bytes,
    /// topology, indexes and write receipt, with no stream state.
    pub fn commit_message(&self, turn: &WitnessTurn) -> MemoryResult<WitnessReceipt> {
        if turn.messages.len() != 1 {
            return Err(crate::memory::MemoryError::bad_request(
                "commit_message needs one message",
            ));
        }
        self.witness(turn)
    }
    /// Starts one message. Supplied initial content stays only in memory. Existing
    /// MESSAGEs require empty initial content and retain their immutable axes.
    /// A new TURN needs a non-system speaker, as on the atomic witness door.
    pub fn begin_message_stream(
        &self,
        turn: &WitnessTurn,
        mode: Option<MessageWriteMode>,
    ) -> MessageStreamResult<MessageStreamHandle> {
        self.begin_message_stream_at(turn, mode, now_ms())
    }
    pub(super) fn begin_message_stream_at(
        &self,
        turn: &WitnessTurn,
        mode: Option<MessageWriteMode>,
        at: u64,
    ) -> MessageStreamResult<MessageStreamHandle> {
        if turn.messages.len() != 1 {
            return Err(MessageStreamError::InvalidRequest("one message required"));
        }
        let message = &turn.messages[0];
        if message.content.len() > MAX_MESSAGE_STREAM_BYTES {
            return Err(MessageStreamError::BufferOverflow);
        }
        let id = message
            .id
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?
            .unwrap_or_else(EntityId::now);
        let conversation = resolve_entity_ref(self.vault, &turn.conversation_ref)?;
        let turn_id = turn
            .turn_ref
            .as_deref()
            .map(|r| resolve_entity_ref(self.vault, r))
            .transpose()?
            .unwrap_or_else(EntityId::now);
        if id == conversation || id == turn_id || conversation == turn_id {
            return Err(MessageStreamError::InvalidRequest(
                "message, turn and conversation IDs must differ",
            ));
        }
        let policy = self.vault.message_stream_policy()?;
        let mode = policy.resolve(&self.actor, mode);
        mode.validate()?;
        let seed = Seed {
            message_id: id,
            generation: EntityId::now(),
            actor: self.actor,
            actor_class: self.actor_class as u8,
            conversation,
            turn: turn_id,
            author: message.author,
            message_type: message.message_type.clone(),
            metadata: message.metadata.clone(),
            is_visible: message.is_visible,
            order: message.order,
            occurred_at: turn.occurred_at,
            created_at_ms: at,
            mode,
            idle_timeout_ms: policy.idle_timeout_ms,
            continuation: false,
            saved: String::new(),
        };
        let handle = MessageStreamHandle {
            message: id,
            generation: seed.generation,
        };
        // Past the vault's row the stream waits its turn here, holding no
        // transaction, lock or lease (rule 5): never refused for the count.
        let turn = self
            .vault
            .message_streams
            .line
            .enter(self.vault, self.actor.as_bytes())?;
        let entry = Arc::new(Mutex::new(State {
            seed,
            base: String::new(),
            pending: message.content.clone(),
            // The idle clock starts once the stream holds its turn: time
            // spent waiting for it is not the stream's idleness.
            last_op_at_ms: at
                .saturating_add(u64::try_from(turn.waited().as_millis()).unwrap_or(u64::MAX)),
            sequence: 0,
            emitted_chars: 0,
            dirty: true,
            terminal: false,
            _turn: Some(turn),
        }));
        // Take the new entry before exposing it to the sweep. No registry lock
        // is held while waiting for an entry or for the LMDB writer.
        let mut state = lock(&entry)?;
        {
            let mut entries = lock(&self.vault.message_streams.entries)?;
            if entries.contains_key(&id) {
                return Err(MessageStreamError::StreamAlreadyActive(id));
            }
            entries.insert(id, Arc::clone(&entry));
        }
        let admitted: MessageStreamResult<()> =
            self.vault
                .try_with_write_txn_grouped(|txn| -> MessageStreamResult<()> {
                    if storage::ACTIVE.contains(&self.vault.store, txn, &id)? {
                        return Err(MessageStreamError::StreamAlreadyActive(id));
                    }
                    state.base = committed_text(self.vault, txn, &state.seed)?.unwrap_or_default();
                    state.emitted_chars = state.base.chars().count();
                    state.seed.continuation = crate::ports::EntityStoreRead::port_entity_present(
                        &self.vault.store,
                        txn,
                        &id,
                    )?;
                    if state.seed.continuation && !state.pending.is_empty() {
                        return Err(MessageStreamError::InvalidRequest(
                            "continuation starts with empty content",
                        ));
                    }
                    if state.base.len() > MAX_MESSAGE_STREAM_BYTES {
                        return Err(MessageStreamError::BufferOverflow);
                    }
                    #[cfg(not(feature = "sync"))]
                    if state.seed.continuation {
                        return Err(MessageStreamError::InvalidRequest(
                            "continuation requires entity documents (sync feature)",
                        ));
                    }
                    authorize(self.vault, txn, &state.seed, &state.text())?;
                    // Container constraints are checked again by the canonical writer.
                    super::super::validation::validate_existing_witness_turn(
                        &self.vault.store,
                        txn,
                        &state.seed.turn,
                        &state.seed.conversation,
                        super::super::codec::incoming_turn_speaker(&[state
                            .seed
                            .message(String::new())])?,
                        super::super::person_author_in_txn(self.vault, txn, state.seed.actor)?,
                    )?;
                    if state.seed.author == crate::memory::WitnessAuthor::System
                        && !crate::ports::EntityStoreRead::port_entity_present(
                            &self.vault.store,
                            txn,
                            &state.seed.turn,
                        )?
                    {
                        return Err(MessageStreamError::InvalidRequest(
                            "system stream requires an existing turn",
                        ));
                    }
                    // Supplied initial content is the first checkpoint.
                    storage::ACTIVE.put(
                        &self.vault.store,
                        txn,
                        &id,
                        &state.checkpoint(state.pending.clone()),
                    )?;
                    Ok(())
                });
        if let Err(error) = admitted {
            state.terminal = true;
            self.vault.message_streams.remove(handle)?;
            return Err(error);
        }
        Ok(handle)
    }
    /// Accepts a delta only if every bound and any scheduled publication pass.
    /// A delta that adds text is checkpointed into the stream's seed, in one
    /// write transaction, before it is accepted or published: no partial is
    /// ever seen that a crash would not recover. An empty keepalive writes
    /// nothing. No token, heartbeat, text-index update, CRDT op or offline
    /// queue row is written.
    pub fn append_to_stream(
        &self,
        handle: MessageStreamHandle,
        delta: &str,
    ) -> MessageStreamResult<()> {
        self.append_to_stream_at(handle, delta, now_ms())
    }
    pub(super) fn append_to_stream_at(
        &self,
        handle: MessageStreamHandle,
        delta: &str,
        at: u64,
    ) -> MessageStreamResult<()> {
        let entry = self.stream_entry(handle)?;
        let mut state = lock(&entry)?;
        state.check(handle)?;
        if state
            .base
            .len()
            .saturating_add(state.pending.len())
            .saturating_add(delta.len())
            > MAX_MESSAGE_STREAM_BYTES
        {
            return Err(MessageStreamError::BufferOverflow);
        }
        let text = format!("{}{}", state.text(), delta);
        let chars = text.chars().count();
        let next = state
            .sequence
            .checked_add(1)
            .ok_or(MessageStreamError::InvalidRequest(
                "stream sequence overflow",
            ))?;
        let emit = should_emit(
            state.seed.mode,
            &text,
            chars.saturating_sub(state.emitted_chars),
        );
        #[cfg(feature = "sync")]
        let partial = if emit {
            super::presence::StreamPresence::prepare(&state.seed, &text, next)?
        } else {
            None
        };
        if delta.is_empty() {
            let txn = self.vault.store.env.read_txn()?;
            authorize(self.vault, &txn, &state.seed, &text)?;
        } else {
            let row = state.checkpoint(format!("{}{}", state.pending, delta));
            self.vault
                .try_with_write_txn_grouped(|txn| -> MessageStreamResult<()> {
                    authorize(self.vault, txn, &row, &text)?;
                    Ok(storage::checkpoint(self.vault, txn, &row)?)
                })?;
        }
        // Saved: the delta is accepted whatever its publication does.
        state.pending.push_str(delta);
        state.sequence = next;
        state.last_op_at_ms = at;
        state.dirty = true;
        if emit {
            #[cfg(feature = "sync")]
            if let Some(partial) = partial {
                self.vault.message_streams.presence.publish(partial)?;
            }
            state.emitted_chars = chars;
            state.dirty = false;
        }
        Ok(())
    }
    /// Forces a dirty partial out immediately. Atomic mode deliberately stays private.
    pub fn flush_stream(&self, handle: MessageStreamHandle) -> MessageStreamResult<()> {
        let entry = self.stream_entry(handle)?;
        let mut state = lock(&entry)?;
        state.check(handle)?;
        if !state.dirty {
            return Ok(());
        }
        let text = state.text();
        let txn = self.vault.store.env.read_txn()?;
        authorize(self.vault, &txn, &state.seed, &text)?;
        drop(txn);
        // Every accepted delta is already checkpointed, so this text is saved.
        #[cfg(feature = "sync")]
        if let Some(partial) =
            super::presence::StreamPresence::prepare(&state.seed, &text, state.sequence)?
        {
            self.vault.message_streams.presence.publish(partial)?;
        }
        state.emitted_chars = text.chars().count();
        state.dirty = false;
        Ok(())
    }
    /// Opens a continuation stream on an existing MESSAGE, reading its
    /// immutable axes, TURN and conversation from the stored row: the caller
    /// names only the MESSAGE. The stored text stays the base; the stream adds
    /// only what is appended to it. The ordinary continuation checks apply.
    pub fn begin_message_continuation(
        &self,
        message: &EntityId,
        mode: Option<MessageWriteMode>,
    ) -> MessageStreamResult<MessageStreamHandle> {
        let turn = {
            let txn = self.vault.store.env.read_txn()?;
            let body = committed_body(self.vault, &txn, message)?
                .ok_or(MessageStreamError::Engine(Error::EntityNotFound))?;
            let edge = |kind| {
                crate::memory::sole_edge_target(&self.vault.store, &txn, message, kind, "message")
            };
            let turn = edge(EdgeKind::PartOf)?
                .ok_or(MessageStreamError::InvalidRequest("message has no turn"))?;
            let conversation = edge(EdgeKind::BelongsTo)?.ok_or(
                MessageStreamError::InvalidRequest("message has no conversation"),
            )?;
            let field = |name: &str| body.get(name);
            let author = field("author")
                .and_then(serde_json::Value::as_str)
                .and_then(crate::memory::WitnessAuthor::parse)
                .ok_or(Error::CorruptedIndex("message author"))?;
            WitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: Some(turn.to_hex()),
                quote: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: Some(message.to_hex()),
                    author,
                    message_type: field("type")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(Error::CorruptedIndex("message type"))?
                        .to_owned(),
                    content: String::new(),
                    metadata: field("metadata").filter(|value| !value.is_null()).cloned(),
                    is_visible: field("is_visible")
                        .and_then(serde_json::Value::as_bool)
                        .ok_or(Error::CorruptedIndex("message visibility"))?,
                    order: field("order")
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|order| u32::try_from(order).ok())
                        .ok_or(Error::CorruptedIndex("message order"))?,
                }],
                occurred_at: self.vault.now_recorded_at(),
            }
        };
        self.begin_message_stream(&turn, mode)
    }
}
fn should_emit(mode: MessageWriteMode, text: &str, new_chars: usize) -> bool {
    match mode {
        MessageWriteMode::Atomic => false,
        MessageWriteMode::Streamed { cadence, .. } => match cadence {
            StreamCadence::PerToken => true,
            StreamCadence::PerSentence => {
                text.trim_end().ends_with(['.', '!', '?', '。', '！', '？'])
            }
            StreamCadence::PerWindow { chars } => new_chars >= chars as usize,
            StreamCadence::Manual => false,
        },
    }
}
pub(super) fn authorize(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seed: &Seed,
    text: &str,
) -> MessageStreamResult<()> {
    verify_actor_binding_in_txn(vault, txn, seed.actor, seed.class()?)?;
    if vault.local_hard_delete_marker_exists_in_txn(txn, &seed.message_id)? {
        return Err(Error::EntityNotFound.into());
    }
    if vault
        .store
        .off_record_sessions
        .owning_session_ref(&seed.conversation)?
        .is_some()
    {
        return Err(MessageStreamError::InvalidRequest(
            "off-record streams require the session door",
        ));
    }
    #[cfg(feature = "sync")]
    if seed.continuation {
        crate::entity_doc::authorize_message_continuation_in_txn(
            vault,
            txn,
            &seed.message_id,
            WriteActor::new(seed.actor, seed.class()?),
        )?;
    }
    for (id, expected_kind) in [
        (
            &seed.conversation,
            crate::registry::ENTITY_TYPE_CONVERSATION,
        ),
        (&seed.turn, crate::registry::ENTITY_TYPE_TURN),
    ] {
        if vault.local_hard_delete_marker_exists_in_txn(txn, id)? {
            return Err(Error::EntityNotFound.into());
        }
        if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)? {
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("stream container header"))?;
            if header.entity_type != expected_kind {
                return Err(MessageStreamError::InvalidRequest("stream container kind"));
            }
        }
    }
    let message = seed.message(text.to_owned());
    let envelope = witness_message_envelope(&message);
    let body = envelope.encode_body()?;
    let policy = resolve_policy_manifest(&vault.store, txn)?;
    check_witness_message_ceiling(
        &vault.store,
        txn,
        WriteActor::new(seed.actor, seed.class()?),
        &envelope,
        &body,
        &policy,
    )?;
    Ok(())
}
/// A MESSAGE's stored body as JSON, its text resolved from its document;
/// `None` when no row exists.
fn committed_body(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> MessageStreamResult<Option<serde_json::Value>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, message)?
    else {
        return Ok(None);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("message header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_MESSAGE {
        return Err(MessageStreamError::InvalidRequest("not a MESSAGE"));
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    #[cfg(feature = "sync")]
    let resolved = crate::entity_doc::resolve_record_body(&vault.store, txn, message, body)?;
    #[cfg(feature = "sync")]
    let body = resolved.as_slice();
    Ok(Some(
        rmp_serde::from_slice(body).map_err(|_| Error::CorruptedIndex("message body"))?,
    ))
}
/// Revalidate immutable axes/topology in the same snapshot used for a continuation.
pub(super) fn committed_text(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seed: &Seed,
) -> MessageStreamResult<Option<String>> {
    let Some(value) = committed_body(vault, txn, &seed.message_id)? else {
        return Ok(None);
    };
    if seed.author == crate::memory::WitnessAuthor::System {
        // System rows intentionally have no AuthoredBy edge. Only a stream's
        // durable actor-bound receipt proves which system writer may continue.
        if storage::receipt(vault, txn, seed.message_id)?.is_none_or(|r| r.actor != seed.actor) {
            return Err(MessageStreamError::WrongActor);
        }
    }
    let text = value
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or(Error::CorruptedIndex("message text"))?
        .to_owned();
    let expected: serde_json::Value = rmp_serde::from_slice(
        &witness_message_envelope(&seed.message(text.clone())).encode_body()?,
    )
    .map_err(|_| Error::CorruptedIndex("message envelope"))?;
    if value != expected {
        return Err(MessageStreamError::InvalidRequest(
            "continuation axes differ",
        ));
    }
    for (kind, target) in [
        (EdgeKind::PartOf, Some(seed.turn)),
        (EdgeKind::BelongsTo, Some(seed.conversation)),
        (
            EdgeKind::AuthoredBy,
            (seed.author != crate::memory::WitnessAuthor::System).then_some(seed.actor),
        ),
    ] {
        if crate::memory::sole_edge_target(&vault.store, txn, &seed.message_id, kind, "message")?
            != target
        {
            return Err(MessageStreamError::WrongActor);
        }
    }
    Ok(Some(text))
}
