//! Begin, append and flush. The only pre-final durable row is a content-free seed.
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
        };
        let handle = MessageStreamHandle {
            message: id,
            generation: seed.generation,
        };
        let entry = Arc::new(Mutex::new(State {
            seed,
            base: String::new(),
            pending: message.content.clone(),
            last_op_at_ms: at,
            sequence: 0,
            emitted_chars: 0,
            dirty: true,
            terminal: false,
        }));
        // Take the new entry before exposing it to the sweep. No registry lock
        // is held while waiting for an entry or for the LMDB writer.
        let mut state = lock(&entry)?;
        {
            let mut entries = lock(&self.vault.message_streams.entries)?;
            if entries.contains_key(&id) {
                return Err(MessageStreamError::StreamAlreadyActive(id));
            }
            if entries.len() >= MAX_MESSAGE_STREAMS {
                return Err(MessageStreamError::TooManyStreams);
            }
            entries.insert(id, Arc::clone(&entry));
        }
        let admitted: MessageStreamResult<()> =
            self.vault
                .try_with_write_txn(|txn| -> MessageStreamResult<()> {
                    if self
                        .vault
                        .store
                        .vault_meta
                        .get(txn, &storage::key(storage::ACTIVE, id))?
                        .is_some()
                    {
                        return Err(MessageStreamError::StreamAlreadyActive(id));
                    }
                    state.base = committed_text(self.vault, txn, &state.seed)?.unwrap_or_default();
                    state.seed.continuation =
                        self.vault.store.entities.get(txn, id.as_bytes())?.is_some();
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
                    )?;
                    if state.seed.author == crate::memory::WitnessAuthor::System
                        && self
                            .vault
                            .store
                            .entities
                            .get(txn, state.seed.turn.as_bytes())?
                            .is_none()
                    {
                        return Err(MessageStreamError::InvalidRequest(
                            "system stream requires an existing turn",
                        ));
                    }
                    let bytes = storage::encode(&state.seed)?;
                    self.vault.store.vault_meta.put(
                        txn,
                        &storage::key(storage::ACTIVE, id),
                        &bytes,
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
    /// No token, heartbeat, text-index update, CRDT op or offline queue row is written.
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
        let txn = self.vault.store.env.read_txn()?;
        authorize(self.vault, &txn, &state.seed, &text)?;
        drop(txn);
        let next = state
            .sequence
            .checked_add(1)
            .ok_or(MessageStreamError::InvalidRequest(
                "stream sequence overflow",
            ))?;
        if should_emit(
            state.seed.mode,
            &text,
            chars.saturating_sub(state.emitted_chars),
        ) {
            #[cfg(feature = "sync")]
            self.vault
                .publish_message_stream(&state.seed, &text, next)?;
            state.emitted_chars = chars;
            state.dirty = false;
        } else {
            state.dirty = true;
        }
        state.pending.push_str(delta);
        state.sequence = next;
        state.last_op_at_ms = at;
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
        #[cfg(feature = "sync")]
        self.vault
            .publish_message_stream(&state.seed, &text, state.sequence)?;
        state.emitted_chars = text.chars().count();
        state.dirty = false;
        Ok(())
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
        if let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? {
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
/// Revalidate immutable axes/topology in the same snapshot used for a continuation.
pub(super) fn committed_text(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seed: &Seed,
) -> MessageStreamResult<Option<String>> {
    let Some(raw) = vault.store.entities.get(txn, seed.message_id.as_bytes())? else {
        return Ok(None);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("message header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_MESSAGE {
        return Err(MessageStreamError::InvalidRequest("not a MESSAGE"));
    }
    if seed.author == crate::memory::WitnessAuthor::System {
        // System rows intentionally have no AuthoredBy edge. Only a stream's
        // durable actor-bound receipt proves which system writer may continue.
        if storage::receipt(vault, txn, seed.message_id)?.is_none_or(|r| r.actor != seed.actor) {
            return Err(MessageStreamError::WrongActor);
        }
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    #[cfg(feature = "sync")]
    let resolved =
        crate::entity_doc::resolve_record_body(&vault.store, txn, &seed.message_id, body)?;
    #[cfg(feature = "sync")]
    let body = resolved.as_slice();
    let value: serde_json::Value =
        rmp_serde::from_slice(body).map_err(|_| Error::CorruptedIndex("message body"))?;
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
#[cfg(feature = "sync")]
impl Vault {
    fn publish_message_stream(&self, seed: &Seed, text: &str, seq: u64) -> MessageStreamResult<()> {
        self.message_streams.presence.publish(seed, text, seq)
    }
}
