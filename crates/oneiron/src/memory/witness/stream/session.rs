//! Native caller-session assistant RAM streaming: one fresh Companion reply.
//!
//! Fresh native path ONLY: the actual opaque [`SessionWitnessBinding`] stays
//! separate from the actual native author (`vault.memory(agent, Agent)` plus an
//! optional sitting). No guest ids, no latest-row inference, no seed/table,
//! custody, presence, or HTTP work. Anonymous ends are ALL RAM truthful
//! [`SessionStreamOutcome::Unretained`]; retained terminals run the native
//! witness plus the existing receipt pair through the SAME sink/writer.
//!
//! The registry holds the SAME entry as `Resident::Session`; this module adds
//! no parallel registry or idle loop. The host idle pump dispatches [`pump`] per entry.

use super::*;
use crate::ContentPart;
use crate::edge::EdgeActorClass;
use crate::memory::{
    MEMORY_CODE_INTERNAL, MemoryError, SessionWitnessBinding, SessionWitnessOutcome,
    WitnessAssertions, WitnessAuthor, WitnessTurn,
};
use crate::session_lifecycle::SessionKey;
use crate::{EntityId, Vault};
use oneiron_model::llm::FinishReason;
use std::cell::RefCell;
use std::sync::{Arc, Mutex, Weak};

/// Observable session partial: the token's own opaque text projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStreamPartial {
    pub stream_id: EntityId,
    pub text: String,
    pub sequence: u64,
}

/// Truthful RAM-only end: no fake MESSAGE id or receipt ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStreamEnd {
    pub stream_id: EntityId,
    pub generation: EntityId,
    pub finality: StreamFinality,
    pub finality_reason: StreamFinalityReason,
    pub finish_reason: Option<FinishReason>,
    pub bytes: u64,
}

/// One session stream's terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStreamOutcome {
    Retained(MessageStreamReceipt),
    Unretained(SessionStreamEnd),
}

/// A closed native stream's actual outcome, native TURN and caller-projected text.
/// An unretained stream has no TURN or MESSAGE to name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStreamFinished {
    pub outcome: SessionStreamOutcome,
    pub turn_id: Option<EntityId>,
    pub text: String,
}

#[derive(Debug, Clone)]
pub(in crate::memory::witness) struct SessionStreamStaged {
    receipt: MessageStreamReceipt,
    turn_id: EntityId,
    text: String,
}

struct ClosedStream {
    outcome: SessionStreamOutcome,
    turn_id: Option<EntityId>,
    text: String,
}

/// Terminal facts the native writer stages its actual receipt against.
///
/// `generation` is the stream token's own generation. The witness writer builds the actual
/// receipt from its native plan and calls [`SessionStreamTerminal::remember`]
/// before its effect. Nothing here rebuilds a receipt from a token id.
#[derive(Debug)]
pub(in crate::memory::witness) struct SessionStreamTerminal {
    pub(in crate::memory::witness) generation: EntityId,
    pub(in crate::memory::witness) finality: StreamFinality,
    pub(in crate::memory::witness) finality_reason: StreamFinalityReason,
    pub(in crate::memory::witness) finish_reason: Option<FinishReason>,
    pub(in crate::memory::witness) staged: RefCell<Option<SessionStreamStaged>>,
}

impl SessionStreamTerminal {
    pub(in crate::memory::witness) fn facts(
        generation: EntityId,
        finality: StreamFinality,
        finality_reason: StreamFinalityReason,
        finish_reason: Option<FinishReason>,
    ) -> Self {
        Self {
            generation,
            finality,
            finality_reason,
            finish_reason,
            staged: RefCell::new(None),
        }
    }
    pub(in crate::memory::witness) fn remember(
        &self,
        receipt: MessageStreamReceipt,
        turn_id: EntityId,
        text: String,
    ) {
        *self.staged.borrow_mut() = Some(SessionStreamStaged {
            receipt,
            turn_id,
            text,
        });
    }
    pub(in crate::memory::witness) fn staged(&self) -> Option<SessionStreamStaged> {
        self.staged.borrow().clone()
    }
}

/// One resident session stream: private RAM buffer ONLY.
pub(super) struct SessionState {
    pub(super) stream_id: EntityId,
    generation: EntityId,
    binding: Arc<SessionWitnessBinding>,
    origin: Weak<Mutex<BTreeMap<EntityId, Resident>>>,
    tokens: Weak<()>,
    agent: EntityId,
    sitting: Option<SessionKey>,
    birth: WitnessTurn,
    text: String,
    sequence: u64,
    last_op_at_ms: u64,
    idle_timeout_ms: u64,
    terminal: bool,
    completion: Option<MessageCompletion>,
    pending_terminal: Option<SessionStreamStaged>,
    closed: Option<ClosedStream>,
    permit: Option<crate::live_rows::LivePermit>,
}

impl SessionState {
    fn remove(&self) -> MessageStreamResult<()> {
        let entries = self
            .origin
            .upgrade()
            .ok_or(MessageStreamError::StreamNotFound)?;
        lock(&entries)?.remove(&self.stream_id);
        Ok(())
    }
    fn check(&self) -> MessageStreamResult<()> {
        if self.terminal {
            return Err(MessageStreamError::StreamNotFound);
        }
        Ok(())
    }
}

/// Opaque cloneable native capability: the token's live RAM state.
///
/// Non-serializable by construction: no `Serialize`, schema, Vault capture, or cycle.
#[derive(Clone)]
pub struct SessionMessageStream {
    state: Arc<Mutex<SessionState>>,
    _token: Arc<()>,
}

impl std::fmt::Debug for SessionMessageStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.state.lock() {
            Ok(state) => f
                .debug_struct("SessionMessageStream")
                .field("stream_id", &state.stream_id)
                .field("generation", &state.generation)
                .field("sequence", &state.sequence)
                .field("terminal", &state.terminal)
                .finish_non_exhaustive(),
            Err(_) => f
                .debug_struct("SessionMessageStream")
                .field("poisoned", &true)
                .finish_non_exhaustive(),
        }
    }
}

impl SessionMessageStream {
    /// Accepts one delta into RAM. Empty delta is a keepalive: sequence + clock move.
    pub fn append(&self, vault: &Vault, delta: &str) -> MessageStreamResult<()> {
        let mut state = lock(&self.state)?;
        state.check()?;
        check_caller_locked(vault, &mut state)?;
        resolve_pending_locked(vault, &mut state)?;
        state.check()?;
        if state.text.len().saturating_add(delta.len()) > MAX_MESSAGE_STREAM_BYTES {
            return Err(MessageStreamError::BufferOverflow);
        }
        let author = native_author(vault, state.agent, state.sitting);
        let admit = admit_turn(&state.birth, format!("{}{}", state.text, delta));
        state.binding.admit_stream(&author, &admit)?;
        let next = state
            .sequence
            .checked_add(1)
            .ok_or(MessageStreamError::InvalidRequest(
                "stream sequence overflow",
            ))?;
        if !delta.is_empty() {
            state.text.push_str(delta);
        }
        state.sequence = next;
        state.last_op_at_ms = now_ms();
        Ok(())
    }
    /// Token's own projected partial. No idle clock refresh.
    pub fn partial(&self, vault: &Vault) -> MessageStreamResult<SessionStreamPartial> {
        let mut state = lock(&self.state)?;
        state.check()?;
        check_caller_locked(vault, &mut state)?;
        resolve_pending_locked(vault, &mut state)?;
        state.check()?;
        let author = native_author(vault, state.agent, state.sitting);
        let admit = admit_turn(&state.birth, state.text.clone());
        state.binding.admit_stream(&author, &admit)?;
        let projected = state.binding.project_stream_text(vault, &state.text)?;
        Ok(SessionStreamPartial {
            stream_id: state.stream_id,
            text: projected,
            sequence: state.sequence,
        })
    }
    /// Same projected partial as [`Self::partial`]. No idle clock refresh.
    pub fn flush(&self, vault: &Vault) -> MessageStreamResult<SessionStreamPartial> {
        self.partial(vault)
    }
    /// Current finality of this caller's native stream, including an idle end.
    pub fn completion(&self, vault: &Vault) -> MessageStreamResult<MessageCompletion> {
        let mut state = lock(&self.state)?;
        check_caller_locked(vault, &mut state)?;
        resolve_pending_locked(vault, &mut state)?;
        Ok(state.completion.clone().unwrap_or(MessageCompletion {
            incomplete: true,
            generating: !state.terminal,
            finish_reason: None,
        }))
    }
    /// Resolves a closed stream and projects its exact terminal text for the
    /// original caller now. This read does not refresh the idle clock.
    pub fn finished(&self, vault: &Vault) -> MessageStreamResult<Option<SessionStreamFinished>> {
        let mut state = lock(&self.state)?;
        check_caller_locked(vault, &mut state)?;
        resolve_pending_locked(vault, &mut state)?;
        let Some(closed) = &state.closed else {
            return Ok(None);
        };
        let text = state
            .binding
            .project_finished_stream_text(vault, &closed.text)?;
        Ok(Some(SessionStreamFinished {
            outcome: closed.outcome.clone(),
            turn_id: closed.turn_id,
            text,
        }))
    }
    /// Explicit final end.
    pub fn finalize(&self, vault: &Vault) -> MessageStreamResult<SessionStreamOutcome> {
        let mut state = lock(&self.state)?;
        state.check()?;
        finish_locked(
            vault,
            &mut state,
            StreamFinality::Final,
            StreamFinalityReason::ExplicitFinalize,
            None,
            &WitnessAssertions::default(),
            Vec::new(),
        )
    }
    /// Model end, recording why the model stopped.
    pub fn finalize_model(
        &self,
        vault: &Vault,
        finish: FinishReason,
        assertions: &WitnessAssertions,
        parts: Vec<ContentPart>,
    ) -> MessageStreamResult<SessionStreamOutcome> {
        let (finality, reason) = map_finish(&finish);
        let mut state = lock(&self.state)?;
        state.check()?;
        finish_locked(
            vault,
            &mut state,
            finality,
            reason,
            Some(finish),
            assertions,
            parts,
        )
    }
    /// Cancelled end, keeping accepted text under a cancelled finality.
    pub fn cancel(
        &self,
        vault: &Vault,
        reason: StreamCancelReason,
    ) -> MessageStreamResult<SessionStreamOutcome> {
        let reason = map_cancel(reason)?;
        let mut state = lock(&self.state)?;
        state.check()?;
        finish_locked(
            vault,
            &mut state,
            StreamFinality::Cancelled,
            reason,
            None,
            &WitnessAssertions::default(),
            Vec::new(),
        )
    }
}

impl SessionWitnessBinding {
    /// One fresh native assistant stream: one Companion MESSAGE, no caller ids.
    pub fn begin_assistant_stream(
        self,
        vault: &Vault,
        agent: EntityId,
        sitting: Option<SessionKey>,
        turn: &WitnessTurn,
    ) -> MessageStreamResult<SessionMessageStream> {
        if turn.messages.len() != 1 {
            return Err(MessageStreamError::InvalidRequest("one message required"));
        }
        let birth = &turn.messages[0];
        if birth.author != WitnessAuthor::Companion {
            return Err(MessageStreamError::InvalidRequest(
                "session assistant streams carry one Companion message",
            ));
        }
        if birth.id.is_some() || turn.turn_ref.is_some() {
            return Err(MessageStreamError::InvalidRequest(
                "session assistant streams mint their own ids",
            ));
        }
        if birth.parts.is_some() {
            return Err(MessageStreamError::InvalidRequest(
                "content parts ride the terminal",
            ));
        }
        if birth.content.len() > MAX_MESSAGE_STREAM_BYTES {
            return Err(MessageStreamError::BufferOverflow);
        }
        let author = native_author(vault, agent, sitting);
        self.admit_stream(&author, turn)?;
        let policy = vault.message_stream_policy()?;
        let at = now_ms();
        let permit = vault.message_streams.line.enter(vault, agent.as_bytes())?;
        if let Err(error) = self.admit_stream(&author, turn) {
            drop(permit);
            return Err(error.into());
        }
        let stream_id = EntityId::now();
        let generation = EntityId::now();
        let waited_ms = u64::try_from(permit.waited().as_millis()).unwrap_or(u64::MAX);
        let token = Arc::new(());
        let entry = Arc::new(Mutex::new(SessionState {
            stream_id,
            generation,
            binding: Arc::new(self),
            origin: Arc::downgrade(&vault.message_streams.entries),
            tokens: Arc::downgrade(&token),
            agent,
            sitting,
            birth: turn.clone(),
            text: birth.content.clone(),
            sequence: 0,
            last_op_at_ms: at.saturating_add(waited_ms),
            idle_timeout_ms: policy.idle_timeout_ms,
            terminal: false,
            completion: None,
            pending_terminal: None,
            closed: None,
            permit: Some(permit),
        }));
        {
            let mut entries = lock(&vault.message_streams.entries)?;
            if entries.contains_key(&stream_id) {
                return Err(MessageStreamError::StreamAlreadyActive(stream_id));
            }
            entries.insert(stream_id, super::Resident::Session(Arc::clone(&entry)));
        }
        Ok(SessionMessageStream {
            state: entry,
            _token: token,
        })
    }
}

/// One idle-sweep step for a session entry: `None` when not due.
pub(super) fn pump(
    vault: &Vault,
    entry: &Arc<Mutex<SessionState>>,
    now: u64,
) -> MessageStreamResult<Option<SessionStreamOutcome>> {
    let mut state = lock(entry)?;
    if state.terminal || now.saturating_sub(state.last_op_at_ms) < state.idle_timeout_ms {
        return Ok(None);
    }
    let reason = idle_reason(state.idle_timeout_ms);
    let outcome = finish_locked(
        vault,
        &mut state,
        StreamFinality::Partial,
        reason,
        None,
        &WitnessAssertions::default(),
        Vec::new(),
    );
    if let Err(MessageStreamError::Memory(error)) = &outcome
        && error.code != MEMORY_CODE_INTERNAL
        && state.pending_terminal.is_none()
        && state.tokens.upgrade().is_none()
    {
        // Only actual private tokens keep a refused orphan retryable. Registry
        // and pump references keep its state alive, but do not own its text.
        retire_locked(&mut state)?;
    }
    outcome.map(Some)
}

fn native_author(
    vault: &Vault,
    agent: EntityId,
    sitting: Option<SessionKey>,
) -> crate::memory::Memory<'_> {
    let author = vault.memory(agent, EdgeActorClass::Agent);
    match sitting {
        Some(key) => author.with_session(key),
        None => author,
    }
}

fn admit_turn(birth: &WitnessTurn, text: String) -> WitnessTurn {
    let mut turn = birth.clone();
    if let Some(message) = turn.messages.first_mut() {
        message.content = text;
    }
    turn
}

fn terminal_turn(
    birth: &WitnessTurn,
    text: String,
    assertions: &WitnessAssertions,
    parts: Vec<ContentPart>,
) -> WitnessTurn {
    let mut turn = birth.clone();
    if let Some(message) = turn.messages.first_mut() {
        message.content = text;
        message.parts = if parts.is_empty() { None } else { Some(parts) };
    }
    turn.assertions
        .cited
        .extend(assertions.cited.iter().cloned());
    turn.assertions
        .created
        .extend(assertions.created.iter().cloned());
    turn
}

fn idle_reason(idle_timeout_ms: u64) -> StreamFinalityReason {
    if idle_timeout_ms == DEFAULT_MESSAGE_STREAM_IDLE_MS {
        StreamFinalityReason::IdleTimeout30s
    } else {
        StreamFinalityReason::IdleTimeout {
            timeout_ms: idle_timeout_ms,
        }
    }
}

fn map_cancel(reason: StreamCancelReason) -> MessageStreamResult<StreamFinalityReason> {
    match reason {
        StreamCancelReason::UserInterrupted => Ok(StreamFinalityReason::UserInterrupted),
        StreamCancelReason::AgentAborted => Ok(StreamFinalityReason::AgentAborted),
        StreamCancelReason::ExternalSignal => Ok(StreamFinalityReason::ExternalSignal),
        StreamCancelReason::Custom(text) if text.len() <= 1024 => {
            Ok(StreamFinalityReason::Custom(text))
        }
        StreamCancelReason::Custom(_) => Err(MessageStreamError::InvalidRequest(
            "cancel reason exceeds 1024 bytes",
        )),
    }
}

fn map_finish(finish: &FinishReason) -> (StreamFinality, StreamFinalityReason) {
    match finish {
        FinishReason::Stop | FinishReason::ToolCalls => (
            StreamFinality::Final,
            StreamFinalityReason::ExplicitFinalize,
        ),
        FinishReason::Length
        | FinishReason::ContentFiltered
        | FinishReason::Other { .. }
        | FinishReason::Incomplete { .. } => (
            StreamFinality::Partial,
            StreamFinalityReason::ExplicitFinalize,
        ),
        FinishReason::Cancelled => (
            StreamFinality::Cancelled,
            StreamFinalityReason::ExternalSignal,
        ),
    }
}

fn completion_for(
    finality: StreamFinality,
    finish_reason: Option<FinishReason>,
) -> MessageCompletion {
    let complete = finality == StreamFinality::Final
        && matches!(
            finish_reason,
            None | Some(FinishReason::Stop | FinishReason::ToolCalls)
        );
    MessageCompletion {
        incomplete: !complete,
        generating: false,
        finish_reason,
    }
}

fn check_caller_locked(vault: &Vault, state: &mut SessionState) -> MessageStreamResult<()> {
    let origin = state
        .origin
        .upgrade()
        .ok_or(MessageStreamError::StreamNotFound)?;
    if !Arc::ptr_eq(&origin, &vault.message_streams.entries) {
        return Err(MessageStreamError::StreamNotFound);
    }
    if let Err(error) = state.binding.check_stream_caller(vault) {
        // Only this caller-only check can retire a revoked/closed private stream.
        // Storage and corruption failures remain retryable, as for recorded streams.
        if error.code != MEMORY_CODE_INTERNAL {
            retire_locked(state)?;
        }
        return Err(error.into());
    }
    Ok(())
}

fn retire_locked(state: &mut SessionState) -> MessageStreamResult<()> {
    state.terminal = true;
    state.completion = None;
    state.pending_terminal = None;
    state.closed = None;
    state.permit.take();
    state.text.clear();
    state.remove()
}

#[expect(
    clippy::too_many_arguments,
    reason = "the session close joins its outcome, assertions and parts"
)]
fn finish_locked(
    vault: &Vault,
    state: &mut SessionState,
    finality: StreamFinality,
    finality_reason: StreamFinalityReason,
    finish_reason: Option<FinishReason>,
    assertions: &WitnessAssertions,
    parts: Vec<ContentPart>,
) -> MessageStreamResult<SessionStreamOutcome> {
    check_caller_locked(vault, state)?;
    if let Some(receipt) = resolve_pending_locked(vault, state)? {
        return Ok(SessionStreamOutcome::Retained(receipt));
    }
    let author = native_author(vault, state.agent, state.sitting);
    let turn = terminal_turn(&state.birth, state.text.clone(), assertions, parts);
    state.binding.admit_stream(&author, &turn)?;
    let terminal =
        SessionStreamTerminal::facts(state.generation, finality, finality_reason, finish_reason);
    let bytes = state.text.len() as u64;
    match state
        .binding
        .witness_stream_terminal(&author, &turn, &terminal)
    {
        Ok(SessionWitnessOutcome::Retained(_)) => {
            let Some(receipt) = terminal.staged() else {
                return Err(MessageStreamError::Memory(Box::new(MemoryError::new(
                    MEMORY_CODE_INTERNAL,
                    "session terminal retained without its staged receipt",
                    &["Cancel the stream; nothing was returned."],
                ))));
            };
            retained_locked(state, receipt)
        }
        Ok(SessionWitnessOutcome::Unretained) => {
            let end = SessionStreamEnd {
                stream_id: state.stream_id,
                generation: state.generation,
                finality: terminal.finality,
                finality_reason: terminal.finality_reason.clone(),
                finish_reason: terminal.finish_reason.clone(),
                bytes,
            };
            let completion = completion_for(end.finality, end.finish_reason.clone());
            state.terminal = true;
            state.completion = Some(completion);
            state.closed = Some(ClosedStream {
                outcome: SessionStreamOutcome::Unretained(end.clone()),
                turn_id: None,
                text: state.text.clone(),
            });
            state.permit.take();
            state.text.clear();
            state.remove()?;
            Ok(SessionStreamOutcome::Unretained(end))
        }
        Err(error) => {
            let Some(candidate) = terminal.staged() else {
                return Err(error.into());
            };
            state.pending_terminal = Some(candidate.clone());
            match state
                .binding
                .stream_terminal_receipt(vault, &candidate.receipt)
            {
                Ok(Some(found)) if found == candidate.receipt => retained_locked(state, candidate),
                Ok(None) => {
                    state.pending_terminal = None;
                    Err(error.into())
                }
                Ok(Some(_)) => Err(error.into()),
                Err(read_error) => Err(read_error.into()),
            }
        }
    }
}

// A failed postcommit read proves neither commit nor rollback. Resolve the
// exact generation before accepting more text or minting another MESSAGE.
fn resolve_pending_locked(
    vault: &Vault,
    state: &mut SessionState,
) -> MessageStreamResult<Option<MessageStreamReceipt>> {
    let Some(candidate) = state.pending_terminal.clone() else {
        return Ok(None);
    };
    match state
        .binding
        .stream_terminal_receipt(vault, &candidate.receipt)?
    {
        Some(found) if found == candidate.receipt => {
            retained_locked(state, candidate)?;
            Ok(Some(found))
        }
        None => {
            state.pending_terminal = None;
            Ok(None)
        }
        Some(_) => Err(MessageStreamError::Memory(Box::new(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "session terminal receipt changed",
            &["Retry after repairing the stored stream receipt."],
        )))),
    }
}

fn retained_locked(
    state: &mut SessionState,
    staged: SessionStreamStaged,
) -> MessageStreamResult<SessionStreamOutcome> {
    let SessionStreamStaged {
        receipt,
        turn_id,
        text,
    } = staged;
    state.completion = Some(MessageCompletion {
        incomplete: !receipt.complete(),
        generating: false,
        finish_reason: receipt.finish_reason.clone(),
    });
    state.terminal = true;
    state.pending_terminal = None;
    state.closed = Some(ClosedStream {
        outcome: SessionStreamOutcome::Retained(receipt.clone()),
        turn_id: Some(turn_id),
        text,
    });
    state.permit.take();
    state.text.clear();
    state.remove()?;
    Ok(SessionStreamOutcome::Retained(receipt))
}
