//! Sealing the one compaction request of an in-flight crossing.
//!
//! A request names its window, its sources and whose log it is cut from. A
//! chat window (FIX 5029) also carries its conversation binding: the
//! conversation its turns were read from and the branch read. Its turn
//! numbers are that conversation's order within the window's SESSION, and
//! its prior is read in that conversation's own lineage.

use super::*;
use crate::compaction::EpochScope;

/// The compaction job the driver hands the host to run on ITS runtime.
///
/// Created only by [`CompactionDriver::request_for`]. Hosts may read, move or
/// clone it, but integration requires the original fields and job identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionRequest {
    /// Unique to this issued job, including across abandoned or replaced drivers.
    pub(super) request_id: EntityId,
    /// The SESSION whose window is being compacted — the same `session_ref`
    /// vocabulary the admission door above uses.
    pub session_ref: EntityId,
    /// Ordered message-log span between the last epoch boundary and the
    /// watermark, assembled by the host: the engine never holds the log.
    pub window: Vec<CompactionWindowMessage>,
    /// Token ceiling for the produced summary text: the rounded profile
    /// summary allocation, with a minimum of one token.
    pub summary_token_budget: u64,
    /// First turn number this epoch covers, read DURABLY from the lineage's
    /// prior epoch summaries: prior `turn_end + 1`, or the window's first turn
    /// for the lineage's first epoch.
    pub turn_start: u64,
    /// The recorded snapshot point.
    pub watermark: CompactionWatermark,
    /// Text that must survive the swap word for word: a failure, a note the
    /// agent asked to keep. Each occurs verbatim in some window message.
    pub pins: Vec<String>,
    /// Every record the window's text was read from: the summary's
    /// `DerivedFrom` set, so erasing one retires the summary and a reader
    /// who may not read one reads no summary.
    pub sources: Vec<EntityId>,
    /// Whether the engine read this window's text from `sources` itself,
    /// rather than receiving caller-asserted or outcome-scanned ids (FIX 6999).
    pub window_read_from_sources: bool,
    /// What the agent asked the summary to keep (`self.compact({note})`,
    /// `self.fold(span, {note})`), as free text. Unlike a pin it need not
    /// occur in the window, and no check holds the summary to it.
    pub note: Option<String>,
    /// Whose log the window is cut from.
    pub(crate) log: WindowLog,
}

/// The conversation a chat window's turns were read from, and the branch
/// its reader read: a DAG conversation's HEAD, `None` for any other (FIX
/// 5029). The epoch counts in this conversation's lineage within the
/// window's SESSION, its turns numbered by their place in the conversation's
/// order there, on a DAG only along that branch's retained chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConversationBinding {
    pub(crate) conversation: EntityId,
    pub(crate) branch: Option<EntityId>,
}

/// Whose message log a window is cut from: a conversation, whose board turns
/// the mint folds and whose lineage is its durable epoch summaries; or a log
/// the host numbers itself (an executor run), whose lineage is the host's
/// own coverage rows, so erasing a summary never moves the run's position.
/// A conversation log bound to one conversation (FIX 5029) counts in that
/// conversation's lineage within the SESSION; one bound to none counts in
/// the SESSION's own.
/// A host log also says how many of its calls the `sources` were read from:
/// the next epoch lets this one stand for the ids those calls served, and
/// which run it is, the trigger its epoch's birth names (a fold names none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowLog {
    Conversation(Option<ConversationBinding>),
    Host {
        prior: Option<crate::compaction::PriorEpoch>,
        calls: u64,
        run: Option<EntityId>,
    },
}

impl CompactionRequest {
    /// Seals a host-requested conversation window without inventing a
    /// threshold crossing. The same gate and transactional mint judge it.
    pub(in crate::compaction) fn for_host(
        vault: &Vault,
        session_ref: EntityId,
        window: Vec<CompactionWindowMessage>,
        pins: Vec<String>,
        token_ceiling: u64,
    ) -> Result<Self> {
        let (turn_start, last) = validate_window_span(&window)?;
        let sources = conversation_sources(vault, &window)?;
        let rtxn = vault.store.env.read_txn()?;
        validate_epoch_boundary(
            prior_epoch_in_txn(&vault.store, &rtxn, &EpochScope::of_session(session_ref))?,
            turn_start,
        )?;
        Ok(Self {
            request_id: vault.store.clock.entity_id()?,
            session_ref,
            window,
            summary_token_budget: token_ceiling,
            turn_start,
            watermark: CompactionWatermark {
                learned_at: vault.now_recorded_at(),
                turn_id: None,
                turn: Some(last),
            },
            pins,
            sources,
            window_read_from_sources: false,
            note: None,
            log: WindowLog::Conversation(None),
        })
    }

    /// The host calls a host-numbered log's `sources` were read from; `None`
    /// for a conversation.
    pub(crate) const fn host_calls(&self) -> Option<u64> {
        match self.log {
            WindowLog::Conversation(_) => None,
            WindowLog::Host { calls, .. } => Some(calls),
        }
    }

    /// The lineage the request's epoch counts in (FIX 5029): its bound
    /// conversation's within its SESSION, else the SESSION's own.
    pub(crate) const fn epoch_scope(&self) -> EpochScope {
        match self.log {
            WindowLog::Conversation(Some(binding)) => {
                EpochScope::of_conversation(self.session_ref, binding.conversation)
            }
            WindowLog::Conversation(None) | WindowLog::Host { .. } => {
                EpochScope::of_session(self.session_ref)
            }
        }
    }
}

fn conversation_sources(
    vault: &Vault,
    window: &[CompactionWindowMessage],
) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut seen = BTreeSet::new();
    let mut sources = Vec::new();
    for message in window {
        if seen.insert(message.turn_id) {
            sources.push(message.turn_id);
        }
        if seen.insert(message.message_id)
            && stored_or_deleted_in(vault, &rtxn, &message.message_id)?
        {
            sources.push(message.message_id);
        }
    }
    Ok(sources)
}

impl CompactionDriver {
    /// Builds the single compaction job for the in-flight crossing.
    ///
    /// A successful call seals this request. Further calls fail without
    /// replacing it. The host may clone the returned request for its runtime,
    /// but must return it unchanged to [`Self::integrate`]. Invalid windows do
    /// not consume the crossing. Distinct turn numbers must be contiguous and
    /// nondecreasing; multiple messages in the same turn are valid.
    ///
    /// Legal only in `Compacting`: outside it the recorded watermark has no
    /// referent, so the call is a typed refusal rather than a guess. The HOST
    /// supplies `window` from its own message log — the engine never holds the
    /// log — and then runs `backend.compact(&request)` on its own runtime.
    ///
    /// The span START is read DURABLY from the session's prior epoch
    /// summaries (prior `turn_end + 1`, or the window's first turn for the
    /// first epoch). Epoch NUMBER is deliberately absent from this request:
    /// it is minted only inside [`Self::integrate`]'s write transaction.
    pub fn request_for(
        &mut self,
        vault: &Vault,
        session_ref: &EntityId,
        window: Vec<CompactionWindowMessage>,
    ) -> Result<CompactionRequest> {
        // Every record the window's text was read from (OF-013): each TURN
        // and each MESSAGE, uncut. A deleted MESSAGE stays a source, so the
        // summary is born withdrawn; an id the vault never stored is none.
        let sources = conversation_sources(vault, &window)?;
        self.seal_request(
            vault,
            session_ref,
            window,
            Vec::new(),
            sources,
            false,
            WindowLog::Conversation(None),
        )
    }

    /// Seals the flight's request. A conversation log's prior is read now,
    /// in its lineage (FIX 5029): a window read before another flight landed
    /// over its turns is refused here, before any model call.
    pub(in crate::compaction) fn seal_request(
        &mut self,
        vault: &Vault,
        session_ref: &EntityId,
        window: Vec<CompactionWindowMessage>,
        pins: Vec<String>,
        sources: Vec<EntityId>,
        window_read_from_sources: bool,
        log: WindowLog,
    ) -> Result<CompactionRequest> {
        let prior = match log {
            WindowLog::Conversation(binding) => {
                let scope = match binding {
                    Some(binding) => {
                        EpochScope::of_conversation(*session_ref, binding.conversation)
                    }
                    None => EpochScope::of_session(*session_ref),
                };
                let rtxn = vault.store.env.read_txn()?;
                prior_epoch_in_txn(&vault.store, &rtxn, &scope)?
            }
            WindowLog::Host { prior, .. } => prior,
        };
        self.seal_request_as(
            vault.store.clock.entity_id()?,
            session_ref,
            window,
            pins,
            sources,
            prior,
            None,
            window_read_from_sources,
            log,
        )
    }

    /// [`Self::seal_request`] with the request's id and the epoch before it
    /// already in hand: a host that reads through a room's view supplies
    /// both.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::compaction) fn seal_request_as(
        &mut self,
        request_id: EntityId,
        session_ref: &EntityId,
        window: Vec<CompactionWindowMessage>,
        pins: Vec<String>,
        sources: Vec<EntityId>,
        prior: Option<crate::compaction::PriorEpoch>,
        note: Option<String>,
        window_read_from_sources: bool,
        log: WindowLog,
    ) -> Result<CompactionRequest> {
        let CompactionState::Compacting { watermark, request } = &self.state else {
            return Err(Error::InvariantViolation(
                "request_for is legal only while compacting",
            ));
        };
        if request.is_some() {
            return Err(Error::InvariantViolation(
                "compaction flight already has a request",
            ));
        }
        let watermark = *watermark;
        let (turn_start, _) = validate_window_span(&window)?;
        validate_epoch_boundary(prior, turn_start)?;

        let request = CompactionRequest {
            request_id,
            session_ref: *session_ref,
            summary_token_budget: self.summary_token_budget(),
            window,
            turn_start,
            watermark,
            pins,
            sources,
            window_read_from_sources,
            note,
            log,
        };
        self.state = CompactionState::Compacting {
            watermark,
            request: Some(Box::new(request.clone())),
        };
        Ok(request)
    }
}

/// Whether the vault stores `id`, or stored it until a deletion whose
/// tombstone stands.
fn stored_or_deleted_in(vault: &Vault, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(
        crate::ports::EntityStoreRead::port_entity_record(&vault.store, rtxn, id)?.is_some()
            || crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, rtxn, id)?
                .deleted,
    )
}
