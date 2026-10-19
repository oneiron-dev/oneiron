//! `chat_breakpoint_storage` (FIX 4465 D): a self agent's per-reply chat
//! breakpoint, the restart-readable seed its Continue and Retry reuse. One
//! row per reply MESSAGE and stream generation, host-only and never in the
//! MESSAGE's own metadata, with no shared latest-request slot. It binds the
//! answering agent, its reader, the conversation and branch, the SESSION the
//! log's latest turn was witnessed into, the request exactly as its rung sent
//! it (the rung's prompt first) with its digest, the rung by its provider,
//! place, wire model and the digest of its offer, and the retained turns and
//! summaries the request was read from, by revision. It names no credential:
//! a reuse proves its reader again, as the reader is now, and re-admits the
//! rung through the live route. The flight's own copy stays in its flight.
//!
//! Its words are the conversation's, so erasing any record of the
//! conversation drops the conversation's breakpoints.

use serde::{Deserialize, Serialize};

use crate::compaction::ConversationTurnSpan;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::bytes_to_hex_lower;
use crate::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, LlmRequest, Result, Vault, WriteActor};

/// Breakpoints. Key: id16(conversation) + id16(message) + id16(generation).
const BREAKPOINTS: SideTable<(EntityId, EntityId, EntityId), ChatBreakpoint, Named> =
    SideTable::new(&side_table::CHAT_BREAKPOINT);

/// The rung a reply's request was captured on, by ref: its provider, its
/// place in the configured ladder, the model its wire names and the digest
/// of the offer it was admitted under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatBreakpointRung {
    pub provider: String,
    pub position: usize,
    pub wire_model: String,
    pub offer_digest: String,
}

/// One reply's breakpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatBreakpoint {
    /// The agent definition that answered.
    pub agent: EntityId,
    /// The actor its log was read as, and its class.
    pub reader: EntityId,
    pub reader_class: u8,
    pub conversation: EntityId,
    /// A DAG conversation's HEAD when the log was read.
    #[serde(default)]
    pub branch: Option<EntityId>,
    #[serde(default)]
    pub session: Option<EntityId>,
    /// The request as its rung sent it, as JSON.
    pub request: String,
    /// The hex BLAKE3 of that request's canonical bytes.
    pub request_digest: String,
    pub rung: ChatBreakpointRung,
    /// The hex BLAKE3 of the agent's instructions the request carried.
    #[serde(default)]
    pub instructions_digest: Option<String>,
    /// The retained turns the request holds, in order, by revision.
    pub sources: Vec<ConversationTurnSpan>,
    /// The landed summaries the request holds in place of their turns.
    pub summaries: Vec<EntityId>,
}

/// Why a kept breakpoint no longer stands: the fork it captured is not the
/// one a reuse would send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatBreakpointStale {
    /// Its request is not the one its digest names.
    RequestChanged,
    /// A turn it was read from reads other words, rows or authors now, or
    /// its reader reads it no longer.
    SourceMoved,
    /// A summary it holds was withdrawn.
    SummaryWithdrawn,
}

impl ChatBreakpointStale {
    /// The stable name a log line carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestChanged => "request_changed",
            Self::SourceMoved => "source_moved",
            Self::SummaryWithdrawn => "summary_withdrawn",
        }
    }
}

impl ChatBreakpoint {
    /// The captured request, while it is the one its digest names.
    #[must_use]
    pub fn captured_request(&self) -> Option<LlmRequest> {
        let request: LlmRequest = serde_json::from_str(&self.request).ok()?;
        let digest = request.canonical_hash().ok()?;
        (bytes_to_hex_lower(&digest) == self.request_digest).then_some(request)
    }

    /// The reader its log was read as.
    #[must_use]
    pub fn reader(&self) -> Option<WriteActor> {
        EdgeActorClass::try_from_u8(self.reader_class)
            .map(|class| WriteActor::new(self.reader, class))
    }
}

/// Keeps `seed` as the breakpoint of `message`'s stream `generation`, beside
/// every other generation's: a Continue's new generation and a Retry's new
/// reply each keep their own, and the source's stays as it was. The row is
/// what the side-row wall stores.
///
/// # Errors
///
/// Storage errors.
pub fn keep_chat_breakpoint(
    vault: &Vault,
    message: EntityId,
    generation: EntityId,
    mut seed: ChatBreakpoint,
) -> Result<()> {
    let key = (seed.conversation, message, generation);
    vault.with_write_txn_grouped(|txn| {
        BREAKPOINTS.admit(vault, txn, &key, &mut seed)?;
        BREAKPOINTS.put(vault, txn, &key, &seed)
    })
}

/// The breakpoint of `message`'s latest stream generation in
/// `conversation`, when one was kept for it.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
pub fn chat_breakpoint(
    vault: &Vault,
    conversation: EntityId,
    message: EntityId,
) -> Result<Option<ChatBreakpoint>> {
    let txn = vault.store.env.read_txn()?;
    let Some((_, generation)) =
        crate::memory::message_stream_finality_in_txn(vault, &txn, &message)?
    else {
        return Ok(None);
    };
    BREAKPOINTS.get(&vault.store, &txn, &(conversation, message, generation))
}

/// Whether `seed` still stands, read again as its reader in one snapshot:
/// its request is its digest's, every turn it was read from projects the
/// same fingerprint, and every summary it holds still stands.
///
/// # Errors
///
/// Storage errors.
pub fn chat_breakpoint_stands(
    vault: &Vault,
    seed: &ChatBreakpoint,
) -> Result<std::result::Result<(), ChatBreakpointStale>> {
    use crate::ports::EntityStore;
    if seed.captured_request().is_none() {
        return Ok(Err(ChatBreakpointStale::RequestChanged));
    }
    let Some(reader) = seed.reader() else {
        return Ok(Err(ChatBreakpointStale::SourceMoved));
    };
    let txn = vault.store.env.read_txn()?;
    for span in &seed.sources {
        let Some(row) = vault.port_entity_get(&txn, &span.turn)? else {
            return Ok(Err(ChatBreakpointStale::SourceMoved));
        };
        let pinned = crate::dreamer_consolidation::live_turn_text_in(
            vault, &txn, reader, &span.turn, &row.body,
        )
        .ok()
        .and_then(|text| text.summary_fingerprint().ok())
        .map(|fingerprint| bytes_to_hex_lower(&fingerprint));
        if pinned.as_deref() != Some(span.fingerprint.as_str()) {
            return Ok(Err(ChatBreakpointStale::SourceMoved));
        }
    }
    for summary in &seed.summaries {
        let standing =
            crate::ports::EntityStoreRead::port_entity_record(&vault.store, &txn, summary)?
                .is_some_and(|record| {
                    record.entity_type == ENTITY_TYPE_SUMMARY
                        && crate::compaction::decode_epoch_summary_body(&record.body).is_ok()
                });
        if !standing {
            return Ok(Err(ChatBreakpointStale::SummaryWithdrawn));
        }
    }
    Ok(Ok(()))
}

/// Drops the breakpoints an erase of `id` covers: every one of the
/// conversation `id` is, or that its TURN, MESSAGE or landed summary belongs
/// to. A source whose conversation does not resolve drops every breakpoint,
/// since one may hold its words. Registered in `deletion/derived_rows.rs`.
pub(crate) fn erase_chat_breakpoints_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(record) = crate::ports::EntityStoreRead::port_entity_record(store, txn, id)? else {
        return Ok(());
    };
    let conversation = match record.entity_type {
        ENTITY_TYPE_CONVERSATION => Ok(Some(*id)),
        ENTITY_TYPE_TURN => {
            crate::memory::sole_edge_target(store, txn, id, EdgeKind::ChildOf, "turn")
        }
        ENTITY_TYPE_MESSAGE => {
            crate::memory::sole_edge_target(store, txn, id, EdgeKind::BelongsTo, "message")
        }
        ENTITY_TYPE_SUMMARY => Ok(crate::compaction::conversation_receipt_in(store, txn, id)?
            .and_then(|receipt| receipt.evidence().map(|evidence| evidence.conversation))),
        _ => return Ok(()),
    };
    match conversation {
        Ok(Some(conversation)) => {
            BREAKPOINTS.delete_from(store, txn, conversation.as_bytes())?;
        }
        Ok(None) => {}
        Err(_) => {
            BREAKPOINTS.delete_from(store, txn, &[])?;
        }
    }
    Ok(())
}
