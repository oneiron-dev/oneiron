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
//! A row is kept for its stream generation before that generation's call is
//! sent (FIX 5028), so a reply a crash cuts before its terminal is recovered
//! on the same generation with its breakpoint in place. A generation whose
//! kept call gives way to another call, or whose stream ends with no
//! terminal, drops its row. A reuse re-reads the row's turns as its reader
//! reads them now, a room's audience through the room's held projection, as
//! the log was read (FIX 5031).
//!
//! Its words are the conversation's, so erasing any record of the
//! conversation drops the conversation's breakpoints: every row is keyed
//! under its conversation, a Retry's whose MESSAGE has not landed yet
//! included. The craft notes its request shows are pinned by revision too
//! (FIX 8135): a reuse finds each still standing as it was shown, and erasing
//! one drops the breakpoints that show it, and only those.
//!
//! A row also holds the answering agent's instructions and the words read
//! for its reader (FIX 5033). Erasing the agent's definition drops every
//! breakpoint it answered. A hard erase of an actor drops every breakpoint
//! read as it or answered by it. A row binds the user turn its request
//! answers, by the TURN and MESSAGE rows its witness wrote, apart from its
//! log: a first turn's log holds no line, but its request holds the user's
//! words. Erasing any record a row was read from drops that row, and
//! withdrawing a summary drops each row that holds it. A keep re-checks, in
//! its own write, that no record its row binds is gone or withdrawn, so a
//! late keep never brings a row back. Keeping a generation forgets the
//! older generations of the same MESSAGE that no read addresses. No age,
//! count or size bound applies across a conversation.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{ManifestEntry, ManifestKind};
use crate::compaction::ConversationTurnSpan;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::bytes_to_hex_lower;
use crate::memory::{Memory, RoomTurnHandle};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE,
    ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::secret_custody::CustodyWrite;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault, WriteActor};
use oneiron_model::llm::LlmRequest;

/// Breakpoints. Key: id16(conversation) + id16(message) + id16(generation).
const BREAKPOINTS: SideTable<(EntityId, EntityId, EntityId), ChatBreakpoint, Named> =
    SideTable::new(&side_table::CHAT_BREAKPOINT);
/// Whether a masked copy of a `CHAT_BREAKPOINT` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn chat_breakpoint_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<ChatBreakpoint, Named>(bytes)
}

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

/// The user turn a breakpoint's request answers, by the rows its witness
/// wrote (FIX 5033). The request holds its words; no span of the log names
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatBreakpointUserTurn {
    /// The user's TURN.
    pub turn: EntityId,
    /// The MESSAGE rows its words were witnessed into.
    pub messages: Vec<EntityId>,
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
    /// The user turn the request answers (FIX 5033). A breakpoint that
    /// binds none, or none of its MESSAGEs, is never kept.
    pub user_turn: Option<ChatBreakpointUserTurn>,
    /// The craft rows the request shows as the host's own snapshot read them
    /// when it assembled the request (FIX 9439), frozen with the request its
    /// digest names: a reuse names these, never rows read from the
    /// request's user text. Empty for a request that shows none, and on a
    /// breakpoint kept before them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub craft_entries: Vec<ManifestEntry>,
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
    /// A craft note its request shows was erased, lost its live support, or
    /// reads another revision now (FIX 8135).
    CraftWithdrawn,
}

impl ChatBreakpointStale {
    /// The stable name a log line carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestChanged => "request_changed",
            Self::SourceMoved => "source_moved",
            Self::SummaryWithdrawn => "summary_withdrawn",
            Self::CraftWithdrawn => "craft_withdrawn",
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

    /// Every record the request was read from (FIX 5033): each turn of its
    /// log with its MESSAGEs, the user turn it answers with its MESSAGEs,
    /// and each summary it holds.
    fn read_records(&self) -> impl Iterator<Item = EntityId> + '_ {
        let log = self
            .sources
            .iter()
            .flat_map(|span| std::iter::once(span.turn).chain(span.messages.iter().copied()));
        let user = self
            .user_turn
            .iter()
            .flat_map(|user| std::iter::once(user.turn).chain(user.messages.iter().copied()));
        log.chain(user).chain(self.summaries.iter().copied())
    }
}

/// Keeps `seed` as the breakpoint of `message`'s stream `generation`. A
/// Continue's new generation keeps its own beside its source's, and a
/// Retry's new reply keeps its own beside its source reply's. The row is
/// what the side-row wall stores. A generation keeps its row once: kept
/// before its call was sent (FIX 5028), the terminal's keep confirms it and
/// writes nothing again.
///
/// The same write re-checks the records the seed binds (FIX 5033). When one
/// is gone or withdrawn, or the seed binds no user turn, nothing is kept:
/// its erase or withdrawal already took the rows that hold it, and a reuse
/// finds the breakpoint missing. The write then forgets each
/// other generation of `message` that is neither its latest terminal's nor
/// its stream's in flight: no read addresses it again.
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
        if !BREAKPOINTS.contains(&vault.store, &*txn, &key)?
            && !seed_binds_gone_in_txn(vault, txn, message, &seed)?
        {
            BREAKPOINTS.admit(vault, txn, &key, &mut seed)?;
            BREAKPOINTS.put(vault, txn, &key, &seed)?;
        }
        forget_superseded_in_txn(vault, txn, seed.conversation, message, Some(generation))
    })
}

/// Forgets the generations of `message` in `conversation` that no read
/// addresses (FIX 5033). A reply's terminal calls it once it confirms the
/// seed its generation kept before its call was sent: the generation the
/// reply continued is no longer the latest. A write opens only when a row
/// is to go.
///
/// # Errors
///
/// Storage errors.
pub fn forget_superseded_chat_breakpoints(
    vault: &Vault,
    conversation: EntityId,
    message: EntityId,
) -> Result<()> {
    {
        let txn = vault.store.env.read_txn()?;
        if superseded_generations_in_txn(vault, &txn, conversation, message, None)?.is_empty() {
            return Ok(());
        }
    }
    vault.with_write_txn_grouped(|txn| {
        forget_superseded_in_txn(vault, txn, conversation, message, None)
    })
}

/// Whether a record `seed` binds is missing, gone or withdrawn in `txn`
/// (FIX 5033). The seed must bind the user turn it answers and at least one
/// of its MESSAGEs. The answering agent's definition, the conversation,
/// each record the request was read from and each craft note it shows must
/// be stored and not deleted. No record it was read from may read
/// withdrawn: a withdrawn summary keeps its row without its words, and a
/// pending walk's withdrawal counts. The reader, the reply MESSAGE and the
/// conversation's HEAD must not be deleted; a Retry's MESSAGE that has not
/// landed yet is not.
fn seed_binds_gone_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: EntityId,
    seed: &ChatBreakpoint,
) -> Result<bool> {
    if seed
        .user_turn
        .as_ref()
        .is_none_or(|user| user.messages.is_empty())
    {
        return Ok(true);
    }
    let read: Vec<EntityId> = seed.read_records().collect();
    let craft = seed
        .craft_entries
        .iter()
        .filter(|entry| entry.kind == ManifestKind::ActorClaim)
        .filter_map(|entry| EntityId::from_hex(&entry.reference).ok());
    let stored: Vec<EntityId> = [seed.agent, seed.conversation]
        .into_iter()
        .chain(read.iter().copied())
        .chain(craft)
        .collect();
    for id in &stored {
        if !crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, id)? {
            return Ok(true);
        }
    }
    for id in &read {
        if crate::ports::stale_in_txn(&vault.store, txn, id)? {
            return Ok(true);
        }
    }
    let named: Vec<EntityId> = [seed.reader, message]
        .into_iter()
        .chain(seed.branch)
        .chain(stored)
        .collect();
    crate::llm::owner_gone_in_txn(vault, txn, &named)
}

/// The generations of `message` in `conversation` whose rows no read
/// addresses (FIX 5033): neither `kept`, nor the MESSAGE's latest
/// terminal's, which [`chat_breakpoint`] reads, nor its stream's in flight
/// or recoverable, which its lifecycle releases. While a stream seed that
/// does not decode stands, every generation is held.
fn superseded_generations_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
    message: EntityId,
    kept: Option<EntityId>,
) -> Result<Vec<EntityId>> {
    let Some(held) = crate::memory::message_stream_held_generations_in_txn(vault, txn, &message)?
    else {
        return Ok(Vec::new());
    };
    let mut prefix = conversation.as_bytes().to_vec();
    prefix.extend_from_slice(message.as_bytes());
    Ok(BREAKPOINTS
        .scan_keys(&vault.store, txn, &prefix)?
        .into_iter()
        .map(|(_, _, generation)| generation)
        .filter(|generation| kept != Some(*generation) && !held.contains(generation))
        .collect())
}

/// Forgets, in the caller's write, each row of `message` in `conversation`
/// that [`superseded_generations_in_txn`] names, with the custody it lifted.
fn forget_superseded_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    conversation: EntityId,
    message: EntityId,
    kept: Option<EntityId>,
) -> Result<()> {
    let superseded = superseded_generations_in_txn(vault, txn, conversation, message, kept)?;
    let write = CustodyWrite::of(vault);
    for generation in superseded {
        forget_chat_breakpoint_in_txn(&write, txn, &(conversation, message, generation))?;
    }
    Ok(())
}

/// Drops the breakpoint of `message`'s stream `generation` in
/// `conversation` (FIX 5028), with the custody its row lifted: a generation
/// whose kept call gave way to another call, or whose stream never started,
/// keeps none. Every other generation's row stays.
///
/// # Errors
///
/// Storage errors.
pub fn forget_chat_breakpoint(
    vault: &Vault,
    conversation: EntityId,
    message: EntityId,
    generation: EntityId,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        forget_chat_breakpoint_in_txn(
            &CustodyWrite::of(vault),
            txn,
            &(conversation, message, generation),
        )
    })
}

/// [`forget_chat_breakpoint`] in the caller's write, for the row `key`
/// names: a stream retired with no terminal drops its generation's row in
/// the write that drops its recovery seed.
pub(crate) fn forget_chat_breakpoint_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    key: &(EntityId, EntityId, EntityId),
) -> Result<()> {
    let place = format!("side:{}", BREAKPOINTS.decl().name);
    let origin = crate::batch::secret_scan::side_row_origin(&place, &BREAKPOINTS.key_bytes(key))?;
    crate::secret_custody::revoke_side_row_custody_with_context_in_txn(write, txn, &origin)?;
    BREAKPOINTS.delete(write.store, txn, key)?;
    Ok(())
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

/// Whether `seed` still stands, read again in one snapshot as `memory`, its
/// reader's handle as it stands now (where it sits, under its live
/// authority): its request is its digest's, every turn it was read from
/// projects the same fingerprint through the lane its log was read through,
/// a room's audience through the room's held projection (FIX 5031), every
/// summary it holds still stands for that reader (its evidence and words
/// read through the same lane), and every craft note it shows still
/// reads, with live support, at the revision it showed (FIX 8135). A handle
/// of another reader, or a room projection that refuses or holds, finds its
/// sources moved.
///
/// # Errors
///
/// Storage errors.
pub fn chat_breakpoint_stands(
    memory: &Memory<'_>,
    seed: &ChatBreakpoint,
) -> Result<std::result::Result<(), ChatBreakpointStale>> {
    if seed.captured_request().is_none() {
        return Ok(Err(ChatBreakpointStale::RequestChanged));
    }
    if seed.reader != memory.actor() || seed.reader_class != memory.actor_class() as u8 {
        return Ok(Err(ChatBreakpointStale::SourceMoved));
    }
    let vault = memory.vault();
    let Ok(room) = crate::compaction::chat_log_room(memory, seed.conversation) else {
        return Ok(Err(ChatBreakpointStale::SourceMoved));
    };
    let Ok(key) = room
        .as_ref()
        .map_or(memory, RoomTurnHandle::memory)
        .read_key()
    else {
        return Ok(Err(ChatBreakpointStale::SourceMoved));
    };
    let read = vault.scoped_read(key);
    let txn = vault.store.env.read_txn()?;
    for span in &seed.sources {
        let pinned = crate::dreamer_consolidation::scoped_turn_text_in(&read, &txn, &span.turn)
            .ok()
            .flatten()
            .and_then(|text| text.summary_fingerprint().ok())
            .map(|fingerprint| bytes_to_hex_lower(&fingerprint));
        if pinned.as_deref() != Some(span.fingerprint.as_str()) {
            return Ok(Err(ChatBreakpointStale::SourceMoved));
        }
    }
    // Each summary is read as a chat log reads it, through the same reader:
    // its evidence and words must stand for that reader now, not only be
    // stored (FIX 5027, 5031).
    for summary in &seed.summaries {
        if !crate::compaction::summary_stands_in(&read, &txn, summary)? {
            return Ok(Err(ChatBreakpointStale::SummaryWithdrawn));
        }
    }
    for entry in &seed.craft_entries {
        if !craft_entry_stands_in(vault, &txn, entry)? {
            return Ok(Err(ChatBreakpointStale::CraftWithdrawn));
        }
    }
    Ok(Ok(()))
}

/// Whether the craft note `entry` names still reads on `txn`, with live
/// support, at the revision the request showed. A row that is no actor
/// claim pins nothing.
fn craft_entry_stands_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entry: &ManifestEntry,
) -> Result<bool> {
    if entry.kind != ManifestKind::ActorClaim {
        return Ok(true);
    }
    let Ok(claim) = EntityId::from_hex(&entry.reference) else {
        return Ok(false);
    };
    let Some(body) = vault.get_claim_in_txn(txn, &claim)? else {
        return Ok(false);
    };
    if !crate::claim::has_live_support_in_txn(&vault.store, txn, &body)? {
        return Ok(false);
    }
    Ok(crate::actor_claims::CraftNote::new(claim, body)?.revision == entry.version)
}

/// Drops the breakpoints an erase of `id` covers: every one of the
/// conversation `id` is, or that its TURN, MESSAGE or landed summary belongs
/// to, and each one whose request was read from that TURN, MESSAGE or
/// summary, the user turn it answers included, whatever conversation keys
/// it (FIX 5033); for a CLAIM, each one whose request shows it as craft (FIX
/// 8135); for an AGENT_DEF, each one that agent answered, since its request
/// holds the agent's instructions (FIX 5033). Every other row is kept as it
/// was. A source whose conversation does not resolve drops every
/// breakpoint, since one may hold its words. Registered in
/// `deletion/derived_rows.rs`.
pub(crate) fn erase_chat_breakpoints_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let store = write.store;
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
        ENTITY_TYPE_CLAIM => return erase_craft_breakpoints_in_txn(write, txn, id),
        ENTITY_TYPE_AGENT_DEF => {
            return forget_breakpoints_where_in_txn(write, txn, |seed| seed.agent == *id);
        }
        _ => return Ok(()),
    };
    match conversation {
        Ok(Some(conversation)) => {
            crate::secret_custody::revoke_side_row_prefix_custody_in_txn(
                write,
                txn,
                &BREAKPOINTS,
                conversation.as_bytes(),
            )?;
            BREAKPOINTS.delete_from(store, txn, conversation.as_bytes())?;
        }
        Ok(None) => {}
        Err(_) => {
            crate::secret_custody::revoke_side_row_prefix_custody_in_txn(
                write,
                txn,
                &BREAKPOINTS,
                &[],
            )?;
            BREAKPOINTS.delete_from(store, txn, &[])?;
        }
    }
    if record.entity_type != ENTITY_TYPE_CONVERSATION {
        forget_breakpoints_where_in_txn(write, txn, |seed| {
            seed.read_records().any(|read| read == *id)
        })?;
    }
    Ok(())
}

/// Drops each breakpoint whose request holds summary `id`, as a withdrawal
/// marks it stale (FIX 5033). The summary keeps its row without its words,
/// so a presence check does not fence it. Called where a withdrawal marks a
/// row; any other row is passed by.
pub(crate) fn forget_withdrawn_summary_breakpoints_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let summary = crate::ports::EntityStoreRead::port_entity_record(write.store, txn, id)?
        .is_some_and(|record| record.entity_type == ENTITY_TYPE_SUMMARY);
    if !summary {
        return Ok(());
    }
    forget_breakpoints_where_in_txn(write, txn, |seed| seed.summaries.contains(id))
}

/// Drops each breakpoint whose request shows claim `claim` as craft.
fn erase_craft_breakpoints_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    claim: &EntityId,
) -> Result<()> {
    let reference = claim.to_hex();
    forget_breakpoints_where_in_txn(write, txn, |seed| {
        seed.craft_entries
            .iter()
            .any(|entry| entry.kind == ManifestKind::ActorClaim && entry.reference == reference)
    })
}

/// The hard erase of `actor` drops every breakpoint read as it or answered
/// by it (FIX 5033): its row holds the words read for that reader and the
/// agent's instructions. CHAT_BREAKPOINT's actor scrub, so marker-only
/// replay and checkpoint restore run it too.
pub(crate) fn scrub_chat_breakpoint_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    forget_breakpoints_where_in_txn(&CustodyWrite::of(vault), txn, |seed| {
        seed.reader == *actor || seed.agent == *actor
    })
}

/// Drops each breakpoint `covered` selects, with the custody its row lifted
/// (FIX 5033). A row that does not decode goes too: it may hold the words
/// the erase takes, and no reuse reads it.
fn forget_breakpoints_where_in_txn(
    write: &CustodyWrite<'_>,
    txn: &mut heed::RwTxn<'_>,
    covered: impl Fn(&ChatBreakpoint) -> bool,
) -> Result<()> {
    let mut keys = Vec::new();
    for row in BREAKPOINTS.iter_raw_from(write.store, &*txn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <(EntityId, EntityId, EntityId) as SideKey>::decode_key(&key) else {
            continue;
        };
        if BREAKPOINTS
            .decode_value(&bytes)
            .ok()
            .is_none_or(|seed| covered(&seed))
        {
            keys.push(key);
        }
    }
    for key in &keys {
        forget_chat_breakpoint_in_txn(write, txn, key)?;
    }
    Ok(())
}
