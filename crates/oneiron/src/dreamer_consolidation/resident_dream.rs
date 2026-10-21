//! A resident's own dreaming (OF-490, ARCH-0026 frame): each resident dreams
//! under its own stamp, on its own model or on the vault weaver's model and
//! window, and the weaver never reads its diary. Since its last dreaming it
//! reads its sealed scratchpads, its receipts, its INBOX rows and the health
//! cards about it (`resident_health`), oldest first, as many as the window
//! holds, and writes one diary entry in its own voice. It may also propose
//! craft notes about itself, actor.lesson and actor.failure_mode candidates,
//! which land Proposed beside the entry.
//! What it did not read stays for its next dreaming.
//!
//! The host lends the model and the instruction; the engine ships no
//! dreaming prompt, only the reply's shape ([`CRAFT_ASK`]). The Nightly
//! recipe queues one child per resident whose definition is on and whose
//! dreaming is not off, unless the owner set it a free-time policy: then its
//! dreaming is its cycle's own-time item instead (FIX 4453).

use super::step_charge::StepChargeTally;
use crate::actor_claims::ResidentCraftCandidate;
use crate::agent_def::DreamingMode;
use crate::agent_inbox_lens::{AgentInboxDiaryReview, ResolvedInboxText};
use crate::dreamer_runner::{
    DREAMER_RESIDENT_DREAM_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerParkCause,
};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, WakeAttemptContext,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{Error, Result};
use crate::llm::manifest::ModelRole;
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, HostInferenceContext, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelTierRef, ResponseFormat, StepOutcome, TierPrecedence, call_as_step_checked,
};
use crate::receipt::ReceiptQuery;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, Vault, WriteActor};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod reply;

/// The window a resident dreams in when the host names none, in tokens.
pub const RESIDENT_DREAM_WINDOW_DEFAULT_TOKENS: u64 = 32_000;
/// The share of the window its inputs may fill; the rest is the entry's.
const INPUT_SHARE_DIVISOR: u64 = 2;
/// A fork chain of more hops than this, followed back to a resident, is
/// logged once per walk (FIX 7057). It is walked whole all the same: this
/// bounds nothing.
const LONG_FORK_LINEAGE: usize = 16;
/// The fence that opens a dreaming reply's craft notes, after its entry.
const CRAFT_FENCE: &str = "```oneiron-craft";
/// The reply's shape, after the cut: the entry, then optionally the
/// resident's craft notes about itself (OF-490). The host's instruction
/// stays the voice; this only says where the notes go.
const CRAFT_ASK: &str = "Write your diary entry. After it you may propose craft notes about \
     yourself: end the reply with one block fenced ```oneiron-craft holding \
     {\"lessons\":[\"<what you will do differently>\"],\
     \"failure_modes\":[\"<a lapse of yours that keeps recurring>\"]}, either list empty \
     when you have none. Nothing follows the closing fence; everything before the block is \
     the diary entry.";

/// Each resident's committed progress: what its dreaming already read.
const PROGRESS: SideTable<EntityId, ResidentDreamProgress, Named> =
    SideTable::new(&side_table::DREAMER_RESIDENT_PROGRESS);
/// The sealed scratchpads a resident's dreaming already read. Key: resident,
/// pad.
const PADS: SideTable<(EntityId, EntityId), [u8; 1], Raw> =
    SideTable::new(&side_table::DREAMER_RESIDENT_PADS);
/// The diary entry one dreaming attempt landed (its first part), so a
/// replay writes none.
const LANDED: SideTable<crate::attempt_queue::AttemptId, EntityId, Named> =
    SideTable::new(&side_table::DREAMER_RESIDENT_LANDED);

/// What a resident's dreaming has read so far. Each source keeps the time
/// and id of the last row it read, so a cut that stops inside one second
/// resumes after that row, not after the second.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentDreamProgress {
    /// The newest receipt time it read, in Unix seconds.
    pub receipts_after: u64,
    /// That receipt's `kind:id`.
    pub receipt_after_id: String,
    /// The newest INBOX row time it read.
    pub inbox_after: u64,
    /// That row's item id.
    pub inbox_after_id: String,
    /// The INBOX row past the cursor its last dreaming read only in part.
    #[serde(default)]
    pub inbox_partial: Option<ResidentDreamPartial>,
    /// The sealed pad its last dreaming read only in part.
    #[serde(default)]
    pub pad_partial: Option<ResidentDreamPartial>,
    /// The time the newest health card about it that it read was last
    /// touched (FIX 1145).
    #[serde(default)]
    pub health_after: u64,
    /// That card's `health:` handle.
    #[serde(default)]
    pub health_after_id: String,
    /// The time the newest health card about one of its forks that it read
    /// was last touched (FIX 5913): a cursor of its own, so a fork's card
    /// never moves it past a card about it unread.
    #[serde(default)]
    pub fork_health_after: u64,
    /// That card's `health:` handle.
    #[serde(default)]
    pub fork_health_after_id: String,
    pub dreamed_at: u64,
    pub entries: u64,
}

/// An input one dreaming read only in part, because it did not fit any
/// window whole: the next dreaming reads on from `read` bytes into it, so it
/// is read whole across dreamings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentDreamPartial {
    /// The row's time (an INBOX row's), or 0 for a pad.
    pub at: u64,
    /// The INBOX row's item id, or the pad's hex id.
    pub id: String,
    /// The bytes of its words (a pad's body) read so far.
    pub read: u64,
}

/// What the host lends one resident's dreaming.
pub struct ResidentDreamModel<'a> {
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
    pub model: ModelId,
    pub inference: HostInferenceContext<'a>,
    /// The vault role whose route it shares when it inherits the weaver's
    /// model; `None` when it dreams on its own.
    pub role: Option<ModelRole>,
    /// The host's dreaming instruction.
    pub instruction: &'a str,
    /// The tokens one call's input may fill on this model, when known.
    pub window_tokens: Option<u64>,
}

/// The payload input naming the resident a dreaming child dreams for.
pub(crate) fn resident_dream_input(resident: EntityId) -> rmpv::Value {
    rmpv::Value::Map(vec![(
        rmpv::Value::from("resident"),
        rmpv::Value::Binary(resident.as_bytes().to_vec()),
    )])
}

/// The resident a dreaming child's payload names.
pub fn resident_of_dream_input(input: &rmpv::Value) -> Result<EntityId> {
    let rmpv::Value::Map(entries) = input else {
        return Err(invalid("resident dream input is not a map"));
    };
    let mut found = None;
    for (key, value) in entries {
        match (key.as_str(), value) {
            (Some("resident"), rmpv::Value::Binary(bytes)) if found.is_none() => {
                found = Some(
                    EntityId::from_bytes(
                        bytes
                            .as_slice()
                            .try_into()
                            .map_err(|_| invalid("resident is not an id16"))?,
                    )
                    .map_err(|_| invalid("resident is not an entity id"))?,
                );
            }
            // A free-time cycle's item names its cycle too (FIX 4453); the
            // binding its cycle stamped is what it runs under.
            (Some("cycle"), rmpv::Value::Binary(_)) => {}
            _ => return Err(invalid("resident dream input has an unknown field")),
        }
    }
    found.ok_or_else(|| invalid("resident dream input names no resident"))
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("resident dream: {reason}"))
}

impl Vault {
    /// The residents that dream tonight: every enabled agent definition
    /// whose dreaming is not off, by row id.
    pub(crate) fn dreaming_residents(&self) -> Result<Vec<EntityId>> {
        let mut residents = Vec::new();
        let mut after = None;
        loop {
            let page = self.entities_by_type_page(
                crate::registry::ENTITY_TYPE_AGENT_DEF,
                after.as_ref(),
                256,
            )?;
            let Some(last) = page.last().copied() else {
                break;
            };
            for id in page {
                // A row that does not decode dreams no one's dreaming.
                if let Ok(Some(definition)) = self.get_agent_definition(&id)
                    && definition.enabled
                    && definition.dreaming_mode() != DreamingMode::Off
                {
                    residents.push(id);
                }
            }
            after = Some(last);
        }
        Ok(residents)
    }

    /// What `resident`'s dreaming has read so far.
    pub fn resident_dream_progress(&self, resident: EntityId) -> Result<ResidentDreamProgress> {
        let txn = self.store.env.read_txn()?;
        resident_dream_progress_in_txn(self, &txn, resident)
    }
}

/// [`Vault::resident_dream_progress`] in the caller's snapshot: the weave
/// report reads it into the resident's own digest (OF-499).
pub(crate) fn resident_dream_progress_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    resident: EntityId,
) -> Result<ResidentDreamProgress> {
    Ok(PROGRESS
        .get(&vault.store, txn, &resident)?
        .unwrap_or_default())
}

/// The inputs one dreaming reads, and the progress reading them makes.
#[derive(Debug, Default)]
struct DreamCut {
    sections: Vec<(&'static str, Vec<String>)>,
    pads: Vec<EntityId>,
    receipts_after: Option<(u64, String)>,
    inbox_after: Option<(u64, String)>,
    inbox_partial: Option<ResidentDreamPartial>,
    pad_partial: Option<ResidentDreamPartial>,
    health_after: Option<(u64, String)>,
    fork_health_after: Option<(u64, String)>,
}

/// Moves a `(time, id)` read cursor forward, never back.
fn advance(at: &mut u64, id: &mut String, read: Option<&(u64, String)>) {
    if let Some((read_at, read_id)) = read
        && (*read_at, read_id.as_str()) > (*at, id.as_str())
    {
        *at = *read_at;
        id.clone_from(read_id);
    }
}

impl DreamCut {
    fn is_empty(&self) -> bool {
        self.sections.iter().all(|(_, lines)| lines.is_empty())
    }

    fn text(&self) -> String {
        let mut text = String::new();
        for (title, lines) in &self.sections {
            if lines.is_empty() {
                continue;
            }
            text.push_str("## ");
            text.push_str(title);
            text.push('\n');
            for line in lines {
                text.push_str(line);
                text.push('\n');
            }
            text.push('\n');
        }
        text
    }
}

/// Room left in the window, counted as each input is added.
struct Room(u64);

impl Room {
    fn take(&mut self, text: &str) -> bool {
        let tokens = crate::count_context_pack_tokens(text) as u64;
        if tokens > self.0 {
            return false;
        }
        self.0 -= tokens;
        true
    }

    /// The longest non-empty prefix of `body`, cut at a character, that
    /// fits what is left once `render` frames it and `mark` follows, with the
    /// bytes of `body` it holds; `None` when no such prefix fits.
    fn fit_part(
        &self,
        body: &str,
        render: impl Fn(&str) -> String,
        mark: &str,
    ) -> Option<(String, usize)> {
        let mut end = body.len();
        loop {
            let end_at = body.floor_char_boundary(end);
            if end_at == 0 {
                return None;
            }
            let cut = format!("{}{mark}", render(&body[..end_at]));
            if crate::count_context_pack_tokens(&cut) as u64 <= self.0 {
                return Some((cut, end_at));
            }
            end = end_at * 9 / 10;
        }
    }
}

/// The words a dreaming quotes for one INBOX row, who they are quoted from,
/// and whether they read as data: the row's own resolved `words`, else a
/// pending diary read's stated reason, its reader's words, quoted whole as
/// data (OF-490, Rule 5); `None` for a row of pointers only.
fn diary_review_words<'a>(
    words: Option<&'a ResolvedInboxText>,
    review: Option<&'a AgentInboxDiaryReview>,
) -> Option<(EntityId, &'a str, bool)> {
    match (words, review) {
        (Some(words), _) => Some((
            words.identity_ref,
            words.text.as_str(),
            words.claims_not_instructions,
        )),
        (None, Some(review)) if !review.reason.is_empty() => {
            Some((review.reader, review.reason.as_str(), true))
        }
        (None, _) => None,
    }
}

/// What a row's quoted words, cut to fit, end with.
const WORDS_CUT_MARK: &str = "\n  > (the words run on past this dreaming's window)";
/// What a pad's body, cut to fit, ends with.
const PAD_CUT_MARK: &str = "\n(the pad runs on past this dreaming's window)";

/// Where an input an earlier dreaming read in part reads on from: `read`
/// bytes in, at a character, when `partial` is that input; else its start.
fn read_on_from(partial: Option<&ResidentDreamPartial>, at: u64, id: &str, body: &str) -> usize {
    partial
        .filter(|partial| partial.at == at && partial.id == id)
        .map_or(0, |partial| {
            body.floor_char_boundary(usize::try_from(partial.read).unwrap_or(usize::MAX))
        })
}

/// The agent definitions forked from `resident` whose sealed pads its
/// dreaming reads: each whose fork chain reaches it before any other bound
/// resident. A fork that is a bound resident itself dreams over its own.
fn resident_forks(vault: &Vault, resident: EntityId) -> Result<Vec<EntityId>> {
    let mut forks = Vec::new();
    let mut after = None;
    loop {
        let page = vault.entities_by_type_page(
            crate::registry::ENTITY_TYPE_AGENT_DEF,
            after.as_ref(),
            256,
        )?;
        let Some(last) = page.last().copied() else {
            break;
        };
        for id in page {
            if id != resident && forked_from_resident(vault, id, resident) {
                forks.push(id);
            }
        }
        after = Some(last);
    }
    Ok(forks)
}

/// Whether `fork`'s chain of fork parents reaches `resident` first. A bound
/// resident on the way, or one whose binding does not read, ends the chain;
/// so do a row that does not decode, the chain's root and a cycle. A visited
/// set stops a cycle, never a count (FIX 7057): a chain of any length is
/// followed to its end.
fn forked_from_resident(vault: &Vault, fork: EntityId, resident: EntityId) -> bool {
    let unbound = |id: EntityId| matches!(vault.settled_resident_agent(id), Ok(None));
    if !unbound(fork) {
        return false;
    }
    let mut seen = BTreeSet::from([fork]);
    let mut at = fork;
    loop {
        let Ok(Some(definition)) = vault.get_agent_definition(&at) else {
            return false;
        };
        let Some(parent) = definition.forked_from else {
            return false;
        };
        if parent == resident {
            return true;
        }
        if !seen.insert(parent) || !unbound(parent) {
            return false;
        }
        if seen.len() == LONG_FORK_LINEAGE + 1 {
            tracing::warn!(
                kind = "fork_lineage_long",
                past = LONG_FORK_LINEAGE,
                "a resident's fork walk follows an unusually long fork lineage"
            );
        }
        at = parent;
    }
}

/// Reads what `resident` has not dreamed over yet, oldest first within each
/// source, until the window's input share is full. Every receipt and INBOX
/// row past the cursor is a candidate, so a busy stretch is read over later
/// dreamings rather than cut to its newest page.
fn cut_for(
    vault: &Vault,
    resident: EntityId,
    progress: &ResidentDreamProgress,
    window_tokens: u64,
) -> Result<DreamCut> {
    let mut room = Room(window_tokens / INPUT_SHARE_DIVISOR);
    let mut cut = DreamCut::default();

    // Its own sealed pads, then each of its forks': "A fork's sealed
    // scratchpad feeds its resident's diary at the next dreaming."
    let authors: Vec<EntityId> = std::iter::once(resident)
        .chain(resident_forks(vault, resident)?)
        .collect();
    let pads = {
        let txn = vault.store.env.read_txn()?;
        let mut pads = Vec::new();
        for &author in &authors {
            for pad in vault.sealed_scratchpads_in_txn(&txn, author)? {
                if !PADS.contains(&vault.store, &txn, &(resident, pad))? {
                    pads.push((pad, author));
                }
            }
        }
        pads
    };
    let mut pad_lines = Vec::new();
    for (pad, author) in pads {
        let Some(note) = vault.read_note(&pad)? else {
            continue;
        };
        if !note.author_ref.is(author) {
            continue;
        }
        let body = note.markdown.trim();
        let from = read_on_from(progress.pad_partial.as_ref(), 0, &pad.to_hex(), body);
        let mut head = if author == resident {
            format!("### {}", pad.to_hex())
        } else {
            format!("### {} (fork {})", pad.to_hex(), author.to_hex())
        };
        if from > 0 {
            head.push_str(&format!(" (read on from byte {from})"));
        }
        let render = |part: &str| format!("{head}\n{part}");
        let line = render(&body[from..]);
        if room.take(&line) {
            pad_lines.push(line);
            cut.pads.push(pad);
            continue;
        }
        // The first pad a dreaming reads goes in part when it does not fit
        // whole, and reads on at the next dreaming: a pad longer than any
        // window is read whole across dreamings, never skipped.
        if pad_lines.is_empty()
            && let Some((part, read)) = room.fit_part(&body[from..], render, PAD_CUT_MARK)
            && room.take(&part)
        {
            pad_lines.push(part);
            cut.pad_partial = Some(ResidentDreamPartial {
                at: 0,
                id: pad.to_hex(),
                read: (from + read) as u64,
            });
        }
        break;
    }
    cut.sections.push(("Sealed scratchpads", pad_lines));

    // Every receipt past the cursor, not the newest page of them: the cut
    // reads them oldest first, so the cursor never passes one unread.
    let after = (progress.receipts_after, progress.receipt_after_id.as_str());
    let mut receipts: Vec<_> = vault
        .receipts(
            ReceiptQuery::new(usize::MAX)
                .with_actor(resident.to_hex())
                .with_time_bounds(
                    (progress.receipts_after > 0).then_some(progress.receipts_after),
                    None,
                ),
        )?
        .into_iter()
        .map(|receipt| {
            let id = format!("{}:{}", receipt.receipt_kind.as_str(), receipt.receipt_id);
            ((receipt.occurred_at, id), receipt)
        })
        .filter(|((at, id), _)| (*at, id.as_str()) > after)
        .collect();
    receipts.sort_by(|a, b| a.0.cmp(&b.0));
    let mut receipt_lines = Vec::new();
    for (key, receipt) in receipts {
        let mut line = format!(
            "- {} {} {}",
            receipt.occurred_at,
            receipt.receipt_kind.as_str(),
            receipt.outcome
        );
        if let Some(job) = &receipt.job_ref {
            line.push_str(&format!(" job {job}"));
        }
        if !room.take(&line) {
            break;
        }
        receipt_lines.push(line);
        cut.receipts_after = Some(key);
    }
    cut.sections.push(("Receipts", receipt_lines));

    // A standing membership with nothing on its thread yet has no time and
    // nothing to read.
    let after = (progress.inbox_after, progress.inbox_after_id.as_str());
    let mut inbox: Vec<_> = vault
        .agent_inbox_slice(resident, usize::MAX, None)?
        .into_iter()
        .filter(|item| item.occurred_at > 0 && (item.occurred_at, item.item_id.as_str()) > after)
        .collect();
    inbox.sort_by(|a, b| (a.occurred_at, &a.item_id).cmp(&(b.occurred_at, &b.item_id)));
    // Each row's words, read as the resident through its own lane: only a
    // row addressed to it, on an identity it may read, carries any. A lane
    // the resident cannot open leaves the rows as index lines.
    let texts = match vault
        .memory(resident, EdgeActorClass::Agent)
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
    {
        Ok(read) => vault.resolve_agent_inbox_texts(&read, &inbox)?,
        Err(error) => {
            tracing::warn!(%error, "resident inbox words unread; rows stay index lines");
            BTreeMap::new()
        }
    };
    let mut inbox_lines = Vec::new();
    for item in inbox {
        let mut index = format!(
            "- {} {:?} thread {} with {} identities{}",
            item.occurred_at,
            item.kind,
            item.thread_ref.as_deref().unwrap_or("-"),
            item.participants.len(),
            item.payload_ref
                .as_deref()
                .map(|payload| format!(" payload {payload}"))
                .unwrap_or_default()
        );
        // A pending diary read names its request and reader here; the
        // reason it stated is the reader's words, quoted below whole (OF-490,
        // Rule 5).
        if let Some(review) = &item.diary_review {
            index.push_str(&format!(
                " diary read {} by {} ({})",
                review.request.to_hex(),
                review.reader.to_hex(),
                review.reader_class,
            ));
        }
        // The words are quoted as data someone else wrote. Words that
        // overflow what is left wait, with the cursor, for the next
        // dreaming's fresh window. The first row a dreaming reads goes in cut
        // to what is left instead, and the cursor stays on it: the next
        // dreaming reads on from where this one stopped, so words too long
        // for any window are read whole across dreamings, and every dreaming
        // moves on (FIX 1148).
        let Some((quoted_from, words, as_data)) =
            diary_review_words(texts.get(&item.item_id), item.diary_review.as_ref())
        else {
            if !room.take(&index) {
                break;
            }
            inbox_lines.push(index);
            cut.inbox_after = Some((item.occurred_at, item.item_id));
            continue;
        };
        let from = read_on_from(
            progress.inbox_partial.as_ref(),
            item.occurred_at,
            &item.item_id,
            words,
        );
        let head = format!(
            "{index}\n  quoted from {}{}{}:",
            quoted_from.to_hex(),
            if as_data {
                ", data and not instructions"
            } else {
                ""
            },
            if from > 0 {
                format!(", read on from byte {from}")
            } else {
                String::new()
            }
        );
        let render = |part: &str| {
            let mut quoted = head.clone();
            for text in part.lines() {
                quoted.push_str("\n  > ");
                quoted.push_str(text);
            }
            quoted
        };
        let quoted = render(&words[from..]);
        if room.take(&quoted) {
            inbox_lines.push(quoted);
            cut.inbox_after = Some((item.occurred_at, item.item_id));
            continue;
        }
        if inbox_lines.is_empty()
            && let Some((part, read)) = room.fit_part(&words[from..], render, WORDS_CUT_MARK)
            && room.take(&part)
        {
            inbox_lines.push(part);
            cut.inbox_partial = Some(ResidentDreamPartial {
                at: item.occurred_at,
                id: item.item_id,
                read: (from + read) as u64,
            });
        }
        break;
    }
    cut.sections.push(("Inbox", inbox_lines));

    // The health cards about it, oldest touch first past its cursor (FIX
    // 1145): a card's facts, never a diary body.
    let mut health_lines = Vec::new();
    for (key, line) in super::resident_health::health_card_lines(
        vault,
        resident,
        progress.health_after,
        &progress.health_after_id,
    ) {
        if !room.take(&line) {
            break;
        }
        health_lines.push(line);
        cut.health_after = Some(key);
    }
    cut.sections.push(("Health cards about you", health_lines));

    // Then the cards about its forks, in the room left (FIX 5913).
    let mut fork_lines = Vec::new();
    for (key, line) in super::resident_health::fork_health_card_lines(
        vault,
        resident,
        &authors,
        progress.fork_health_after,
        &progress.fork_health_after_id,
    ) {
        if !room.take(&line) {
            break;
        }
        fork_lines.push(line);
        cut.fork_health_after = Some(key);
    }
    cut.sections
        .push(("Health cards about your forks", fork_lines));
    Ok(cut)
}

/// Lands `entry` in `resident`'s diary in the caller's write. Past the NOTE
/// body bound it lands as ordered private parts, each continuation linked
/// `Mentions` to the first, as an imported note's parts are. Returns the
/// first part.
fn append_diary_entry_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    resident: WriteActor,
    entry: &str,
    at: u64,
) -> Result<EntityId> {
    let mut parts = Vec::new();
    for part in super::note_parts::parts(entry, crate::note::MAX_NOTE_BYTES) {
        parts.push(crate::memory::append_agent_diary_in_txn(
            vault,
            txn,
            resident,
            part.to_owned(),
            at,
        )?);
    }
    let (&first, continuations) = parts
        .split_first()
        .ok_or_else(|| invalid("the entry landed no note"))?;
    if !continuations.is_empty() {
        let mut batch = vault.batch_in();
        for part in continuations {
            batch = batch.edge(part, EdgeKind::Mentions, &first, 1.0);
        }
        let mut content = crate::federation::ActorContentTxn::new(vault, txn, resident)?;
        content.apply_batch(batch)?;
        content.finish()?;
    }
    Ok(first)
}

/// A dreaming reply's diary entry and the craft notes it proposes: a reply
/// that ends with one ```oneiron-craft block whose lessons and failure
/// modes parse proposes them, and its entry is what precedes the block. Any
/// other reply is all entry and proposes nothing: a note is never made up.
fn split_craft_notes(reply: &str) -> (&str, Vec<ResidentCraftCandidate>) {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CraftBlock {
        #[serde(default)]
        lessons: Vec<String>,
        #[serde(default)]
        failure_modes: Vec<String>,
    }
    let parsed = reply
        .strip_suffix("```")
        .and_then(|rest| rest.rsplit_once(CRAFT_FENCE))
        .and_then(|(entry, block)| {
            let block = serde_json::from_str::<CraftBlock>(block.trim()).ok()?;
            Some((entry.trim_end(), block))
        });
    let Some((entry, block)) = parsed else {
        return (reply, Vec::new());
    };
    let craft = block
        .lessons
        .into_iter()
        .map(ResidentCraftCandidate::Lesson)
        .chain(
            block
                .failure_modes
                .into_iter()
                .map(ResidentCraftCandidate::FailureMode),
        )
        .collect();
    (entry, craft)
}

/// Lands a dreaming's craft notes as Proposed candidates on the resident
/// (OF-490), in the entry's write. The notes write in their own savepoint:
/// a refusal rolls back alone, is logged, and the entry still lands.
fn propose_craft_notes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    resident: EntityId,
    attempt: crate::attempt_queue::AttemptId,
    craft: &[ResidentCraftCandidate],
    at: u64,
) -> Result<()> {
    if craft.is_empty() {
        return Ok(());
    }
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match crate::actor_claims::write_resident_craft_candidates_in_txn(
        vault,
        &mut savepoint,
        resident,
        attempt,
        craft,
        at,
    ) {
        Ok(_) => savepoint.commit()?,
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            ?attempt,
            "a resident's dreaming craft notes were not proposed"
        ),
    }
    Ok(())
}

/// Runs one resident's dreaming: reads its cut, asks its model with the
/// host's instruction, and writes the reply as one entry of its own diary,
/// under its own stamp. A replay after the entry landed writes none.
pub async fn run_resident_dream(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: ResidentDreamModel<'_>,
) -> Result<DreamerAttemptExecution> {
    let attempt_id = attempt.status.attempt.id;
    if attempt.status.payload.attempt_type != DREAMER_RESIDENT_DREAM_ATTEMPT_KIND {
        return Err(invalid("not a resident dreaming attempt"));
    }
    let resident: WriteActor = ctx.vault.resident_actor_for_attempt(attempt_id)?;
    let resident_id = resident.entity_ref();
    {
        let txn = ctx.vault.store.env.read_txn()?;
        if LANDED.contains(&ctx.vault.store, &txn, &attempt_id)? {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }
    }
    // A free-time cycle's own-time item (FIX 4453) dreams only while its
    // cycle is open and its agent did not choose rest; its receipt lands with
    // its entry. One that lands no entry gets no success receipt.
    let free_time =
        match crate::dreamer_runner::free_time_item_to_run(ctx.vault, attempt_id, resident_id)? {
            crate::dreamer_runner::FreeTimeItemRun::Done => {
                return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
            }
            crate::dreamer_runner::FreeTimeItemRun::Unbound => None,
            crate::dreamer_runner::FreeTimeItemRun::Run(binding) => Some(binding),
        };
    let Some(definition) = ctx.vault.get_agent_definition(&resident_id)? else {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    };
    if !definition.enabled || definition.dreaming_mode() == DreamingMode::Off {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    }
    let progress = ctx.vault.resident_dream_progress(resident_id)?;
    let cut = cut_for(
        ctx.vault,
        resident_id,
        &progress,
        model
            .window_tokens
            .unwrap_or(RESIDENT_DREAM_WINDOW_DEFAULT_TOKENS),
    )?;
    if cut.is_empty() {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    }
    let locality = model
        .inference
        .selected_locality()
        .ok_or_else(|| invalid("the host binding names no locality"))?;
    // OF-490: it dreams knowing its own craft, every note, loaded on this
    // attempt so its manifest names them: fixed input beside its cut, never
    // diary progress, so no cut defers or consumes it. A craft that does not
    // read leaves the dreaming as it was.
    let craft = match ctx
        .vault
        .load_resident_craft(attempt_id, &resident_id, ctx.now_ms / 1_000)
    {
        Ok(notes) => crate::actor_claims::craft_message_text(&notes),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), ?attempt_id, "a resident's craft did not read; it dreams without it");
            None
        }
    };
    let mut messages = vec![LlmMessage {
        role: LlmMessageRole::System,
        content: vec![ContentPart::Text {
            text: model.instruction.to_owned(),
        }],
    }];
    if let Some(text) = craft {
        messages.push(LlmMessage {
            role: LlmMessageRole::System,
            content: vec![ContentPart::Text { text }],
        });
    }
    messages.push(LlmMessage {
        role: LlmMessageRole::User,
        content: vec![ContentPart::Text {
            text: format!("{}\n\n{CRAFT_ASK}", cut.text()),
        }],
    });
    let request = LlmRequest {
        model: model.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            // Its dreaming is its own time (FIX 4453). Its own records leave
            // the vault as an extraction's do, so the call is admitted, gated
            // and routed as extraction: the tier below reads that row too.
            purpose: CallPurpose::AutonomyOwnTime,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("dreaming".into()),
            ),
            response_format: ResponseFormat::Text,
            locality,
        }
        .with_purpose_defaults(),
        messages,
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    let authorized = match model.role {
        Some(role) => ctx
            .vault
            .authorize_model_role(role, request, &model.inference)?,
        None => ctx
            .vault
            .authorize_raw_inference(request, &model.inference)?,
    };
    let mut request = authorized.into_request();
    super::roles::bind_reasoning(ctx.vault, model.backend, &mut request)?;
    let step_hash = request
        .canonical_hash()
        .map_err(|_| invalid("the dreaming request did not hash"))?;
    let step_ctx = DurableStepContext {
        vault: ctx.vault,
        attempt_id,
        run_id: attempt.status.attempt.run_id.clone(),
        envelope_actor: resident,
        subject: resident_id,
        deadline: Some(ctx.deadline),
        now_ms: ctx.now_ms,
    };
    let mut charges = StepChargeTally::default();
    let response = match call_as_step_checked(
        &step_ctx,
        model.backend,
        model.guard,
        request,
        &reply::check_diary_reply,
    )
    .await
    {
        Ok(StepOutcome::Finished { response, .. }) => {
            charges.record_terminal_metered(ctx, attempt_id, step_hash, &response.usage)?;
            response
        }
        Ok(StepOutcome::Trapped { .. }) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: "durable step trapped for resume".to_owned(),
                cause: DreamerParkCause::Signal,
            });
        }
        Err(DurableStepError::SpentFinalizeRefused { usage }) => {
            charges.record_usage(&usage);
            return Ok(charges.checkpoint());
        }
        Err(DurableStepError::DeadlineHardCut) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                cause: DreamerParkCause::Checkpoint,
            });
        }
        Err(DurableStepError::FinalizeRefused) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: "wake pass finalize window".to_owned(),
                cause: DreamerParkCause::Checkpoint,
            });
        }
        // An empty entry the check refused was paid and never memoized: it
        // is asked again after its retry delay (FIX 7431).
        Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
            charges.record_usage(&usage);
            return Ok(charges.park_for(&errors.join("; "), DreamerParkCause::Retry));
        }
        Err(DurableStepError::Engine(error)) => return Err(error),
        Err(other) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: other.to_string(),
                cause: DreamerParkCause::of_step(&other),
            });
        }
    };
    if ctx.deadline.expired() {
        return Ok(charges.checkpoint());
    }
    let (entry, craft) = match reply::diary_entry(&response) {
        Ok(read) => read,
        // Only a memo stored before the check can hold no entry: it goes,
        // and the Retry asks again (FIX 7431, OF-193a).
        Err(reason) => return charges.park_refused_reply(ctx.vault, attempt_id, step_hash, reason),
    };
    let now = ctx.now_ms / 1_000;
    // The entry, every part of it, its craft notes, its landing marker and
    // the progress it read commit in one write: a crash between them neither
    // drops the progress nor lands the entry twice.
    ctx.vault.with_write_txn_grouped(|txn| {
        if LANDED.contains(&ctx.vault.store, txn, &attempt_id)? {
            return Ok(());
        }
        let at = crate::ports::recorded_at_in_txn(&ctx.vault.store, txn)?;
        let entry_id = append_diary_entry_in_txn(ctx.vault, txn, resident, &entry, at)
            .map_err(|error| invalid(&format!("diary entry: {error}")))?;
        propose_craft_notes_in_txn(ctx.vault, txn, resident_id, attempt_id, &craft, at)?;
        LANDED.put(&ctx.vault.store, txn, &attempt_id, &entry_id)?;
        if let Some(binding) = &free_time {
            crate::dreamer_runner::record_own_time_landed_in_txn(ctx.vault, txn, binding, at)?;
        }
        for pad in &cut.pads {
            PADS.put(&ctx.vault.store, txn, &(resident_id, *pad), &[1])?;
        }
        let mut progress = PROGRESS
            .get(&ctx.vault.store, txn, &resident_id)?
            .unwrap_or_default();
        advance(
            &mut progress.receipts_after,
            &mut progress.receipt_after_id,
            cut.receipts_after.as_ref(),
        );
        advance(
            &mut progress.inbox_after,
            &mut progress.inbox_after_id,
            cut.inbox_after.as_ref(),
        );
        advance(
            &mut progress.health_after,
            &mut progress.health_after_id,
            cut.health_after.as_ref(),
        );
        advance(
            &mut progress.fork_health_after,
            &mut progress.fork_health_after_id,
            cut.fork_health_after.as_ref(),
        );
        // A part read moves its input's offset on; an input read to its end
        // (a pad marked read, a row the cursor passed) has none left.
        if let Some(partial) = &cut.pad_partial {
            progress.pad_partial = Some(partial.clone());
        } else if progress
            .pad_partial
            .as_ref()
            .is_some_and(|partial| cut.pads.iter().any(|pad| pad.to_hex() == partial.id))
        {
            progress.pad_partial = None;
        }
        if let Some(partial) = &cut.inbox_partial {
            progress.inbox_partial = Some(partial.clone());
        } else if progress.inbox_partial.as_ref().is_some_and(|partial| {
            (progress.inbox_after, progress.inbox_after_id.as_str())
                >= (partial.at, partial.id.as_str())
        }) {
            progress.inbox_partial = None;
        }
        progress.dreamed_at = now;
        progress.entries += 1;
        PROGRESS.put(&ctx.vault.store, txn, &resident_id, &progress)
    })?;
    // Its own digest renders from its dreaming, read as it, once this
    // dreaming's progress is committed (OF-499). A refused render leaves the
    // row to the deadline timer and fails no dreaming.
    if let Err(error) =
        ctx.vault
            .render_scheduled_weave_digest(resident_id, EdgeActorClass::Agent, now)
    {
        tracing::warn!(?error, "resident weave digest refused after dreaming");
    }
    Ok(DreamerAttemptExecution::Completed {
        completed_units: charges.units,
    })
}
