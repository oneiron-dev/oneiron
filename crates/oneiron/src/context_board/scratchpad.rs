//! The one session scratchpad (OF-548): a `scratchpad` NOTE per run, sealed
//! when its own session ends, projected as the SCRATCHPAD board section
//! (ARCH-0032 NoteKind defaults, `dr:P16`, #scratchpad-marks).
//!
//! The pad is a NOTE, so it is an entity: exact-author private admission,
//! BM25 and indexed-idle text, and the kind's AfterSeal/SessionSealed
//! defaults. This module keeps only what a NOTE has no field for: the pad
//! each (actor, session) writes and each pad's author and session. A pad
//! belongs to its own session or fork (FIX 9748): opening another session's
//! pad never seals it. The seal is the NOTE seal (`note/lifecycle.rs`), the
//! one seal authority every NOTE shares.
//! Line marks and pins have no NOTE body field either, so each line carries a
//! fixed engine-owned header the write door stamps and the projection reads
//! back: `[-]`, `[keep]`, `[scratch]`, `[pin]`, `[pin keep]`, `[pin scratch]`,
//! then one space, then the agent's text. Text after the header is never
//! read as a mark. A line edited outside this door that lacks a header reads
//! as unmarked and unpinned, whole.

use super::{
    BoardFrameError, BoardSection, MAX_BOARD_ROW_BYTES, SectionPolicy, ShedRank, one_line_token,
    quoted_leaf,
};
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
};
use crate::note::{NoteProgramEdit, NoteProgramEditOutcome};
use crate::side_table::{self, Named, SideKey, SideTable};
use serde::{Deserialize, Serialize};
use std::ops::Range;

/// The registered NOTE kind every pad is born as.
const PAD_KIND: &str = "scratchpad";

/// Longest line the write door takes, in bytes: a quarter of the board row
/// ceiling, so the quoted, fully escaped line and its engine tokens still fit
/// one [`MAX_BOARD_ROW_BYTES`] row.
pub const SCRATCHPAD_LINE_MAX_BYTES: usize = MAX_BOARD_ROW_BYTES / 4;

/// Longest session id a pad is keyed by: the board cursor's session bound.
const SESSION_MAX_BYTES: usize = 256;

/// The newest unpinned lines the board shows in full.
const NEWEST_FULL: usize = 8;
/// Older lines the board folds to their first words; the rest are counted.
const FOLDED_SHOWN: usize = 16;
/// The words an older line folds to.
const FOLD_WORDS: usize = 6;
/// The newest matching lines one recall returns in full; the rest are
/// counted.
pub const SCRATCHPAD_RECALL_LINES: usize = 16;

/// Every line header, brackets excluded, with the mark and pin it stands for.
/// The write door stamps one; nothing outside this list is a header.
const HEADERS: [(&str, Option<ScratchpadMark>, bool); 6] = [
    ("-", None, false),
    ("keep", Some(ScratchpadMark::Keep), false),
    ("scratch", Some(ScratchpadMark::Scratch), false),
    ("pin", None, true),
    ("pin keep", Some(ScratchpadMark::Keep), true),
    ("pin scratch", Some(ScratchpadMark::Scratch), true),
];

const TAG_SESSION: u8 = 1;
const TAG_PAD: u8 = 3;

/// Scratchpad pointers. Key: one tag byte, then an id, then (for a session
/// pointer) the session bytes; see [`PadKey`].
const PAD: SideTable<PadKey, PadRow, Named> = SideTable::new(&side_table::CONTEXT_BOARD_SCRATCHPAD);

#[derive(Clone, Debug, PartialEq, Eq)]
enum PadKey {
    /// The pad one (actor, session) writes: tag 1 ‖ actor ‖ session bytes.
    /// The one pointer a live pad has (FIX 9748).
    Session { actor: EntityId, session: String },
    /// Every pad, written at its birth: tag 3 ‖ pad NOTE id.
    Pad { pad: EntityId },
}

impl SideKey for PadKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Session { actor, session } => {
                out.push(TAG_SESSION);
                out.extend_from_slice(actor.as_bytes());
                out.extend_from_slice(session.as_bytes());
            }
            Self::Pad { pad } => {
                out.push(TAG_PAD);
                out.extend_from_slice(pad.as_bytes());
            }
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (&tag, rest) = bytes.split_first()?;
        let (id, rest) = rest.split_at_checked(16)?;
        let id = EntityId::from_bytes(id.try_into().ok()?).ok()?;
        match tag {
            TAG_SESSION if !rest.is_empty() => Some(Self::Session {
                actor: id,
                session: std::str::from_utf8(rest).ok()?.to_owned(),
            }),
            TAG_PAD if rest.is_empty() => Some(Self::Pad { pad: id }),
            _ => None,
        }
    }
}

/// One pad: its author, the session that writes it, and its NOTE.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PadRow {
    actor: [u8; 16],
    session: String,
    pad: [u8; 16],
}

/// An optional line mark (ARCH-0032 #scratchpad-marks). After the seal the
/// Dreamer extracts every `keep` line, never a `scratch` line, and decides
/// each unmarked one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScratchpadMark {
    Keep,
    Scratch,
}

/// What one append wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScratchpadAppendReceipt {
    /// The pad NOTE the line landed in.
    pub pad: EntityId,
    /// This line opened the pad: it was the session's first.
    pub opened: bool,
    /// This session's earlier pad, sealed because a racing first line of the
    /// same session opened this one. Another session's pad is never sealed
    /// here (FIX 9748), so it is `None` otherwise.
    pub sealed_prior: Option<EntityId>,
}

/// The SCRATCHPAD section of one session's live pad.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScratchpadBoard {
    /// The pad NOTE the section was read from.
    pub pad: EntityId,
    pub section: BoardSection,
}

/// One pad line a recall matched, in full, folded or not on the board.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScratchpadRecallLine {
    /// The line's place in the pad, from 0 for the oldest.
    pub index: usize,
    pub mark: Option<ScratchpadMark>,
    pub pin: bool,
    pub text: String,
}

/// What a recall over one session's pad found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScratchpadRecall {
    /// The pad NOTE searched.
    pub pad: EntityId,
    pub sealed: bool,
    /// How many lines matched; `lines` holds the newest
    /// [`SCRATCHPAD_RECALL_LINES`] of them, newest first.
    pub matched: usize,
    pub lines: Vec<ScratchpadRecallLine>,
}

/// One stored pad line.
struct PadLine<'a> {
    mark: Option<ScratchpadMark>,
    pin: bool,
    text: &'a str,
}

fn parse_line(line: &str) -> PadLine<'_> {
    line.strip_prefix('[')
        .and_then(|rest| rest.split_once("] "))
        .and_then(|(head, text)| {
            HEADERS
                .iter()
                .find(|(name, _, _)| *name == head)
                .map(|&(_, mark, pin)| PadLine { mark, pin, text })
        })
        .unwrap_or(PadLine {
            mark: None,
            pin: false,
            text: line,
        })
}

/// A sealed pad's markdown as the Dreamer's after-seal review reads it
/// (ARCH-0032 #scratchpad-marks): every `scratch` line blanked to spaces, so
/// it never reaches the model and every byte offset still indexes the stored
/// markdown. With it, the byte range of each `keep` line's text (after its
/// header) that holds any text.
pub(crate) fn sealed_pad_review_text(markdown: &str) -> (String, Vec<Range<usize>>) {
    let mut text = String::with_capacity(markdown.len());
    let mut keep = Vec::new();
    let mut at = 0;
    for line in markdown.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let parsed = parse_line(body);
        match parsed.mark {
            Some(ScratchpadMark::Scratch) => {
                text.extend(std::iter::repeat_n(' ', body.len()));
                text.push_str(&line[body.len()..]);
            }
            mark => {
                if mark == Some(ScratchpadMark::Keep) && !parsed.text.trim().is_empty() {
                    keep.push(at + body.len() - parsed.text.len()..at + body.len());
                }
                text.push_str(line);
            }
        }
        at += line.len();
    }
    (text, keep)
}

/// A sealed pad's markdown as the review's one re-ask reads it (FIX 2240):
/// only the lines holding a `missed` range stay; every other line is
/// blanked to spaces, so every byte offset still indexes the stored
/// markdown.
pub(crate) fn sealed_pad_reask_text(markdown: &str, missed: &[Range<usize>]) -> String {
    let mut text = String::with_capacity(markdown.len());
    let mut at = 0;
    for line in markdown.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let end = at + body.len();
        if missed
            .iter()
            .any(|range| at <= range.start && range.end <= end)
        {
            text.push_str(line);
        } else {
            text.extend(std::iter::repeat_n(' ', body.len()));
            text.push_str(&line[body.len()..]);
        }
        at += line.len();
    }
    text
}

fn mark_token(mark: Option<ScratchpadMark>) -> &'static str {
    match mark {
        None => "",
        Some(ScratchpadMark::Keep) => " keep",
        Some(ScratchpadMark::Scratch) => " scratch",
    }
}

/// At most `max` bytes of `text`, cut on a char boundary.
pub(super) fn clip(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn full_row(kind: &str, line: &PadLine<'_>) -> String {
    format!(
        "{kind}{} {}",
        mark_token(line.mark),
        quoted_leaf(clip(line.text, SCRATCHPAD_LINE_MAX_BYTES))
    )
}

fn fold_row(line: &PadLine<'_>) -> String {
    let mut words = line.text.split_whitespace();
    let mut head = words
        .by_ref()
        .take(FOLD_WORDS)
        .collect::<Vec<_>>()
        .join(" ");
    if words.next().is_some() {
        head.push('…');
    }
    format!(
        "fold{} {}",
        mark_token(line.mark),
        quoted_leaf(clip(&head, SCRATCHPAD_LINE_MAX_BYTES))
    )
}

/// Every pinned line in full in the section's never-shed floor, beside the
/// reader line, so the agent always sees who can read its pad and what it
/// pinned (FIX 8146). Of the unpinned lines, the newest show in full, older
/// ones fold to their first words and the rest count as `older: +N`.
fn pad_section(
    pad: EntityId,
    text: &str,
    readers: String,
) -> Result<BoardSection, BoardFrameError> {
    let lines: Vec<PadLine<'_>> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_line)
        .collect();
    let mut floor = vec![readers];
    floor.extend(
        lines
            .iter()
            .filter(|line| line.pin)
            .map(|line| full_row("pin", line)),
    );
    let unpinned: Vec<&PadLine<'_>> = lines.iter().filter(|line| !line.pin).collect();
    let newest = unpinned.len().saturating_sub(NEWEST_FULL);
    let hidden = newest.saturating_sub(FOLDED_SHOWN);
    let mut rows = vec![format!("pad: {} lines: {}", pad.to_hex(), lines.len())];
    if hidden > 0 {
        rows.push(format!("older: +{hidden}"));
    }
    rows.extend(unpinned[hidden..newest].iter().map(|line| fold_row(line)));
    rows.extend(unpinned[newest..].iter().map(|line| full_row("line", line)));
    BoardSection::new(
        "SCRATCHPAD",
        floor,
        rows,
        vec![format!("count: {}", lines.len())],
        SectionPolicy {
            pinned: false,
            shed_rank: Some(ShedRank::PluginSections),
        },
    )
}

/// The words a recall query asks for: case-folded, each once.
fn recall_words(query: &str) -> Vec<String> {
    let mut words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    words.sort();
    words.dedup();
    words
}

/// Whether a pad line answers a recall: its text holds every query word,
/// case-folded. The one match rule, so a later ruling (ranked, any-word)
/// changes it here.
fn recall_matches(text: &str, words: &[String]) -> bool {
    let text = text.to_lowercase();
    words.iter().all(|word| text.contains(word.as_str()))
}

fn validate_session(session: &str) -> MemoryResult<()> {
    if session.trim().is_empty() || session.len() > SESSION_MAX_BYTES {
        return Err(MemoryError::bad_request(format!(
            "scratchpad session must be 1 to {SESSION_MAX_BYTES} bytes"
        )));
    }
    Ok(())
}

fn corrupt_pad() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        "scratchpad pointer does not match its pad",
        &["Report this scratchpad state."],
    )
}

fn sealed_pad() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "this session's scratchpad is sealed",
        &["A sealed pad takes no writes; the next run opens a new pad."],
    )
}

impl crate::Vault {
    /// The pads `actor` wrote that are sealed, in key order: what its own
    /// dreaming reads (OF-490).
    pub(crate) fn sealed_scratchpads_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
    ) -> crate::error::Result<Vec<EntityId>> {
        let mut sealed = Vec::new();
        for (key, row) in PAD.scan_from(&self.store, txn, &[TAG_PAD])? {
            if let PadKey::Pad { pad } = key
                && row.actor == *actor.as_bytes()
                && crate::note::note_sealed_in_txn(&self.store, txn, pad)?
            {
                sealed.push(pad);
            }
        }
        Ok(sealed)
    }

    /// Whether `pad` is a scratchpad and sealed: the gate an after-seal
    /// extraction reads (ARCH-0032 NoteKind defaults).
    pub fn scratchpad_sealed(&self, pad: EntityId) -> crate::error::Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.scratchpad_sealed_in_txn(&txn, pad)
    }

    /// [`Self::scratchpad_sealed`] inside the caller's read.
    pub(crate) fn scratchpad_sealed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        pad: EntityId,
    ) -> crate::error::Result<bool> {
        Ok(PAD.contains(&self.store, txn, &PadKey::Pad { pad })?
            && crate::note::note_sealed_in_txn(&self.store, txn, pad)?)
    }
}

/// The pointer rows an erase of `id` purges: each session pointer
/// `id` writes as the actor or names as its pad, and pad `id`'s own row. An
/// erased author's pads keep their rows and seals: each pad is its own NOTE
/// and stays a sealed pad until it is erased itself.
fn rows_erased_with(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> crate::error::Result<Vec<PadKey>> {
    Ok(PAD
        .scan(&vault.store, txn)?
        .into_iter()
        .filter(|(key, row)| match key {
            PadKey::Session { actor, .. } => actor == id || row.pad == *id.as_bytes(),
            PadKey::Pad { pad } => pad == id,
        })
        .map(|(key, _)| key)
        .collect())
}

/// Seals `pad` through the NOTE seal, unless it was deleted or archived
/// since: such a pad is past sealing, and its pointers move on all the same.
fn seal_pad_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    pad: EntityId,
    actor: EntityId,
) -> crate::error::Result<()> {
    if !crate::ports::TombstoneStore::port_tombstone_is_deleted(vault, txn, &pad)? {
        crate::note::seal_note_in_txn(vault, txn, pad, actor)?;
    }
    Ok(())
}

/// Seals the pad `actor`'s session `session` writes, in the caller's write,
/// when that session ends (FIX 9748): that pad alone, never another
/// session's. `None` when the session has no pad.
pub(crate) fn seal_session_pad_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    session: &str,
) -> crate::error::Result<Option<EntityId>> {
    let key = PadKey::Session {
        actor,
        session: session.to_owned(),
    };
    let Some(row) = PAD.get(&vault.store, txn, &key)? else {
        return Ok(None);
    };
    let pad = EntityId::from_bytes(row.pad)?;
    seal_pad_in_txn(vault, txn, pad, actor)?;
    Ok(Some(pad))
}

/// Whether an erase of `id` has scratchpad rows to purge.
pub(crate) fn scratchpad_erase_scope_exists(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> crate::error::Result<bool> {
    Ok(!rows_erased_with(vault, txn, id)?.is_empty())
}

/// Purges the scratchpad rows naming erased actor or NOTE `id` (OF-548), so
/// an erased pad leaves no pointer behind: the session's next line opens a
/// new pad instead of failing on the missing one. `true` when a row went.
pub(crate) fn erase_scratchpad_rows_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> crate::error::Result<bool> {
    let mut removed = false;
    for key in rows_erased_with(vault, txn, id)? {
        removed |= PAD.delete(&vault.store, txn, &key)?;
    }
    Ok(removed)
}

impl Memory<'_> {
    /// The pad this actor's session writes, and whether it is sealed.
    fn scratchpad_pointer(&self, session: &str) -> MemoryResult<Option<(EntityId, bool)>> {
        let store = &self.vault().store;
        let txn = store.env.read_txn().map_err(crate::error::Error::from)?;
        let key = PadKey::Session {
            actor: self.actor(),
            session: session.to_owned(),
        };
        let Some(row) = PAD.get(store, &txn, &key)? else {
            return Ok(None);
        };
        if row.actor != *self.actor().as_bytes() || row.session != session {
            return Err(corrupt_pad());
        }
        let pad = EntityId::from_bytes(row.pad)?;
        let sealed = crate::note::note_sealed_in_txn(store, &txn, pad)?;
        Ok(Some((pad, sealed)))
    }

    /// Appends one line to this session's live pad. The session's first line
    /// births a new `scratchpad` NOTE: a new pad per run (`dr:P16`), each
    /// session's or fork's its own, so another session's pad, live or not,
    /// is never sealed here (FIX 9748). A sealed pad refuses writes. The
    /// mark and pin ride the line as its header.
    pub fn scratchpad_append(
        &self,
        session: &str,
        text: &str,
        mark: Option<ScratchpadMark>,
        pin: bool,
    ) -> MemoryResult<ScratchpadAppendReceipt> {
        validate_session(session)?;
        let text = one_line_token(text);
        let text = text.trim();
        if text.is_empty() || text.len() > SCRATCHPAD_LINE_MAX_BYTES {
            return Err(MemoryError::bad_request(format!(
                "scratchpad line must be 1 to {SCRATCHPAD_LINE_MAX_BYTES} bytes"
            )));
        }
        let head = HEADERS
            .iter()
            .find(|&&(_, line_mark, line_pin)| line_mark == mark && line_pin == pin)
            .map_or("-", |&(name, _, _)| name);
        let line = format!("[{head}] {text}\n");
        if let Some((pad, sealed)) = self.scratchpad_pointer(session)? {
            if sealed {
                return Err(sealed_pad());
            }
            let doc = self
                .vault()
                .note_program_document(pad)?
                .ok_or_else(corrupt_pad)?;
            let end = doc.anchor(doc.text().chars().count())?;
            let outcome = self.edit_note(
                &pad.to_hex(),
                &NoteProgramEdit::InsertAfter {
                    anchor: end,
                    text: line,
                },
            )?;
            if !matches!(outcome, NoteProgramEditOutcome::Edited { .. }) {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "scratchpad line did not land on the live pad",
                    &["Only the pad's author writes its pad."],
                ));
            }
            return Ok(ScratchpadAppendReceipt {
                pad,
                opened: false,
                sealed_prior: None,
            });
        }
        let pad = EntityId::from_hex(&self.create_note(PAD_KIND, &line)?.id_hex)?;
        let actor = self.actor();
        let row = PadRow {
            actor: *actor.as_bytes(),
            session: session.to_owned(),
            pad: *pad.as_bytes(),
        };
        let sealed_prior = self.with_verified_actor_write_txn(|txn| {
            let store = &self.vault().store;
            // Two first lines racing for one session both birth a pad; the
            // later commit seals the earlier, so the session still holds one.
            // Only this session's own pointer is read: no other session's
            // pad is sealed.
            let prior = seal_session_pad_in_txn(self.vault(), txn, actor, session)?;
            PAD.put(store, txn, &PadKey::Pad { pad }, &row)?;
            let session = PadKey::Session {
                actor,
                session: session.to_owned(),
            };
            PAD.put(store, txn, &session, &row)?;
            Ok(prior)
        })?;
        Ok(ScratchpadAppendReceipt {
            pad,
            opened: true,
            sealed_prior,
        })
    }

    /// Seals this session's pad at the end of its run: it takes no more
    /// writes, leaves the live board, and stays a referenceable NOTE.
    /// Sealing a sealed pad changes nothing; a session without a pad seals
    /// nothing and returns `None`. Only this session's own pad is sealed.
    pub fn scratchpad_seal(&self, session: &str) -> MemoryResult<Option<EntityId>> {
        validate_session(session)?;
        let actor = self.actor();
        self.with_verified_actor_write_txn(|txn| {
            Ok(seal_session_pad_in_txn(self.vault(), txn, actor, session)?)
        })
    }

    /// The SCRATCHPAD section of this session's live pad, read through the
    /// actor's own scoped read, which admits a pad to its exact author only.
    /// `None` when the session has no pad, its pad is sealed, or the read
    /// withholds it.
    pub fn scratchpad_board_section(&self, session: &str) -> MemoryResult<Option<ScratchpadBoard>> {
        validate_session(session)?;
        let Some((pad, false)) = self.scratchpad_pointer(session)? else {
            return Ok(None);
        };
        let Some(text) = self.pad_markdown(pad)? else {
            return Ok(None);
        };
        let readers = super::readers::sealed_pad_readers_line(&self.sealed_pad_readers()?);
        let section = pad_section(pad, &text, readers).map_err(|error| {
            MemoryError::new(
                MEMORY_CODE_INTERNAL,
                error.to_string(),
                &["Report this scratchpad render."],
            )
        })?;
        Ok(Some(ScratchpadBoard { pad, section }))
    }

    /// Searches the whole of this session's pad, folded lines included, for
    /// the lines that hold every word of `query` (ARCH-0032
    /// #scratchpad-marks: a recall searches the whole pad), read through the
    /// actor's own scoped read. A sealed pad is still its session's to
    /// search. `None` when the session has no pad or the read withholds it.
    pub fn scratchpad_recall(
        &self,
        session: &str,
        query: &str,
    ) -> MemoryResult<Option<ScratchpadRecall>> {
        validate_session(session)?;
        let words = recall_words(query);
        if words.is_empty() || query.len() > SCRATCHPAD_LINE_MAX_BYTES {
            return Err(MemoryError::bad_request(format!(
                "scratchpad recall query must be 1 to {SCRATCHPAD_LINE_MAX_BYTES} bytes of words"
            )));
        }
        let Some((pad, sealed)) = self.scratchpad_pointer(session)? else {
            return Ok(None);
        };
        let Some(text) = self.pad_markdown(pad)? else {
            return Ok(None);
        };
        let matching: Vec<(usize, PadLine<'_>)> = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(parse_line)
            .enumerate()
            .filter(|(_, line)| recall_matches(line.text, &words))
            .collect();
        let lines = matching
            .iter()
            .rev()
            .take(SCRATCHPAD_RECALL_LINES)
            .map(|(index, line)| ScratchpadRecallLine {
                index: *index,
                mark: line.mark,
                pin: line.pin,
                text: line.text.to_owned(),
            })
            .collect();
        Ok(Some(ScratchpadRecall {
            pad,
            sealed,
            matched: matching.len(),
            lines,
        }))
    }

    /// The markdown of pad `pad`, read as this actor, which admits a pad to
    /// its exact author only. `None` when the read withholds it or the NOTE
    /// is not a pad.
    fn pad_markdown(&self, pad: EntityId) -> MemoryResult<Option<String>> {
        let Some(view) = self.get_entity_tolerant(&pad.to_hex())?.value else {
            return Ok(None);
        };
        Ok(view
            .body
            .as_ref()
            .filter(|body| body["kind"] == PAD_KIND)
            .and_then(|body| body["markdown"].as_str())
            .map(str::to_owned))
    }
}
