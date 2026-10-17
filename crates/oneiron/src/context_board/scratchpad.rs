//! The one session scratchpad (OF-548): a `scratchpad` NOTE per run, sealed
//! at its end and rotated on the next, projected as the SCRATCHPAD board
//! section (ARCH-0032 NoteKind defaults, `dr:P16`, #scratchpad-marks).
//!
//! The pad is a NOTE, so it is an entity: exact-author private admission,
//! BM25 and indexed-idle text, and the kind's AfterSeal/SessionSealed
//! defaults. This module keeps only what a NOTE has no field for: the pad
//! each (actor, session) writes, the actor's one unsealed pad, and the seal.
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

/// The registered NOTE kind every pad is born as.
const PAD_KIND: &str = "scratchpad";

/// Longest line the write door takes, in bytes: a quarter of the board row
/// ceiling, so the quoted, fully escaped line and its engine tokens still fit
/// one [`MAX_BOARD_ROW_BYTES`] row.
pub const SCRATCHPAD_LINE_MAX_BYTES: usize = MAX_BOARD_ROW_BYTES / 4;

/// Longest session id a pad is keyed by: the board cursor's session bound.
const SESSION_MAX_BYTES: usize = 256;

/// The newest lines the board shows in full.
const NEWEST_FULL: usize = 8;
/// Older pinned lines the board shows in full; earlier pins fold.
const PINNED_FULL: usize = 16;
/// Older lines the board folds to their first words; the rest are counted.
const FOLDED_SHOWN: usize = 16;
/// The words an older line folds to.
const FOLD_WORDS: usize = 6;

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
const TAG_LIVE: u8 = 2;
const TAG_SEALED: u8 = 3;

/// Scratchpad pointers and seals. Key: one tag byte, then an id, then (for a
/// session pointer) the session bytes; see [`PadKey`].
const PAD: SideTable<PadKey, PadRow, Named> = SideTable::new(&side_table::CONTEXT_BOARD_SCRATCHPAD);

#[derive(Clone, Debug, PartialEq, Eq)]
enum PadKey {
    /// The pad one (actor, session) writes: tag 1 ‖ actor ‖ session bytes.
    Session { actor: EntityId, session: String },
    /// The actor's one unsealed pad: tag 2 ‖ actor.
    Live { actor: EntityId },
    /// A sealed pad: tag 3 ‖ pad NOTE id.
    Sealed { pad: EntityId },
}

impl SideKey for PadKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Session { actor, session } => {
                out.push(TAG_SESSION);
                out.extend_from_slice(actor.as_bytes());
                out.extend_from_slice(session.as_bytes());
            }
            Self::Live { actor } => {
                out.push(TAG_LIVE);
                out.extend_from_slice(actor.as_bytes());
            }
            Self::Sealed { pad } => {
                out.push(TAG_SEALED);
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
            TAG_LIVE if rest.is_empty() => Some(Self::Live { actor: id }),
            TAG_SEALED if rest.is_empty() => Some(Self::Sealed { pad: id }),
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
    /// The actor's prior unsealed pad, sealed because this line opened a new one.
    pub sealed_prior: Option<EntityId>,
}

/// The SCRATCHPAD section of one session's live pad.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScratchpadBoard {
    /// The pad NOTE the section was read from.
    pub pad: EntityId,
    pub section: BoardSection,
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

fn mark_token(mark: Option<ScratchpadMark>) -> &'static str {
    match mark {
        None => "",
        Some(ScratchpadMark::Keep) => " keep",
        Some(ScratchpadMark::Scratch) => " scratch",
    }
}

/// At most `max` bytes of `text`, cut on a char boundary.
fn clip(text: &str, max: usize) -> &str {
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

/// Pinned and newest lines in full, older lines folded to their first words
/// and the rest counted as `older: +N`. The reader line is the section's
/// pinned floor: the agent always sees who can read its pad.
fn pad_section(pad: EntityId, text: &str) -> Result<BoardSection, BoardFrameError> {
    let lines: Vec<PadLine<'_>> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_line)
        .collect();
    let newest = lines.len().saturating_sub(NEWEST_FULL);
    let mut pinned: Vec<usize> = (0..newest).filter(|&index| lines[index].pin).collect();
    let pinned = pinned.split_off(pinned.len().saturating_sub(PINNED_FULL));
    let older: Vec<usize> = (0..newest)
        .filter(|index| !pinned.contains(index))
        .collect();
    let hidden = older.len().saturating_sub(FOLDED_SHOWN);
    let mut rows = vec![format!("pad: {} lines: {}", pad.to_hex(), lines.len())];
    rows.extend(pinned.iter().map(|&index| full_row("pin", &lines[index])));
    if hidden > 0 {
        rows.push(format!("older: +{hidden}"));
    }
    rows.extend(older[hidden..].iter().map(|&index| fold_row(&lines[index])));
    rows.extend(
        lines[newest..]
            .iter()
            .map(|line| full_row(if line.pin { "pin" } else { "line" }, line)),
    );
    BoardSection::new(
        "SCRATCHPAD",
        vec!["readers: owner-only".to_owned()],
        rows,
        vec![format!("count: {}", lines.len())],
        SectionPolicy {
            pinned: false,
            shed_rank: Some(ShedRank::PluginSections),
        },
    )
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
        Ok(PAD
            .scan_from(&self.store, txn, &[TAG_SEALED])?
            .into_iter()
            .filter_map(|(key, row)| match key {
                PadKey::Sealed { pad } if row.actor == *actor.as_bytes() => Some(pad),
                _ => None,
            })
            .collect())
    }

    /// Whether `pad` is a scratchpad this door sealed: the gate an
    /// after-seal extraction reads (ARCH-0032 NoteKind defaults).
    pub fn scratchpad_sealed(&self, pad: EntityId) -> crate::error::Result<bool> {
        let txn = self.store.env.read_txn()?;
        PAD.contains(&self.store, &txn, &PadKey::Sealed { pad })
    }
}

/// The pointer and seal rows an erase of `id` purges: each session and live
/// pointer `id` writes as the actor or names as its pad, and the seal of pad
/// `id`. An erased author's sealed pads keep their seals: each pad is its own
/// NOTE and stays sealed until it is erased itself.
fn rows_erased_with(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> crate::error::Result<Vec<PadKey>> {
    Ok(PAD
        .scan(&vault.store, txn)?
        .into_iter()
        .filter(|(key, row)| match key {
            PadKey::Session { actor, .. } | PadKey::Live { actor } => {
                actor == id || row.pad == *id.as_bytes()
            }
            PadKey::Sealed { pad } => pad == id,
        })
        .map(|(key, _)| key)
        .collect())
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
        let sealed = PAD.contains(store, &txn, &PadKey::Sealed { pad })?;
        Ok(Some((pad, sealed)))
    }

    /// Appends one line to this session's live pad. The session's first line
    /// births a new `scratchpad` NOTE and seals the actor's prior unsealed
    /// pad: one live pad per actor, a new one per run (`dr:P16`). A sealed
    /// pad refuses writes. The mark and pin ride the line as its header.
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
            // later commit seals the earlier, so the actor still holds one.
            let prior = match PAD.get(store, txn, &PadKey::Live { actor })? {
                Some(live) => {
                    let prior = EntityId::from_bytes(live.pad)?;
                    PAD.put(store, txn, &PadKey::Sealed { pad: prior }, &live)?;
                    Some(prior)
                }
                None => None,
            };
            let session = PadKey::Session {
                actor,
                session: session.to_owned(),
            };
            PAD.put(store, txn, &session, &row)?;
            PAD.put(store, txn, &PadKey::Live { actor }, &row)?;
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
    /// nothing and returns `None`.
    pub fn scratchpad_seal(&self, session: &str) -> MemoryResult<Option<EntityId>> {
        validate_session(session)?;
        let actor = self.actor();
        self.with_verified_actor_write_txn(|txn| {
            let store = &self.vault().store;
            let key = PadKey::Session {
                actor,
                session: session.to_owned(),
            };
            let Some(row) = PAD.get(store, txn, &key)? else {
                return Ok(None);
            };
            let pad = EntityId::from_bytes(row.pad)?;
            PAD.put(store, txn, &PadKey::Sealed { pad }, &row)?;
            if PAD
                .get(store, txn, &PadKey::Live { actor })?
                .is_some_and(|live| live.pad == row.pad)
            {
                PAD.delete(store, txn, &PadKey::Live { actor })?;
            }
            Ok(Some(pad))
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
        let Some(view) = self.get_entity(&pad.to_hex())?.value else {
            return Ok(None);
        };
        let Some(text) = view
            .body
            .as_ref()
            .filter(|body| body["kind"] == PAD_KIND)
            .and_then(|body| body["markdown"].as_str())
        else {
            return Ok(None);
        };
        let section = pad_section(pad, text).map_err(|error| {
            MemoryError::new(
                MEMORY_CODE_INTERNAL,
                error.to_string(),
                &["Report this scratchpad render."],
            )
        })?;
        Ok(Some(ScratchpadBoard { pad, section }))
    }
}
