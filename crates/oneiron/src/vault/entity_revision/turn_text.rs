//! A TURN's text revision: the revision that pins the words a turn serves.
//!
//! A TURN's text is its messages' (ARCH-0004), which its own row does not
//! hold, so the row's revision pins none of it. The text revision commits to
//! the row revision read and to the state of each source message whose text
//! it joins (ARCH-0002: one frontier per source): the message's stored row
//! and, for a message whose text lives in an entity document, that
//! document's frontier. One text revision is one set of words; an edit to
//! any source makes another.
//!
//! A read pinned at a text revision serves the words it was read with, at
//! whichever retained revision of the turn's row it named. Each source is
//! found again among the states its own history retains: a row-backed
//! message's retained row revisions, and a document-backed one's retained
//! document states, never its rows from before the move, which a purge of
//! the document's history does not reach. The row revisions its document
//! took over at its birth stand for it as their rows did, their words read
//! from the document at the state each names. Every retained state of every
//! source is searched. A message the turn gained since, or one that showed
//! no text at some state, may read as absent. A source that was erased,
//! archived or purged since is not found, and the revision then resolves to
//! nothing, as a pin whose revision is gone does: it never serves other
//! words under the revision it showed.
//!
//! The revision's first two bytes hint at its turn and its third is its row
//! revision's first, so a pin of another turn, or of a row this turn never
//! had, is refused before any source is read.

use super::storage::{
    entity_owns_revision_in_txn, reference, retained_rows_in_txn, row_aliases_in_txn,
    row_revisions_starting_with_in_txn, state,
};
use super::{ReadMode, RevisionRef};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::side_table::{self, HexId, Named, SideTable};
use crate::store::ManifestDbs;
use crate::{EntityId, Vault};
use heed::RoTxn;

/// Entity-document heads: which messages' words live in a document.
const DOCUMENT_HEADS: SideTable<HexId, rmpv::Value, Named> =
    SideTable::new(&side_table::ENTITY_DOC_HEAD);

#[cfg(test)]
thread_local! {
    /// Searches past a turn's current sources, which a check counts.
    pub(crate) static HISTORY_SEARCHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The words a read of a TURN serves, under the revision that pins them.
pub(crate) struct TurnText {
    /// The text revision; the row's own for a turn whose messages show no
    /// text, which its row revision pins whole.
    pub(crate) revision: RevisionRef,
    /// Each source message the revision joins, with its text there and the
    /// body that text is read from (empty unless the read was for release),
    /// in message order. Every reader is given only those it may read.
    pub(crate) messages: Vec<(EntityId, String, Vec<u8>)>,
}

impl TurnText {
    /// The messages a door that releases the words gives the reader
    /// `readable` admits, from a read for release. A turn's text is its
    /// messages' words without the rest of their bodies, so a message whose
    /// body the write door refuses gives none: the body its words are read
    /// from, its document's text in it, at the state the revision read, as a
    /// lossy door withholds a refused body whole. A message with no body kept
    /// gives none either. Words the write door's text rules refuse are given
    /// by none.
    pub(crate) fn released(
        self,
        mut readable: impl FnMut(&EntityId) -> Result<bool>,
    ) -> Result<Vec<(EntityId, String)>> {
        let mut messages = Vec::with_capacity(self.messages.len());
        for (id, words, body) in self.messages {
            if readable(&id)?
                && !body.is_empty()
                && !crate::batch::export::write_door_refuses_body(&body)
                && !crate::batch::secret_scan::write_door_refuses_raw(words.as_bytes())
            {
                messages.push((id, words));
            }
        }
        Ok(messages)
    }
}

/// The words a read of `turn` at `mode` serves and the text revision that
/// pins them. A pin at one of the row's own revisions reads the current
/// words; a pin at a text revision reads the words it was served with, or
/// nothing once they can no longer be found. `None` also for a turn that is
/// gone or archived. `store` is the content read: the vault's own, or a
/// room's view, whose turns and messages compose with base. A read for a
/// door that releases the words (`release`) keeps each message's body for
/// [`TurnText::released`]; any other read keeps none.
pub(crate) fn served_turn_text_in_txn(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    mode: ReadMode,
    release: bool,
) -> Result<Option<TurnText>> {
    let row = match mode {
        ReadMode::Pinned(revision) => {
            if !entity_owns_revision_in_txn(store, txn, turn, revision)? {
                return Ok(resolve_in_txn(vault, store, txn, turn, revision, release)?
                    .map(|(_, messages)| TurnText { revision, messages }));
            }
            revision
        }
        ReadMode::Live | ReadMode::Indexed => {
            let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, turn)?
            else {
                return Ok(None);
            };
            state(store, txn, turn)?.map_or_else(
                || reference(turn, &raw),
                |current| match mode {
                    ReadMode::Indexed => current.indexed,
                    _ => current.live,
                },
            )
        }
    };
    let Some(sources) = current_sources_in_txn(vault, store, txn, turn, release)? else {
        return Ok(None);
    };
    let revision = if sources.is_empty() {
        row
    } else {
        text_revision(
            turn,
            row,
            &digest(sources.iter().map(|(id, state)| (id, &state.commitment))),
        )
    };
    Ok(Some(TurnText {
        revision,
        messages: sources
            .into_iter()
            .map(|(id, state)| (id, state.text, state.body))
            .collect(),
    }))
}

/// The row revision `revision` was read at, when it is a text revision of
/// `turn` whose words can still be found. The row may have moved since; any
/// revision of it the vault retains still resolves.
pub(crate) fn turn_row_for_text_revision_in_txn(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    revision: RevisionRef,
) -> Result<Option<RevisionRef>> {
    Ok(resolve_in_txn(vault, store, txn, turn, revision, false)?.map(|(row, _)| row))
}

/// One state of a source message: what a text revision commits to for it,
/// the text it shows there, and its body there, that text read from it.
struct SourceState {
    commitment: Vec<u8>,
    text: String,
    body: Vec<u8>,
}

/// The row revision and words `revision` was served with: the turn's current
/// sources first, then each set its sources' retained states can make.
fn resolve_in_txn(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    revision: RevisionRef,
    release: bool,
) -> Result<Option<Served>> {
    if revision.0[..2] != turn_hint(turn) {
        return Ok(None);
    }
    let rows = row_revisions_starting_with_in_txn(store, txn, turn, revision.0[2])?;
    if rows.is_empty() {
        return Ok(None);
    }
    let Some(members) = crate::tagging::turn_members_in_txn(vault, store, txn, turn, release)?
    else {
        return Ok(None);
    };
    let target = Target {
        turn,
        revision,
        rows,
    };
    let mut current = Vec::with_capacity(members.len());
    for (id, text, body) in members {
        let state = current_state_in_txn(vault, store, txn, &id, text, body)?;
        current.push((id, state));
    }
    let now: Vec<_> = current
        .iter()
        .filter_map(|(id, state)| Some((*id, state.as_ref()?)))
        .collect();
    if let Some(served) = target.served(&now) {
        return Ok(Some(served));
    }
    #[cfg(test)]
    HISTORY_SEARCHES.with(|count| count.set(count.get() + 1));
    let mut sources = Vec::with_capacity(current.len());
    for (id, state) in current {
        sources.push(source_in_txn(vault, store, txn, id, state, release)?);
    }
    Ok(target.search(&sources))
}

/// A row revision and the words read with it, in message order, as
/// [`TurnText::messages`] holds them.
type Served = (RevisionRef, Vec<(EntityId, String, Vec<u8>)>);

/// A text revision being looked for: its turn, and the row revisions it may
/// have been read at.
struct Target<'a> {
    turn: &'a EntityId,
    revision: RevisionRef,
    rows: Vec<RevisionRef>,
}

/// A member of the turn: the states it retains in which it shows text, and
/// whether it may have shown none (now, or at a state it retains).
struct Source {
    id: EntityId,
    may_be_absent: bool,
    states: Vec<SourceState>,
}

impl Target<'_> {
    /// The row and words when the `chosen` source states, read at one of
    /// the rows, make the revision.
    fn served(&self, chosen: &[(EntityId, &SourceState)]) -> Option<Served> {
        if chosen.is_empty() {
            return None;
        }
        let sources = digest(chosen.iter().map(|(id, state)| (id, &state.commitment)));
        let row = self
            .rows
            .iter()
            .copied()
            .find(|row| text_revision(self.turn, *row, &sources) == self.revision)?;
        let messages = chosen
            .iter()
            .map(|(id, state)| (*id, state.text.clone(), state.body.clone()))
            .collect();
        Some((row, messages))
    }

    /// Each set of states `sources` can make, until one is the revision or
    /// every set was tried.
    /// A member may stand at any state it retains, and as absent when it
    /// shows no text now or at a state it retains. Members past the first
    /// `present` are absent too: the turn gained them after.
    fn search(&self, sources: &[Source]) -> Option<Served> {
        let choices: Vec<Vec<Option<usize>>> = sources
            .iter()
            .map(|source| {
                (0..source.states.len())
                    .map(Some)
                    .chain(source.may_be_absent.then_some(None))
                    .collect()
            })
            .collect();
        for present in (1..=sources.len()).rev() {
            if choices[..present].iter().any(Vec::is_empty) {
                continue;
            }
            let mut picks = vec![0_usize; present];
            loop {
                let chosen: Vec<(EntityId, &SourceState)> = sources[..present]
                    .iter()
                    .zip(&choices)
                    .zip(&picks)
                    .filter_map(|((source, options), pick)| {
                        options[*pick].map(|state| (source.id, &source.states[state]))
                    })
                    .collect();
                if let Some(served) = self.served(&chosen) {
                    return Some(served);
                }
                if !next_pick(&mut picks, &choices) {
                    break;
                }
            }
        }
        None
    }
}

/// Moves `picks` to the next set, as an odometer over each member's
/// `choices`; `false` once every set was picked.
fn next_pick(picks: &mut [usize], choices: &[Vec<Option<usize>>]) -> bool {
    for (pick, options) in picks.iter_mut().zip(choices) {
        *pick += 1;
        if *pick < options.len() {
            return true;
        }
        *pick = 0;
    }
    false
}

/// The turn's sources as they stand: each member that shows text, with its
/// current state. `None` for a turn that is gone or archived.
fn current_sources_in_txn(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    release: bool,
) -> Result<Option<Vec<(EntityId, SourceState)>>> {
    let Some(members) = crate::tagging::turn_members_in_txn(vault, store, txn, turn, release)?
    else {
        return Ok(None);
    };
    let mut sources = Vec::with_capacity(members.len());
    for (id, text, body) in members {
        if let Some(state) = current_state_in_txn(vault, store, txn, &id, text, body)? {
            sources.push((id, state));
        }
    }
    Ok(Some(sources))
}

/// The state `message` stands at, when it shows `text`, read from `body`.
/// An entity document is the vault's, so its frontier is read on the vault's
/// own store.
fn current_state_in_txn(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    message: &EntityId,
    text: Option<String>,
    body: Vec<u8>,
) -> Result<Option<SourceState>> {
    let Some(text) = text else {
        return Ok(None);
    };
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, message)? else {
        return Ok(None);
    };
    let frontier = crate::entity_doc::source_frontier_in_txn(&vault.store, txn, message)?;
    let commitment = match frontier {
        Some(frontier) => document_commitment(message, &raw, &frontier),
        None => row_commitment(message, &raw),
    };
    Ok(Some(SourceState {
        commitment,
        text,
        body,
    }))
}

/// Whether `message`'s words live in its entity document, which no row
/// revision of it holds.
pub(crate) fn message_has_document_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    message: &EntityId,
) -> Result<bool> {
    DOCUMENT_HEADS.contains(&vault.store, txn, &HexId(*message))
}

/// The member `message` as a search may pick it: every state it retains in
/// which it shows text, `current` first. A row-backed message's are its
/// row at each retained revision; a document-backed one's are its
/// document's retained states, and the row revisions its birth took over
/// read at the states they name. Each keeps its body for `release`.
fn source_in_txn(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    message: EntityId,
    current: Option<SourceState>,
    release: bool,
) -> Result<Source> {
    let mut source = Source {
        id: message,
        may_be_absent: current.is_none(),
        states: current.into_iter().collect(),
    };
    let mut push =
        |commitment: Vec<u8>, body: Vec<u8>| match crate::tagging::shown_message_text(&body) {
            Some(text) => {
                if !source
                    .states
                    .iter()
                    .any(|state| state.commitment == commitment)
                {
                    source.states.push(SourceState {
                        commitment,
                        text,
                        body: if release { body } else { Vec::new() },
                    });
                }
            }
            None => source.may_be_absent = true,
        };
    // Once its text lives in its document, its rows from before the move
    // never stand for it: a row revision its birth took over is read from
    // the document, at the state it names there (FIX 8802).
    if DOCUMENT_HEADS.contains(&vault.store, txn, &HexId(message))? {
        if let Some(raw) =
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &message)?
            && let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..)
            && let Some(history) = crate::entity_doc::record_body_history_in_txn(
                &vault.store,
                txn,
                &message,
                body,
                None,
            )?
        {
            for state in history {
                push(
                    document_commitment(&message, &raw, &state.frontier),
                    state.body,
                );
            }
            let aliases = row_aliases_in_txn(&vault.store, txn, &message)?;
            for (revision, body) in crate::entity_doc::record_bodies_at_in_txn(
                &vault.store,
                txn,
                &message,
                body,
                aliases,
            )? {
                push(revision_commitment(revision), body);
            }
        }
        return Ok(source);
    }
    for raw in retained_rows_in_txn(store, txn, &message)? {
        push(
            row_commitment(&message, &raw),
            raw.get(ENTITY_METADATA_HEADER_LEN..)
                .unwrap_or_default()
                .to_vec(),
        );
    }
    Ok(source)
}

/// A message whose text is its row: the row as stored.
fn row_commitment(id: &EntityId, raw: &[u8]) -> Vec<u8> {
    revision_commitment(reference(id, raw))
}

/// The row of a message at `revision`, its reference: a document's birth
/// keeps the revision of the row it took over, never the row's bytes.
fn revision_commitment(revision: RevisionRef) -> Vec<u8> {
    let mut commitment = vec![b'r'];
    commitment.extend_from_slice(&revision.0);
    commitment
}

/// A message whose text lives in an entity document: the pointer row as
/// stored, and the document's frontier.
fn document_commitment(id: &EntityId, raw: &[u8], frontier: &[u8]) -> Vec<u8> {
    let mut commitment = vec![b'd'];
    commitment.extend_from_slice(&reference(id, raw).0);
    commitment.extend_from_slice(frontier);
    commitment
}

/// One digest of a set of source states, in message order.
fn digest<'a>(sources: impl IntoIterator<Item = (&'a EntityId, &'a Vec<u8>)>) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    for (id, commitment) in sources {
        digest.update(id.as_bytes());
        digest.update(&(commitment.len() as u64).to_be_bytes());
        digest.update(commitment);
    }
    *digest.finalize().as_bytes()
}

/// The text revision of `turn` read at `row` with `sources`: the turn's
/// hint, the row's first byte, then 13 bytes of their digest.
fn text_revision(turn: &EntityId, row: RevisionRef, sources: &[u8; 32]) -> RevisionRef {
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:turn-text-revision:v1");
    digest.update(turn.as_bytes());
    digest.update(&row.0);
    digest.update(sources);
    let mut bytes = [0; 16];
    bytes[..2].copy_from_slice(&turn_hint(turn));
    bytes[2] = row.0[0];
    bytes[3..].copy_from_slice(&digest.finalize().as_bytes()[..13]);
    RevisionRef(bytes)
}

/// The first two bytes of each text revision of `turn`.
fn turn_hint(turn: &EntityId) -> [u8; 2] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:turn-text-revision:turn");
    digest.update(turn.as_bytes());
    let hash = digest.finalize();
    [hash.as_bytes()[0], hash.as_bytes()[1]]
}
