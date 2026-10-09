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
//! found again among the states its own history retains: its row's retained
//! revisions and its document's retained changes. A message the turn gained
//! since, or one hidden then, reads as absent. A source that was erased,
//! archived or purged since, or that this search does not reach, is not
//! found, and the revision then resolves to nothing, as a pin whose revision
//! is gone does: it never serves other words under the revision it showed.

use super::storage::{
    entity_owns_revision_in_txn, reference, retained_rows_in_txn, row_revisions_in_txn, state,
};
use super::{ReadMode, RevisionRef};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::{EntityId, Vault};
use heed::RoTxn;

/// Retained row revisions, and document changes, of one source message a
/// search reads; a text revision that needs one past these is not found.
const MAX_SOURCE_STATES: usize = 64;
/// Sets of source states one search tries before it gives up.
const MAX_SOURCE_SETS: usize = 4096;

/// The words a read of a TURN serves, under the revision that pins them.
pub(crate) struct TurnText {
    /// The text revision; the row's own for a turn whose messages show no
    /// text, which its row revision pins whole.
    pub(crate) revision: RevisionRef,
    /// Each source message the revision joins, with its text there, in
    /// message order. Every reader is given only those it may read.
    pub(crate) messages: Vec<(EntityId, String)>,
}

impl TurnText {
    /// The messages `readable` admits: the turn as one reader is shown it.
    pub(crate) fn readable(
        self,
        mut readable: impl FnMut(&EntityId) -> Result<bool>,
    ) -> Result<Vec<(EntityId, String)>> {
        let mut messages = Vec::with_capacity(self.messages.len());
        for (id, text) in self.messages {
            if readable(&id)? {
                messages.push((id, text));
            }
        }
        Ok(messages)
    }
}

/// The words a read of `turn` at `mode` serves and the text revision that
/// pins them. A pin at one of the row's own revisions reads the current
/// words; a pin at a text revision reads the words it was served with, or
/// nothing once they can no longer be found. `None` also for a turn that is
/// gone or archived.
pub(crate) fn served_turn_text_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    mode: ReadMode,
) -> Result<Option<TurnText>> {
    let row = match mode {
        ReadMode::Pinned(revision) => {
            if !entity_owns_revision_in_txn(&vault.store, txn, turn, revision)? {
                return Ok(resolve_in_txn(vault, txn, turn, revision)?
                    .map(|(_, messages)| TurnText { revision, messages }));
            }
            revision
        }
        ReadMode::Live | ReadMode::Indexed => {
            let Some(raw) =
                crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, turn)?
            else {
                return Ok(None);
            };
            state(&vault.store, txn, turn)?.map_or_else(
                || reference(turn, &raw),
                |current| match mode {
                    ReadMode::Indexed => current.indexed,
                    _ => current.live,
                },
            )
        }
    };
    let Some(sources) = current_sources_in_txn(vault, txn, turn)? else {
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
            .map(|(id, state)| (id, state.text))
            .collect(),
    }))
}

/// The row revision `revision` was read at, when it is a text revision of
/// `turn` whose words can still be found. The row may have moved since; any
/// revision of it the vault retains still resolves.
pub(crate) fn turn_row_for_text_revision_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    revision: RevisionRef,
) -> Result<Option<RevisionRef>> {
    Ok(resolve_in_txn(vault, txn, turn, revision)?.map(|(row, _)| row))
}

/// One state of a source message: what a text revision commits to for it,
/// and the text it shows there.
struct SourceState {
    commitment: Vec<u8>,
    text: String,
}

/// The row revision and words `revision` was served with: the turn's current
/// sources first, then each set its sources' retained states can make.
fn resolve_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    revision: RevisionRef,
) -> Result<Option<Served>> {
    let Some(members) = crate::tagging::turn_members_in_txn(vault, txn, turn)? else {
        return Ok(None);
    };
    let target = Target {
        turn,
        revision,
        rows: row_revisions_in_txn(&vault.store, txn, turn)?,
    };
    let mut current = Vec::with_capacity(members.len());
    for (id, text) in members {
        let state = current_state_in_txn(vault, txn, &id, text)?;
        current.push((id, state));
    }
    let now: Vec<_> = current
        .iter()
        .filter_map(|(id, state)| Some((*id, state.as_ref()?)))
        .collect();
    if let Some(served) = target.served(&now) {
        return Ok(Some(served));
    }
    let mut sources = Vec::with_capacity(current.len());
    for (id, state) in current {
        let shown = state.is_some();
        sources.push(Source {
            id,
            shown,
            states: source_states_in_txn(vault, txn, &id, state)?,
        });
    }
    Ok(target.search(&sources))
}

/// A row revision and the words read with it, in message order.
type Served = (RevisionRef, Vec<(EntityId, String)>);

/// A text revision being looked for: its turn, and the row revisions it may
/// have been read at.
struct Target<'a> {
    turn: &'a EntityId,
    revision: RevisionRef,
    rows: Vec<RevisionRef>,
}

/// A member of the turn: the states it retains in which it shows text, and
/// whether it shows text now.
struct Source {
    id: EntityId,
    shown: bool,
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
            .map(|(id, state)| (*id, state.text.clone()))
            .collect();
        Some((row, messages))
    }

    /// Each set of states `sources` can make, at most [`MAX_SOURCE_SETS`].
    /// A member may stand at any state it retains, and as absent when it
    /// shows no text now (hidden or emptied since). Members past the first
    /// `present` are absent too: the turn gained them after.
    fn search(&self, sources: &[Source]) -> Option<Served> {
        let choices: Vec<Vec<Option<usize>>> = sources
            .iter()
            .map(|source| {
                (0..source.states.len())
                    .map(Some)
                    .chain((!source.shown).then_some(None))
                    .collect()
            })
            .collect();
        let mut budget = MAX_SOURCE_SETS;
        for present in (1..=sources.len()).rev() {
            if choices[..present].iter().any(Vec::is_empty) {
                continue;
            }
            let mut picks = vec![0_usize; present];
            loop {
                budget = budget.checked_sub(1)?;
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
    txn: &RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<Vec<(EntityId, SourceState)>>> {
    let Some(members) = crate::tagging::turn_members_in_txn(vault, txn, turn)? else {
        return Ok(None);
    };
    let mut sources = Vec::with_capacity(members.len());
    for (id, text) in members {
        if let Some(state) = current_state_in_txn(vault, txn, &id, text)? {
            sources.push((id, state));
        }
    }
    Ok(Some(sources))
}

/// The state `message` stands at, when it shows `text`.
fn current_state_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    message: &EntityId,
    text: Option<String>,
) -> Result<Option<SourceState>> {
    let Some(text) = text else {
        return Ok(None);
    };
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, message)?
    else {
        return Ok(None);
    };
    #[cfg(feature = "sync")]
    let frontier = crate::entity_doc::source_frontier_in_txn(&vault.store, txn, message)?;
    #[cfg(not(feature = "sync"))]
    let frontier: Option<Vec<u8>> = None;
    let commitment = match frontier {
        Some(frontier) => document_commitment(message, &raw, &frontier),
        None => row_commitment(message, &raw),
    };
    Ok(Some(SourceState { commitment, text }))
}

/// Every state `message` retains in which it shows text, `current` first:
/// its row at each retained revision, and its document after each retained
/// change.
fn source_states_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    message: &EntityId,
    current: Option<SourceState>,
) -> Result<Vec<SourceState>> {
    let mut states: Vec<SourceState> = current.into_iter().collect();
    let mut push = |commitment: Vec<u8>, text: Option<String>| {
        if let Some(text) = text
            && !states.iter().any(|state| state.commitment == commitment)
        {
            states.push(SourceState { commitment, text });
        }
    };
    for raw in retained_rows_in_txn(&vault.store, txn, message, MAX_SOURCE_STATES)? {
        let text = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .and_then(crate::tagging::shown_message_text);
        push(row_commitment(message, &raw), text);
    }
    #[cfg(feature = "sync")]
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, message)?
        && let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..)
        && let Some(history) = crate::entity_doc::record_body_history_in_txn(
            &vault.store,
            txn,
            message,
            body,
            MAX_SOURCE_STATES,
        )?
    {
        for state in history {
            push(
                document_commitment(message, &raw, &state.frontier),
                crate::tagging::shown_message_text(&state.body),
            );
        }
    }
    Ok(states)
}

/// A message whose text is its row: the row as stored.
fn row_commitment(id: &EntityId, raw: &[u8]) -> Vec<u8> {
    let mut commitment = vec![b'r'];
    commitment.extend_from_slice(&reference(id, raw).0);
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

fn text_revision(turn: &EntityId, row: RevisionRef, sources: &[u8; 32]) -> RevisionRef {
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:turn-text-revision:v1");
    digest.update(turn.as_bytes());
    digest.update(&row.0);
    digest.update(sources);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    RevisionRef(bytes)
}
