//! The follower's keyframe (FIX 7510): how a session sizes its calls and
//! how it folds its retained frames when its prefix would pass the model's
//! window. A fold splits every part it reads into groups that fit, folds
//! each, and folds the folds again until one remains: nothing is cut, no
//! frame is skipped, and the vault is never read again for it. A keyframe
//! replaces only the prefix it covers; the frames, the log and the queue
//! stay as they are.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::store::Store;
use crate::{EntityId, Vault};

use super::log::Log;
use super::state::{
    self, CallEvidence, FollowerResult, Pin, Receipt, ResultKey, Session, SessionKey, Writer,
    held_session_in_txn,
};

/// One session's sizing: the input window the host lends its model, when
/// it lends one, and the policy's bytes-per-token packing estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sizing {
    window: Option<u64>,
    bytes_per_token: u64,
}

impl Sizing {
    pub(crate) fn new(window: Option<u64>, bytes_per_token: u32) -> Self {
        Self {
            window,
            bytes_per_token: u64::from(bytes_per_token.max(1)),
        }
    }

    /// Whether `bytes` of input fit the window by the estimate. With no
    /// window lent every input fits, and a refused call hands its spans
    /// back to their own rungs.
    pub(crate) fn fits(&self, bytes: usize) -> bool {
        self.window.is_none_or(|window| {
            u64::try_from(bytes)
                .unwrap_or(u64::MAX)
                .div_ceil(self.bytes_per_token)
                <= window
        })
    }

    /// The bytes one call may hold beside `reserved` by the estimate; none
    /// when no window is lent.
    pub(crate) fn room(&self, reserved: usize) -> Option<usize> {
        self.window.map(|window| {
            usize::try_from(window.saturating_mul(self.bytes_per_token))
                .unwrap_or(usize::MAX)
                .saturating_sub(reserved)
        })
    }
}

/// `parts` packed in order into groups of at most `room` bytes each; a part
/// longer than that is cut at character boundaries into pieces that fit,
/// every byte kept. With no room known, one group holds them all.
pub(crate) fn fold_groups(parts: &[String], room: Option<usize>) -> Vec<Vec<String>> {
    let Some(room) = room else {
        return vec![parts.to_vec()];
    };
    let room = room.max(1);
    let mut groups = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut used = 0_usize;
    for part in parts {
        for piece in pieces(part, room) {
            if !current.is_empty() && used.saturating_add(piece.len()) > room {
                groups.push(std::mem::take(&mut current));
                used = 0;
            }
            used = used.saturating_add(piece.len());
            current.push(piece);
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

/// `text` cut at character boundaries into pieces of at most `room` bytes
/// (a character wider than that stands alone), in order, whole.
fn pieces(text: &str, room: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while rest.len() > room {
        let mut cut = room;
        while cut > 0 && !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        if cut == 0 {
            cut = rest.char_indices().nth(1).map_or(rest.len(), |(at, _)| at);
        }
        let (head, tail) = rest.split_at(cut);
        out.push(head.to_owned());
        rest = tail;
    }
    if !rest.is_empty() || out.is_empty() {
        out.push(rest.to_owned());
    }
    out
}

/// A keyframe as a prepare reads it: its bytes and the TURNs it folds.
pub(super) struct Standing {
    pub(super) bytes: String,
    pub(super) turns: Vec<EntityId>,
}

/// One fold to run: the parts it folds in order (the standing keyframe
/// first, then each frame through `covers_through`), and what its keyframe
/// will cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FoldWork {
    pub(crate) seq: u64,
    pub(crate) parts: Vec<String>,
    pub(crate) covers_through: u64,
    pub(crate) prior: Option<ResultKey>,
    pub(crate) turns: Vec<EntityId>,
    pub(crate) pins: Vec<Pin>,
}

/// Whether the session holds anything to fold through `through`.
pub(super) fn foldable(session: &Session, through: u64) -> bool {
    through > session.state.covered_through
}

/// The fold of the standing keyframe and every frame the log holds through
/// `through`, under the session's next sequence.
pub(super) fn fold_work(
    session: &mut Session,
    standing: Option<&Standing>,
    log: &Log,
    through: u64,
) -> FoldWork {
    let mut parts = Vec::new();
    let mut turns = BTreeSet::new();
    let mut pins = BTreeSet::new();
    if let Some(standing) = standing {
        parts.push(standing.bytes.clone());
        turns.extend(standing.turns.iter().copied());
    }
    for held in log.frames.iter().filter(|held| held.ordinal <= through) {
        parts.push(held.frame.bytes.clone());
        turns.insert(held.frame.turn);
        pins.extend(held.frame.pins.iter().cloned());
    }
    let seq = session.state.next_seq;
    session.state.next_seq = seq.saturating_add(1);
    FoldWork {
        seq,
        parts,
        covers_through: through,
        prior: session.state.keyframe,
        turns: turns.into_iter().collect(),
        pins: pins.into_iter().collect(),
    }
}

/// A keyframe's bytes as the model reads them.
#[derive(Serialize)]
struct KeyframeView {
    keyframe: String,
    covers: String,
    text: String,
}

/// Renders a keyframe of `text` covering the frames through `through`.
pub(super) fn render_keyframe(seq: u64, through: u64, text: &str) -> Result<String> {
    serde_json::to_string(&KeyframeView {
        keyframe: format!("K{seq}"),
        covers: format!("F1-F{through}"),
        text: text.to_owned(),
    })
    .map_err(|_| Error::InvalidConfig("follower keyframe encoding".into()))
}

/// A finished fold, to stand as the session's keyframe.
pub(crate) struct KeyframeCommit<'a> {
    pub(crate) key: SessionKey,
    pub(crate) writer: Writer,
    pub(crate) work: &'a FoldWork,
    pub(crate) text: String,
    pub(crate) calls: Vec<CallEvidence>,
    pub(crate) receipt: Receipt,
}

/// Stands a fold as the session's keyframe in one transaction: its result
/// row, the coverage it folds and a new epoch. False, with nothing written,
/// when this writer no longer holds the session or another fold stood.
pub(crate) fn commit_keyframe_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    commit: KeyframeCommit<'_>,
) -> Result<bool> {
    let Some(mut session) = held_session_in_txn(&vault.store, txn, commit.key, commit.writer)?
    else {
        return Ok(false);
    };
    let work = commit.work;
    if session.state.keyframe != work.prior || session.state.covered_through >= work.covers_through
    {
        return Ok(false);
    }
    let key = (commit.writer.attempt, work.seq);
    let epoch = session.state.epoch.saturating_add(1);
    let result = FollowerResult::Keyframe {
        session: session.key,
        epoch,
        covers_through: work.covers_through,
        turns: work.turns.clone(),
        bytes: render_keyframe(work.seq, work.covers_through, &commit.text)?,
        calls: commit.calls,
        receipt: commit.receipt,
    };
    state::put_result_in_txn(vault, txn, &key, &result)?;
    session.state.keyframe = Some(key);
    session.state.covered_through = work.covers_through;
    session.state.applied_through = session.state.applied_through.max(work.covers_through);
    session.state.fold_due = false;
    session.state.epoch = epoch;
    state::save_in_txn(&vault.store, txn, &session)?;
    Ok(true)
}

/// The erase hook, in the erasing transaction: the erased TURNs' frames go,
/// a keyframe that folds their words goes and its coverage opens again, a
/// prepared suffix that asks of them goes, and every result forgets them.
/// Withdrawn words are never sent again; the epoch moves on.
pub(crate) fn erase_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turns: &[EntityId],
) -> Result<()> {
    if turns.is_empty() {
        return Ok(());
    }
    for mut session in state::erase_sessions_in_txn(store, txn)? {
        let gone = state::forget_frames_in_txn(store, txn, &session.key, turns)?;
        let mut changed = !gone.is_empty();
        let mut drop_keyframe = gone
            .iter()
            .any(|ordinal| *ordinal <= session.state.covered_through);
        // A keyframe whose row no longer reads goes too.
        if let Some(key) = session.state.keyframe {
            drop_keyframe |= match state::result_in_txn(store, txn, &key) {
                Ok(Some(FollowerResult::Keyframe { turns: folded, .. })) => {
                    folded.iter().any(|turn| turns.contains(turn))
                }
                _ => true,
            };
        }
        if drop_keyframe {
            session.state.keyframe = None;
            session.state.covered_through = 0;
            changed = true;
        }
        if session.state.suffix.as_ref().is_some_and(|suffix| {
            suffix
                .spans
                .iter()
                .any(|asked| turns.contains(&asked.span.turn))
        }) {
            session.state.suffix = None;
            changed = true;
        }
        if changed {
            session.state.epoch = session.state.epoch.saturating_add(1);
            state::save_in_txn(store, txn, &session)?;
        }
    }
    state::forget_results_in_txn(store, txn, turns)
}

impl Vault {
    /// An explicit keyframe event (FIX 7510): every follower session folds
    /// its retained frames into a keyframe before its next suffix, once the
    /// suffix it has prepared drains. Returns how many sessions it marked.
    pub fn dreamer_follower_keyframe(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<usize> {
        self.with_write_txn_grouped(|txn| {
            crate::dreamer_runner::maintenance::validate_owner_in_txn(self, txn, owner)?;
            let sessions = state::sessions_in_txn(&self.store, txn)?;
            let marked = sessions.len();
            for mut session in sessions {
                session.state.fold_due = true;
                state::save_in_txn(&self.store, txn, &session)?;
            }
            Ok(marked)
        })
    }
}
