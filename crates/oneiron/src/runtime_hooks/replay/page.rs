//! `hooks.replay` a page at a time (FIX 8629): at most
//! [`MAX_REPLAY_ENTRIES`] entries a page, and a cursor to the rest. A fact
//! hook's cursor holds each source's own frontier, moved past every fact a
//! page scanned, whether or not the hook took it, so a page that kept no
//! entry still moves on. A verb hook's cursor holds the saved-run index key
//! (commit time, run key) its page ended at.

use std::ops::Bound;
use std::sync::Arc;

use heed::RoTxn;

use super::{
    HookReplayEntry, MAX_REPLAY_BATCHES, MAX_REPLAY_ENTRIES, REPLAY_BATCH, Replay, SavedRun,
};
use crate::claim::ScopedRead;
use crate::receipt::hex_lower;
use crate::runtime_hooks::body::{HookBodyRuntime, HookVerdict};
use crate::runtime_hooks::source::{self, FactPosition, FactPositionHex, FactSource};
use crate::runtime_hooks::store::{self, HookRunRef, RunKey};
use crate::runtime_hooks::verb::VERB_RUNS;
use crate::skill_hub::pack_catalog::{HookPhase, PackHookBinding};
use crate::{EntityId, Error, Result, Vault};

/// Where one fact source's replay stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceFrontier {
    /// Not read yet: from the source's start.
    Start,
    /// Read through this position.
    After(FactPosition),
    /// Read to its end.
    End,
}

/// Each fact source's frontier, in [`FactSource::ALL`] order.
type Frontiers = [SourceFrontier; FactSource::ALL.len()];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CursorAt {
    Facts(Frontiers),
    /// The saved-run index key a verb hook's page ended at.
    Runs(u64, RunKey),
}

/// Where the next page of a replay starts. As text, `facts;<a>;<b>`, each
/// source in [`FactSource::ALL`] order as `start`, `end` or the hex of the
/// position read through, or `runs;<commit ms>;<run key as 64 hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookReplayCursor(CursorAt);

impl HookReplayCursor {
    /// The cursor's text form.
    #[must_use]
    pub fn to_text(self) -> String {
        match self.0 {
            CursorAt::Facts(frontiers) => {
                let mut text = "facts".to_owned();
                for frontier in frontiers {
                    text.push(';');
                    match frontier {
                        SourceFrontier::Start => text.push_str("start"),
                        SourceFrontier::After(position) => text.push_str(&position.hex()),
                        SourceFrontier::End => text.push_str("end"),
                    }
                }
                text
            }
            CursorAt::Runs(commit_ms, key) => format!("runs;{commit_ms};{}", hex_lower(&key)),
        }
    }

    /// The cursor `text` names.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for text no replay page returned.
    pub fn parse(text: &str) -> Result<Self> {
        let foreign = || Error::InvalidConfig("cursor is not a hook replay page's".to_owned());
        let mut parts = text.trim().split(';');
        match parts.next() {
            Some("facts") => {
                let mut frontiers = [SourceFrontier::Start; FactSource::ALL.len()];
                for (slot, source) in FactSource::ALL.iter().enumerate() {
                    frontiers[slot] = match parts.next().ok_or_else(foreign)? {
                        "start" => SourceFrontier::Start,
                        "end" => SourceFrontier::End,
                        hex => SourceFrontier::After(
                            FactPositionHex(format!("{}:{hex}", source.as_str()))
                                .parse()
                                .map_err(|_| foreign())?,
                        ),
                    };
                }
                if parts.next().is_some() {
                    return Err(foreign());
                }
                Ok(Self(CursorAt::Facts(frontiers)))
            }
            Some("runs") => {
                let commit_ms = parts
                    .next()
                    .and_then(|ms| ms.parse().ok())
                    .ok_or_else(foreign)?;
                let key = parts.next().and_then(run_key).ok_or_else(foreign)?;
                if parts.next().is_some() {
                    return Err(foreign());
                }
                Ok(Self(CursorAt::Runs(commit_ms, key)))
            }
            _ => Err(foreign()),
        }
    }
}

/// A run key from its 64 hex.
fn run_key(hex: &str) -> Option<RunKey> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (at, pair) in bytes.chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        key[at] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(key)
}

/// One page of a replay: its entries, and where the next page starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookReplayEntryPage {
    pub entries: Vec<HookReplayEntry>,
    /// The next page's cursor; `None` once the replay read every entry its
    /// hook takes.
    pub next: Option<HookReplayCursor>,
}

impl Vault {
    /// [`Self::hooks_replay_listing`] a page at a time: at most `limit`
    /// entries ([`MAX_REPLAY_ENTRIES`] a page) after `cursor`, or after
    /// `since` when no cursor is given, with the next page's cursor, beside
    /// the rows its entries stand on.
    ///
    /// # Errors
    ///
    /// As [`Self::hooks_replay`]; a cursor of the other kind of hook as
    /// [`Error::InvalidConfig`].
    pub fn hooks_replay_page_listing(
        &self,
        runtime: &dyn HookBodyRuntime,
        verdict: Option<Arc<dyn HookVerdict>>,
        binding: EntityId,
        since: Option<FactPositionHex>,
        cursor: Option<HookReplayCursor>,
        limit: usize,
    ) -> Result<(HookReplayEntryPage, Vec<EntityId>)> {
        let (binding_id, row) = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .ok_or(Error::EntityNotFound)?;
        let (page, rows) = self.hooks_replay_binding_page(
            runtime,
            verdict.as_deref(),
            binding_id,
            &row,
            since,
            cursor,
            limit,
        )?;
        // The binding was read from its stored row, so it is one of the rows
        // the answer stands on (FIX 4710).
        let mut rows = rows;
        rows.push(binding_id);
        rows.sort_unstable();
        rows.dedup();
        Ok((page, rows))
    }

    /// One page of `row`'s replay as given, stored or not
    /// ([`Self::hooks_replay_binding_listing`]): a fact hook over its
    /// sources from `cursor` (from `since`, or every source's start, when
    /// none), a verb hook over its saved runs older than `cursor`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the replay's binding, its runtimes and its page bounds"
    )]
    pub(crate) fn hooks_replay_binding_page(
        &self,
        runtime: &dyn HookBodyRuntime,
        verdict: Option<&dyn HookVerdict>,
        binding_id: EntityId,
        row: &PackHookBinding,
        since: Option<FactPositionHex>,
        cursor: Option<HookReplayCursor>,
        limit: usize,
    ) -> Result<(HookReplayEntryPage, Vec<EntityId>)> {
        let limit = limit.clamp(1, MAX_REPLAY_ENTRIES);
        let body = self.bound_body(row);
        let other_kind =
            || Error::InvalidConfig("cursor is another kind of hook's replay page".to_owned());
        if row.selector.phase != HookPhase::Fact {
            if since.is_some() {
                return Err(Error::InvalidConfig(
                    "since is a fact position: a verb hook replays its newest runs".to_owned(),
                ));
            }
            let after = match cursor.map(|cursor| cursor.0) {
                None => None,
                Some(CursorAt::Runs(commit_ms, key)) => Some((commit_ms, key)),
                Some(CursorAt::Facts(_)) => return Err(other_kind()),
            };
            let (runs, next) = saved_runs_page(self, binding_id, after, limit)?;
            return self.replaying(runtime, verdict, binding_id, row, body, |replay, lane| {
                Ok(HookReplayEntryPage {
                    entries: runs.iter().map(|run| replay.saved(lane, run)).collect(),
                    next,
                })
            });
        }
        let frontiers = match (cursor.map(|cursor| cursor.0), since) {
            (Some(CursorAt::Facts(frontiers)), _) => frontiers,
            (Some(CursorAt::Runs(..)), _) => return Err(other_kind()),
            (None, Some(since)) => {
                let position = since.parse()?;
                FactSource::ALL.map(|source| {
                    if source == position.source() {
                        SourceFrontier::After(position)
                    } else {
                        SourceFrontier::End
                    }
                })
            }
            (None, None) => [SourceFrontier::Start; FactSource::ALL.len()],
        };
        self.replaying(runtime, verdict, binding_id, row, body, |replay, lane| {
            replay.walk_page(lane, frontiers, limit)
        })
    }
}

impl Replay<'_> {
    /// The fact sources from `frontiers` until `limit` entries the hook
    /// takes, each source read at most [`MAX_REPLAY_BATCHES`] batches a page;
    /// a source with more left keeps its frontier for the next page.
    fn walk_page(
        &self,
        lane: &ScopedRead<'_>,
        mut frontiers: Frontiers,
        limit: usize,
    ) -> Result<HookReplayEntryPage> {
        let mut entries = Vec::new();
        'sources: for (slot, source) in FactSource::ALL.iter().enumerate() {
            for _ in 0..MAX_REPLAY_BATCHES {
                let after = match frontiers[slot] {
                    SourceFrontier::End => continue 'sources,
                    SourceFrontier::Start => None,
                    SourceFrontier::After(position) => Some(position),
                };
                if entries.len() >= limit {
                    break 'sources;
                }
                let batch = source::read_after(self.vault, *source, after, REPLAY_BATCH)?;
                for entry in &batch.entries {
                    if entries.len() >= limit {
                        // The page is full: this entry starts the next one.
                        break 'sources;
                    }
                    if let Some(found) = self.entry(lane, entry)? {
                        entries.push(found);
                    }
                    frontiers[slot] = SourceFrontier::After(entry.position);
                }
                frontiers[slot] = match (batch.more, batch.through) {
                    (true, Some(through)) => SourceFrontier::After(through),
                    _ => SourceFrontier::End,
                };
            }
        }
        let next = frontiers
            .iter()
            .any(|frontier| *frontier != SourceFrontier::End)
            .then_some(HookReplayCursor(CursorAt::Facts(frontiers)));
        Ok(HookReplayEntryPage { entries, next })
    }
}

/// `binding`'s saved runs older than `after` (from the newest when `None`),
/// newest first, at most `limit`, and the cursor of the rest: fact and verb
/// runs alike, in commit order, as one read sees them.
fn saved_runs_page(
    vault: &Vault,
    binding: EntityId,
    after: Option<(u64, RunKey)>,
    limit: usize,
) -> Result<(Vec<SavedRun>, Option<HookReplayCursor>)> {
    let rtxn = vault.store.env.read_txn()?;
    let low = (binding, 0, [0u8; 32]);
    let high = match after {
        Some((commit_ms, key)) => (binding, commit_ms, key),
        None => (binding, u64::MAX, [u8::MAX; 32]),
    };
    let high_bound = if after.is_some() {
        Bound::Excluded(&high)
    } else {
        Bound::Included(&high)
    };
    let mut runs = Vec::new();
    let mut last = None;
    let mut more = false;
    let (from, to) = (Bound::Included(&low), high_bound);
    for row in store::RUN_INDEX.iter_rev_range(&vault.store, &rtxn, from, to)? {
        let ((_, commit_ms, key), run) = row?;
        if runs.len() == limit {
            more = true;
            break;
        }
        runs.push(saved_run_in(vault, &rtxn, run)?);
        last = Some((commit_ms, key));
    }
    let next = last
        .filter(|_| more)
        .map(|(commit_ms, key)| HookReplayCursor(CursorAt::Runs(commit_ms, key)));
    Ok((runs, next))
}

/// The saved row a run index row names.
fn saved_run_in(vault: &Vault, rtxn: &RoTxn<'_>, run: HookRunRef) -> Result<SavedRun> {
    let saved = match run {
        HookRunRef::Fact(key) => store::MEMOS
            .get(&vault.store, rtxn, &key)?
            .map(|memo| SavedRun::Fact(key, memo)),
        HookRunRef::Verb(key) => VERB_RUNS
            .get(&vault.store, rtxn, &key)?
            .map(|saved| SavedRun::Verb(key, saved)),
    };
    saved.ok_or(Error::CorruptedIndex(
        "a hook run index row names no saved run",
    ))
}
