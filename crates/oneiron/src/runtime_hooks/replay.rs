//! `hooks.replay` (ARCH-0080 §6): runs a hook's body over past entries and
//! shows each outcome beside the one its run recorded. It lands nothing. A
//! run pinned its input, its reads and its verdicts, and replay reuses them;
//! where nothing is pinned and the entity has moved on, the entry says
//! history is missing rather than reading newer state. A fact hook replays
//! over its sources, a verb hook over its newest saved runs.

mod body;
mod page;

use std::cell::RefCell;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::receipt::hex_lower;
use crate::skill_hub::pack_catalog::{HookPhase, PackHookBinding};
use crate::{EntityId, Error, Result, Vault};

use super::body::{HookBodyRuntime, HookVerdict};
use super::filter;
use super::grant::{HookGrant, effective_grant};
use super::read;
use super::runner::{Verdict, bounded};
use super::source::{FactEntry, FactKind, FactPositionHex, FactSource};
use super::store::{self, HookReadPin, HookRunRecord, HookRunRef, HookVerdictPin, RunKey};
use super::verb::{HookVerbRunRecord, VERB_RUNS};

pub use self::page::{HookReplayCursor, HookReplayEntryPage};

/// Entries one replay page returns at most: a larger limit is served a page
/// at a time ([`HookReplayCursor`]).
const MAX_REPLAY_ENTRIES: usize = 256;
/// Entries one source read takes.
const REPLAY_BATCH: usize = 256;
/// Source reads one replay page makes per source.
const MAX_REPLAY_BATCHES: usize = 64;

/// One past entry the hook takes, and what its body returns for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct HookReplayEntry {
    pub case: HookReplayCase,
    pub result: HookReplayResult,
}

/// What a replayed entry is: a fact the hook took, or a verb run it saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "on", rename_all = "snake_case")]
pub enum HookReplayCase {
    /// A fact the hook took, at its source position.
    Fact {
        source: FactSource,
        position: FactPositionHex,
        kind: FactKind,
        #[serde(with = "crate::serialize::entity_ref")]
        #[schemars(with = "String")]
        entity: EntityId,
    },
    /// A verb run the hook saved, by its run key.
    Verb {
        /// The run's key, as 64 hex.
        run_key: String,
        /// The call's invocation, as 32 hex.
        invocation: String,
        verb: String,
        phase: HookPhase,
    },
}

/// How a replayed outcome stands to the one its run recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookReplayCompare {
    /// The same outcome, as JSON.
    Same,
    /// Another outcome, or none where the run returned one.
    Differs,
    /// Nothing to compare with: the run kept no outcome, or none ran.
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HookReplayResult {
    /// The body ran on this entry. Nothing landed.
    Ran {
        outcome_json: Option<String>,
        /// The outcome kind, or `refused` / `failed`.
        outcome: String,
        reason: Option<String>,
        /// The outcome the live run recorded, when one ran.
        recorded: Option<String>,
        /// The outcome JSON the live run recorded, when it kept one.
        recorded_outcome_json: Option<String>,
        compare: HookReplayCompare,
        /// The input came from the run's saved row: its memo, or its saved
        /// verb run.
        from_memo: bool,
        /// No run pinned this entry's reads; they read current rows.
        reads_live: bool,
    },
    /// The hook's current grant no longer shows a saved dependency.
    Withheld { reason: String },
    /// The entry's inputs are gone: replay will not read newer state instead.
    MissingHistory { reason: String },
}

/// A run the run index names, with its saved row.
pub(super) enum SavedRun {
    Fact(RunKey, HookRunRecord),
    Verb(RunKey, HookVerbRunRecord),
}

impl SavedRun {
    const fn key(&self) -> &RunKey {
        match self {
            Self::Fact(key, _) | Self::Verb(key, _) => key,
        }
    }
}

/// `binding`'s newest `limit` saved runs, newest first, as one read sees
/// them: fact and verb runs alike, in commit order.
pub(super) fn saved_runs(vault: &Vault, binding: EntityId, limit: usize) -> Result<Vec<SavedRun>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut runs = Vec::new();
    for row in store::RUN_INDEX
        .iter_rev_from(&vault.store, &rtxn, binding.as_bytes())?
        .take(limit)
    {
        let (_, run) = row?;
        let saved = match run {
            HookRunRef::Fact(key) => store::MEMOS
                .get(&vault.store, &rtxn, &key)?
                .map(|memo| SavedRun::Fact(key, memo)),
            HookRunRef::Verb(key) => VERB_RUNS
                .get(&vault.store, &rtxn, &key)?
                .map(|saved| SavedRun::Verb(key, saved)),
        };
        runs.push(saved.ok_or(Error::CorruptedIndex(
            "a hook run index row names no saved run",
        ))?);
    }
    Ok(runs)
}

impl Vault {
    /// Replays `binding`: a fact hook over entries after `since` (every
    /// source from its start when `None`), a verb hook over its newest saved
    /// runs, returning at most `limit` entries the hook takes. `verdict`
    /// answers a generative fact hook's `ai.verdict` on an entry no run
    /// pinned; without it those calls are refused.
    pub fn hooks_replay(
        &self,
        runtime: &dyn HookBodyRuntime,
        verdict: Option<Arc<dyn HookVerdict>>,
        binding: EntityId,
        since: Option<FactPositionHex>,
        limit: usize,
    ) -> Result<Vec<HookReplayEntry>> {
        self.hooks_replay_listing(runtime, verdict, binding, since, limit)
            .map(|(entries, _)| entries)
    }

    /// [`Self::hooks_replay`], beside the rows its entries stand on: the
    /// stored binding, its body's source, each entry's fact entity (a live
    /// entry's actor too) and every row a replayed read served, as the run
    /// pinned it and as it reads now, and the rows each verdict an entry
    /// heard resolved its evidence to.
    ///
    /// # Errors
    ///
    /// As [`Self::hooks_replay`].
    pub fn hooks_replay_listing(
        &self,
        runtime: &dyn HookBodyRuntime,
        verdict: Option<Arc<dyn HookVerdict>>,
        binding: EntityId,
        since: Option<FactPositionHex>,
        limit: usize,
    ) -> Result<(Vec<HookReplayEntry>, Vec<EntityId>)> {
        let total = limit.max(1);
        let mut entries = Vec::new();
        let mut rows: Vec<EntityId> = Vec::new();
        let mut cursor = None;
        let mut since = since;
        loop {
            let remaining = total.saturating_sub(entries.len());
            if remaining == 0 {
                break;
            }
            let page_limit = remaining.min(MAX_REPLAY_ENTRIES);
            let (page, listed) = self.hooks_replay_page_listing(
                runtime,
                verdict.clone(),
                binding,
                since.take(),
                cursor,
                page_limit,
            )?;
            entries.extend(page.entries);
            rows.extend(listed);
            let Some(next) = page.next else {
                break;
            };
            if entries.len() >= total {
                break;
            }
            cursor = Some(next);
        }
        rows.sort_unstable();
        rows.dedup();
        Ok((entries, rows))
    }

    /// [`Self::hooks_replay`] over `row` as given, stored or not: a hub
    /// hook replays as the binding its Candidate pack would get, as its test
    /// (ARCH-0080 §9).
    pub(crate) fn hooks_replay_binding(
        &self,
        runtime: &dyn HookBodyRuntime,
        verdict: Option<&dyn HookVerdict>,
        binding_id: EntityId,
        row: &PackHookBinding,
        since: Option<FactPositionHex>,
        limit: usize,
    ) -> Result<Vec<HookReplayEntry>> {
        self.hooks_replay_binding_listing(runtime, verdict, binding_id, row, since, limit)
            .map(|(entries, _)| entries)
    }

    /// [`Self::hooks_replay_binding`], beside the rows its entries stand on
    /// as [`Self::hooks_replay_listing`] lists them, but for the binding
    /// itself: `binding_id` is the identity `row` replays as, which may name
    /// no stored row (a Candidate pack's hook replays as the binding it
    /// would get), so it is never listed. Its body's source, each entry's
    /// fact row and every row a read or verdict served are listed (FIX 4710).
    pub(crate) fn hooks_replay_binding_listing(
        &self,
        runtime: &dyn HookBodyRuntime,
        verdict: Option<&dyn HookVerdict>,
        binding_id: EntityId,
        row: &PackHookBinding,
        since: Option<FactPositionHex>,
        limit: usize,
    ) -> Result<(Vec<HookReplayEntry>, Vec<EntityId>)> {
        let total = limit.max(1);
        let mut entries = Vec::new();
        let mut rows: Vec<EntityId> = Vec::new();
        let mut cursor = None;
        let mut since = since;
        loop {
            let remaining = total.saturating_sub(entries.len());
            if remaining == 0 {
                break;
            }
            let page_limit = remaining.min(MAX_REPLAY_ENTRIES);
            let (page, listed) = self.hooks_replay_binding_page(
                runtime,
                verdict,
                binding_id,
                row,
                since.take(),
                cursor,
                page_limit,
            )?;
            entries.extend(page.entries);
            rows.extend(listed);
            let Some(next) = page.next else {
                break;
            };
            if entries.len() >= total {
                break;
            }
            cursor = Some(next);
        }
        rows.sort_unstable();
        rows.dedup();
        Ok((entries, rows))
    }

    /// `body` over `runs`, each on what it saved, by hex run key: one
    /// body's pass over a regen's golden set (ARCH-0080 §8). Its verdicts
    /// come from the pins only: it asks no model.
    pub(super) fn hooks_replay_runs(
        &self,
        runtime: &dyn HookBodyRuntime,
        binding_id: EntityId,
        row: &PackHookBinding,
        body: &str,
        runs: &[SavedRun],
    ) -> Result<Vec<(String, HookReplayEntry)>> {
        self.replaying(
            runtime,
            None,
            binding_id,
            row,
            Ok(body.to_owned()),
            |replay, lane| {
                Ok(runs
                    .iter()
                    .map(|run| (hex_lower(run.key()), replay.saved(lane, run)))
                    .collect())
            },
        )
        .map(|(runs, _)| runs)
    }

    /// Runs `walk` with `row`'s replay, on its grant's reader's Recorded
    /// lane, beside the rows its entries stood on.
    fn replaying<T>(
        &self,
        runtime: &dyn HookBodyRuntime,
        verdict: Option<&dyn HookVerdict>,
        binding_id: EntityId,
        row: &PackHookBinding,
        body: std::result::Result<String, String>,
        walk: impl FnOnce(&Replay<'_>, &ScopedRead<'_>) -> Result<T>,
    ) -> Result<(T, Vec<EntityId>)> {
        let grant = effective_grant(self, binding_id, row)?;
        let memory = self.memory(grant.reader, filter::edge_class(grant.reader_class));
        let lane = memory
            .read_lane(ClaimReadStatus::Recorded)
            .map_err(|error| Error::InvalidConfig(format!("{}: {}", error.code, error.message)))?;
        let replay = Replay {
            vault: self,
            runtime,
            verdict,
            binding_id,
            binding: row,
            grant: &grant,
            body,
            // Only rows that exist: the binding id may be one no row holds
            // yet, so the stored-binding wrapper lists it (FIX 4710).
            rows: RefCell::new(vec![row.source]),
        };
        let walked = walk(&replay, &lane)?;
        let mut rows = replay.rows.into_inner();
        rows.sort_unstable();
        rows.dedup();
        Ok((walked, rows))
    }

    /// The body `row` binds, or why it does not load.
    fn bound_body(&self, row: &PackHookBinding) -> std::result::Result<String, String> {
        self.pack_hook_body(row)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|_| "hook body is not UTF-8".to_owned())
            })
    }
}

struct Replay<'r> {
    vault: &'r Vault,
    runtime: &'r dyn HookBodyRuntime,
    /// Answers `ai.verdict` on an entry no run pinned.
    verdict: Option<&'r dyn HookVerdict>,
    binding_id: EntityId,
    binding: &'r PackHookBinding,
    grant: &'r HookGrant,
    body: std::result::Result<String, String>,
    /// The rows its entries name and their bodies' reads served, so far.
    rows: RefCell<Vec<EntityId>>,
}

impl Replay<'_> {
    /// Lists the rows one verdict's evidence resolved to.
    fn heard(&self, evidence: &[EntityId]) {
        self.rows.borrow_mut().extend(evidence.iter().copied());
    }

    /// Lists every row `pins` served.
    fn served(&self, pins: &[HookReadPin]) {
        self.rows.borrow_mut().extend(
            pins.iter()
                .flat_map(|pin| pin.rows.iter().map(|row| row.id)),
        );
    }

    fn entry(&self, lane: &ScopedRead<'_>, entry: &FactEntry) -> Result<Option<HookReplayEntry>> {
        if !filter::verbs_admit_kind(&self.binding.selector.verbs, entry.kind) {
            return Ok(None);
        }
        let key = store::run_key(self.binding_id, self.binding, entry)?;
        let result = match store::memo(self.vault, &key)? {
            Some(memo) => self.from_memo(lane, &memo),
            None => match self.live(lane, entry)? {
                Some(result) => result,
                None => return Ok(None),
            },
        };
        self.rows.borrow_mut().push(entry.entity);
        Ok(Some(HookReplayEntry {
            case: HookReplayCase::Fact {
                source: entry.position.source(),
                position: entry.position.to_hex(),
                kind: entry.kind,
                entity: entry.entity,
            },
            result,
        }))
    }

    /// One saved run, on what it saved.
    fn saved(&self, lane: &ScopedRead<'_>, run: &SavedRun) -> HookReplayEntry {
        match run {
            SavedRun::Fact(_, memo) => {
                self.rows.borrow_mut().push(memo.entity);
                HookReplayEntry {
                    case: HookReplayCase::Fact {
                        source: memo.source,
                        position: FactPositionHex(format!(
                            "{}:{}",
                            memo.source.as_str(),
                            memo.position
                        )),
                        kind: memo.fact,
                        entity: memo.entity,
                    },
                    result: self.from_memo(lane, memo),
                }
            }
            SavedRun::Verb(key, saved) => HookReplayEntry {
                case: HookReplayCase::Verb {
                    run_key: hex_lower(key),
                    invocation: saved.invocation.to_hex(),
                    verb: saved.verb.clone(),
                    phase: saved.phase,
                },
                result: self.verb_run(lane, saved),
            },
        }
    }
}

/// Reads a replay serves only while each answers what the run's next pin
/// says it answered then.
struct PinnedReads<'p> {
    pins: &'p [HookReadPin],
    served: usize,
    scratch: Vec<HookReadPin>,
    /// The entry's reason once a read's history is gone.
    missing: Option<String>,
}

impl<'p> PinnedReads<'p> {
    const fn new(pins: &'p [HookReadPin]) -> Self {
        Self {
            pins,
            served: 0,
            scratch: Vec::new(),
            missing: None,
        }
    }

    fn answer(
        &mut self,
        lane: &ScopedRead<'_>,
        grant: &HookGrant,
        request: &str,
    ) -> std::result::Result<String, String> {
        // A read that fails fails as it did live, and was pinned by none.
        let live = read::answer(lane, grant, request, &mut self.scratch)?;
        let pinned = self.pins.get(self.served);
        self.served += 1;
        let hash = blake3::hash(live.as_bytes()).to_hex();
        if pinned.is_some_and(|pin| pin.request == request && pin.response_hash == hash.as_str()) {
            Ok(live)
        } else {
            self.missing
                .get_or_insert_with(|| format!("a read's history is gone: {}", bounded(request)));
            Err("this read's history is gone".to_owned())
        }
    }
}

/// Verdicts a replay answers from the run's pins, in order. It never asks a
/// model: a request that is not its pin byte for byte, or one past the
/// pins, is history gone.
struct PinnedVerdicts<'p> {
    pins: &'p [HookVerdictPin],
    asked: usize,
    missing: Option<String>,
}

impl<'p> PinnedVerdicts<'p> {
    const fn new(pins: &'p [HookVerdictPin]) -> Self {
        Self {
            pins,
            asked: 0,
            missing: None,
        }
    }

    /// The pinned reply, beside the rows its evidence resolved to; a gone
    /// history reads none.
    fn answer(&mut self, request: &str) -> (std::result::Result<String, String>, &'p [EntityId]) {
        let pinned = self.pins.get(self.asked);
        self.asked += 1;
        match pinned {
            Some(pin) if pin.request_json == request => match pin.evidence.as_deref() {
                Some(evidence) => (pin.reply.clone(), evidence),
                None => {
                    self.missing.get_or_insert_with(|| {
                        "a verdict's evidence rows are not known".to_owned()
                    });
                    (Err("this verdict's history is gone".to_owned()), &[])
                }
            },
            _ => {
                self.missing.get_or_insert_with(|| {
                    format!("a verdict's history is gone: {}", bounded(request))
                });
                (Err("this verdict's history is gone".to_owned()), &[])
            }
        }
    }
}

fn input_too_large() -> HookReplayResult {
    HookReplayResult::MissingHistory {
        reason: "the run's input was too large to pin".to_owned(),
    }
}

fn ran(
    verdict: Verdict,
    recorded: Option<&str>,
    recorded_outcome_json: Option<&str>,
    from_memo: bool,
    reads_live: bool,
) -> HookReplayResult {
    HookReplayResult::Ran {
        compare: compare(verdict.outcome_json.as_deref(), recorded_outcome_json),
        outcome_json: verdict.outcome_json,
        outcome: verdict.token,
        reason: verdict.reason,
        recorded: recorded.map(str::to_owned),
        recorded_outcome_json: recorded_outcome_json.map(str::to_owned),
        from_memo,
        reads_live,
    }
}

/// How `outcome` stands to `recorded`: equal as JSON values, key order
/// aside; text that is not JSON compares byte for byte.
fn compare(outcome: Option<&str>, recorded: Option<&str>) -> HookReplayCompare {
    let Some(recorded) = recorded else {
        return HookReplayCompare::Incomplete;
    };
    let same = outcome.is_some_and(|outcome| {
        match (
            serde_json::from_str::<Value>(outcome),
            serde_json::from_str::<Value>(recorded),
        ) {
            (Ok(outcome), Ok(recorded)) => outcome == recorded,
            _ => outcome == recorded,
        }
    });
    if same {
        HookReplayCompare::Same
    } else {
        HookReplayCompare::Differs
    }
}
