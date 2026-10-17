//! `hooks.replay` (ARCH-0080 §6): runs a hook's body over past entries and
//! shows each outcome beside the one its run recorded. It lands nothing. A
//! run pinned its input, its reads and its verdicts, and replay reuses them;
//! where nothing is pinned and the entity has moved on, the entry says
//! history is missing rather than reading newer state. A fact hook replays
//! over its sources, a verb hook over its newest saved runs.

use std::sync::Arc;
use std::time::{Duration, Instant};

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
use super::runner::{Verdict, ask_verdict, bounded, input_json, judge};
use super::source::{self, FactEntry, FactKind, FactPosition, FactPositionHex, FactSource};
use super::store::{self, HookReadPin, HookRunRecord, HookRunRef, HookVerdictPin, RunKey};
use super::verb::{HookVerbRunRecord, VERB_RUNS};

/// Entries one replay returns at most.
const MAX_REPLAY_ENTRIES: usize = 256;
/// Entries one source read takes.
const REPLAY_BATCH: usize = 256;
/// Source reads one replay makes per source.
const MAX_REPLAY_BATCHES: usize = 64;

/// One past entry the hook takes, and what its body returns for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookReplayEntry {
    pub case: HookReplayCase,
    pub result: HookReplayResult,
}

/// What a replayed entry is: a fact the hook took, or a verb run it saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "on", rename_all = "snake_case")]
pub enum HookReplayCase {
    /// A fact the hook took, at its source position.
    Fact {
        source: FactSource,
        position: FactPositionHex,
        kind: FactKind,
        #[serde(with = "crate::serialize::entity_ref")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookReplayCompare {
    /// The same outcome, as JSON.
    Same,
    /// Another outcome, or none where the run returned one.
    Differs,
    /// Nothing to compare with: the run kept no outcome, or none ran.
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
        let (binding_id, row) = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .ok_or(Error::EntityNotFound)?;
        self.hooks_replay_binding(runtime, verdict.as_deref(), binding_id, &row, since, limit)
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
        let limit = limit.clamp(1, MAX_REPLAY_ENTRIES);
        let body = self.bound_body(row);
        if row.selector.phase != HookPhase::Fact {
            if since.is_some() {
                return Err(Error::InvalidConfig(
                    "since is a fact position: a verb hook replays its newest runs".to_owned(),
                ));
            }
            let runs = saved_runs(self, binding_id, limit)?;
            return self.replaying(runtime, verdict, binding_id, row, body, |replay, lane| {
                Ok(runs.iter().map(|run| replay.saved(lane, run)).collect())
            });
        }
        let since = since.as_ref().map(FactPositionHex::parse).transpose()?;
        self.replaying(runtime, verdict, binding_id, row, body, |replay, lane| {
            replay.walk(lane, since, limit)
        })
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
    }

    /// Runs `walk` with `row`'s replay, on its grant's reader's Recorded
    /// lane.
    fn replaying<T>(
        &self,
        runtime: &dyn HookBodyRuntime,
        verdict: Option<&dyn HookVerdict>,
        binding_id: EntityId,
        row: &PackHookBinding,
        body: std::result::Result<String, String>,
        walk: impl FnOnce(&Replay<'_>, &ScopedRead<'_>) -> Result<T>,
    ) -> Result<T> {
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
        };
        walk(&replay, &lane)
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
}

impl Replay<'_> {
    /// The fact sources after `since`, or each from its start, until
    /// `limit` entries the hook takes.
    fn walk(
        &self,
        lane: &ScopedRead<'_>,
        since: Option<FactPosition>,
        limit: usize,
    ) -> Result<Vec<HookReplayEntry>> {
        let starts: Vec<_> = match since {
            Some(position) => vec![(position.source(), Some(position))],
            None => FactSource::ALL
                .iter()
                .map(|source| (*source, None))
                .collect(),
        };
        let mut entries = Vec::new();
        for (source, mut after) in starts {
            for _ in 0..MAX_REPLAY_BATCHES {
                let batch = source::read_after(self.vault, source, after, REPLAY_BATCH)?;
                for entry in &batch.entries {
                    if entries.len() >= limit {
                        return Ok(entries);
                    }
                    if let Some(found) = self.entry(lane, entry)? {
                        entries.push(found);
                    }
                }
                if !batch.more {
                    break;
                }
                after = batch.through;
            }
        }
        Ok(entries)
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
            SavedRun::Fact(_, memo) => HookReplayEntry {
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
            },
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

    /// A run pinned this entry: its input as it was, each read only when it
    /// answers what it answered then, and each verdict as the run heard it.
    fn from_memo(&self, lane: &ScopedRead<'_>, memo: &HookRunRecord) -> HookReplayResult {
        let Some(input) = memo.input_json.as_deref() else {
            return input_too_large();
        };
        if !memo.verdicts_complete {
            return HookReplayResult::MissingHistory {
                reason: "the run's verdicts were too large to pin".to_owned(),
            };
        }
        let mut reads = PinnedReads::new(&memo.reads);
        let mut verdicts = PinnedVerdicts::new(&memo.verdicts);
        let result = match &self.body {
            Ok(body) => self.runtime.run_fact_hook(
                body,
                input,
                self.binding.selector.budget_ms,
                &mut |request: &str| reads.answer(lane, self.grant, request),
                &mut |request: &str| verdicts.answer(request),
            ),
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        if let Some(reason) = reads.missing.or(verdicts.missing) {
            return HookReplayResult::MissingHistory { reason };
        }
        ran(
            judge(self.binding, result),
            Some(memo.outcome.as_str()),
            memo.outcome_json.as_deref(),
            true,
            false,
        )
    }

    /// A verb run saved this case: its input as it was, a post-hook's view
    /// of the result in it, and each read only when it answers what it
    /// answered then. A verb hook calls no model.
    fn verb_run(&self, lane: &ScopedRead<'_>, saved: &HookVerbRunRecord) -> HookReplayResult {
        let Some(input) = saved.input_json.as_deref() else {
            return input_too_large();
        };
        let mut reads = PinnedReads::new(&saved.reads);
        let result = match &self.body {
            Ok(body) => self.runtime.run_hook(
                body,
                input,
                self.binding.selector.budget_ms,
                &mut |request: &str| reads.answer(lane, self.grant, request),
            ),
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        if let Some(reason) = reads.missing {
            return HookReplayResult::MissingHistory { reason };
        }
        ran(
            judge(self.binding, result),
            Some(saved.outcome.as_str()),
            saved.outcome_json.as_deref(),
            true,
            false,
        )
    }

    /// No run pinned this entry. The live entity stands in only while its
    /// body is the one the entry wrote; a generative hook's verdicts ask the
    /// live ladder, as the runner would.
    fn live(&self, lane: &ScopedRead<'_>, entry: &FactEntry) -> Result<Option<HookReplayResult>> {
        let Some(seen) = read::fact_row(lane, self.grant, entry.entity)? else {
            return Ok(None);
        };
        let actor = filter::actor_class(self.vault, entry.actor)?;
        if !filter::fact_matches(
            self.vault,
            &self.binding.selector,
            entry.kind,
            entry.entity,
            seen.claim.as_ref(),
            actor,
        )? {
            return Ok(None);
        }
        if entry.body_hash != Some(seen.body_hash) {
            return Ok(Some(HookReplayResult::MissingHistory {
                reason: "the entity changed after this entry and no run pinned its input"
                    .to_owned(),
            }));
        }
        let now = self
            .vault
            .store
            .clock
            .now_recorded_at()
            .saturating_mul(1_000);
        let input = input_json(
            self.binding_id,
            self.binding,
            entry,
            actor,
            &seen.claim_json,
            now,
        )?;
        let budget_ms = self.binding.selector.budget_ms;
        let deadline = Instant::now() + Duration::from_millis(u64::from(budget_ms));
        let mut pins = Vec::new();
        let result = match &self.body {
            Ok(body) => {
                let mut answer = |request: &str| read::answer(lane, self.grant, request, &mut pins);
                let mut verdict = |request: &str| {
                    ask_verdict(self.binding, self.grant, self.verdict, request, deadline)
                };
                self.runtime
                    .run_fact_hook(body, &input, budget_ms, &mut answer, &mut verdict)
            }
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        Ok(Some(ran(
            judge(self.binding, result),
            None,
            None,
            false,
            true,
        )))
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

    fn answer(&mut self, request: &str) -> std::result::Result<String, String> {
        let pinned = self.pins.get(self.asked);
        self.asked += 1;
        match pinned {
            Some(pin) if pin.request_json == request => pin.reply.clone(),
            _ => {
                self.missing.get_or_insert_with(|| {
                    format!("a verdict's history is gone: {}", bounded(request))
                });
                Err("this verdict's history is gone".to_owned())
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
