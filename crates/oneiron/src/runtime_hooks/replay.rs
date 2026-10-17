//! `hooks.replay` (ARCH-0080 §6): runs a hook's body over past entries and
//! shows each outcome. It lands nothing. A run pinned its inputs, and replay
//! reuses them; where nothing is pinned and the entity has moved on, the entry
//! says history is missing rather than reading newer state.

use serde::Serialize;

use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::skill_hub::pack_catalog::{HookPhase, PackHookBinding};
use crate::{EntityId, Error, Result, Vault};

use super::body::HookBodyRuntime;
use super::filter;
use super::grant::{HookGrant, effective_grant};
use super::read;
use super::runner::{Verdict, bounded, input_json, judge};
use super::source::{self, FactEntry, FactKind, FactPositionHex, FactSource};
use super::store::{self, HookRunRecord};

/// Entries one replay returns at most.
const MAX_REPLAY_ENTRIES: usize = 256;
/// Entries one source read takes.
const REPLAY_BATCH: usize = 256;
/// Source reads one replay makes per source.
const MAX_REPLAY_BATCHES: usize = 64;

/// One past entry the hook takes, and what its body returns for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookReplayEntry {
    pub position: FactPositionHex,
    pub kind: FactKind,
    #[serde(with = "crate::serialize::entity_ref")]
    pub entity: EntityId,
    pub result: HookReplayResult,
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
        /// The input came from the run's pinned memo row.
        from_memo: bool,
        /// No run pinned this entry's reads; they read current rows.
        reads_live: bool,
    },
    /// The entry's inputs are gone: replay will not read newer state instead.
    MissingHistory { reason: String },
}

impl Vault {
    /// Replays `binding` over entries after `since` (every source from its
    /// start when `None`), returning at most `limit` entries the hook takes.
    pub fn hooks_replay(
        &self,
        runtime: &dyn HookBodyRuntime,
        binding: EntityId,
        since: Option<FactPositionHex>,
        limit: usize,
    ) -> Result<Vec<HookReplayEntry>> {
        self.hooks_replay_body(runtime, binding, None, since, limit)
    }

    /// [`Self::hooks_replay`] with `body` run in place of the bound one: a
    /// regen candidate over the hook's golden set (ARCH-0080 §8).
    pub(super) fn hooks_replay_body(
        &self,
        runtime: &dyn HookBodyRuntime,
        binding: EntityId,
        body: Option<String>,
        since: Option<FactPositionHex>,
        limit: usize,
    ) -> Result<Vec<HookReplayEntry>> {
        let (binding_id, row) = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .ok_or(Error::EntityNotFound)?;
        self.hooks_replay_binding(runtime, binding_id, &row, body, since, limit)
    }

    /// [`Self::hooks_replay_body`] over `row` as given, stored or not: a hub
    /// hook replays as the binding its Candidate pack would get, as its test
    /// (ARCH-0080 §9).
    pub(crate) fn hooks_replay_binding(
        &self,
        runtime: &dyn HookBodyRuntime,
        binding_id: EntityId,
        row: &PackHookBinding,
        body: Option<String>,
        since: Option<FactPositionHex>,
        limit: usize,
    ) -> Result<Vec<HookReplayEntry>> {
        if row.selector.phase != HookPhase::Fact {
            return Err(Error::InvalidConfig("only a fact hook replays".to_owned()));
        }
        let since = since.as_ref().map(FactPositionHex::parse).transpose()?;
        let limit = limit.clamp(1, MAX_REPLAY_ENTRIES);
        let grant = effective_grant(self, binding_id, row)?;
        let memory = self.memory(grant.reader, filter::edge_class(grant.reader_class));
        let lane = memory
            .read_lane(ClaimReadStatus::Recorded)
            .map_err(|error| Error::InvalidConfig(format!("{}: {}", error.code, error.message)))?;
        let replay = Replay {
            vault: self,
            runtime,
            binding_id,
            binding: row,
            grant: &grant,
            body: match body {
                Some(body) => Ok(body),
                None => self
                    .pack_hook_body(row)
                    .map_err(|error| error.to_string())
                    .and_then(|bytes| {
                        String::from_utf8(bytes).map_err(|_| "hook body is not UTF-8".to_owned())
                    }),
            },
        };
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
                let batch = source::read_after(self, source, after, REPLAY_BATCH)?;
                for entry in &batch.entries {
                    if entries.len() >= limit {
                        return Ok(entries);
                    }
                    if let Some(found) = replay.entry(&lane, entry)? {
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
}

struct Replay<'r> {
    vault: &'r Vault,
    runtime: &'r dyn HookBodyRuntime,
    binding_id: EntityId,
    binding: &'r PackHookBinding,
    grant: &'r HookGrant,
    body: std::result::Result<String, String>,
}

impl Replay<'_> {
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
            position: entry.position.to_hex(),
            kind: entry.kind,
            entity: entry.entity,
            result,
        }))
    }

    /// A run pinned this entry: its input as it was, and each read only when
    /// it answers what it answered then.
    fn from_memo(&self, lane: &ScopedRead<'_>, memo: &HookRunRecord) -> HookReplayResult {
        let Some(input) = memo.input_json.as_deref() else {
            return HookReplayResult::MissingHistory {
                reason: "the run's input was too large to pin".to_owned(),
            };
        };
        let mut missing: Option<String> = None;
        let mut served = 0_usize;
        let mut scratch = Vec::new();
        let result = match &self.body {
            Ok(body) => {
                let mut answer = |request: &str| {
                    let pinned = memo.reads.get(served);
                    served += 1;
                    let live = read::answer(lane, self.grant, request, &mut scratch)?;
                    let hash = blake3::hash(live.as_bytes()).to_hex();
                    if pinned.is_some_and(|pin| {
                        pin.request == request && pin.response_hash == hash.as_str()
                    }) {
                        Ok(live)
                    } else {
                        missing.get_or_insert_with(|| request.to_owned());
                        Err("this read's history is gone".to_owned())
                    }
                };
                self.runtime
                    .run_hook(body, input, self.binding.selector.budget_ms, &mut answer)
            }
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        if let Some(request) = missing {
            return HookReplayResult::MissingHistory {
                reason: format!("a read's history is gone: {}", bounded(&request)),
            };
        }
        ran(
            judge(self.binding, result),
            Some(memo.outcome.clone()),
            true,
            false,
        )
    }

    /// No run pinned this entry. The live entity stands in only while its
    /// body is the one the entry wrote.
    fn live(&self, lane: &ScopedRead<'_>, entry: &FactEntry) -> Result<Option<HookReplayResult>> {
        let Some(seen) = read::fact_row(lane, self.grant, entry.entity)? else {
            return Ok(None);
        };
        let actor = filter::actor_class(self.vault, entry.actor)?;
        if !filter::fact_matches(
            &self.binding.selector,
            entry.kind,
            seen.claim.as_ref(),
            actor,
        ) {
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
        let mut pins = Vec::new();
        let result = match &self.body {
            Ok(body) => {
                let mut answer = |request: &str| read::answer(lane, self.grant, request, &mut pins);
                self.runtime
                    .run_hook(body, &input, self.binding.selector.budget_ms, &mut answer)
            }
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        Ok(Some(ran(judge(self.binding, result), None, false, true)))
    }
}

fn ran(
    verdict: Verdict,
    recorded: Option<String>,
    from_memo: bool,
    reads_live: bool,
) -> HookReplayResult {
    HookReplayResult::Ran {
        outcome_json: verdict.outcome_json,
        outcome: verdict.token,
        reason: verdict.reason,
        recorded,
        from_memo,
        reads_live,
    }
}
