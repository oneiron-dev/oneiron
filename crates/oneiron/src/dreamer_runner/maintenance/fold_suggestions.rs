//! Fold suggestions per agent type (FIX 12572; owner 2026-11-03 20:31 and
//! 20:33, ledger engine-20261103-board-layout-addons and
//! engine-20261103-log-fold-by-kind): the Coach reads which kinds of spans
//! each agent type's runs fold, and how often they unfold them again, and
//! suggests a fold default for that agent type. A suggestion only: it lands
//! Proposed in the owner's run tray, and no run reads it back.
//! IDLE-FOLD-POLICY = A (E+ keeps, folds or lets the cache expire while an
//! agent waits) is untouched, and no model is called.
//!
//! An agent type is its AGENT_DEF row. A dispatch attempt's run is the code
//! run with the attempt's id (the resident pump's rule), so each fold ledger
//! joins to the definition its run was launched from. A run with no dispatch
//! attempt (a host action, a reader child, an off-record room) has no agent
//! type, and this pass does not read it.
//!
//! "Folds well" is read from behaviour: a fold the agent never unfolded is
//! kept. The suggested default is how old the agent's kept folds were when
//! it marked them: the median number of steps between a fold's last step
//! and the step it was marked at, beside the median span it folded.
//!
//! The pass suggests again only when an agent type's suggested defaults
//! change, so an unchanged habit does not fill the run tray every night.

use std::collections::{BTreeMap, BTreeSet};

use super::coach::{COACH_FOLD_DEFAULT_PREDICATE, COACH_FOLD_SUGGESTIONS_FACET};
use super::proposals;
use crate::agent_dispatch::{agent_dispatch_actor, decode_agent_dispatch_input};
use crate::attempt_queue::dispatch_payload::AGENT_DISPATCH_ATTEMPT_TYPE;
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::compaction::{FOLD_LEDGERS, FoldKind, FoldLedger};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Result, Vault, WriteEnvelope};

/// The fewest runs of one agent type that folded one kind before the Coach
/// suggests a default for it. Canon names no number: three runs, so one
/// task's habit is not taken for the agent type's.
const FOLD_SUGGESTION_MIN_RUNS: usize = 3;
/// The largest share of one kind's folds, in percent, the agent type may
/// have unfolded again for that kind still to count as folded well. Canon
/// names no number: one in five.
const FOLD_SUGGESTION_MAX_UNFOLD_PERCENT: u64 = 20;
const STATE_DOMAIN: &[u8] = b"oneiron:coach-fold-suggestions:v1";

/// A hash of the defaults the Coach last suggested for one agent type, so an
/// unchanged habit is not suggested again. Key: id16 of the AGENT_DEF row.
const SUGGESTED: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::COACH_FOLD_SUGGESTED);

/// The kind a suggestion names: a fold by kind, or whole steps.
fn kind_name(kind: Option<FoldKind>) -> &'static str {
    kind.map_or("whole_step", FoldKind::as_str)
}

/// What one agent type's runs folded of one kind.
#[derive(Default)]
struct KindTally {
    runs: BTreeSet<EntityId>,
    folds: u64,
    unfolded: u64,
    /// For each kept fold, the steps between its last step and the step it
    /// was marked at.
    kept_ages: Vec<u64>,
    /// For each kept fold, the steps it spans.
    kept_spans: Vec<u64>,
}

/// One agent type's folds, by kind.
struct AgentFolds {
    /// The definition's `agent_id`, as its runs were launched with it.
    agent_id: String,
    kinds: BTreeMap<&'static str, KindTally>,
}

/// One suggested fold default.
struct FoldSuggestion {
    kind: &'static str,
    /// Fold this kind once it is this many steps old; `None` when no kept
    /// fold recorded the step it was marked at.
    keep_last_steps: Option<u64>,
    median_span_steps: u64,
    runs: usize,
    folds: u64,
    unfolded: u64,
}

/// One pass over every dispatched agent run's fold ledger. An agent type
/// whose suggestion cannot land is left for the next night; the others
/// still run.
pub(super) fn run(vault: &Vault, attempt: &DreamerAdmittedAttempt, now: u64) -> Result<()> {
    vault.require_coach_attempt(attempt, COACH_FOLD_SUGGESTIONS_FACET)?;
    let agents = tally(vault)?;
    if agents.is_empty() {
        return Ok(());
    }
    let envelope = proposals::run_tray_envelope(
        vault,
        COACH_FOLD_SUGGESTIONS_FACET,
        attempt.status.attempt.id,
    )?;
    for (definition, agent) in &agents {
        let suggestions = agent.suggestions();
        if suggestions.is_empty() {
            continue;
        }
        if let Err(error) = suggest(vault, &envelope, *definition, agent, &suggestions, now) {
            tracing::warn!(kind = ?error.kind(), "a fold suggestion did not land");
        }
    }
    Ok(())
}

/// Every dispatched agent run's folds, by its agent type. The queue's live
/// attempts bound the read, as the health review's do.
fn tally(vault: &Vault) -> Result<BTreeMap<EntityId, AgentFolds>> {
    let attempts = AttemptQueue::new(vault).list()?;
    let txn = vault.store.env.read_txn()?;
    let mut agents = BTreeMap::new();
    for record in &attempts {
        let Some((definition, agent_id)) = dispatched_definition(record) else {
            continue;
        };
        let Ok(run) = EntityId::from_bytes(*record.id.as_bytes()) else {
            continue;
        };
        // A ledger that does not decode is read as no folds.
        let Ok(Some(ledger)) = FOLD_LEDGERS.get(&vault.store, &txn, &run) else {
            continue;
        };
        if ledger.folds.is_empty() {
            continue;
        }
        agents
            .entry(definition)
            .or_insert_with(|| AgentFolds {
                agent_id,
                kinds: BTreeMap::new(),
            })
            .read(run, &ledger);
    }
    Ok(agents)
}

/// The AGENT_DEF row an agent-dispatch attempt launched, with the
/// definition's `agent_id` as it was frozen at dispatch.
fn dispatched_definition(record: &AttemptRecord) -> Option<(EntityId, String)> {
    if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
        return None;
    }
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    let input = decode_agent_dispatch_input(&payload.input).ok()?;
    let definition = agent_dispatch_actor(&input).ok()?.entity_ref();
    Some((definition, input.definition.agent_id.clone()))
}

impl AgentFolds {
    fn read(&mut self, run: EntityId, ledger: &FoldLedger) {
        for fold in &ledger.folds {
            let tally = self.kinds.entry(kind_name(fold.kind)).or_default();
            tally.runs.insert(run);
            tally.folds = tally.folds.saturating_add(1);
            if ledger.unfolds.iter().any(|append| append.fold == fold.fold) {
                tally.unfolded = tally.unfolded.saturating_add(1);
                continue;
            }
            if let Some(at) = fold.marked_at {
                tally.kept_ages.push(at.saturating_sub(fold.through));
            }
            tally
                .kept_spans
                .push(fold.through.saturating_sub(fold.from).saturating_add(1));
        }
    }

    /// The defaults this agent type folds well enough to suggest.
    fn suggestions(&self) -> Vec<FoldSuggestion> {
        self.kinds
            .iter()
            .filter_map(|(kind, tally)| tally.suggestion(*kind))
            .collect()
    }
}

impl KindTally {
    fn suggestion(&self, kind: &'static str) -> Option<FoldSuggestion> {
        if self.runs.len() < FOLD_SUGGESTION_MIN_RUNS
            || self.unfolded.saturating_mul(100)
                > self
                    .folds
                    .saturating_mul(FOLD_SUGGESTION_MAX_UNFOLD_PERCENT)
        {
            return None;
        }
        Some(FoldSuggestion {
            kind,
            keep_last_steps: median(&self.kept_ages),
            median_span_steps: median(&self.kept_spans)?,
            runs: self.runs.len(),
            folds: self.folds,
            unfolded: self.unfolded,
        })
    }
}

/// The upper median, or `None` for no values.
fn median(values: &[u64]) -> Option<u64> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.get(sorted.len() / 2).copied()
}

impl FoldSuggestion {
    fn value(&self, definition: EntityId, agent_id: &str) -> serde_json::Value {
        serde_json::json!({
            "agent": definition.to_hex(),
            "agent_id": agent_id,
            "kind": self.kind,
            "keep_last_steps": self.keep_last_steps,
            "median_span_steps": self.median_span_steps,
            "runs": self.runs,
            "folds": self.folds,
            "unfolded": self.unfolded,
        })
    }
}

/// A hash of the defaults themselves, never of the counts behind them.
fn suggestion_state(definition: EntityId, suggestions: &[FoldSuggestion]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(STATE_DOMAIN);
    hash.update(definition.as_bytes());
    for suggestion in suggestions {
        hash.update(suggestion.kind.as_bytes());
        hash.update(&[0]);
        hash.update(&suggestion.keep_last_steps.unwrap_or(u64::MAX).to_be_bytes());
        hash.update(&suggestion.median_span_steps.to_be_bytes());
    }
    *hash.finalize().as_bytes()
}

/// One agent type's suggestions in one write: one Proposed finding per kind,
/// citing the definition, filed only when the defaults changed since the
/// last suggestion.
fn suggest(
    vault: &Vault,
    envelope: &WriteEnvelope,
    definition: EntityId,
    agent: &AgentFolds,
    suggestions: &[FoldSuggestion],
    now: u64,
) -> Result<()> {
    let state = suggestion_state(definition, suggestions);
    vault.with_write_txn_grouped(|txn| {
        if SUGGESTED.get(&vault.store, &*txn, &definition)? == Some(state) {
            return Ok(());
        }
        for suggestion in suggestions {
            proposals::emit_in_txn(
                vault,
                txn,
                definition,
                COACH_FOLD_DEFAULT_PREDICATE,
                &suggestion.value(definition, &agent.agent_id),
                &[definition],
                envelope,
                now,
            )?;
        }
        SUGGESTED.put(&vault.store, txn, &definition, &state)
    })
}
