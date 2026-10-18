//! Durable steps and landed compaction boundaries of an attached run.

use serde::{Deserialize, Serialize};

use crate::code_run::{
    ExecutorStorage,
    fold_api::{FoldHistoryRequest, FoldUnfoldRequest},
};
use crate::compaction::{FoldDescription, FoldList, FoldReply, FoldUnfold, SelfFoldCall};
use crate::task_verb::HostBinding;
use crate::{EntityId, Error, Result, Vault};

use super::store::{load_context_output, observation_output_path, script_output_path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoldHistory {
    pub run: String,
    /// Count of checkpointed steps, not an in-flight step or a caller's ordinal.
    pub completed_steps: u64,
    /// Last step covered by a committed epoch, inclusive; none before the first.
    pub compacted_through: Option<u64>,
    pub state: FoldList,
    pub folds: Vec<FoldDescription>,
    pub unfolds: Vec<FoldUnfold>,
    pub epochs: Vec<FoldHistoryEpoch>,
    pub steps: Vec<FoldHistoryStep>,
    pub next: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoldHistoryEpoch {
    pub summary_ref: String,
    pub epoch: u64,
    pub from: u64,
    pub through: u64,
    /// None when the source was withdrawn; the retained boundary remains.
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoldHistoryStep {
    pub step: u64,
    pub code: String,
    pub console: String,
}

/// Reads only checkpointed steps under the host's sealed live lease. The host
/// holds the run's guard and admits every returned source through its caller's
/// current read key before releasing any bytes. A pending compact ask is not
/// a settlement: only a landed fold or epoch in this snapshot proves one.
pub fn read_fold_history(
    vault: &Vault,
    proof: &HostBinding,
    input: &FoldHistoryRequest,
) -> Result<(FoldHistory, Vec<EntityId>)> {
    proof.leased_record(vault)?;
    let run = proof.executor_run().ok_or(Error::InvalidClaimBody(
        "history requires a host-bound executor run",
    ))?;
    if input.limit == 0 {
        return Err(Error::InvalidConfig(
            "history limit must be positive".into(),
        ));
    }
    let storage = ExecutorStorage::Canonical(vault);
    let record = storage
        .get_code_run_replay_record(&run)?
        .ok_or(Error::InvalidClaimBody(
            "the live run has no durable replay",
        ))?;
    let completed_steps = u64::try_from(record.step_checkpoints.len())
        .map_err(|_| Error::ArithmeticOverflow("executor step count"))?;
    let mut ledger = storage.code_run_folds(run)?;
    let epochs = storage.code_run_compaction_epochs(run)?;
    let compacted_through = epochs.iter().map(|(row, _)| row.last()).max();
    let decode = |value| {
        serde_json::from_value(value)
            .map_err(|_| Error::InvariantViolation("fold history state did not decode"))
    };
    let state: FoldReply<FoldList> =
        decode(ledger.answer(&SelfFoldCall::List, completed_steps, compacted_through))?;
    let FoldReply::Answer(state) = state else {
        return Err(Error::InvariantViolation("fold list was refused"));
    };
    let mut folds = Vec::new();
    for fold in ledger.folds.clone() {
        let description: FoldReply<FoldDescription> = serde_json::from_value(ledger.answer(
            &SelfFoldCall::Describe { fold: fold.fold },
            completed_steps,
            compacted_through,
        ))
        .map_err(|_| Error::InvariantViolation("fold description did not decode"))?;
        if let FoldReply::Answer(description) = description {
            folds.push(description);
        }
    }
    let mut sources = record.agent_verb_rows().ok_or_else(|| {
        Error::InvalidConfig("run history contains an answer with unlisted sources".into())
    })?;
    sources.extend(
        ledger
            .folds
            .iter()
            .flat_map(|fold| fold.sources.iter().copied()),
    );
    sources.extend(epochs.iter().map(|(row, _)| row.summary_id()));
    sources.sort_unstable();
    sources.dedup();
    let end = input
        .from
        .saturating_add(u64::try_from(input.limit).unwrap_or(u64::MAX))
        .min(completed_steps);
    let mut steps = Vec::new();
    for step in input.from..end {
        // The same withdrawal law as an executor unfold: raw turns whose
        // derived fold was withdrawn cannot be brought back by history.
        if ledger
            .covering(step)
            .is_some_and(|fold| fold.summary.is_none())
            || epochs
                .iter()
                .any(|(row, text)| row.covers(run, step) && text.is_none())
        {
            return Err(Error::InvalidConfig("history source was withdrawn".into()));
        }
        steps.push(FoldHistoryStep {
            step,
            code: load_context_output(&storage, &record, &script_output_path(step))?,
            console: load_context_output(&storage, &record, &observation_output_path(step))?,
        });
    }
    proof.leased_record(vault)?;
    Ok((
        FoldHistory {
            run: run.to_hex(),
            completed_steps,
            compacted_through,
            state,
            folds,
            unfolds: ledger.unfolds,
            epochs: epochs
                .into_iter()
                .map(|(row, text)| FoldHistoryEpoch {
                    summary_ref: row.summary_id().to_hex(),
                    epoch: row.epoch(),
                    from: row.first(),
                    through: row.last(),
                    text,
                })
                .collect(),
            steps,
            next: (end < completed_steps).then_some(end),
        },
        sources,
    ))
}

/// The existing ledger's description, under the same host lease and current
/// source admission as history. It reads no raw step merely to describe a fold.
pub fn read_fold_description(
    vault: &Vault,
    proof: &HostBinding,
    input: &FoldUnfoldRequest,
) -> Result<(FoldReply<FoldDescription>, Vec<EntityId>)> {
    proof.leased_record(vault)?;
    let run = proof.executor_run().ok_or(Error::InvalidClaimBody(
        "fold description requires a host-bound executor run",
    ))?;
    let storage = ExecutorStorage::Canonical(vault);
    let record = storage
        .get_code_run_replay_record(&run)?
        .ok_or(Error::InvalidClaimBody(
            "the live run has no durable replay",
        ))?;
    let step = u64::try_from(record.step_checkpoints.len())
        .map_err(|_| Error::ArithmeticOverflow("executor step count"))?;
    let prefix_end = storage
        .code_run_compaction_coverage(run)?
        .iter()
        .map(|row| row.last())
        .max();
    let mut ledger = storage.code_run_folds(run)?;
    let number = crate::compaction::parse_fold_handle(&input.fold)?;
    let mut sources = record.agent_verb_rows().ok_or_else(|| {
        Error::InvalidConfig("run history contains an answer with unlisted sources".into())
    })?;
    if let Some(fold) = ledger.fold(number) {
        sources.extend(fold.sources.iter().copied());
    }
    sources.sort_unstable();
    sources.dedup();
    let answer = serde_json::from_value(ledger.answer(
        &SelfFoldCall::Describe { fold: number },
        step,
        prefix_end,
    ))
    .map_err(|_| Error::InvariantViolation("fold description did not decode"))?;
    proof.leased_record(vault)?;
    Ok((answer, sources))
}
