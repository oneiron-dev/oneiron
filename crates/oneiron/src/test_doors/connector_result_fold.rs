//! Doors for `tests/connector_result_fold.rs` (FIX 14541): a run's steps with their consoles and
//! the `connector.call`s each made, a fold mark by kind, the folds the idle pass seals for the
//! run's marks (with no model call) landed in its ledger, and the stub a step's console shows as
//! the request renders it. Compiled only under `--cfg oneiron_test_support`; never API.

use crate::code_run::{
    AgentVerbAnswer, CodeRunBridgeCall, CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord,
    CodeRunStepCheckpoint, ExecutorStorage, SelfAgentVerbCall, SelfCall, SelfDispatchOutcome,
};
use crate::compaction::{FoldKind, FoldMark};
use crate::task_verb::sdk::AgentVerb;
use crate::{EntityId, Error, Result, Vault};

/// One `connector.call` a seeded step made: the connector and tool it named, and the reply it got
/// (a `connector.call` reply, tagged by `outcome`).
#[doc(hidden)]
pub struct SeededConnectorCall {
    pub name: &'static str,
    pub tool: &'static str,
    pub reply: serde_json::Value,
}

/// One step of a seeded run: its console, and its own `connector.call`s, in order.
#[doc(hidden)]
pub struct SeededStep {
    pub console: &'static [u8],
    pub calls: Vec<SeededConnectorCall>,
}

/// Writes `run`'s replay record with one step per entry of `steps`: each step's console stored as
/// the executor stores it, its calls appended to the run's bridge calls, and its checkpoint keeping
/// their range, as a REPL step's does.
///
/// # Errors
/// A call that does not record, and storage.
#[doc(hidden)]
pub fn seed_steps(vault: &Vault, run: EntityId, steps: &[SeededStep]) -> Result<()> {
    let mut record = CodeRunReplayRecord::new(run, CodeRunDeterminism::new(0, [0; 32]));
    for (seq, step) in (0_u64..).zip(steps) {
        let output = CodeRunRawOutput::from_bytes(
            crate::engine_executor::observation_output_path(seq),
            step.console,
        )?;
        vault.put_code_run_raw_output(Some(run), &output, step.console)?;
        record.outputs.push(output);
        let start = record.bridge_calls.len();
        for call in &step.calls {
            let made = SelfCall::AgentVerb(SelfAgentVerbCall {
                verb: AgentVerb::ConnectorCall,
                input: serde_json::json!({
                    "name": call.name,
                    "tool": call.tool,
                    "arguments": {},
                }),
            });
            let answer =
                SelfDispatchOutcome::AgentVerb(AgentVerbAnswer::new(call.reply.clone(), None));
            record.bridge_calls.push(CodeRunBridgeCall::record(
                record.bridge_calls.len() as u64,
                &made,
                &answer,
                0,
                0,
            )?);
        }
        let end = record.bridge_calls.len();
        record.step_checkpoints.push(
            CodeRunStepCheckpoint::new(seq, format!("t{seq}"), [0; 32], 0)?
                .ending_at(end as u64)
                .with_bridge_calls(start, end),
        );
    }
    vault.put_code_run_replay_record(&record)
}

/// Marks `run`'s steps `from` through `through` for a fold of `kind` (by its name), as the fold
/// verb does at step `through`; returns the mark's fold number.
///
/// # Errors
/// An unknown kind name, and storage.
#[doc(hidden)]
pub fn mark_kind_fold(
    vault: &Vault,
    run: EntityId,
    kind: &str,
    (from, through): (u64, u64),
) -> Result<u64> {
    let kind: FoldKind = serde_json::from_value(serde_json::Value::from(kind))
        .map_err(|_| Error::InvalidConfig(format!("`{kind}` names no fold kind")))?;
    ExecutorStorage::Canonical(vault).update_code_run_folds(run, |ledger| {
        ledger.last = ledger.last.saturating_add(1);
        ledger.marks.push(FoldMark {
            fold: ledger.last,
            from,
            through,
            note: None,
            failed: None,
            kind: Some(kind),
            marked_at: Some(through),
        });
        ledger.last
    })
}

/// One fold by kind the idle pass sealed: its number, its kind's name, and what each step it
/// folded keeps.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFoldView {
    pub fold: u64,
    pub kind: &'static str,
    pub steps: Vec<SealedStepView>,
}

/// One step a sealed fold folded: its seq, how many handles its stub keeps, and each connector
/// call that replied in it, as `(verb, bridge call)`.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedStepView {
    pub step: u64,
    pub handles: usize,
    pub connector_calls: Vec<(String, u64)>,
}

/// Seals `run`'s pending kind marks from durable state, as a parked run's idle fold does (with
/// `actor` as the byline and no model call), lands them in the run's ledger, and answers each
/// fold it landed. Empty when no mark applies.
///
/// # Errors
/// Storage.
#[doc(hidden)]
pub fn seal_kind_folds(
    vault: &Vault,
    run: EntityId,
    actor: EntityId,
) -> Result<Vec<SealedFoldView>> {
    let sealed =
        crate::engine_executor::parked_kind_folds(vault, run, actor).map_err(seal_error)?;
    let Some(sealed) = sealed else {
        return Ok(Vec::new());
    };
    let views = sealed
        .records
        .iter()
        .map(|fold| SealedFoldView {
            fold: fold.fold,
            kind: fold.kind.map_or("whole_step", FoldKind::as_str),
            steps: fold
                .outputs
                .iter()
                .map(|output| SealedStepView {
                    step: output.step,
                    handles: output.handles.len(),
                    connector_calls: output
                        .connector_calls
                        .iter()
                        .map(|call| (call.verb.clone(), call.call))
                        .collect(),
                })
                .collect(),
        })
        .collect();
    ExecutorStorage::Canonical(vault)
        .update_code_run_folds(run, |ledger| ledger.land(sealed.records, &[]))?;
    Ok(views)
}

/// The stub step `seq`'s console shows, as the request renders it before masking, with the
/// fold's note: from the first console fold (`repl_output`, `connector_result`) that landed over
/// it. `None` when no console fold covers it.
///
/// # Errors
/// Storage, and a run with no replay record.
#[doc(hidden)]
pub fn console_stub(vault: &Vault, run: EntityId, seq: u64) -> Result<Option<String>> {
    let storage = ExecutorStorage::Canonical(vault);
    let ledger = storage.code_run_folds(run)?;
    let record = storage
        .get_code_run_replay_record(&run)?
        .ok_or(Error::CorruptedIndex("seeded run has no replay record"))?;
    Ok(ledger
        .console_covering(seq)
        .and_then(|fold| crate::engine_executor::console_fold_stub(fold, &record, seq, true)))
}

/// The vault's own error under an executor error the seal returned, as the idle pass reads it.
fn seal_error(error: crate::engine_executor::EngineExecutorError) -> Error {
    match error {
        crate::engine_executor::EngineExecutorError::Engine(error) => error,
        _ => Error::InvariantViolation("a seeded run's kind folds did not seal"),
    }
}
