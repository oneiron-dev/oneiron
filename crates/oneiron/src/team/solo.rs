//! FIX 11532: the solo close writer - a solo run's team receipt.
//!
//! Solo runs close through the agent/workflow/Dreamer pumps, none of which
//! calls `record_team_receipt`, so the learned view never shows the `solo`
//! pattern and model rows omit solo runs. The writer records the SAME
//! `TeamReceipt` shape for a solo run, keyed by its run id, so the
//! receipt-generic readers (the payoff table, the choice-learning folds,
//! the planner card) see solo rows with no reader changes.
//!
//! The writer self-gates on bound solo attribution: it writes only for a
//! run whose bound attribution carries the single `solo` role, or - where
//! nothing bound - for an `agent.dispatch` run dispatched with no team that
//! ran. Anywhere else it is a truthful no-op: team members, wrappers,
//! non-agent kinds and never-ran leaves write nothing.

use std::collections::BTreeMap;

use crate::Vault;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatcher, decode_agent_dispatch_input,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Result;
use crate::learning::TypeRef;
use crate::self_heal::audit::ObjectiveConfession;

use super::pattern::{TeamAxis, TeamPattern};
use super::receipt::{DecidedBy, TeamReceipt, TeamShape, record_team_receipt, team_receipt_in_txn};

/// How far back the retry chain is walked for the run's first try
/// (precedent: `TOTAL_HOPS_PER_CALL` in `autoreason_campaign::authoring`).
const RETRY_CHAIN_LIMIT: usize = 256;

/// Records the solo run's team receipt once. Returns whether it wrote one
/// now (FIX 11532). Never fails a close: storage errors propagate to the
/// hook, which logs and continues.
///
/// # Errors
///
/// Storage errors, a malformed dispatch payload, a workflow target with no
/// agent actor, and a receipt the contract refuses.
pub fn record_solo_receipt(vault: &Vault, attempt: AttemptId, now: u64) -> Result<bool> {
    let Some(status) = DreamerRunnerStore::new(vault).status(attempt)? else {
        return Ok(false);
    };
    let input = if status.payload.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE {
        Some(decode_agent_dispatch_input(&status.payload.input)?)
    } else {
        None
    };
    let txn = vault.store.env.read_txn()?;
    let attribution = crate::receipt::attempt_pack_attribution_in_txn(&vault.store, &txn, attempt)?;
    // The solo gate: bound solo attribution, else a ran agent dispatch with
    // no team (covers bind-failure runs; a run that ran is a row). The run
    // ran when its executor stamped the try or the try left a result.
    let ran = status.attempt.executor_model.is_some() || status.attempt.result_ref.is_some();
    let solo = match &attribution {
        Some(fields) => crate::skill_attribution::is_solo_attribution(fields),
        None => input
            .as_ref()
            .is_some_and(|input| input.team.is_none() && ran),
    };
    if !solo {
        return Ok(false);
    }
    let team_ref = format!("solo:{}", bytes_to_hex_lower(attempt.as_bytes()));
    if team_receipt_in_txn(vault, &txn, &team_ref)?.is_some() {
        return Ok(false);
    }
    let project = attribution
        .as_ref()
        .and_then(|fields| fields.project)
        .or_else(|| input.as_ref().and_then(|input| input.project_ref));
    let type_ref = match (&attribution, &input) {
        (Some(fields), _) => fields.type_ref.clone(),
        (None, Some(input)) => TypeRef::from(&input.type_ref),
        // Unreached: the gate passed with neither bound attribution nor a
        // dispatch input. The unsure placement, never untyped.
        (None, None) => crate::task_type::type_tree(vault, None)?.root(),
    };
    let models = match &attribution {
        // Already `id@revision`: the attribution door enforces it.
        Some(fields) => vec![fields.executor.clone()],
        // The stamp the try loaded under, else the seat its run was born on;
        // neither is unknown, never a refusal (FIX 10192).
        None => crate::skill_attribution::run_executor_model_in_txn(vault, &txn, &status.attempt)?
            .into_iter()
            .collect(),
    };
    let actor = match (&attribution, &input) {
        (Some(fields), _) => fields.decider,
        (None, Some(input)) => input.target.agent_definition_ref()?,
        // Unreached, as for `type_ref`: with neither, writing nothing is the
        // safe direction.
        (None, None) => return Ok(false),
    };
    let confessions = match vault.sealed_attempt_receipt_in_txn(&txn, attempt)? {
        // One sealed try: its flaw count, 1 or 0.
        Some(seal) => Some(u32::from(
            seal.confession
                .objectives
                .iter()
                .any(ObjectiveConfession::confesses_flaw),
        )),
        None => None,
    };
    let dispatcher = AgentDispatcher::new(vault);
    let scope = dispatcher.attempt_spend_scope_in_txn(&txn, attempt)?;
    let spend_units = match &scope {
        // An open scope is unmeasurable; a stated cap still reads below.
        Some(scope) if scope.closed_at.is_some() => Some(scope.spent_units),
        _ => None,
    };
    let cap_units = match &scope {
        Some(scope) => Some(
            dispatcher
                .spend_read_at_in_txn(&txn, &scope.scope)?
                .cap_units,
        ),
        None => None,
    };
    #[allow(clippy::cast_precision_loss)]
    let (spend, spend_cap) = (
        spend_units.map(|units| units as f64),
        cap_units.map(|units| units as f64),
    );
    let run = EntityId::from_bytes(*attempt.as_bytes())?;
    let calls = match vault.get_code_run_replay_record_in_txn(&txn, &run)? {
        Some(record) => Some(u64::try_from(record.bridge_calls.len()).unwrap_or(u64::MAX)),
        None => None,
    };
    let earliest = earliest_try_created_at(vault, &txn, &status.attempt)?;
    let receipt = TeamReceipt {
        team_ref,
        project,
        type_ref,
        pattern: TeamPattern::Solo,
        // A solo run loads no pattern skill: its signal lives in the
        // receipts L09 folds, never in a pattern cell.
        pattern_skill: None,
        axis: TeamAxis::Converge,
        models,
        shape: TeamShape {
            width: 1,
            roles: BTreeMap::from([("solo".to_owned(), 1)]),
        },
        decided_by: DecidedBy::Leader { actor },
        // Solo runs fill no campaign grid.
        coverage: None,
        confessions,
        spend,
        spend_cap,
        elapsed_secs: now.saturating_sub(earliest),
        calls,
        outcome: None,
        at: now,
    };
    drop(txn);
    receipt.validate()?;
    record_team_receipt(vault, &receipt)?;
    Ok(true)
}

/// The run's first try: `record`'s `created_at`, back along the tries it
/// retries, at most `RETRY_CHAIN_LIMIT` hops. A missing row ends the walk;
/// the minimum over the tries seen is kept.
fn earliest_try_created_at(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
) -> Result<u64> {
    let queue = AttemptQueue::new(vault);
    let mut earliest = record.created_at;
    let mut next = record.retry_of;
    for _ in 0..RETRY_CHAIN_LIMIT {
        let Some(id) = next else {
            break;
        };
        let Some(prior) = queue.get_in_txn(txn, id)? else {
            break;
        };
        earliest = earliest.min(prior.created_at);
        next = prior.retry_of;
    }
    Ok(earliest)
}
