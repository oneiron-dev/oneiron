//! The arm reads, `vault.arms.get` and `vault.arms.list`, under the proof
//! `verb_grant_caller`: the owner reads every arm; an agent whose live owner
//! Grant lists the verb reads the arms of each line that Grant reaches
//! ([`Memory::verb_grant_caller_admits_over_in_txn`]) and holds a role on
//! (lead, reviewer or planner; design r2 section 5.1), and no other. An arm
//! the caller may not read answers as one that does not exist.
use std::collections::BTreeMap;

use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::gpu_line::{LineRole, doors_caller, line_in_txn};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};

use super::{ArmList, ArmListRequest, ArmRef, ArmView, forecast_scores as forecast_scores_of};

/// The verb that reads one arm.
pub const ARMS_GET_VERB: &str = "vault.arms.get";
/// The verb that lists arms.
pub const ARMS_LIST_VERB: &str = "vault.arms.list";

/// `vault.arms.get` as `memory`'s caller, with the owner's own proof when
/// its credential is owner-grade: the arm `input` names, when the caller may
/// read its line.
///
/// # Errors
///
/// `bad_request` for an id that does not parse; `forbidden` for a caller
/// the verb does not admit; `not_found` for an arm that is not stored or
/// whose line the caller may not read; a store read failure.
pub fn arm_get_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &ArmRef,
) -> MemoryResult<ArmView> {
    let id = input.id()?;
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    memory.verb_grant_caller_admits_in_txn(&txn, owner, ARMS_GET_VERB)?;
    match vault.experiment_arm_in_txn(&txn, &id)? {
        Some(arm) if reads_line_in_txn(memory, &txn, owner, ARMS_GET_VERB, arm.line)? => {
            Ok(ArmView::of(arm, false))
        }
        Some(_) | None => Err(MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "no experiment arm of a line the caller may read has this id",
            &["List the arms with vault.arms.list."],
        )),
    }
}

/// `vault.arms.list` as `memory`'s caller: the arms it may read under
/// `input`'s filters, newest first, and the forecast scores of each line it
/// reads over the arms the line and family filters select.
///
/// # Errors
///
/// `bad_request` for a filter id that does not parse; `forbidden` for a
/// caller the verb does not admit; a store read failure.
pub fn arm_list_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &ArmListRequest,
) -> MemoryResult<ArmList> {
    let (line, family) = input.filters()?;
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    memory.verb_grant_caller_admits_in_txn(&txn, owner, ARMS_LIST_VERB)?;
    let mut readable: BTreeMap<EntityId, bool> = BTreeMap::new();
    let mut selected = Vec::new();
    for arm in vault.experiment_arms_in_txn(&txn)? {
        if line.is_some_and(|line| line != arm.line)
            || family.is_some_and(|family| family != arm.family)
        {
            continue;
        }
        let reads = match readable.get(&arm.line) {
            Some(reads) => *reads,
            None => {
                let reads = reads_line_in_txn(memory, &txn, owner, ARMS_LIST_VERB, arm.line)?;
                readable.insert(arm.line, reads);
                reads
            }
        };
        if reads {
            selected.push(arm);
        }
    }
    let mut forecast_scores = Vec::new();
    for (line, reads) in readable {
        if !reads {
            continue;
        }
        // pass 34: the threshold is the line's own setting; an arm whose line
        // is gone (only the owner reads it) scores at the engine's default.
        let score_after = line_in_txn(vault, &txn, &line)?.map_or(
            crate::gpu_line::defaults::FORECAST_SCORE_AFTER,
            |gpu_line| gpu_line.budget.forecast_score_after,
        );
        forecast_scores.extend(forecast_scores_of(line, &selected, score_after));
    }
    let mut arms: Vec<ArmView> = selected
        .into_iter()
        .filter(|arm| !input.open_only || arm.is_open())
        .map(|arm| ArmView::of(arm, false))
        .collect();
    arms.sort_by(|a, b| (b.arm.admitted_at_ms, b.arm.id).cmp(&(a.arm.admitted_at_ms, a.arm.id)));
    Ok(ArmList {
        arms,
        forecast_scores,
    })
}

/// Whether the admitted caller may read the line of `project`: the line
/// cover, then a role on the line. A refusal of either hides the line; any
/// other error stands. Only the owner reads an arm whose line is gone.
fn reads_line_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: Option<&AuthenticatedOwner>,
    verb: &str,
    project: EntityId,
) -> MemoryResult<bool> {
    let hidden = |error: MemoryError| {
        if error.code == MEMORY_CODE_FORBIDDEN {
            Ok(false)
        } else {
            Err(error)
        }
    };
    let caller = match doors_caller::admit_in_txn(memory, txn, owner, verb, project) {
        Ok(caller) => caller,
        Err(error) => return hidden(error),
    };
    let Some(line) = line_in_txn(memory.vault(), txn, &project)? else {
        return Ok(caller.owner().is_some());
    };
    match caller.require_role(&line, &READ_ROLES, verb) {
        Ok(()) => Ok(true),
        Err(error) => hidden(error),
    }
}

/// The roles that read a line's arms: any of the three.
const READ_ROLES: [LineRole; 3] = [LineRole::Lead, LineRole::Reviewer, LineRole::Planner];
