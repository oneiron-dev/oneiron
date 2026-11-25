//! The arm reads, `vault.arms.get` and `vault.arms.list`, under the proof
//! `verb_grant_caller`: the owner reads every arm; an agent whose live owner
//! Grant lists the verb reads the arms of each line that Grant reaches, and
//! no other ([`Memory::verb_grant_caller_admits_over_in_txn`]). An arm the
//! caller may not read answers as one that does not exist.
use std::collections::BTreeMap;

use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};

use super::{ArmList, ArmListRequest, ArmRef, ArmView};

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
/// `input`'s filters, newest first.
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
    let mut arms = Vec::new();
    for arm in vault.experiment_arms_in_txn(&txn)? {
        if line.is_some_and(|line| line != arm.line)
            || family.is_some_and(|family| family != arm.family)
            || (input.open_only && !arm.is_open())
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
            arms.push(ArmView::of(arm, false));
        }
    }
    arms.sort_by(|a, b| (b.arm.admitted_at_ms, b.arm.id).cmp(&(a.arm.admitted_at_ms, a.arm.id)));
    Ok(ArmList { arms })
}

/// Whether the admitted caller may read the line of `project`: a refusal of
/// the line cover hides the line; any other error stands.
fn reads_line_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: Option<&AuthenticatedOwner>,
    verb: &str,
    project: EntityId,
) -> MemoryResult<bool> {
    match memory.verb_grant_caller_admits_over_in_txn(txn, owner, verb, project) {
        Ok(_) => Ok(true),
        Err(error) if error.code == MEMORY_CODE_FORBIDDEN => Ok(false),
        Err(error) => Err(error),
    }
}
