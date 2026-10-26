//! A consult answer's word on the ask its consult belongs to.
//! Entry: `record_answer`.

use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "one consult answer over its writer and the owner proof"
)]
pub(in crate::task_verb) fn record_answer(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    body: &super::super::consult_result::TaskVerbBody,
    actor: crate::WriteActor,
    answer: (
        &super::super::TaskTerminalRecord,
        Option<&super::super::TaskAskOptionId>,
    ),
    owner: Option<&crate::consent::AuthenticatedOwner>,
    now: u64,
) -> Result<Option<EntityId>> {
    let (terminal, option) = answer;
    let Some(payload) = &body.consult else {
        return Ok(None);
    };
    let id = payload.correlation_ref;
    let Some(group) = read_group(vault, txn, id)? else {
        return Ok(None);
    };
    // Correlation alone NEVER confers group membership. A forged sibling may
    // settle itself, but cannot settle an unrelated handle or mutate siblings.
    if !group
        .members
        .iter()
        .any(|member| member.task == task.to_hex() && member.actor == actor.entity_ref().to_hex())
    {
        return Ok(None);
    }
    if let Some(super::super::ConsultResultSummary::Answer { evidence_refs }) = &terminal.summary {
        admit_word(
            vault,
            txn,
            id,
            &group,
            actor,
            &TaskAskWord {
                result_ref: terminal.result_ref.ok_or_else(invalid)?,
                option: option.cloned(),
                inform_for: None,
                companion_for: None,
                confirmation: None,
                provenance_refs: evidence_refs.iter().copied().collect(),
            },
            owner,
            now,
        )?;
    }
    Ok(Some(id))
}
