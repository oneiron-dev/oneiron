//! Durable, once-per-person soft-confirm notice for a companion commitment.
use super::{TaskAskAnswer, TaskAskWord};
use crate::{EntityId, Result, Vault};

pub(super) const SOFT_CONFIRM: &str = "tasks.ask_soft_confirm";

pub(super) fn notice(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group: EntityId,
    person: EntityId,
) -> Result<Option<super::TaskAskSoftConfirmNotice>> {
    let id = super::ask_record::derived_id(
        b"oneiron.tasks.ask.soft_confirm.v1",
        group,
        person.as_bytes(),
    )?;
    let Some(notice): Option<super::TaskAskSoftConfirmNotice> =
        super::ask_record::read(vault, txn, id, SOFT_CONFIRM)?
    else {
        return Ok(None);
    };
    let ask =
        super::ask_record::read_group(vault, txn, group)?.ok_or_else(super::ask_record::invalid)?;
    // A person's authenticated reply or an already-settled revision closes
    // confirmation; do not deliver a stale companion prompt afterwards.
    if super::ask_settlement::read_result(vault, txn, group)?.is_some()
        || super::ask_record::evidence_in(vault, txn, group, &ask)?
            .iter()
            .any(|entry| entry.source == super::TaskAskSource::Human && entry.person_ref == person)
    {
        return Ok(None);
    }
    if !ask.effective.what.commitment
        || notice.group_ref != group
        || notice.person_ref != person
        || notice.revision != ask.effective.what.revision
        || Some(notice.deadline) != ask.effective.until
        || !super::ask_record::evidence_in(vault, txn, group, &ask)?
            .iter()
            .any(|entry| {
                entry.source == super::TaskAskSource::Companion
                    && entry.person_ref == person
                    && entry.answer.word_ref == notice.companion_answer_ref
                    && entry.answer.task_ref == notice.task_ref
                    && entry.word.option == notice.option
            })
    {
        return Err(super::ask_record::invalid());
    }
    Ok(Some(notice))
}

pub(super) fn put_notice(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: (EntityId, EntityId),
    answer: &TaskAskAnswer,
    word: &TaskAskWord,
    effective: &super::TaskAskSpec,
    now: u64,
) -> Result<()> {
    let (group, person) = subject;
    let id = super::ask_record::derived_id(
        b"oneiron.tasks.ask.soft_confirm.v1",
        group,
        person.as_bytes(),
    )?;
    if super::ask_record::read::<super::TaskAskSoftConfirmNotice>(vault, txn, id, SOFT_CONFIRM)?
        .is_some()
    {
        return Ok(());
    }
    super::ask_record::put(
        vault,
        txn,
        id,
        SOFT_CONFIRM,
        &super::TaskAskSoftConfirmNotice {
            group_ref: group,
            revision: effective.what.revision,
            person_ref: person,
            companion_answer_ref: answer.word_ref,
            option: word.option.clone(),
            task_ref: answer.task_ref,
            deadline: effective.until.ok_or_else(super::ask_record::invalid)?,
        },
        now,
    )?;
    super::ask_soft_confirm_delivery::register(vault, txn, group, person)
}
